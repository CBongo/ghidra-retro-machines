/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package retromachines;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import static retromachines.BankDataflowEngine.position;

import retromachines.HelperDiscovery.HelperModel;

/**
 * Per-call-site helper <em>argument recovery</em>: what value a caller actually passed a
 * bank-switch helper, and the prologue/save-restore machinery that proves whether the caller's
 * register (or a memory cell it wrote) still holds that value by the time the helper's mechanism
 * reads it.
 *
 * <p>Extracted verbatim from {@code BoardBankAnalyzer}'s "Helper-call propagation" section (bead
 * grm-shnf, QR-12 increment 3b), one of three siblings split along the section's natural fault
 * lines -- see {@link HelperDiscovery}'s class javadoc for the shared move rationale (zero
 * {@code this.} references, zero non-static instance fields, every member already {@code static}
 * as of grm-shnf step 2, so the cut is compile-time verbatim rather than a behavior change).
 *
 * <p>This class holds {@link #recoverCallArgument}, {@link #valueSuppliedInsideHelper}, both
 * {@link #inboundArgumentCell} overloads, {@link #callSiteRegisters}, {@link #surviving} and
 * {@link #crossableWrapperJoin}; the prologue-preservation cluster (both
 * {@link #argumentSurvivesPrologue} overloads -- the {@link List}-of-{@link PrologueSegment} form
 * delegates to the three-address form, and the two were not split apart --
 * {@link #forgetCellsThePushMayHaveHit}, {@link #prologueSegments}, {@link #argumentReloadSource}
 * and {@link #writesStackPointer}); the shared {@link HelperModel} accessors
 * {@link #helperValueSite} and {@link #insideHelperEntry}; and {@link CallEffect}/{@code NO_HOOKS}.
 * {@code BoardBankAnalyzer.added()} never reaches this class directly (it calls only
 * {@link HelperDiscovery}'s and {@link SaveRestoreTrampolines}' entry points), but
 * {@code StoredValueScanner.findMatchingPush} reaches {@link #writesStackPointer} via a qualified
 * call, and {@link BankDataflowEngine} reaches {@link #recoverCallArgument} via
 * {@code import static} exactly as it did before this bead, since that method was already
 * {@code static} as of grm-shnf step 2.
 *
 * <p>Two residual cross-class edges, costing an import each and nothing more:
 * {@link HelperDiscovery#findCallEdgeWrappers} calls {@link #argumentSurvivesPrologue} and
 * {@link #prologueSegments} here, and {@link SaveRestoreTrampolines#restoresEntryBank} calls
 * {@link #insideHelperEntry} and {@link #argumentReloadSource} here -- both targets widened from
 * {@code private} to package-private {@code static} by this move (the same accepted category as
 * every prior QR-12 increment's visibility widenings), and {@link #writesStackPointer} was
 * already package-private since {@code StoredValueScanner} needed it.
 */
final class HelperArgumentRecovery {

	private HelperArgumentRecovery() {
	}

	/**
	 * Recovers the bank argument at a helper call site by running the shared backward scan
	 * for an immediate value in the register the helper actually reads ({@code LDA #bank /
	 * JSR SelectBank}, or the X/Y equivalent). The argument register is taken from the
	 * helper's own mechanism-write ({@link HelperDiscovery.HelperModel#argReg}) rather than guessed, so a
	 * caller that also loads an unrelated immediate into another register no longer misleads
	 * the scan. By the helper convention the register holds the <em>field value itself</em>,
	 * so no mechanism transform is applied beyond the field-local width mask -- the scan
	 * resolves in the helper's own mechanism's field-local {@code [0, width)} space (same
	 * convention as {@link BankSwitchStrategy#computeSwitch}). The recovered byte is then
	 * handed to the matched strategy's {@link BankSwitchStrategy#depositHelperArgument},
	 * which knows -- from the helper's own recognized {@link HelperDiscovery.HelperModel#switchSite} --
	 * whether this mechanism's field-local space is one field (the recovered byte deposits
	 * verbatim, owning the whole field-local width, the historical behavior) or several
	 * disjoint sub-fields keyed by which switch site is in play (serial-shift) OR by the
	 * caller's own TRACKED STATE at the call site (select-data -- a bare data-write helper's
	 * routing depends on whichever register the caller's select last picked, which the
	 * switch site's address alone cannot tell us): only that call knows which sub-field the
	 * recovered value actually commits through, and therefore which bits this call site may
	 * claim ownership of ({@link CallEffect#ownedMask} -- see
	 * {@link BankSwitchStrategy.HelperDeposit}'s javadoc for why that is tracked separately
	 * from the value's own known bits). To support the state-routed case, {@code callSiteIn}
	 * (the caller's board-absolute state under which this call executes -- the same
	 * {@code outState} {@link BankDataflowEngine#runDataflow} folds the call's own effect into) is narrowed to
	 * this helper's mechanism's field-local space exactly like {@code argValue} before being
	 * handed to {@link BankSwitchStrategy#depositHelperArgument}; a strategy whose routing is
	 * address-keyed instead (serial-shift) simply ignores it. Both the value and the
	 * owned-bits mask are positioned back into the board's absolute state bits before
	 * returning, exactly as a direct dataflow switch's result is. Returns an unknown value
	 * owning the WHOLE mechanism when the argument register itself is unknown (the helper's
	 * sites disagreed on it) -- conservatively wiping everything this helper's mechanism
	 * could possibly touch, the historical behavior for that degrade case.
	 * <p>
	 * <b>The "register holds the field value" convention is a fallback, not the whole story</b>
	 * (grm-hum increment 2). It is blind in three ways: the argument may arrive in a register
	 * other than the one the helper's mechanism write stores (Contra's helper takes its bank in
	 * Y and stores A, and {@link HelperDiscovery#findHelpers} can only see the store); the value may need the
	 * mechanism's own {@code shift}/{@code mask} extraction; and on a bus-conflict board the
	 * driven value is not the latched one. So this also hands the strategy the CALL SITE'S WHOLE
	 * REGISTER ENVIRONMENT ({@link #callSiteRegisters}), letting a strategy that can do better --
	 * {@code memory-latch} does -- re-evaluate its own switch site under those registers instead.
	 * {@code argValue} keeps its exact prior meaning either way, because {@code select-data}
	 * decodes a byte field out of it.
	 * <p>
	 * <b>The convention also assumes the helper does not eat its own argument</b> (grm-mu7).
	 * {@code argReg} is whatever register the mechanism write STORES, which is the only
	 * evidence {@link HelperDiscovery#findHelpers} has -- but a helper whose prologue reloads the bank from
	 * RAM ({@code LDA $65 / STA $E000}) stores A without ever reading the caller's A, so the
	 * caller's value is not the argument and depositing it would ship a confident wrong bank.
	 * {@link #argumentSurvivesPrologue} tests that precondition over {@code entry..firstSite},
	 * and a failure falls through rather than short-circuiting, so the strategy still decides
	 * ownership and only the bits this call really writes are poisoned.
	 * <p>
	 * <b>That fallback has THREE outcomes, not two</b> (bead grm-67g), tried in this order once
	 * the caller's register is ruled out:
	 * <ol>
	 * <li>the caller's byte arriving through MEMORY -- {@link #inboundArgumentCell} proves the
	 * helper consumes a cell it never writes, and {@link StoredValueScanner#callerCellValue}
	 * reads what the caller stored there (smb3's {@code $0720});</li>
	 * <li>the helper's OWN value where its body supplies a constant --
	 * {@link #valueSuppliedInsideHelper} (grm-cxb), reading whichever site the strategy says
	 * consumes the byte ({@link #helperValueSite});</li>
	 * <li>unknown.</li>
	 * </ol>
	 * So a failed prologue test is not by itself a guarantee of silence. It is skipped for a strategy
	 * that re-derives the value inside the
	 * helper instead of consuming {@code argValue} -- see
	 * {@link BankSwitchStrategy#consumesHelperArgument}, and note that memory-latch's Contra
	 * helper is a prologue-clobber case that must keep resolving.
	 * <p>
	 * {@code envCache} memoizes that environment per call address for the duration of one
	 * {@link BankDataflowEngine#runDataflow}; see its declaration there for why it is not optional.
	 * <p>
	 * <b>The environment is PROLOGUE-FILTERED, per register</b> (bead grm-k90). What
	 * {@link #callSiteRegisters} scans is the caller's raw A/X/Y, and for a WRAPPER model the
	 * wrapper's body executes between the caller and the point the env claims to describe -- it
	 * may freely write X or Y, and {@link HelperDiscovery#isPassThroughInto} admits an {@code LDX #imm} without
	 * blinking. For a CALL-EDGE wrapper it is worse than theoretical: the scan stops at
	 * {@code relay.calleeEntry()} and never walks the wrapper's prefix at all, so an unfiltered
	 * env would hand a strategy a register value the wrapper had already overwritten. Each of
	 * A/X/Y is therefore passed through only where
	 * {@link #argumentSurvivesPrologue(Program, List, char)} holds for THAT register over
	 * {@link #prologueSegments}, and comes back {@link BankState#unknown()} otherwise. The test
	 * is per-register precisely because the answers differ: on Contra's {@code FUN_c139} wrapper
	 * ({@code LDA $8000 / STA $07ec}, falling into {@code FUN_c13f}) A does not survive and Y
	 * does, and it is Y the latch actually consumes.
	 * <p>
	 * This is uniform across ordinary helpers, pass-through wrappers and call-edge wrappers, and
	 * for an ordinary helper it is not a behavior change in any measured case -- the same
	 * predicate over the same span already gated {@code argValue} just above. Note the
	 * interaction with the crossable join below: for a PASS-THROUGH wrapper the scan now walks
	 * the wrapper's prefix itself, so a register the filter would have zeroed is one the scan
	 * clobbers on its own before ever reaching the stop. The filter is therefore
	 * redundant-but-harmless there, and load-bearing for the call-edge case where the prefix is
	 * never walked. It is kept for both because "the env describes the caller's registers as
	 * they are at the point the env stops" is the invariant, and an invariant that holds only on
	 * the paths that happen to re-derive it is not one.
	 * <p>
	 * <b>And it nominates the join the scan may cross</b> ({@link #crossableWrapperJoin}), which
	 * is what makes the stop reachable at all for a pass-through wrapper. The bead's own filed
	 * hypothesis -- that these call sites fail because {@code recoverCallArgument} gates the
	 * whole path on {@code argumentSurvivesPrologue} with {@code reg == argReg == 'A'} -- is
	 * WRONG for memory-latch, and worth recording so nobody re-derives it: that gate is skipped
	 * entirely, because {@link BankSwitchStrategy#consumesHelperArgument} is false for
	 * memory-latch. The real failure was the join refusal killing the walk two instructions
	 * short of the env's stop.
	 */
	static CallEffect recoverCallArgument(Program program, Instruction callInstr,
			HelperModel helper, BankState callSiteIn, Map<Address, RegisterEnv> envCache,
			Set<Function> restoringTrampolines) {
		if (restoringTrampolines.contains(helper.function())) {
			// A VERIFIED no-op (grm-mej.3): this helper puts the entry bank back before returning,
			// so the call owns nothing. Answered before argReg is even consulted, because the
			// argument is genuinely irrelevant here -- it selects the bank the INNER call runs in,
			// and that is over by the time the caller resumes. See
			// SaveRestoreTrampolines.restoresEntryBank.
			return new CallEffect(BankState.unknown(), 0);
		}
		Character reg = helper.argReg();
		if (reg == null) {
			return new CallEffect(BankState.unknown(), helper.effectMask());
		}
		int stateMask = helper.effectMask() >>> helper.lsb();
		BankState local = StoredValueScanner.resolveStoredValue(program, callInstr, reg,
			BankState.unknown(), stateMask, NO_HOOKS);
		// grm-mu7: what the caller left in argReg is this helper's argument only if the helper
		// still has it when the first switch site reads it. Withholding the value (rather than
		// short-circuiting the whole call) is deliberate -- it routes the call down the exact
		// path an unresolvable caller-side scan already takes, so the strategy still decides
		// which bits this site owns and poisons only those. Strategies that re-derive the value
		// inside the helper are exempt; see BankSwitchStrategy.consumesHelperArgument.
		//
		// grm-67g: the caller's byte may still reach the site THROUGH MEMORY even when it does not
		// reach it in the register -- smb3's `LDA #$1b / STA $0720 / JSR $ffc2` against a helper
		// that reloads A from $0720. So this branch makes two attempts before giving up, in the
		// order caller's-cell then helper's-own-constant, and both are strictly additive: it only
		// ever runs where the register answer was already discarded.
		if ((helper.strategy() == null || helper.strategy().consumesHelperArgument()) &&
			!argumentSurvivesPrologue(program, prologueSegments(helper), reg)) {
			Address inbound = inboundArgumentCell(program, helper, reg);
			BankState viaCell = inbound == null ? BankState.unknown()
					: StoredValueScanner.callerCellValue(program, callInstr, inbound, stateMask,
						NO_HOOKS);
			// Partial knowledge counts, matching how combine() and setFieldFromByte already treat
			// a per-bit answer. NO_HOOKS for the same reason the caller-side register scan above
			// uses it: that scan runs in the CALLER, outside any mechanism's interpretation -- see
			// callSiteRegisters. With no resolveLoad there is also nothing whose validity a
			// mid-scan mechanism write could invalidate; a store to $8000 is stepped over on the
			// strength of being a provably different cell, which is the honest reason.
			local = viaCell.knownMask() != 0 ? viaCell
					: valueSuppliedInsideHelper(program, helper, reg, stateMask);
		}
		Instruction switchSite = helper.switchSite() == null ? null
				: program.getListing().getInstructionAt(helper.switchSite());
		if (helper.strategy() == null || switchSite == null) {
			return new CallEffect(position(local, helper.lsb(), helper.effectMask()),
				helper.effectMask());
		}
		BankState localIn = new BankState(
			(callSiteIn.knownMask() & helper.effectMask()) >>> helper.lsb(),
			(callSiteIn.bits() & helper.effectMask()) >>> helper.lsb());
		// helper.entry(), not function().getEntryPoint(): the mini-inline scan must stop where
		// control actually arrived. For a mid-body entry those differ, and stopping at the
		// function entry would walk the scan back through the very prologue this call skipped.
		// For a CALL-EDGE wrapper it is the relay's callee entry instead: the scan runs inside
		// the WRAPPED helper, so stopping at the wrapper's entry would let it run off the
		// helper's own entry and back into the wrapper's tail (grm-2dr increment 2).
		Address scanStop = insideHelperEntry(helper);
		RegisterEnv callerRegs = envCache.computeIfAbsent(callInstr.getMinAddress(),
			a -> callSiteRegisters(program, callInstr, scanStop,
				crossableWrapperJoin(program, helper.firstSite(), scanStop), helper));
		BankSwitchStrategy.HelperDeposit deposit = helper.strategy()
				.depositHelperArgument(program, switchSite, local, localIn, stateMask, callerRegs);
		BankState positionedValue = position(deposit.value(), helper.lsb(), helper.effectMask());
		int positionedOwnedMask = (deposit.ownedMask() << helper.lsb()) & helper.effectMask();
		return new CallEffect(positionedValue, positionedOwnedMask);
	}

	/**
	 * Whether a value the CALLER left in {@code reg} is still there when the helper's first
	 * recognized switch site reads it -- the soundness precondition for
	 * {@link #recoverCallArgument} handing that value to a strategy that takes it at face
	 * value (grm-mu7).
	 * <p>
	 * <b>The bound is {@code firstSite}, emphatically not {@code switchSite}.</b> The argument
	 * has to survive as far as the FIRST site because that is where the mechanism consumes it;
	 * what happens after is the mechanism's own business, and a serial-shift chain's
	 * {@code STA/LSR A/STA/...} clobbers A four times between its first write and its last by
	 * design. Walking to {@code switchSite} would therefore decline every serial-shift helper
	 * on the planet -- it would "fix" this bug by disabling the feature.
	 * <p>
	 * <b>{@code entry}, not the function's entry point.</b> The prologue this must inspect is
	 * the part of it a given call actually runs. Bionic Commando's {@code FUN_dca8} is exactly
	 * why: entering at {@code $DCA8} runs {@code LDA $65} and the caller's A is irrelevant,
	 * while entering at {@code $DCAA} -- the mid-body entry its jump table really uses -- skips
	 * that load and takes the bank in A. One function, two answers, told apart by nothing but
	 * this address; a mid-body entry equal to {@code firstSite} walks an empty range and
	 * correctly keeps its argument.
	 * <p>
	 * Declining conditions, all conservative -- a false decline costs one annotation, a false
	 * accept ships a wrong bank:
	 * <ul>
	 * <li><b>Anything that writes {@code reg}</b>, asked of the language rather than a mnemonic
	 * list so an undocumented or synthetic opcode cannot slip past.</li>
	 * <li><b>Any call</b>: the callee's register effects are not modeled here at all.</li>
	 * <li><b>A gap in the disassembly</b>, i.e. the walk cannot reach {@code firstSite} through
	 * contiguous instructions. Undisassembled bytes in the middle of a helper body are bytes
	 * whose register effects are unknown, which is not the same as harmless.</li>
	 * <li><b>A missing {@code firstSite}</b> -- {@code HelperDiscovery.findHelpers}' multi-mechanism degrade
	 * case, where the model no longer describes one coherent mechanism and there is nothing
	 * meaningful to walk to.</li>
	 * </ul>
	 * <b>A CLOBBER IS NOT A LOSS WHEN THE PROLOGUE SAVED THE ARGUMENT FIRST.</b> This is not a
	 * refinement, it is the difference between working and not working, and it was measured the
	 * expensive way: the first version of this method tested only "does anything write
	 * {@code reg}", and that silently destroyed three real ROMs. Castlevania 2's {@code FUN_c187},
	 * byte-exact:
	 * <pre>
	 *   c187  PHA            ; save the caller's bank argument
	 *   c188  LDA #$01       ; the naive test declines HERE
	 *   c18a  STA $0103
	 *   c18d  PLA            ; ...but this puts the argument back
	 *   c18e  STA $FFFF      ; firstSite: the chain consumes A, correctly
	 * </pre>
	 * The argument survives perfectly well -- across the stack. Declining cost Kid Icarus all 215
	 * of its overlay instructions, Dodgeball all 10692 of its, and Castlevania 2 both of its bank
	 * comments; the synthetic goldens all passed, because none of them saves and restores.
	 * <p>
	 * So the walk carries an abstract state instead of a single flag: whether {@code reg} still
	 * holds the caller's value, a shadow stack of which pushed bytes ARE that value, and the set
	 * of memory cells it was stored to and not yet overwritten. {@code PHA} pushes the current
	 * answer, {@code PLA} pops it back, and {@code PHP}/{@code PLP} are modelled purely to keep
	 * the depth honest so an interleaved status push cannot make a later {@code PLA} pop the
	 * wrong byte. Anything else that moves the stack pointer abandons the model rather than guess
	 * at the new depth.
	 * <p>
	 * <b>The memory half is not optional either</b> -- the same three ROMs need both. Double
	 * Dribble's {@code FUN_ff08} restores from the stack and then immediately parks the argument
	 * in RAM, because it needs A again for an unrelated shadow:
	 * <pre>
	 *   ff11  PLA            ; the argument is back...
	 *   ff12  STA $0103      ; ...and immediately parked in memory
	 *   ff15  LDA $ff        ; A reused for the mirroring shadow
	 *   ff1a  STA $ff
	 *   ff1c  LDA $0103      ; the argument is reloaded HERE
	 *   ff1f  STA $FFFF      ; firstSite
	 * </pre>
	 * A load counts as a restore only when it reads a cell this walk watched the argument being
	 * written to and nothing has written since; every other write to {@code reg} loses it. An
	 * indexed store forgets every tracked cell, since its target is runtime-dependent and could
	 * have landed on any of them.
	 * <p>
	 * <b>This is a PRESERVATION model, not a value model.</b> It answers only "does the caller's
	 * byte still reach the first site", never "what is it" -- the value still comes from the
	 * caller-side scan. Teaching {@link StoredValueScanner} to carry values through the stack and
	 * across blocks is a different and much larger capability, tracked by {@code grm-mej.3} and
	 * blocked on {@code grm-mej.2}; nothing here anticipates it.
	 * <p>
	 * <b>Soundness of the save/restore half.</b> The clobber half of this walk is linear in
	 * address order, which is a proxy for execution order in the same way
	 * {@code HelperDiscovery.HelperModel.switchSite}'s max-address rule is, and it errs SAFE: a prologue that
	 * branches around a clobber is declined even though the argument survives the taken path.
	 * The save/restore half does not get that for free -- a branch that skipped a {@code PLA}
	 * would make "restored" a claim about a path that never runs, and that error points the
	 * unsafe way. It is therefore trusted only over genuinely straight-line code: any
	 * non-fall-through flow in the range abandons the shadow stack, after which a {@code PLA} is
	 * an ordinary clobber again. Clobber detection itself is unaffected and stays conservative.
	 * <p>
	 * <b>Where the memory half and the stack half collide</b>: a push writes memory too, at
	 * {@code $0100 + S}, so a tracked cell in the stack page could be clobbered by the very
	 * {@code PHA} this walk models as a pure save. {@link StackFloor} draws that line, applied
	 * by {@link #forgetCellsThePushMayHaveHit}; the same floor governs
	 * {@code StoredValueScanner.forwardedStoreValue} and {@link #inboundArgumentCell}, so all
	 * three walks now make one assumption instead of three tacit ones.
	 */
	/**
	 * Drops every tracked cell a {@code PHA}/{@code PHP} could have landed on, per
	 * {@link StackFloor}. The pushes are otherwise {@code modelled = true} and so skip the
	 * generic {@code argumentCells.removeIf} below -- which is right for the register half (a
	 * push does not clobber {@code reg}) and wrong for the memory half, since a push does write
	 * memory, at an address no detector in {@link StoredValueScanner} can name because it is
	 * {@code $0100 + S}. Below the floor this removes nothing, which is the whole point: the
	 * measured cell in Double Dribble and Castlevania 2 is {@code $0103}.
	 */
	private static void forgetCellsThePushMayHaveHit(Program program, Set<Address> argumentCells) {
		argumentCells.removeIf(cell -> StackFloor.mayAliasStack(program, cell));
	}

	static boolean argumentSurvivesPrologue(Program program, Address entry, Address firstSite,
			char reg) {
		if (entry == null || firstSite == null || entry.compareTo(firstSite) > 0) {
			return false;
		}
		Register register = program.getLanguage().getRegister(String.valueOf(reg));
		if (register == null) {
			return false; // cannot ask the question -> do not assume the favorable answer
		}
		Register stackPointer = program.getCompilerSpec().getStackPointer();
		Listing listing = program.getListing();
		// Does argReg still hold what the CALLER left in it?
		boolean holdsArgument = true;
		// The saved-value stack: one entry per byte this walk watched being pushed, true when
		// that byte IS the caller's argument. Only consulted while straightLine holds.
		Deque<Boolean> saved = new ArrayDeque<>();
		// The memory half of the same idea: cells this walk watched the argument being stored to
		// and which nothing has overwritten since, so a load from one is a restore.
		//
		// Note the DUAL of this set, inboundArgumentCell (grm-67g): a cell enters here only when
		// the HELPER stores argReg into it, and enters there only when the helper never does. A
		// helper cannot satisfy both, which is what lets recoverCallArgument try them in sequence
		// without the order mattering.
		Set<Address> argumentCells = new LinkedHashSet<>();
		// Whether the save/restore model is still trustworthy. Cleared by anything that moves
		// the stack pointer in a way this does not model, and by any non-fall-through flow --
		// see the javadoc's soundness note.
		boolean straightLine = true;
		Address cursor = entry;
		while (cursor.compareTo(firstSite) < 0) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null || instr.getFlowType().isCall()) {
				return false;
			}
			boolean modelled = false;
			if (reg == 'A') {
				switch (instr.getMnemonicString()) {
					case "PHA" -> {
						if (straightLine) {
							saved.push(holdsArgument);
						}
						forgetCellsThePushMayHaveHit(program, argumentCells);
						modelled = true;
					}
					case "PLA" -> {
						if (straightLine && !saved.isEmpty()) {
							holdsArgument = saved.pop();
						}
						else {
							// Popping a byte this walk never watched being pushed: it belongs to
							// the caller's frame or to code we did not model, and the depth is out
							// of step from here on either way.
							holdsArgument = false;
							straightLine = false;
						}
						modelled = true;
					}
					case "PHP" -> {
						// Modelled only to keep the DEPTH right, so an interleaved status push
						// cannot make a later PLA pop the wrong byte. A status byte is never the
						// argument.
						if (straightLine) {
							saved.push(Boolean.FALSE);
						}
						forgetCellsThePushMayHaveHit(program, argumentCells);
						modelled = true;
					}
					case "PLP" -> {
						if (straightLine && !saved.isEmpty()) {
							saved.pop();
						}
						else {
							straightLine = false;
						}
						modelled = true;
					}
					default -> {
						// fall through to the generic tests below
					}
				}
			}
			if (!modelled) {
				// Any write to a cell we were relying on ends that reliance, whatever wrote it
				// (a plain store, or an INC/ASL-style read-modify-write).
				argumentCells.removeIf(cell -> StoredValueScanner.writesAddress(instr, cell));
				Character stored = StoredValueScanner.storeRegister(instr);
				if (stored != null && stored.charValue() == reg && holdsArgument && straightLine) {
					Address cell = StoredValueScanner.plainAbsoluteTarget(instr);
					if (cell != null) {
						argumentCells.add(cell);
					}
					else {
						// An indexed store's target is runtime-dependent, so it may have landed on
						// any tracked cell. Forget all of them rather than pick.
						argumentCells.clear();
					}
				}
				if (StoredValueScanner.writesRegister(instr, register)) {
					// A load is a RESTORE when it reads back a cell this walk watched the argument
					// being written to; every other write to argReg loses it.
					Address from = argumentReloadSource(instr, reg);
					holdsArgument = straightLine && from != null && argumentCells.contains(from);
				}
				// Anything else that touches the stack pointer (TXS, or a PHX/PLX-style push on a
				// variant that has one) desynchronises the depth, so stop believing the model
				// rather than let a later PLA pop the wrong entry.
				if (stackPointer == null || writesStackPointer(instr, stackPointer)) {
					straightLine = false;
				}
			}
			// A branch or jump means the walk's straight line is not necessarily a real path, so
			// a PLA after it cannot be trusted to pair with a PHA before it. Plain clobber
			// detection is unaffected and stays conservative.
			if (instr.getFlows().length > 0) {
				straightLine = false;
				argumentCells.clear();
			}
			cursor = instr.getMaxAddress().next();
			if (cursor == null) {
				return false; // ran off the end of the space before reaching firstSite
			}
		}
		return cursor.equals(firstSite) && holdsArgument;
	}

	/**
	 * The byte the helper puts into {@code reg} itself, for the case where
	 * {@link #argumentSurvivesPrologue} has just proved the CALLER's byte does not reach the
	 * first switch site (grm-cxb).
	 * <p>
	 * <b>Declining is not the only honest answer there.</b> Something reaches that site, and once
	 * the caller's value is ruled out it can only have come from inside the helper. Kid Icarus's
	 * {@code FUN_eb07} is the shape that makes this worth doing:
	 * <pre>
	 *   eb07  LDA #$0F       ; the helper supplies its OWN value
	 *   eb09  STA $9FFF      ; firstSite -- $9FFF decodes to MMC1 target 0, Control
	 *   eb0c  LSR A / STA $9FFF / ...
	 * </pre>
	 * It takes no argument at all, and {@code 0x0F} commits {@code mirroring=3, prg_mode=3}. But a
	 * chain helper never has a {@code constState} -- writes 1-4 of a chain echo the in-state and
	 * write 5 commits, so {@link HelperDiscovery#findHelpers}' multi-site disagreement rule nulls it, by design
	 * -- so every one of them is routed through per-call recovery, where the prologue guard sees
	 * that {@code LDA #$0F} clobber and declines. Scanning here recovers the answer the helper's
	 * own body already knows: {@code SerialShiftBankSwitchStrategy.computeSwitch} resolves exactly
	 * this byte, from exactly this instruction, when it evaluates the chain's commit.
	 * <p>
	 * <b>The caller's registers are passed as explicitly UNKNOWN</b>, not omitted. The scan must
	 * stop at {@code entry} -- otherwise it walks back into whatever code physically precedes the
	 * helper and reads it as a prologue -- but it must also not adopt the caller's values there,
	 * because the whole reason we are here is that those values provably do not survive.
	 * {@link RegisterEnv} carries both halves of that: the stop address, and what to believe at
	 * it.
	 * <p>
	 * Bionic Commando's {@code FUN_dca8} ({@code LDA $65}) still declines, on its own merits: the
	 * scan reaches a RAM load it cannot resolve and returns unknown. That is the difference this
	 * whole area turns on -- a helper that supplies a CONSTANT is knowable, one that supplies a
	 * RAM read is not, and neither has anything to do with the caller.
	 * <p>
	 * <b>This is now the LAST resort, not the only one</b> (bead grm-67g):
	 * {@link #recoverCallArgument} tries {@link #inboundArgumentCell} first, so a RAM load whose
	 * cell the CALLER wrote is answered there. The {@code FUN_dca8} decline therefore stands only
	 * where no caller stored to {@code $65} in the same basic block -- which is the honest
	 * refinement, since "the helper reads RAM" was never the real question. "Whose byte is in that
	 * RAM" is.
	 */
	private static BankState valueSuppliedInsideHelper(Program program, HelperModel helper,
			char reg, int stateMask) {
		Address readAt = helperValueSite(helper);
		Instruction site = readAt == null ? null : program.getListing().getInstructionAt(readAt);
		if (site == null) {
			return BankState.unknown();
		}
		RegisterEnv insideOnly = new RegisterEnv(insideHelperEntry(helper), BankState.unknown(),
			BankState.unknown(), BankState.unknown());
		return StoredValueScanner.resolveStoredValue(program, site, reg, BankState.unknown(),
			stateMask, NO_HOOKS, insideOnly);
	}

	/**
	 * The site at which this helper's mechanism CONSUMES the byte in {@code argReg} -- which of a
	 * multi-write helper's sites is the one whose value ends up in the tracked field (bead
	 * grm-67g).
	 * <p>
	 * WHICH site that is, is the strategy's call and not a constant. For every single-site
	 * mechanism {@code firstSite} and {@code switchSite} are the same instruction and the question
	 * does not arise; the two multi-site shapes want opposite answers, and select-data reading
	 * {@code firstSite} is what shipped smb3's confident wrong {@code r7=7} -- {@code firstSite}
	 * there holds the {@code $8000} register-SELECT byte, not the bank. See
	 * {@link BankSwitchStrategy#suppliesHelperValueAtFirstSite}.
	 * <p>
	 * <b>This is NOT the same bound as {@link #argumentSurvivesPrologue}'s</b>, which is
	 * emphatically {@code firstSite} for every strategy -- and the two are consistent rather than
	 * in tension. That predicate asks whether the CALLER's byte is still in the register when the
	 * mechanism starts, and a serial-shift chain clobbers A four times between its first write and
	 * its last BY DESIGN, so walking to {@code switchSite} there would decline every serial-shift
	 * helper on the planet. The clobbers that make that true all fall AFTER {@code firstSite}, so
	 * for serial-shift this method answers {@code firstSite} too and both walks stop short of
	 * them. One selector therefore serves both multi-site shapes without a special case.
	 * <p>
	 * Two consumers: {@link #valueSuppliedInsideHelper} (what the helper's own body puts in the
	 * register) and {@link #inboundArgumentCell} (what cell the caller's byte arrives in). Same
	 * question, different storage class.
	 */
	private static Address helperValueSite(HelperModel helper) {
		return helper.strategy() == null || helper.strategy().suppliesHelperValueAtFirstSite()
				? helper.firstSite()
				: helper.switchSite();
	}

	/**
	 * Where a backward scan that runs INSIDE the helper must stop -- the address control
	 * arrived at in the body that actually contains {@code firstSite}.
	 * <p>
	 * For every ordinary helper, and for a pass-through wrapper, that is {@code entry}: the
	 * wrapper is address-contiguous with the helper, so one body's worth of addresses runs from
	 * {@code entry} to {@code firstSite} and stopping at {@code entry} is right. For a CALL-EDGE
	 * wrapper it is emphatically not: {@code entry} is the WRAPPER's, while {@code firstSite}
	 * lives in the wrapped helper, and the addresses between them are the wrapper's own tail.
	 * A scan bounded by the wrapper's entry would run off the helper's entry, walk backwards
	 * through that tail, and read instructions the call never executed as the helper's prologue
	 * -- the precise hazard {@link #valueSuppliedInsideHelper}'s javadoc already warns about for
	 * the unbounded case.
	 * <p>
	 * Two consumers: {@link #valueSuppliedInsideHelper}'s {@link RegisterEnv} stop address, and
	 * the one {@link #recoverCallArgument} hands {@link #callSiteRegisters} for
	 * {@link BankSwitchStrategy#depositHelperArgument}'s mini-inlining.
	 * <p>
	 * <b>For a pass-through wrapper, contiguity makes the walk POSSIBLE but does not make this
	 * stop REACHABLE</b> (bead grm-k90) -- the gap in the paragraph above, and the whole of
	 * Contra's defect. The addresses do run linearly from {@code entry} to {@code firstSite}, so
	 * the answer here is right; what the argument omits is that the WRAPPED helper's own entry
	 * sits on that line and is a control-flow join, because the callers who bypass the wrapper
	 * jump straight to it. {@code StoredValueScanner}'s join refusal fires there and the scan
	 * returns unknown two instructions short of this stop. That is repaired by licensing exactly
	 * that one join rather than by moving the stop -- see {@link #crossableWrapperJoin}, which
	 * also records why moving it would have been the worse fix.
	 */
	// Package-private (not private): SaveRestoreTrampolines.restoresEntryBank also needs
	// this stop address (grm-shnf step 3).
	static Address insideHelperEntry(HelperModel helper) {
		return helper.relay() == null ? helper.entry() : helper.relay().calleeEntry();
	}

	/**
	 * One half-open, linear-by-address stretch {@code [from, to)} of the prologue a call runs
	 * before the helper's mechanism reads its argument (bead grm-2dr increment 2).
	 * <p>
	 * Package-private so a Tier 2 test can construct one; {@code HelperArgumentRecovery}'s own
	 * records are private, which is what kept increment 1's wrapper tests at the predicate
	 * level.
	 */
	record PrologueSegment(Address from, Address to) {}

	/**
	 * {@link #argumentSurvivesPrologue} over a prologue that is more than one contiguous span:
	 * a literal AND, evaluating each segment independently (bead grm-2dr increment 2).
	 * <p>
	 * <b>The single-segment case is byte-for-byte unchanged</b> -- same method, same body, same
	 * answer -- because a one-element list delegates once and returns exactly what the three-
	 * address form returns. Only a call-edge wrapper ever supplies two.
	 * <p>
	 * <b>Resetting the save/restore model between segments is deliberate, and it errs in the
	 * safe direction.</b> Each delegated call starts with fresh {@code holdsArgument},
	 * {@code saved}, {@code argumentCells} and {@code straightLine}, so a {@code PHA} in
	 * segment 1 cannot pair with a {@code PLA} in segment 2, and a cell the argument was stored
	 * to in segment 1 cannot make a segment-2 load read as a restore. Both refusals
	 * UNDER-approximate survival, so the cost is at most a missing annotation -- never a
	 * confidently wrong bank, which this engine treats as strictly worse. blmaster is
	 * unaffected either way: its {@code STA $DB} and {@code LDA $DB} both live in segment 1.
	 * <p>
	 * An EMPTY segment ({@code from.equals(to)}) is trivially true, and that is load-bearing
	 * rather than incidental: the loop's bound test is {@code cursor < to}, so it never
	 * executes and the method returns {@code cursor.equals(to) && holdsArgument}. That is
	 * exactly blmaster's second segment, since {@code FUN_e63c}'s {@code STA $FFFF} IS its entry
	 * instruction and so its {@code entry} and {@code firstSite} coincide.
	 * <p>
	 * An EMPTY LIST is false, not vacuously true -- there is no prologue to have proved
	 * anything about, and returning true there would hand a strategy a caller's byte on no
	 * evidence at all.
	 */
	static boolean argumentSurvivesPrologue(Program program, List<PrologueSegment> segments,
			char reg) {
		if (segments.isEmpty()) {
			return false;
		}
		for (PrologueSegment segment : segments) {
			if (!argumentSurvivesPrologue(program, segment.from(), segment.to(), reg)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The stretches of code a call into {@code helper} runs before its mechanism reads the
	 * argument: one span for an ordinary helper, two for a call-edge wrapper.
	 * <p>
	 * DERIVED, not stored on {@link HelperDiscovery.HelperModel}. It is a pure function of {@code entry},
	 * {@code firstSite} and {@code relay}, all already on the record; storing it would duplicate
	 * state that {@link HelperDiscovery.HelperModel#atMidBodyEntry} and
	 * {@link HelperDiscovery.HelperModel#atFallThroughWrapper} re-key underneath, and would drag a list into the
	 * record's equality.
	 * <p>
	 * <b>Why passing the relay's call site as segment 1's END bound does not trip
	 * {@link #argumentSurvivesPrologue}'s own {@code isCall()} rejection.</b> That loop's bound
	 * test is {@code cursor.compareTo(to) < 0}, so it STOPS BEFORE INSPECTING the instruction at
	 * {@code to} -- the relay {@code JSR} is the boundary, never a walked instruction. This
	 * looks like an accident and is not: it is the whole reason segmenting works without
	 * touching the predicate.
	 */
	// Package-private (not private): HelperDiscovery.findCallEdgeWrappers also calls this
	// (grm-shnf step 3).
	static List<PrologueSegment> prologueSegments(HelperModel helper) {
		if (helper.relay() == null) {
			return List.of(new PrologueSegment(helper.entry(), helper.firstSite()));
		}
		return List.of(new PrologueSegment(helper.entry(), helper.relay().callSite()),
			new PrologueSegment(helper.relay().calleeEntry(), helper.firstSite()));
	}

	/**
	 * The address {@code instr} reloads {@code reg} from, when it is a plain load whose target is
	 * statically certain -- the memory half of {@link #argumentSurvivesPrologue}'s save/restore
	 * model, and the load-side predicate of {@link #inboundArgumentCell}. Null for anything else,
	 * including an immediate load (no address operand at all) and an indexed one
	 * ({@link StoredValueScanner#plainAbsoluteTarget} refuses those, since their target is
	 * runtime-dependent).
	 */
	// Package-private (not private): SaveRestoreTrampolines.restoresEntryBank also calls
	// this (grm-shnf step 3).
	static Address argumentReloadSource(Instruction instr, char reg) {
		if (!("LD" + reg).equals(instr.getMnemonicString())) {
			return null;
		}
		return StoredValueScanner.plainAbsoluteTarget(instr);
	}

	/**
	 * The memory cell a helper takes its argument IN, when the caller passes the bank through RAM
	 * rather than in a register (bead grm-67g) -- or null when no such cell is provable.
	 * <p>
	 * <b>The claim.</b> If the helper's LAST write to {@code reg} before its value-consuming site
	 * is a plain load from cell C, and nothing between the entry and that site could have written
	 * C, then C still holds what the CALLER put there. C is therefore an inbound argument, and its
	 * value must be resolved at the CALL SITE ({@link StoredValueScanner#callerCellValue}) rather
	 * than by scanning for {@code reg} there.
	 * <p>
	 * <b>This is the exact dual of {@link #argumentSurvivesPrologue}'s {@code argumentCells}
	 * set</b>, and the two are MUTUALLY EXCLUSIVE by construction. That set admits C only when the
	 * HELPER stores {@code reg} into it (a save/restore across the prologue); this admits C only
	 * when the helper NEVER stores to it. So a helper cannot satisfy both, which is why the order
	 * in which {@link #recoverCallArgument} tries them is not a judgement call -- hoisting this
	 * above the survives-prologue test could not change an answer, only cost a walk.
	 * <p>
	 * <b>Worked example</b>, smb3's {@code FUN_ffc2} with {@code reg == 'A'} and the value site at
	 * {@code $FFC7} (select-data consumes at {@code switchSite}, not {@code firstSite}):
	 * <pre>
	 *   ffc2  LDA #$47      ; clears cell -- an immediate is not a reload
	 *   ffc4  STA $0721     ; lands in `written`, and PROVES a different cell than $0720
	 *   ffc6  STA $8000     ; firstSite, walked THROUGH: the select byte is not the bank
	 *   ffc7  LDA $0720     ; sets cell = $0720   &lt;- the answer
	 *   ffc9  STA $8001     ; the value site; walk stops here
	 * </pre>
	 * The caller side then finishes it: {@code ca23 LDA #$1b / STA $0720 / JSR $ffc2} resolves
	 * {@code $0720} to {@code $1b = 27}. And the counter-example {@code written} exists for is one
	 * instruction away -- a helper whose {@code $FFC4} were {@code STA $0720} would be supplying
	 * its OWN byte, and without that set this would confidently ship {@code $47} as the bank,
	 * which is the very number the regression this bead tracks shipped.
	 * <p>
	 * <b>Not a restoration of anything.</b> smb3's correct {@code r7=27/26} predates the prologue
	 * guard, but it was never sourced from the shadow: {@code local} was simply the caller-side
	 * REGISTER scan, and {@code LDA #$1b / STA $0720 / JSR} happens to leave {@code $1b} still in
	 * A. That is luck the idiom happens to grant, not a mechanism. This rule reaches the same
	 * number for a sound reason, and keeps reaching it when the caller's A is clobbered.
	 * <p>
	 * <b>The bound is {@link #helperValueSite}, not {@code firstSite}</b> -- see that method for
	 * why the two predicates want opposite-looking bounds for the same underlying reason.
	 * <p>
	 * <b>{@link #insideHelperEntry}, not the function's entry point.</b> Bionic Commando's
	 * {@code FUN_dca8} ({@code LDA $65 / STA $E000}) is a real inbound-cell helper when entered at
	 * {@code $DCA8}; entered mid-body at {@code $DCAA} the walk starts past the load, finds no
	 * reload, and correctly returns null -- one function, two answers, exactly as
	 * {@link #argumentSurvivesPrologue} documents for its own walk. It also means a FALL-THROUGH
	 * wrapper's prefix IS walked, which matters more than it looks: {@code HelperDiscovery.isPassThroughInto}
	 * forbids a wrapper from writing the MECHANISM but not from writing ordinary RAM, so a
	 * wrapper containing {@code STA $0720} is admissible and only the walk starting at the
	 * wrapper's entry catches it.
	 * <p>
	 * <b>A CALL-EDGE wrapper declines outright.</b> There {@link #insideHelperEntry} is the
	 * relay's callee entry, so the walk would cover only the second prologue segment and never see
	 * the wrapper's own prefix. blmaster's shape is the counterexample: a wrapper doing
	 * {@code STA $22 / LDA $22 / JSR helper} in front of a helper whose body begins {@code LDA $22}
	 * would look like an inbound cell, and the value would be resolved at the JSR INTO THE WRAPPER
	 * -- i.e. the byte the wrapper was about to overwrite. Stale, confident, wrong. Today the
	 * branch that calls this is unreachable for a relay model at all ({@code HelperDiscovery.findCallEdgeWrappers}
	 * uses {@link #argumentSurvivesPrologue} as its ADMISSION gate, so every relay helper in the
	 * map already answers true there), so this guard is defensive -- but the invariant is one
	 * refactor away from moving. A generalization over {@link #prologueSegments} must NOT reset
	 * {@code written} per segment the way {@link #argumentSurvivesPrologue} resets its shadow
	 * stack: that reset under-approximates and errs safe, while forgetting the wrapper's
	 * {@code STA $22} errs the unsafe way. Same segment list, opposite discipline.
	 * <p>
	 * <b>Every flow declines here</b>, where {@link #argumentSurvivesPrologue} merely stops
	 * trusting its save/restore model. A branch costs that predicate a fold; here it would let a
	 * linear-by-address walk skip a write to C, or count one that never executes, and both point
	 * the unsafe way.
	 * <p>
	 * <b>{@link StoredValueScanner#writesMemory}, not {@code writesAddress}.</b> The reference-only
	 * test under-reports (an indirect store has no concrete result address, refless stores exist,
	 * and the read-modify-write mnemonics are invisible to {@code storeRegister}). In the
	 * save/restore model a missed write is bounded by {@code holdsArgument}; here it is directly a
	 * confident wrong bank.
	 *
	 * <b>A cell in the live part of the stack page is refused</b> ({@link StackFloor}). This walk
	 * is the one place where the hazard is not hypothetical: the caller reached {@code entry}
	 * through a {@code JSR}, which pushed two bytes, and neither that nor a {@code PHA} inside
	 * the range is visible to {@link StoredValueScanner#writesMemory}. Unlike the other two
	 * consumers of the floor, a wrong answer here is a confident wrong bank rather than a
	 * forfeited forward, so the guard matters most here even though the code is smallest.
	 *
	 * @param entry     where control actually arrives -- {@link #insideHelperEntry}
	 * @param valueSite where the mechanism consumes the byte -- {@link #helperValueSite}
	 */
	static Address inboundArgumentCell(Program program, Address entry, Address valueSite, char reg) {
		if (entry == null || valueSite == null || entry.compareTo(valueSite) > 0) {
			return null;
		}
		Register register = program.getLanguage().getRegister(String.valueOf(reg));
		if (register == null) {
			return null; // cannot ask the question -> do not assume the favorable answer
		}
		Listing listing = program.getListing();
		// The cell reg was LAST plainly loaded from, or null when reg's current value came from
		// anywhere else. Set and cleared by the same statement, which is the whole trick.
		Address cell = null;
		// Every address this walk saw written, accumulated over the WHOLE range rather than tested
		// as we go: in FUN_ffc2 the STA $0721 precedes the LDA $0720 that names the cell, so a
		// check applied only after the load would miss a store in the same position.
		Set<Address> written = new LinkedHashSet<>();
		Address cursor = entry;
		while (cursor.compareTo(valueSite) < 0) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null || instr.getFlowType().isCall() || instr.getFlowType().isTerminal() ||
				instr.getFlows().length > 0) {
				return null;
			}
			Address fallThrough = instr.getFallThrough();
			Address next = instr.getMaxAddress().next();
			if (next == null || fallThrough == null || !fallThrough.equals(next)) {
				return null; // a gap, an override, or the end of the space -- not one linear path
			}
			if (StoredValueScanner.writesMemory(instr)) {
				Address target = StoredValueScanner.effectiveOperandTarget(program, instr, NO_HOOKS,
					RegisterEnv.NONE);
				if (target == null) {
					return null; // a write this scanner cannot place may have landed on the cell
				}
				written.add(target);
			}
			if (StoredValueScanner.writesRegister(instr, register)) {
				cell = argumentReloadSource(instr, reg);
			}
			cursor = next;
		}
		// StackFloor: the caller's own JSR pushed a return address, and any PHA in the range was
		// stepped over as inert, both at addresses writesMemory cannot name. A cell at or above
		// the floor may therefore have been clobbered between the caller's store and this load.
		// (The null-cell case reaches mayAliasStack's "unplaceable reads as unsafe" answer and
		// would be rejected by the cell != null test below regardless -- same verdict either way.)
		return cursor.equals(valueSite) && cell != null && !written.contains(cell) &&
			!StackFloor.mayAliasStack(program, cell) ? cell : null;
	}

	/** {@link #inboundArgumentCell} asked of a helper model; null for a call-edge wrapper. */
	private static Address inboundArgumentCell(Program program, HelperModel helper, char reg) {
		if (helper.relay() != null) {
			return null;
		}
		return inboundArgumentCell(program, insideHelperEntry(helper), helperValueSite(helper), reg);
	}

	/**
	 * Whether {@code instr} moves the stack pointer, for {@link #argumentSurvivesPrologue}'s
	 * shadow stack.
	 * <p>
	 * <b>Compared by BASE register, not by identity.</b> The 6502 declares the stack pointer
	 * twice over the same bytes -- a two-byte {@code SP} and a one-byte {@code S} -- and
	 * {@code CompilerSpec.getStackPointer()} answers one while {@code TXS}'s p-code writes the
	 * other. An {@code equals} test (which is what {@link StoredValueScanner#writesRegister}
	 * deliberately does, and must keep doing for A/X/Y) therefore reports that {@code TXS} does
	 * not touch the stack, and the shadow stack would go on trusting a depth that had just moved
	 * underneath it. Measured, not theorised: the {@code TXS} case was the one unit test that
	 * failed on the identity comparison.
	 * <p>
	 * Package-private for a second consumer (grm-mej.3 increment 2):
	 * {@code StoredValueScanner.findMatchingPush} needs the identical base-register-aware test
	 * for its own PHA/PLA depth pairing, over a BACKWARD walk rather than this method's forward
	 * one. Reused verbatim rather than reimplemented so the two walks cannot silently drift apart
	 * on what "moves the stack pointer" means.
	 */
	static boolean writesStackPointer(Instruction instr, Register stackPointer) {
		Register wanted = stackPointer.getBaseRegister();
		for (Object o : instr.getResultObjects()) {
			if (o instanceof Register r && wanted.equals(r.getBaseRegister())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * What A, X and Y hold at {@code callInstr}, packaged with {@code entryAddr} (the called
	 * helper's entry) as the address a backward scan started inside that helper must stop at.
	 * This is what makes {@link BankSwitchStrategy#depositHelperArgument}'s mini-inlining
	 * possible without any input-register discovery: the scan inside the helper is
	 * demand-driven, so supplying all three registers and letting it pull whichever it actually
	 * reads is both simpler and strictly more capable than deducing an argument convention
	 * (grm-hum increment 2 -- Contra's helper takes its bank in Y while {@link HelperDiscovery#findHelpers}
	 * can only see the {@code STA}'s A).
	 * <p>
	 * <b>Masked to {@code 0xFF}, deliberately not to the mechanism's {@code stateMask}.</b> An
	 * index register is not the mechanism's field: Contra's UxROM latch has {@code mask: 0x0F},
	 * and narrowing Y to four bits would truncate the very index used to read the bank table.
	 * {@code argValue}'s {@code stateMask} narrowing in {@link #recoverCallArgument} is a
	 * different question (the field value itself) and keeps it.
	 * <p>
	 * {@link #NO_HOOKS} is used because the scan runs in the CALLER, outside any mechanism's
	 * interpretation: the caller's mechanism writes are not this helper's, and no strategy's
	 * load resolution applies to a register the caller is merely setting up. A register the
	 * scan cannot pin down comes back {@link BankState#unknown()}, which is what keeps a
	 * RAM-sourced argument honestly unresolved instead of guessed.
	 * <p>
	 * <b>Each register is then filtered by whether it SURVIVES the prologue</b> (bead grm-k90).
	 * The three scans above run in the caller and answer "what did the caller leave here"; the
	 * env claims something stronger -- "what holds at {@code entryAddr}" -- and for a WRAPPER
	 * model those differ, because the wrapper's own body runs in between and nothing forbids it
	 * writing X or Y ({@link HelperDiscovery#isPassThroughInto} admits an {@code LDX #imm} without blinking).
	 * {@link #argumentSurvivesPrologue(Program, List, char)} over {@link #prologueSegments} is
	 * exactly the question, so it is asked ONCE PER REGISTER rather than once for
	 * {@link HelperDiscovery.HelperModel#argReg}, and a register that does not survive is handed back as
	 * {@link BankState#unknown()} instead of the caller's stale value. Per-register is the whole
	 * point: on Contra's {@code FUN_c139} A does not survive ({@code LDA $8000}) while Y does,
	 * and Y is the one the latch consumes -- running the test on {@code argReg} alone would let
	 * a clobber of a register nobody reads suppress a correct recovery.
	 * <p>
	 * For an ordinary helper this cannot change an answer that was already right: the scan
	 * inside the helper walks that same prologue itself and meets any clobber before it reaches
	 * the stop. It is LOAD-BEARING for a CALL-EDGE wrapper, where the scan stops at
	 * {@code relay.calleeEntry()} and the wrapper's prefix is never walked at all -- that is the
	 * soundness hole this bead was originally filed on, and it is closed here rather than by
	 * forcing X/Y to unknown for wrapper models wholesale (considered and rejected in grm-2dr
	 * increment 2 as strictly less precise).
	 * <p>
	 * {@code crossableJoin} is passed through untouched; see {@link #crossableWrapperJoin} for
	 * where it comes from and {@link RegisterEnv} for why crossing it is sound.
	 */
	private static RegisterEnv callSiteRegisters(Program program, Instruction callInstr,
			Address entryAddr, Address crossableJoin, HelperModel helper) {
		List<PrologueSegment> prologue = prologueSegments(helper);
		return new RegisterEnv(entryAddr, crossableJoin,
			surviving(program, callInstr, 'A', prologue),
			surviving(program, callInstr, 'X', prologue),
			surviving(program, callInstr, 'Y', prologue));
	}

	/**
	 * What the caller left in {@code reg}, or {@link BankState#unknown()} when the helper's
	 * prologue does not preserve it as far as the site that reads it -- one register's worth of
	 * {@link #callSiteRegisters}' filter (bead grm-k90).
	 * <p>
	 * The survival test is evaluated FIRST and the scan skipped when it fails, which is a small
	 * efficiency win but mostly a statement of intent: a value that cannot be attributed is not
	 * merely discarded afterwards, it is never derived.
	 */
	private static BankState surviving(Program program, Instruction callInstr, char reg,
			List<PrologueSegment> prologue) {
		if (!argumentSurvivesPrologue(program, prologue, reg)) {
			return BankState.unknown();
		}
		return StoredValueScanner.resolveStoredValue(program, callInstr, reg, BankState.unknown(),
			0xFF, NO_HOOKS);
	}

	/**
	 * The one control-flow join a mini-inline scan for {@code helper} may walk through, or
	 * {@code null} for the overwhelmingly common "none" (bead grm-k90).
	 * <p>
	 * <b>The problem it solves.</b> For a PASS-THROUGH WRAPPER, {@link #insideHelperEntry}
	 * correctly reports the WRAPPER's entry as where control arrived -- but that stop is not
	 * REACHABLE. The scan starts at the switch site, inside the wrapped helper, and the wrapped
	 * helper's own entry lies between it and the stop. That entry is a genuine control-flow join,
	 * because the direct callers who bypass the wrapper jump straight to it, so
	 * {@code StoredValueScanner}'s join refusal fires and the walk dies short of the env. On
	 * Contra this is the entire defect: {@code c0cb LDY #1 / JSR $c13f} resolves because its stop
	 * IS the join and {@code stopsAt} is tested first, while the identical {@code c094 LDY #1 /
	 * JSR $c139} warns because its stop is two instructions further back and the join wins the
	 * race.
	 * <p>
	 * <b>What is nominated.</b> "The entry of the body that actually contains {@code firstSite}"
	 * -- which is what {@link #insideHelperEntry}'s javadoc already claims to compute and, for a
	 * pass-through wrapper, does not. It is taken from the function containing {@code firstSite}
	 * rather than stored on {@link HelperDiscovery.HelperModel} deliberately: {@link HelperDiscovery.HelperModel#atFallThroughWrapper}
	 * overwrites {@code entry} with the wrapper's, so recording the wrapped entry would mean a
	 * new field on a ten-field record, and one that would have to be threaded correctly through a
	 * CHAIN of wrappers. Deriving it gets the chained case right for free -- every outer wrapper
	 * is contiguous with the next and contributes no join of its own, so the function containing
	 * {@code firstSite} is the innermost helper however many wrappers are stacked on it.
	 * <p>
	 * <b>The window test is what keeps it honest</b>, and it is not a formality -- it is the only
	 * thing standing between this and licensing a join nobody proved anything about. The nominee
	 * must lie STRICTLY after {@code scanStop} and at or before {@code firstSite}. Walk the four
	 * model shapes:
	 * <ul>
	 * <li>ORDINARY HELPER: the nominee IS {@code scanStop}, not strictly after it, so
	 * {@code null}. Byte-for-byte no change, which is what lets this land without re-blessing
	 * every golden.</li>
	 * <li>MID-BODY ENTRY (Bionic Commando's {@code $DCAA} inside {@code FUN_dca8}): the nominee is
	 * {@code dca8}, BEFORE the stop, so {@code null}. That case must not regress and structurally
	 * cannot -- the whole point of a mid-body entry is that the prologue was skipped, and
	 * licensing a join behind the stop would walk the scan into exactly the code the call
	 * avoided.</li>
	 * <li>PASS-THROUGH WRAPPER (Contra): {@code c139 < c13f <= c142}. Nominated. This is the
	 * fix.</li>
	 * <li>CALL-EDGE WRAPPER: {@code scanStop} is {@code relay.calleeEntry()}. If the wrapped model
	 * is itself a pass-through wrapper the nominee is after it and crossing is licensed by THAT
	 * wrapper's own {@link HelperDiscovery#isPassThroughInto} proof; otherwise the nominee is the stop and this
	 * returns {@code null}.</li>
	 * </ul>
	 * In every nominated case the span between stop and nominee is a pass-through wrapper's body,
	 * which {@link HelperDiscovery#isPassThroughInto} has already proved is straight-line, fully disassembled,
	 * mechanism-inert and reached only by unconditional fallthrough. That proof is the licence;
	 * see {@link RegisterEnv}'s class javadoc for why it is sufficient.
	 * <p>
	 * <b>Why the join is crossed rather than the stop simply MOVED to the nominee.</b> Moving it
	 * would have been a smaller change and it is the wrong one. The scan would then stop at the
	 * wrapped helper's entry and adopt {@link #callSiteRegisters}' prologue-FILTERED values,
	 * throwing away whatever the wrapper's own body supplies -- a wrapper of the shape
	 * {@code LDY #3} / fall-through-into-helper would report Y unknown (the filter correctly says
	 * Y does not survive a prologue that writes it) where today's scan reads the {@code LDY #3}
	 * directly. Crossing keeps the walk going through the wrapper's prefix, so its writes and
	 * loads are read natively by the machinery that already knows how, and the filter is left to
	 * do its work only at the true outer stop.
	 * <p>
	 * Takes {@code firstSite} and {@code scanStop} loose rather than a {@link HelperDiscovery.HelperModel},
	 * and is package-private static, for one reason: {@code HelperDiscovery.HelperModel} is private, so a test
	 * that wanted a model could not build one -- the constraint that kept grm-2dr increment 1's
	 * wrapper tests at the predicate level. Same precedent as {@link #argumentSurvivesPrologue}
	 * and {@link HelperDiscovery#isPassThroughInto}, and the two parameters are the only two the window test
	 * reads anyway.
	 */
	static Address crossableWrapperJoin(Program program, Address firstSite, Address scanStop) {
		if (firstSite == null || scanStop == null) {
			return null;
		}
		Function body = program.getFunctionManager().getFunctionContaining(firstSite);
		if (body == null) {
			return null;
		}
		Address nominee = body.getEntryPoint();
		if (nominee.compareTo(scanStop) <= 0 || nominee.compareTo(firstSite) > 0) {
			return null;
		}
		return nominee;
	}

	/**
	 * A helper call site's positioned effect: {@code state} is the recovered value in the
	 * board's absolute state bits (like {@link SwitchResult#effect}); {@code ownedMask} is
	 * which of those absolute bits this call site is authoritative over -- the mask
	 * {@link BankDataflowEngine#runDataflow} folds {@code state} into via {@link BankDataflowEngine#overwrite}, distinct from
	 * {@code state.knownMask()} for exactly the reason {@link BankSwitchStrategy.HelperDeposit}
	 * documents (a touched-but-unresolved bit is owned and poisoned; an untouched bit is
	 * neither).
	 */
	record CallEffect(BankState state, int ownedMask) {}

	private static final StoredValueScanner.Hooks NO_HOOKS = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return null;
		}
	};
}
