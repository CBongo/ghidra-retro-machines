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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;

/**
 * The {@code serial-shift} mechanism class (bead {@code grm-hsv.1}): MMC1's 5-write
 * bit-serial shift register (iNES mapper 1) -- any write to the register range with bit 7
 * set resets the shifter and forces {@code prg_mode} to fix-last; five consecutive writes
 * with bit 7 clear each contribute one low bit (LSB first), and the 5th write's ADDRESS
 * (bits 14:13 within the range, not a fixed constant -- games write non-canonical
 * addresses inside each register's 8K window) selects which physical register the
 * reassembled 5-bit value commits to.
 * <p>
 * <b>Ground truth, not nesdev-wiki idealization</b> (see the bead's survey of verified
 * mapper-1 disassemblies -- Zelda 1, Final Fantasy, Metroid): every surveyed commercial
 * game emits the commit sequence as a fully UNROLLED, straight-line
 * {@code STA/LSR A/STA/LSR A/STA/LSR A/STA/LSR A/STA} chain (5 stores, 4 shifts) -- never
 * the counted {@code STA/LSR/DEY/BNE} loop the wiki presents as canonical. This strategy's
 * primary recognizer is therefore a STATIC backward-and-forward walk over that unrolled
 * shape; the counted-loop idiom is a deliberately separate, SECONDARY recognizer
 * ({@link #matchCountedLoopBranch}) that shares nothing with the primary path except the
 * field-deposit helpers.
 * <p>
 * <b>Counted-loop idiom -- no engine hook needed.</b> The bead sketched an optional
 * {@code findIdioms(Program, Function)} engine hook for the loop form, on the theory that
 * a loop's commit belongs to its EXIT EDGE, which a per-write {@code computeSwitch} can't
 * express. Prototyping showed the hook is unnecessary: {@code BoardBankAnalyzer}'s
 * dataflow probes {@code computeSwitch} on EVERY instruction (not just mechanism writes),
 * so this strategy simply claims the loop's closing {@code BNE} as a switch site -- the
 * committed state then flows out of the branch's fall-through (the exit edge) exactly like
 * any other switch result, through the same {@code switchResults} fold, merge, annotation,
 * retargeting, and helper machinery, with ZERO engine changes (perfect containment). The
 * committed state also flows around the back edge into the final loop iteration, which is
 * harmless: the body's only effect is the suppressed STA (below), and by the last
 * iteration the hardware really has committed. The in-loop STA itself is recognized by
 * {@link #isCountedLoopBody} -- which DELEGATES to the same branch matcher, so the two
 * recognizers cannot disagree -- and echoes {@code inState} (no poison, no early commit);
 * an STA whose surrounding loop the branch matcher rejects falls through to the primary
 * chain walk and poisons, so a malformed loop can never be silently ignored.
 * <p>
 * Params:
 * <ul>
 * <li>{@code start}/{@code end} -- the register range ($8000-$FFFF on real MMC1).</li>
 * <li>{@code targets} -- a map from write-5's address bits 14:13 (0-3: Control/CHR0/CHR1/
 * PRG) to {@code {fields: [{name, shift, bits}, ...]}}: a MULTI-field deposit from the
 * ONE reassembled 5-bit commit value (e.g. target 0 splits into {@code mirroring} at
 * shift 0 width 2 and {@code prg_mode} at shift 2 width 2; target 3 is {@code prg_bank}
 * at shift 0 width 5). A target index with no {@code targets} entry (MMC1's CHR0/CHR1)
 * is recognized but deliberately left a no-op on every tracked field -- same no-poison
 * contract as {@link SelectDataBankSwitchStrategy}'s untracked-select case.</li>
 * <li>{@code reset} -- field name -> literal value deposited when a bit-7-set write is
 * seen (MMC1: {@code {prg_mode: 3}} -- mirroring and prg_bank are UNTOUCHED by a
 * reset, only prg_mode is forced to fix-last).</li>
 * </ul>
 * Field-local sub-offsets for every field name referenced above come from
 * {@code params._field_layout}, the same {@code sets:}-derived injection
 * {@link BoardBankAnalyzer#configureStrategies} performs for every multi-field mechanism
 * (see {@link SelectDataBankSwitchStrategy}'s class javadoc).
 * <p>
 * <b>Chain-walk algorithm.</b> For a write {@code W} in range with a recognized store
 * register:
 * <ol>
 * <li>Resolve {@code W}'s stored byte via {@link StoredValueScanner} (mask 0xFF). Bit 7
 * UNKNOWN -> honest degrade: poison every field any target or the reset could touch (the
 * "partially-known must not silently assume reset" case -- never guess).</li>
 * <li>Bit 7 known SET -> reset: only the {@code reset} deposits are applied; every other
 * field (including mirroring) passes {@code inState} through unchanged. Because this
 * check runs independently for every write the dataflow visits, four consecutive bit-7-set
 * writes (Zelda's/Metroid's belt-and-suspenders quad reset to all four register
 * addresses) are four independent resets, never mistaken for shift-chain links -- the
 * chain walk below only ever chains bit-7-CLEAR stores.</li>
 * <li>Bit 7 known clear, store register not {@code 'A'} (LSR only shifts A or memory, and
 * every surveyed game shifts A) -> not a recognized shift op -> poison.</li>
 * <li>Otherwise, statically walk BOTH directions from {@code W} through the same basic
 * block: backward while the immediately preceding pair is ({@code LSR A}, another
 * STA-to-range with the same register), forward while the immediately following pair is
 * the same shape -- each step requires an unbroken straight-line fall-through predecessor/
 * successor with no incoming control-flow edge from elsewhere (a branch into the middle of
 * what looks like a chain cannot be soundly attributed). This determines {@code W}'s
 * 1-based position and the chain's total length WITHOUT inspecting any value (purely
 * instruction shape) -- value inspection only happens per-instruction, independently, when
 * the dataflow engine visits each individual write's own bit 7. A total length other than
 * exactly 5 (an isolated write, or one a control-flow edge/other instruction breaks out of
 * a would-be chain) -> poison: it DID hit the mapper register, so conservatism wins.
 * Positions 1-4 of a valid 5-chain: {@code inState} echoed unchanged (no-change contract,
 * same as {@link SelectDataBankSwitchStrategy}'s CHR case) -- the actual commit is deferred
 * to position 5. Position 5: the target is decoded from {@code W}'s OWN address (bits
 * 14:13, not a fixed constant -- covers FF1's non-canonical $9FFF/$BFFF/$DFFF/$FFF9), and
 * the reassembled value comes from a SINGLE backward value-scan of the CHAIN START
 * instruction (the original pre-shift accumulator load): committed bit {@code i} equals
 * that pre-chain byte's bit {@code i}, because each store contributes its current bit 0
 * before the next LSR shifts the next bit into position. An unresolvable pre-chain value
 * degrades to unknown deposited into just that target's fields (the target itself is
 * still certain from the address) -- never a guess, and never poisons unrelated
 * targets.</li>
 * </ol>
 * <p>
 * <b>Strategy-match cache compatibility.</b> Per {@code BoardBankAnalyzer#runDataflow}'s
 * memoization invariant, a non-cacheable strategy's MATCH/no-match decision (is this
 * instruction this mechanism's write at all) must be an instruction-only predicate,
 * independent of {@code inState} -- only the resulting VALUE may vary. That holds here:
 * {@link #computeSwitch} returns non-null for exactly (a) every instruction that writes
 * anywhere in the configured range, unconditionally (reset, echo, commit, and poison are
 * all non-null results), and (b) the closing BNE of a counted loop the shape matcher
 * accepts; only which branch fires -- never whether a result exists --
 * depends on state-independent, purely-instruction-shape analysis (bit 7's resolution
 * itself never consults {@code inState} either, since this mechanism's {@link Hooks}
 * implementation below never resolves a load back to the tracked state -- MMC1's shift
 * register is write-only). {@link #cacheable()} nonetheless stays {@code false} (the
 * default): the RESULT for positions 1-4 and for poison both echo/modify {@code inState}
 * itself, so the value genuinely depends on it even though the match decision does not.
 * {@link #effectDependsOnPriorState()} asks a related but distinct question -- not whether
 * the result VARIES with {@code inState}, but whether an unknown result is EVIDENCE of a
 * missing state bit -- and is answered {@code false} here: echoing {@code inState}
 * unchanged is not a dependence, and nothing in this mechanism ever reads tracked state to
 * decide a value, so this class overrides that method explicitly rather than inheriting its
 * {@link #cacheable()}-derived default.
 */
public class SerialShiftBankSwitchStrategy implements BankSwitchStrategy {

	/** One tracked sub-field's field-local {@code [lsb, lsb+width)} bit position. */
	private record FieldPos(int lsb, int width) {
		int mask() {
			return ((1 << width) - 1) << lsb;
		}
	}

	/** One field deposit out of the reassembled 5-bit commit value: bits
	 *  {@code [shift, shift+bits)} of that value land at {@code pos}. */
	private record TargetField(FieldPos pos, int shift, int bits) {
	}

	/** One field deposit applied unconditionally on a bit-7 reset. */
	private record ResetField(FieldPos pos, int value) {
	}

	/** The result of statically walking the unrolled STA/LSR chain containing one write. */
	private record ChainInfo(int index, int total, Instruction chainStart) {
	}

	private AddressSpace space;
	private long rangeStart;
	private long rangeEnd;

	private Map<Integer, List<TargetField>> targets;
	private List<ResetField> resetFields;
	private final Set<FieldPos> allPoisonFields = new LinkedHashSet<>();

	/** The addresses that MIRROR THE LIVE BANK (grm-mej.2), delivered by {@link #observeMirrors}
	 *  between the analyzer's two dataflow passes. Empty for pass 1 and for any board with no
	 *  derivable mirror, where this strategy behaves exactly as it did before they existed. */
	private BankMirrors mirrors = BankMirrors.none();

	@Override
	public String strategyName() {
		return "serial-shift";
	}

	@Override
	public void observeMirrors(BankMirrors observed) {
		mirrors = observed == null ? BankMirrors.none() : observed;
	}

	@Override
	public void configure(Program program, JsonObject params, int stateMask) {
		space = program.getAddressFactory().getDefaultAddressSpace();
		rangeStart = params.get("start").getAsLong();
		rangeEnd = params.get("end").getAsLong();

		JsonObject fieldLayout =
			params.has("_field_layout") ? params.getAsJsonObject("_field_layout") : new JsonObject();

		targets = new java.util.HashMap<>();
		if (params.has("targets")) {
			for (Map.Entry<String, JsonElement> e : params.getAsJsonObject("targets").entrySet()) {
				int idx = Integer.parseInt(e.getKey());
				List<TargetField> fields = new ArrayList<>();
				for (JsonElement fe : e.getValue().getAsJsonObject().getAsJsonArray("fields")) {
					JsonObject fo = fe.getAsJsonObject();
					FieldPos pos = fieldPos(fieldLayout, fo.get("name").getAsString());
					int shift = fo.get("shift").getAsInt();
					int bits = fo.get("bits").getAsInt();
					fields.add(new TargetField(pos, shift, bits));
					allPoisonFields.add(pos);
				}
				targets.put(idx, fields);
			}
		}

		resetFields = new ArrayList<>();
		if (params.has("reset")) {
			for (Map.Entry<String, JsonElement> e : params.getAsJsonObject("reset").entrySet()) {
				FieldPos pos = fieldPos(fieldLayout, e.getKey());
				resetFields.add(new ResetField(pos, e.getValue().getAsInt()));
				allPoisonFields.add(pos);
			}
		}
	}

	private static FieldPos fieldPos(JsonObject fieldLayout, String fieldName) {
		JsonObject fl = fieldLayout.has(fieldName) ? fieldLayout.getAsJsonObject(fieldName) : null;
		if (fl == null) {
			throw new IllegalArgumentException(
				"serial-shift: no field-layout entry for '" + fieldName +
					"' -- is it listed in this mechanism's 'sets:'?");
		}
		return new FieldPos(fl.get("lsb").getAsInt(), fl.get("width").getAsInt());
	}

	private final StoredValueScanner.Hooks hooks = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return writesInRange(instr) != null;
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			// MMC1's shift register is write-only -- nothing reads it back, at any
			// resolvedTarget.
			return null;
		}
	};

	/**
	 * {@link #hooks} plus mirror consumption for ONE target's field layout (grm-mej.2
	 * increment 3). The target has to be baked in because {@link StoredValueScanner.Hooks} is
	 * handed a load, not a destination, while the byte being reassembled means nothing until you
	 * know WHICH mapper register it is bound for -- so every scan site decodes its own target
	 * (which it already must, from the write's address) and asks with that.
	 * <p>
	 * {@code fields} may be {@code null} (an unconfigured target, i.e. CHR), in which case no
	 * mirror is consulted and this degrades to {@link #hooks} exactly.
	 */
	private StoredValueScanner.Hooks hooksFor(List<TargetField> fields) {
		if (fields == null || mirrors.isEmpty()) {
			return hooks;
		}
		return new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return hooks.isMechanismWrite(instr);
			}

			@Override
			public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return hooks.resolveLoad(loadInstr, resolvedTarget, inStateAtStore);
			}

			@Override
			public BankState resolveMirrorLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return mirroredByte(resolvedTarget, inStateAtStore, fields);
			}
		};
	}

	/**
	 * The RAW PRE-CHAIN BYTE a load of {@code target} yields when {@code target} mirrors the live
	 * bank, or {@code null} when it mirrors nothing this strategy may answer from tracked state.
	 * The inverse of {@link #depositFields}, plus the one thing the inverse alone cannot give.
	 * <p>
	 * <b>ONLY {@link BankMirrors.Kind#ROM_IDENTIFYING} ANSWERS HERE, and the restriction is not
	 * the same one memory-latch applies.</b> There, {@link BankMirrors.Kind#WRITE_THROUGH} answers
	 * too, because a partial byte is enough: the extraction keeps the field bits and throws the
	 * rest away. Here it is worth nothing, and the reason is MMC1's own wire protocol -- bit 7 of
	 * a written byte is an out-of-band RESET signal, so {@link #computeSwitch} refuses to believe
	 * ANY of a byte whose bit 7 it cannot resolve and poisons every tracked field instead
	 * (see the {@code bit7Known} gate). A shadow reconstructed from tracked state knows the field
	 * bits and nothing else, so it would arrive at that gate with bit 7 still unknown, poison
	 * exactly as before, and -- because the poison lands on write 1 and the commit reads state at
	 * write 5 -- destroy the very state a later mirror read would have been answered from. Two
	 * symptoms, one cause; supplying bit 7 dissolves both.
	 * <p>
	 * {@code ROM_IDENTIFYING} supplies it and a shadow cannot. {@code BankMirrors
	 * .romIdentifyingOffsets} admitted the offset only after verifying {@code byte == bank} in
	 * EVERY realized bank's image, so the whole byte is determined by the bank number: every bit
	 * above the reconstructed field range is a PROVED zero, bit 7 among them. That is why
	 * grm-mej.2's "serial-shift consumption is nearly free, its resolveLoad is orthogonal to a RAM
	 * shadow" premise holds only for the identifying half. Admitting {@code WRITE_THROUGH} would
	 * need a further ruling -- that a value currently live in these fields must have been
	 * committed, and a committed byte had bit 7 clear -- which is a real inference and is
	 * deliberately not made here.
	 * <p>
	 * <b>A single field at byte shift 0, or decline.</b> The identifying byte is a BANK NUMBER,
	 * right-justified. A target whose layout is anything else is not a register that takes a bank:
	 * MMC1's Control ({@code mirroring} at shift 0 plus {@code prg_mode} at shift 2) would happily
	 * accept a reconstruction and produce confident nonsense, because a bank number committed to
	 * Control is not a coherent program. This is the same refusal, for the same reason, that
	 * {@code MemoryLatchBankSwitchStrategy.mirroredByte} makes when its {@code shift != 0}.
	 */
	private BankState mirroredByte(Address target, BankState inState, List<TargetField> fields) {
		if (target == null || !mirrors.is(target, BankMirrors.Kind.ROM_IDENTIFYING)) {
			return null;
		}
		if (fields.size() != 1 || fields.get(0).shift() != 0) {
			return null; // not a "takes a bank number" register -- see above
		}
		TargetField tf = fields.get(0);
		// Undo setFieldFromByte: lift the tracked field back down to bit 0 of the byte. Both
		// widths are applied -- the board field's and the byte field's -- because a descriptor may
		// legitimately declare a byte field wider than the state field behind it (MMC1's prg_bank
		// takes 5 bits on the wire for a 4-bit bank universe).
		int byteMask = ((1 << tf.bits()) - 1) & (((1 << tf.pos().width()) - 1));
		int known = (inState.knownMask() >>> tf.pos().lsb()) & byteMask;
		int bits = (inState.bits() >>> tf.pos().lsb()) & byteMask;
		// byte == bank, so everything above the bank's own bits is a PROVED zero -- which is what
		// makes bit 7 resolvable and the whole consumption path reachable at all.
		return new BankState(known | (~byteMask & 0xFF), bits);
	}

	@Override
	public BankState computeSwitch(Program program, Instruction instr, BankState inState) {
		Long offset = writesInRange(instr);
		if (offset == null) {
			// Not a mechanism write. The ONLY non-write instruction this strategy claims is
			// the closing BNE of a counted serial-shift loop (the SECONDARY recognizer --
			// see the "counted-loop idiom" section of the class javadoc): the commit state
			// attaches to the branch, so the loop's exit edge (and, harmlessly, its back
			// edge) carries the committed value. Match decision (matchCountedLoopBranch) is
			// instruction-shape-only, per the engine's strategy-match-cache invariant.
			CountedLoop loop = matchCountedLoopBranch(program, instr);
			if (loop == null) {
				return null;
			}
			return commitCountedLoop(program, loop, inState);
		}

		Character reg = StoredValueScanner.storeRegister(instr);
		if (reg == null) {
			// A read-modify-write store (INC/ASL/... to the range) isn't a plain byte commit
			// this scanner can attribute a value to; it DID hit the register. It poisons --
			// UNLESS it is the self-modifying reset idiom, which is exactly determinable.
			if (selfModifyingRmwResetsShifter(instr, offset)) {
				return applyReset(inState);
			}
			return poisonAll(inState);
		}

		// Counted-loop body suppression: the STA inside a recognized counted loop is
		// covered by the loop's own commit (attached to the BNE above); treating it as an
		// isolated unchained write would poison the very fields the loop is committing.
		// The check DELEGATES to matchCountedLoopBranch so the two recognizers can never
		// disagree: a loop the BNE matcher rejects (wrong trip count, join into the body,
		// unresolvable shape) leaves its STA to fall through to the chain walk below,
		// which poisons -- unsound silence is impossible. Must run before the bit-7
		// resolution: the loop-head STA is a branch target (the BNE's back edge), so the
		// backward value scan aborts at the join and would misreport bit 7 unknown.
		if (isCountedLoopBody(program, instr)) {
			return inState;
		}

		// Structural shortcut, NOT a StoredValueScanner call: LSR unconditionally shifts a
		// 0 into bit 7, so any store whose immediately preceding instruction (straight-line,
		// no incoming control-flow edge) is "LSR A" has a bit 7 that is KNOWN CLEAR by
		// construction -- true regardless of whatever value was shifted in earlier, and
		// therefore true for every write 2-5 of a real chain. This matters because
		// StoredValueScanner deliberately does NOT model LSR bit-wise (its javadoc: shifts
		// leave the value wholly unknown from that point backward) -- calling it directly on
		// writes 2-5 would always report bit 7 unknown and poison every chain before the
		// chain walk ever ran. Only a write NOT immediately preceded by "LSR A" (a chain's
		// write 1, a reset, or an isolated write) needs the general backward value scan.
		boolean bit7Known;
		boolean bit7Set;
		if (precededByLsrA(program, instr)) {
			bit7Known = true;
			bit7Set = false;
		}
		else {
			// The write's OWN address decodes the target, which is what lets a mirror read be
			// interpreted at all (grm-mej.2 increment 3) -- and it must be available HERE, not
			// only at the write-5 commit below, because this gate runs first and a poison here
			// wipes the state the commit would have read.
			BankState storedByte = StoredValueScanner.resolveStoredValue(program, instr, reg,
				inState, 0xFF, hooksFor(targets.get(targetIndex(offset))));
			bit7Known = (storedByte.knownMask() & 0x80) != 0;
			bit7Set = bit7Known && (storedByte.bits() & 0x80) != 0;
		}
		if (!bit7Known) {
			return poisonAll(inState);
		}
		if (bit7Set) {
			return applyReset(inState);
		}

		if (reg != 'A') {
			// LSR only shifts the accumulator (or memory, never modeled as the chain
			// register); every surveyed game's commit chain shifts A.
			return poisonAll(inState);
		}

		ChainInfo chain = analyzeChain(program, instr);
		if (chain == null || chain.total() != 5) {
			return poisonAll(inState);
		}
		if (chain.index() < 5) {
			// Writes 1-4 of a valid 5-chain: no-change echo: the actual commit happens
			// once the 5th write is examined.
			return inState;
		}

		int targetIdx = targetIndex(offset);
		List<TargetField> fields = targets.get(targetIdx);
		if (fields == null) {
			// CHR0/CHR1 (or any un-configured target): recognized, deliberately discarded
			// -- see class javadoc's no-poison contract.
			return inState;
		}

		BankState preChainByte = StoredValueScanner.resolveStoredValue(program, chain.chainStart(),
			reg, inState, 0xFF, hooksFor(fields));
		return depositFields(inState, fields, preChainByte);
	}

	/**
	 * {@code false}: none of the four branches above decide a VALUE by consulting
	 * {@code inState}. The position-5 COMMIT comes from a backward value-scan of the
	 * pre-chain accumulator load ({@code chain.chainStart()}), never from tracked state; the
	 * bit-7-set RESET deposits fixed literals from {@code resetFields}; positions 1-4 and the
	 * bit-7-unknown POISON branch merely pass {@code inState} through unchanged. That last
	 * pair is exactly why {@link #cacheable()} stays {@code false} (see the class javadoc's
	 * "Strategy-match cache compatibility" paragraph) -- an echo makes the RESULT vary with
	 * {@code inState} without making it a genuine dependence, which is precisely the
	 * distinction this method exists to draw.
	 * <p>
	 * <b>The last clause of this javadoc used to be "and this strategy's {@link
	 * StoredValueScanner.Hooks} never resolves a load back to tracked state, so there is no
	 * mechanism by which an unknown outcome here could reflect a missing bank-state bit". That
	 * stopped being true in grm-mej.2 increment 3</b>, which lets a load of a bank-identifying ROM
	 * offset resolve from tracked state. A site that reads one and comes up empty DID need a state
	 * bit it did not have. So the strategy-wide answer stays {@code false} -- it is still right for
	 * every site that does not read a mirror, which on a real cartridge is nearly all of them --
	 * and the per-site overload below answers the sites where it is not.
	 */
	@Override
	public boolean effectDependsOnPriorState() {
		return false;
	}

	/**
	 * The per-site question (grm-mej.2 §2d), answered by re-running this site's own value scan
	 * under an instrumented hook and reporting whether a MIRROR load was actually resolved.
	 * <p>
	 * Same shape and same reason as {@code MemoryLatchBankSwitchStrategy}'s override, but arrived
	 * at from the opposite direction. There the strategy-wide default flipped to {@code true} when
	 * {@code cacheable()} went {@code false}, and the override exists to stop it over-reporting.
	 * Here the strategy-wide answer is an explicit {@code false} that would now UNDER-report: a
	 * chain whose pre-chain byte came from an identifying read-back genuinely does depend on the
	 * bank being known on entry, and silently dropping that is how a real bank-requirement
	 * violation goes unreported.
	 * <p>
	 * Cheap by construction: the mirror set is empty on every board that has none, and the whole
	 * probe short-circuits there. Called once per site in the analyzer's phase 3, never inside the
	 * fixpoint.
	 */
	@Override
	public boolean effectDependsOnPriorState(Program program, Instruction site,
			BankState siteInState) {
		if (mirrors.isEmpty() || site == null) {
			return false;
		}
		Integer targetIdx = targetIndexOf(program, site);
		if (targetIdx == null) {
			return false;
		}
		List<TargetField> fields = targets.get(targetIdx);
		if (fields == null) {
			return false;
		}
		boolean[] consulted = new boolean[1];
		StoredValueScanner.Hooks probe = new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return hooks.isMechanismWrite(instr);
			}

			@Override
			public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return hooks.resolveLoad(loadInstr, resolvedTarget, inStateAtStore);
			}

			@Override
			public BankState resolveMirrorLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				BankState mirrored = mirroredByte(resolvedTarget, inStateAtStore, fields);
				if (mirrored != null) {
					consulted[0] = true;
				}
				return mirrored;
			}
		};
		Instruction scanFrom = scanOriginFor(program, site);
		if (scanFrom == null) {
			return false;
		}
		StoredValueScanner.resolveStoredValue(program, scanFrom, 'A', siteInState, 0xFF, probe);
		return consulted[0];
	}

	/**
	 * Where this site's value scan starts: an unrolled chain's own pre-chain load position (the
	 * chain start, so a write-5 commit is probed at the instruction whose value it actually
	 * reassembles, not at write 5 itself), or a counted loop's counter init. {@code null} when
	 * {@code site} is neither shape.
	 */
	private Instruction scanOriginFor(Program program, Instruction site) {
		if (writesInRange(site) != null) {
			ChainInfo chain = analyzeChain(program, site);
			return chain == null ? site : chain.chainStart();
		}
		CountedLoop loop = matchCountedLoopBranch(program, site);
		return loop == null ? null : loop.counterInit();
	}

	/**
	 * Converts a helper call site's recovered argument byte into this mechanism's
	 * field-local deposit: serial-shift is the one shipped mechanism whose single switch
	 * instruction shape (the unrolled chain's write-5 STA, or a counted loop's closing BNE)
	 * can commit to different DISJOINT target field lists depending on the site's OWN
	 * address -- so unlike the interface default (which owns and deposits across the WHOLE
	 * field-local width, correct only for a single-field mechanism), this decodes
	 * {@code switchSite}'s target exactly as {@link #computeSwitch}/{@link #commitCountedLoop}
	 * do and returns an {@code ownedMask} covering ONLY that target's own fields: a helper
	 * call through the PRG target must not claim ownership of (and thereby wipe)
	 * {@code mirroring}/{@code prg_mode}'s already-known bits, which it never touches --
	 * there is no in-state to echo at a helper call site the way a direct dataflow switch
	 * has, so "don't own it" (leave the caller's fold alone) is the only honest way to avoid
	 * poisoning sibling fields. A target with no configured fields (CHR) owns nothing at all
	 * ({@code ownedMask = 0}) -- the same no-poison-by-omission contract as
	 * {@link #computeSwitch}'s CHR echo, expressed as "touches nothing" instead of "echoes
	 * inState" since there is no inState to echo here.
	 * <p>
	 * {@code inState} (the caller's field-local mechanism state at the call site, per the
	 * interface javadoc) is deliberately IGNORED here: serial-shift's routing is decided
	 * entirely by {@code switchSite}'s own address (which physical register write-5/the
	 * loop's closing BNE targets), never by tracked state -- unlike
	 * {@link SelectDataBankSwitchStrategy}, which has no address-based routing signal and
	 * must consult {@code inState}'s tracked select value instead.
	 */
	@Override
	public HelperDeposit depositHelperArgument(Program program, Instruction switchSite,
			BankState argValue, BankState inState, int stateMask) {
		Integer targetIdx = targetIndexOf(program, switchSite);
		if (targetIdx == null) {
			// switchSite isn't a shape this strategy itself recognizes as a commit -- can't
			// happen for a genuine HelperModel.switchSite (it was recorded because THIS
			// strategy matched it), but stay conservative: own nothing rather than guess.
			return new HelperDeposit(0, new BankState(0, 0));
		}
		List<TargetField> fields = targets.get(targetIdx);
		if (fields == null) {
			// CHR target: owns nothing -- see method javadoc.
			return new HelperDeposit(0, new BankState(0, 0));
		}
		int owned = 0;
		for (TargetField tf : fields) {
			owned |= tf.pos().mask();
		}
		return new HelperDeposit(owned, depositFields(new BankState(0, 0), fields, argValue));
	}

	/** The reassembled commit value's target register index (write-5's/the loop STA's
	 *  address bits 14:13 -- Control/CHR0/CHR1/PRG). */
	private static int targetIndex(long offset) {
		return (int) ((offset >>> 13) & 0x3);
	}

	/** {@code targetIndex}, but starting from a switch-site INSTRUCTION rather than a known
	 *  write offset: recognizes either shape this strategy claims as a switch site (an
	 *  in-range write -- any position of a chain, though only write-5's address is
	 *  meaningful when several share one target as they do on every shipped chain -- or a
	 *  counted loop's closing BNE), or {@code null} if {@code instr} is neither. */
	private Integer targetIndexOf(Program program, Instruction instr) {
		Long offset = writesInRange(instr);
		if (offset != null) {
			return targetIndex(offset);
		}
		CountedLoop loop = matchCountedLoopBranch(program, instr);
		return loop == null ? null : targetIndex(loop.staOffset());
	}

	/** Deposits each of {@code fields}' bits (sliced out of {@code byteValue} at its own
	 *  {@code shift}/{@code bits}) into {@code base} at the field's own position -- the
	 *  shared core of a chain commit, a counted-loop commit, and a helper call-site
	 *  deposit; only what {@code base} is (the current in-state, or "nothing known" when
	 *  there is none) differs between callers. */
	private static BankState depositFields(BankState base, List<TargetField> fields,
			BankState byteValue) {
		BankState result = base;
		for (TargetField tf : fields) {
			BankState fieldValue = extractByteField(byteValue, tf.bits(), tf.shift());
			result = setFieldFromByte(result, tf.pos(), fieldValue);
		}
		return result;
	}

	/**
	 * Whether a read-modify-write into the register range is certainly the self-modifying
	 * shifter-reset idiom (bead grm-4kc). False means "not derivable", and the caller keeps
	 * poisoning -- this only ever converts a poison into a reset, never the reverse.
	 * <p>
	 * <b>The idiom.</b> Bionic Commando's RESET is {@code $FFE1: EE E1 FF  INC $FFE1} -- an
	 * {@code INC} whose operand is its OWN opcode byte. Any write to {@code $8000-$FFFF}
	 * with bit 7 set resets the shifter and forces {@code prg_mode = 3}, and {@code $EE} has
	 * bit 7 set, so this is the most determinable write in the program -- yet
	 * {@link StoredValueScanner#storeRegister} knows only {@code STA}/{@code STX}/{@code STY}
	 * and the whole mechanism was being poisoned at the program's reset vector, which is the
	 * seed every later inference hangs off.
	 * <p>
	 * <b>Why the byte is knowable without any memory-map reasoning.</b> The instruction reads
	 * the address it occupies, so the byte it reads is the byte the CPU just fetched as this
	 * instruction's own opcode. That holds whichever bank is mapped -- invariance comes from
	 * self-reference, not from the block being fixed. It is worth being explicit that the
	 * obvious alternative does NOT work here:
	 * {@link MemoryLatchBankSwitchStrategy}-style "read a bank-invariant ROM byte" refuses any
	 * address an overlay shadows, and {@code nes-mmc1.map} emits 32K-mode overlays
	 * ({@code W8000_M0_B*}) spanning {@code $8000-$FFFF}, so on an MMC1 board it can only ever
	 * answer no. See grm-4kc for the deferred non-self-referential tier.
	 * <p>
	 * <b>A 6502 RMW puts TWO writes on the bus</b> -- the unmodified byte, then the modified
	 * one on the next cycle. {@code INC $FFE1} presents {@code $EE}, then {@code $EF}. Per the
	 * nesdev wiki the MMC1's response to that is asymmetric, and the asymmetry is what decides
	 * this method's rule:
	 * <blockquote>
	 * When the serial port is written to on consecutive cycles, it ignores every write after
	 * the first. In practice, this only happens when the CPU executes read-modify-write
	 * instructions, which first write the original value before writing the modified one on
	 * the next cycle. <b>This restriction only applies to the data being written on bit 0; the
	 * bit 7 reset is never ignored.</b> Bill &amp; Ted's Excellent Adventure does a reset by
	 * using INC on a ROM location containing {@code $FF} and requires that the {@code $00}
	 * write on the next cycle is ignored. Shinsenden, however, uses illegal instruction
	 * {@code $7F} (RRA abs,X) to set bit 7 on the second write and will crash [...] if this
	 * reset is ignored.
	 * </blockquote>
	 * So the test is an <b>OR, not an AND</b>: bit 7 set in EITHER write is a reset. Each half
	 * has a game behind it -- Bill &amp; Ted ({@code $FF -> $00}, set then clear) proves an AND
	 * would decline a real reset; Shinsenden (clear then set) proves the second write counts.
	 * <p>
	 * <b>Two tiers, and the first needs no mnemonic table.</b> The first write is always the
	 * unmodified byte, so bit 7 of that byte means "reset" whatever the instruction is --
	 * which is why {@code ASL}/{@code LSR}/{@code ROL}/{@code ROR}, and even an illegal RMW
	 * opcode this sleigh may not decode, are handled correctly without being enumerated. Only
	 * the clear-then-set direction needs to know the operation, and only {@code INC}/
	 * {@code DEC} are modeled there: {@code LSR} can never set bit 7 (so returning false is
	 * exhaustive, not a gap), {@code ASL}/{@code ROL} would be bit 6 of the byte but no
	 * surveyed game spells the reset that way, and {@code ROR}/{@code RRA} put the CARRY in
	 * bit 7, which is genuinely underivable here. An unmodeled spelling falls through to
	 * {@code poisonAll}, which raises a WARNING bookmark at the instruction -- so it surfaces
	 * as a diagnosable warning rather than as silence.
	 */
	private boolean selfModifyingRmwResetsShifter(Instruction instr, long offset) {
		// Self-reference: does the write land inside this instruction's own bytes? Comparing
		// raw offsets is right even across spaces -- writesInRange already pinned the target
		// to the base space, and an overlay shares the base offset, which is the point: the
		// instruction may well be executing out of one.
		long idx = offset - instr.getMinAddress().getOffset();
		if (idx < 0 || idx >= instr.getLength()) {
			return false;
		}
		int original;
		try {
			original = instr.getByte((int) idx) & 0xFF;
		}
		catch (Exception e) {
			return false;
		}
		if ((original & 0x80) != 0) {
			return true; // tier A: the first write is the unmodified byte, op-independent
		}
		String mnem = instr.getMnemonicString().toUpperCase();
		int modified;
		if (mnem.equals("INC")) {
			modified = (original + 1) & 0xFF;
		}
		else if (mnem.equals("DEC")) {
			modified = (original - 1) & 0xFF;
		}
		else {
			return false;
		}
		return (modified & 0x80) != 0; // tier B: the second write sets bit 7
	}

	private BankState applyReset(BankState inState) {
		BankState result = inState;
		for (ResetField rf : resetFields) {
			int widthMask = (1 << rf.pos().width()) - 1;
			result = setFieldFromByte(result, rf.pos(), BankState.fullyKnown(widthMask, rf.value()));
		}
		return result;
	}

	private BankState poisonAll(BankState inState) {
		BankState result = inState;
		for (FieldPos fp : allPoisonFields) {
			result = setUnknownField(result, fp);
		}
		return result;
	}

	// ------------------------------------------------------------------
	// Counted-loop idiom (SECONDARY recognizer -- see class javadoc)
	// ------------------------------------------------------------------

	/** A matched counted serial-shift loop: {@code head} is the in-loop STA (also the
	 *  BNE's target), {@code counterInit} the {@code LDX/LDY #5} immediately before it
	 *  (the anchor for the pre-loop A-value scan), {@code staOffset} the STA's target
	 *  address (target register = its bits 14:13). */
	private record CountedLoop(Instruction head, Instruction counterInit, long staOffset) {
	}

	/**
	 * Matches the counted serial-shift loop's closing branch -- the NESdev-wiki-canonical
	 * (though never commercially surveyed) form:
	 * <pre>
	 *   LDA #value        ; or any A provenance further back (one backward scan)
	 *   LDY #5            ; or LDX #5 -- must match the loop's own DEC register
	 * loop:
	 *   STA <range>       ; the ONLY mechanism write in the body
	 *   LSR A
	 *   DEY               ; or DEX
	 *   BNE loop          ; <- the instruction this matcher accepts
	 * </pre>
	 * Guards: the four body instructions must be exactly this shape and order (each
	 * linked by fall-through); no control-flow edge may enter the body anywhere except
	 * the BNE's own back edge into the head; the counter init must immediately precede
	 * the head, target the same register the body decrements, and load exactly 5 (the
	 * trip count that makes the shift register commit precisely on the last iteration --
	 * any other count either under-fills the shifter or spills into a second sequence,
	 * neither of which this recognizer can attribute). The trip-count-4-with-pre-loop-STA
	 * variant the bead mentions is NOT recognized (the pre-loop STA would be poisoned by
	 * the primary path as an isolated write) -- acceptable for a secondary recognizer of
	 * an idiom no surveyed commercial game uses; extend if a real title ever needs it.
	 * Everything checked here is instruction shape only -- no value inspection -- which
	 * is what keeps the match/no-match decision compatible with the engine's per-address
	 * strategy-match cache.
	 */
	private CountedLoop matchCountedLoopBranch(Program program, Instruction instr) {
		if (!instr.getMnemonicString().equalsIgnoreCase("BNE")) {
			return null;
		}
		Address[] flows = instr.getFlows();
		if (flows.length != 1) {
			return null;
		}
		Listing listing = program.getListing();
		Instruction head = listing.getInstructionAt(flows[0]);
		if (head == null || !isChainStore(head)) {
			return null;
		}
		Long staOffset = writesInRange(head);
		Instruction lsr = nextFallThrough(listing, head);
		if (lsr == null || !isLsrAccumulator(lsr)) {
			return null;
		}
		Instruction dec = nextFallThrough(listing, lsr);
		if (dec == null) {
			return null;
		}
		String decMnem = dec.getMnemonicString().toUpperCase();
		if (!decMnem.equals("DEX") && !decMnem.equals("DEY")) {
			return null;
		}
		Instruction bne = nextFallThrough(listing, dec);
		if (bne == null || !bne.getMinAddress().equals(instr.getMinAddress())) {
			return null;
		}

		// No stray control flow into the body: the head's only incoming flow ref must be
		// this BNE's back edge, and nothing may branch into the middle instructions.
		if (!onlyFlowRefFrom(program, head, instr) || isControlFlowJoin(program, lsr, head) ||
			isControlFlowJoin(program, dec, lsr) || isControlFlowJoin(program, instr, dec)) {
			return null;
		}

		Instruction counterInit = listing.getInstructionBefore(head.getMinAddress());
		if (counterInit == null || !fallsThroughTo(counterInit, head)) {
			return null;
		}
		char counterReg = decMnem.charAt(2); // 'X' | 'Y'
		if (!counterInit.getMnemonicString().equalsIgnoreCase("LD" + counterReg) ||
			!StoredValueScanner.isImmediate(counterInit)) {
			return null;
		}
		Integer tripCount = StoredValueScanner.immediateOperandValue(counterInit);
		if (tripCount == null || tripCount != 5) {
			return null;
		}
		return new CountedLoop(head, counterInit, staOffset);
	}

	/**
	 * The counted loop's commit, attached to its closing BNE: reassembles the 5-bit value
	 * from ONE backward scan of the pre-loop A value (anchored at the counter init, i.e.
	 * scanning the straight-line code before the loop -- the head itself is a branch
	 * target, so scanning from it would abort at its own back-edge join). Same LSB-first
	 * semantics as the unrolled chain: each iteration stores bit 0 then shifts, so the
	 * committed value is the seed's low 5 bits. A seed whose bit 7 is not known-clear
	 * poisons instead of committing -- with bit 7 possibly set, iteration 1 would have
	 * been a hardware RESET (and the remaining four writes an uncommitted partial
	 * sequence), so nothing about the loop's effect can be trusted.
	 */
	private BankState commitCountedLoop(Program program, CountedLoop loop, BankState inState) {
		// Target decoded BEFORE the seed scan (grm-mej.2 increment 3): a mirror read inside that
		// scan can only be interpreted against the register the loop is committing to, and the
		// bit-7 gate below is exactly what a mirror answer exists to get past.
		int targetIdx = targetIndex(loop.staOffset());
		List<TargetField> fields = targets.get(targetIdx);

		BankState seed = StoredValueScanner.resolveStoredValue(program, loop.counterInit(), 'A',
			inState, 0xFF, hooksFor(fields));
		boolean bit7KnownClear = (seed.knownMask() & 0x80) != 0 && (seed.bits() & 0x80) == 0;
		if (!bit7KnownClear) {
			return poisonAll(inState);
		}

		if (fields == null) {
			// CHR target: recognized, deliberately discarded -- same no-poison contract
			// as the unrolled path.
			return inState;
		}
		return depositFields(inState, fields, seed);
	}

	/** Whether {@code staInstr} is the body store of a counted loop the branch matcher
	 *  accepts -- found by locating the BNE three instructions ahead and DELEGATING to
	 *  {@link #matchCountedLoopBranch}, so suppression and commit can never disagree. */
	private boolean isCountedLoopBody(Program program, Instruction staInstr) {
		Listing listing = program.getListing();
		Instruction lsr = nextFallThrough(listing, staInstr);
		if (lsr == null || !isLsrAccumulator(lsr)) {
			return false;
		}
		Instruction dec = nextFallThrough(listing, lsr);
		if (dec == null) {
			return false;
		}
		Instruction bne = nextFallThrough(listing, dec);
		if (bne == null) {
			return false;
		}
		CountedLoop loop = matchCountedLoopBranch(program, bne);
		return loop != null && loop.head().getMinAddress().equals(staInstr.getMinAddress());
	}

	/** The instruction at {@code from}'s fall-through address, or {@code null}. */
	private static Instruction nextFallThrough(Listing listing, Instruction from) {
		Address ft = from.getFallThrough();
		return ft == null ? null : listing.getInstructionAt(ft);
	}

	/** Whether every incoming flow reference to {@code instr} comes from {@code only} --
	 *  the loop-head variant of {@link #isControlFlowJoin}, where exactly one known
	 *  branch (the loop's own back edge) is permitted. */
	private static boolean onlyFlowRefFrom(Program program, Instruction instr, Instruction only) {
		for (Reference ref : program.getReferenceManager().getReferencesTo(instr.getMinAddress())) {
			if (ref.getReferenceType().isFlow() &&
				!ref.getFromAddress().equals(only.getMinAddress())) {
				return false;
			}
		}
		return true;
	}

	// ------------------------------------------------------------------
	// Static unrolled-chain walk
	// ------------------------------------------------------------------

	/**
	 * Determines {@code sta}'s 1-based position and total length within the maximal
	 * alternating {@code STA-to-range/LSR A} chain containing it, walking backward and
	 * forward from {@code sta} through its basic block (see class javadoc's algorithm
	 * section). Purely a static instruction-shape walk -- no value inspection.
	 */
	private ChainInfo analyzeChain(Program program, Instruction sta) {
		Listing listing = program.getListing();

		int backCount = 0;
		Instruction chainStart = sta;
		Instruction cur = sta;
		while (true) {
			Instruction prevLsr = listing.getInstructionBefore(cur.getMinAddress());
			if (prevLsr == null || !fallsThroughTo(prevLsr, cur) ||
				isControlFlowJoin(program, cur, prevLsr) || !isLsrAccumulator(prevLsr)) {
				break;
			}
			Instruction prevSta = listing.getInstructionBefore(prevLsr.getMinAddress());
			if (prevSta == null || !fallsThroughTo(prevSta, prevLsr) ||
				isControlFlowJoin(program, prevLsr, prevSta) || !isChainStore(prevSta)) {
				break;
			}
			backCount++;
			chainStart = prevSta;
			cur = prevSta;
		}

		int forwardCount = 0;
		cur = sta;
		while (true) {
			Address ft1 = cur.getFallThrough();
			if (ft1 == null) {
				break;
			}
			Instruction nextLsr = listing.getInstructionAt(ft1);
			if (nextLsr == null || !isLsrAccumulator(nextLsr) ||
				isControlFlowJoin(program, nextLsr, cur)) {
				break;
			}
			Address ft2 = nextLsr.getFallThrough();
			if (ft2 == null) {
				break;
			}
			Instruction nextSta = listing.getInstructionAt(ft2);
			if (nextSta == null || !isChainStore(nextSta) ||
				isControlFlowJoin(program, nextSta, nextLsr)) {
				break;
			}
			forwardCount++;
			cur = nextSta;
		}

		return new ChainInfo(backCount + 1, backCount + 1 + forwardCount, chainStart);
	}

	/** Whether {@code instr} is a same-shape chain link: a store of register A to the
	 *  configured range (value/bit-7 is deliberately NOT inspected here -- see class
	 *  javadoc; each such write gets its own independent bit-7 classification when the
	 *  dataflow engine visits it directly). */
	private boolean isChainStore(Instruction instr) {
		return Character.valueOf('A').equals(StoredValueScanner.storeRegister(instr)) &&
			writesInRange(instr) != null;
	}

	/** Whether {@code instr}'s straight-line, non-join predecessor is {@code LSR A} -- see
	 *  the bit-7-known-clear shortcut in {@link #computeSwitch}. */
	private boolean precededByLsrA(Program program, Instruction instr) {
		Listing listing = program.getListing();
		Instruction prev = listing.getInstructionBefore(instr.getMinAddress());
		return prev != null && fallsThroughTo(prev, instr) &&
			!isControlFlowJoin(program, instr, prev) && isLsrAccumulator(prev);
	}

	/** {@code LSR} in accumulator (implied) addressing -- zero operands, or a bare "A"
	 *  operand representation, as opposed to {@code LSR <addr>} (memory RMW). */
	private static boolean isLsrAccumulator(Instruction instr) {
		if (!instr.getMnemonicString().equalsIgnoreCase("LSR")) {
			return false;
		}
		if (instr.getNumOperands() == 0) {
			return true;
		}
		String rep = instr.getDefaultOperandRepresentation(0);
		return rep == null || rep.equalsIgnoreCase("A");
	}

	private static boolean fallsThroughTo(Instruction from, Instruction to) {
		Address ft = from.getFallThrough();
		return ft != null && ft.equals(to.getMinAddress());
	}

	/**
	 * Whether {@code cur} is reachable other than by falling through from {@code prev} --
	 * i.e. some other instruction branches/jumps/calls into it, making an attribution
	 * that assumes only the {@code prev} path unsound. Same logic as
	 * {@code StoredValueScanner}'s private join check, duplicated here (package-private
	 * reuse isn't available across that class's private boundary).
	 */
	private static boolean isControlFlowJoin(Program program, Instruction cur, Instruction prev) {
		Address curAddr = cur.getMinAddress();
		Address prevAddr = prev.getMinAddress();
		for (Reference ref : program.getReferenceManager().getReferencesTo(curAddr)) {
			if (ref.getReferenceType().isFlow() && !ref.getFromAddress().equals(prevAddr)) {
				return true;
			}
		}
		return false;
	}

	// ------------------------------------------------------------------
	// Field/byte helpers (same conventions as SelectDataBankSwitchStrategy)
	// ------------------------------------------------------------------

	private Long writesInRange(Instruction instr) {
		for (Reference ref : instr.getReferencesFrom()) {
			Address to = ref.getToAddress();
			if (ref.getReferenceType().isWrite() && to.getAddressSpace().equals(space) &&
				to.getOffset() >= rangeStart && to.getOffset() <= rangeEnd) {
				return to.getOffset();
			}
		}
		return null;
	}

	private static BankState extractByteField(BankState byteState, int bits, int shift) {
		int widthMask = (1 << bits) - 1;
		return new BankState((byteState.knownMask() >>> shift) & widthMask,
			(byteState.bits() >>> shift) & widthMask);
	}

	private static BankState setUnknownField(BankState base, FieldPos field) {
		int mask = field.mask();
		return new BankState(base.knownMask() & ~mask, base.bits() & ~mask);
	}

	private static BankState setFieldFromByte(BankState base, FieldPos field, BankState fieldValue) {
		int mask = field.mask();
		int knownBits = (fieldValue.knownMask() << field.lsb()) & mask;
		int valueBits = (fieldValue.bits() << field.lsb()) & mask;
		return new BankState((base.knownMask() & ~mask) | knownBits,
			(base.bits() & ~mask) | valueBits);
	}
}
