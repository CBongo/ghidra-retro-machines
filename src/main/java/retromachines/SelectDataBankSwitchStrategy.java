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

import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;

/**
 * The {@code select-data} mechanism class (vision doc §5.2): one address <em>selects</em>
 * a target register, a second address <em>writes</em> whichever register the last select
 * picked -- MMC3's bank-select/bank-data pair (mirrored across {@code $8000-$9FFF}: even
 * address = select, odd address = data, recognized by address parity, not two fixed
 * addresses). Params:
 * <ul>
 * <li>{@code start}/{@code end} -- the mirrored register range.</li>
 * <li>{@code select_field}, {@code select_mask}/{@code select_shift} -- which
 * {@code banking.state} field the select write's target-index bits feed, and where those
 * bits sit in the written byte.</li>
 * <li>{@code mode_field} (optional), {@code mode_mask}/{@code mode_shift} -- MMC3
 * co-emits a PRG-mode bit from the <em>same</em> select-register write that carries the
 * target index (bank-select bit 6); there is no independent mode register to latch, so
 * this mechanism deposits both fields from one recovered byte rather than needing a
 * second {@code mode-register} mechanism instance to race it. Boards with no such bit
 * omit {@code mode_field}.</li>
 * <li>{@code targets} -- a map from select value (string key, MapCompiler-normalized) to
 * the {@code banking.state} field name a data write targets when that value was last
 * selected (MMC3: {@code {"6": "r6", "7": "r7"}} -- R0-R5 are CHR and deliberately have no
 * entry).</li>
 * </ul>
 * Field-local sub-offsets for every name in {@code select_field}/{@code mode_field}/
 * {@code targets} are read out of {@code params._field_layout}, an entry
 * {@link BankStrategyRegistry#configureStrategies} injects for every mechanism from the
 * descriptor's {@code banking.state} packing (see that method's javadoc) -- so field
 * positions are derived from the single source of truth (the state tuple) rather than
 * hand-duplicated as YAML offsets.
 * <p>
 * <b>No-poison contract for untracked targets</b> (grm-6a7.1): a data write whose select
 * value has no {@code targets} entry (MMC3: a CHR register 0-5) is a mechanism write this
 * strategy recognizes but chooses not to represent as a state change -- real games issue
 * these every frame, and poisoning the PRG registers on every one would destroy tracking.
 * The engine's fold ({@code BoardBankAnalyzer#overwrite}) replaces this mechanism's whole
 * {@code effectMask} with whatever {@link #computeSwitch} returns, so "no change" cannot be
 * expressed by narrowing the *mask* of the result -- it has to be expressed by echoing
 * back {@code inState}'s own bits for every field this call leaves alone. Concretely, every
 * branch below starts from {@code inState} and only overwrites (via
 * {@link #setFieldFromByte}/{@link #setUnknownField}) the specific field(s) that switch
 * actually touches; an untracked-target data write returns {@code inState} completely
 * unmodified. This also keeps {@code computeSwitch} non-null for <em>every</em> in-range
 * write regardless of {@code inState} (the match/no-match decision is the address-parity-
 * and-range predicate alone, never the dispatched value), which is what
 * {@code BoardBankAnalyzer}'s per-address strategy-match cache requires of a
 * non-{@link #cacheable()} strategy.
 */
public class SelectDataBankSwitchStrategy implements BankSwitchStrategy {
	/** Creates an unconfigured select-data strategy. */
	public SelectDataBankSwitchStrategy() {
	}

	/** One tracked sub-field's field-local {@code [lsb, lsb+width)} bit position. */
	private record FieldPos(int lsb, int width) {
		int mask() {
			return ((1 << width) - 1) << lsb;
		}
	}

	private AddressSpace space;
	private long rangeStart;
	private long rangeEnd;

	private int selectByteMask;
	private int selectByteShift;
	private int modeByteMask;
	private int modeByteShift;

	private FieldPos selectField;
	private FieldPos modeField; // null when this board has no co-emitted mode bit
	private Map<Integer, FieldPos> targets;
	/** {@link #targets} keyed by the descriptor's FIELD NAME rather than select value -- the
	 *  key {@link BankMirrors#identifyingField} answers in, so {@link #mirroredByte} can tell
	 *  whether the window an identifying byte was read from is banked by a register this
	 *  mechanism tracks at all. */
	private Map<String, FieldPos> targetsByName;

	/**
	 * The addresses that MIRROR THE LIVE BANK on this program (bead grm-mej.2), delivered by
	 * {@link #observeMirrors} between {@code BoardBankAnalyzer}'s two dataflow passes. Empty for
	 * pass 1 and for every board with no derivable mirror, in which case this strategy behaves
	 * exactly as it did before it observed them (bead grm-sen5 -- until then it did not override
	 * {@code observeMirrors} at all, so no select-data board ever got bank-mirror read-back).
	 */
	private BankMirrors mirrors = BankMirrors.none();

	/** Returns the descriptor strategy identifier. */
	@Override
	public String strategyName() {
		return "select-data";
	}

	/** Records bank-mirror locations discovered by the analyzer. */
	@Override
	public void observeMirrors(BankMirrors observed) {
		mirrors = observed == null ? BankMirrors.none() : observed;
	}

	@Override
	public BankMirrors observedMirrors() {
		return mirrors;
	}

	/** Configures select/data address decoding and field mappings. */
	@Override
	public void configure(Program program, JsonObject params, int stateMask) {
		space = program.getAddressFactory().getDefaultAddressSpace();
		rangeStart = params.get("start").getAsLong();
		rangeEnd = params.get("end").getAsLong();

		selectByteMask = params.has("select_mask") ? params.get("select_mask").getAsInt() : 0xFF;
		selectByteShift = params.has("select_shift") ? params.get("select_shift").getAsInt() : 0;
		modeByteMask = params.has("mode_mask") ? params.get("mode_mask").getAsInt() : 0;
		modeByteShift = params.has("mode_shift") ? params.get("mode_shift").getAsInt() : 0;

		JsonObject fieldLayout =
			params.has("_field_layout") ? params.getAsJsonObject("_field_layout") : new JsonObject();

		selectField = fieldPos(fieldLayout, params.get("select_field").getAsString());
		modeField = params.has("mode_field")
				? fieldPos(fieldLayout, params.get("mode_field").getAsString())
				: null;

		targets = new HashMap<>();
		targetsByName = new HashMap<>();
		if (params.has("targets")) {
			for (Map.Entry<String, JsonElement> e : params.getAsJsonObject("targets").entrySet()) {
				String fieldName = e.getValue().getAsString();
				FieldPos pos = fieldPos(fieldLayout, fieldName);
				targets.put(Integer.valueOf(e.getKey()), pos);
				targetsByName.put(fieldName, pos);
			}
		}
	}

	private static FieldPos fieldPos(JsonObject fieldLayout, String fieldName) {
		JsonObject fl = fieldLayout.has(fieldName) ? fieldLayout.getAsJsonObject(fieldName) : null;
		if (fl == null) {
			throw new IllegalArgumentException(
				"select-data: no field-layout entry for '" + fieldName +
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
			// This strategy resolves no load as a bank-INVARIANT constant. The select/data
			// registers themselves are write-only -- a read at $8000-$9FFF hits the ROM
			// window behind them, never the register -- but that only settles the question
			// for the register pair. It says NOTHING about a ROM byte inside a banked window
			// or a RAM shadow, and this hook used to claim it did ("nothing reads them back,
			// at any resolvedTarget"), which is why no MMC3 board got bank-mirror read-back
			// until bead grm-sen5. Reading the bank BACK is resolveMirrorLoad's job below;
			// what stays out of scope here is the bank-invariant ROM byte
			// (MemoryLatchBankSwitchStrategy.bankInvariantRomByte), a separate widening.
			return null;
		}

		@Override
		public BankState resolveMirrorLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return mirroredByte(resolvedTarget, inStateAtStore);
		}

		/**
		 * Answered from {@link #mirrors} by the same kind test
		 * {@code HelperArgumentRecovery.OracleHooks} uses (bead grm-rd6h): a DIRECT-site
		 * read-back of a write-through shadow or ROM-identifying offset is a live-bank mirror
		 * whether or not {@link #mirroredByte} would resolve its VALUE -- see
		 * {@code StoredValueScanner.Hooks#isLiveBankMirror}'s javadoc.
		 */
		@Override
		public boolean isLiveBankMirror(Address target) {
			return mirrors.isLiveBankMirror(target);
		}
	};

	/**
	 * {@link #callerSideHooks()}'s override (bead grm-sen5, same shape as
	 * {@code MemoryLatchBankSwitchStrategy}'s): the same mirror answer as the direct-path
	 * {@link #hooks} above, {@code resolveLoad} withheld per the interface's scope discipline,
	 * and {@code isMechanismWrite} delegating to the SAME {@link #writesInRange} the direct-path
	 * hooks use. That delegation is the mandatory half: a caller-side scan using this object is
	 * handed the REAL tracked in-state at the call, so an {@code isMechanismWrite} answering
	 * {@code false} would let a mirror load BEFORE an intervening select/data write resolve
	 * against the state AFTER it. {@code StoredValueScanner}'s withdraw-on-mechanism-write
	 * (grm-4bgh.7) prevents that once this hook says where the writes are.
	 * <p>
	 * This is what makes {@code LDA <identifying byte> / JSR <bank helper>} -- TMNT's
	 * {@code cec0} shape, read at a helper call site rather than at a mechanism write --
	 * resolvable on a select-data board at all.
	 */
	private final StoredValueScanner.Hooks callerSideHooks = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return writesInRange(instr) != null;
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return null; // scope discipline -- see BankSwitchStrategy.callerSideHooks()
		}

		@Override
		public BankState resolveMirrorLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return mirroredByte(resolvedTarget, inStateAtStore);
		}
	};

	/** Returns hooks for resolving loads while scanning selector writes. */
	@Override
	public StoredValueScanner.Hooks callerSideHooks() {
		return callerSideHooks;
	}

	/**
	 * The RAW BYTE a load of {@code target} yields when {@code target} mirrors a live bank
	 * this mechanism tracks, or {@code null} when it mirrors nothing this strategy may answer
	 * from tracked state (bead grm-sen5).
	 * <p>
	 * <b>ONLY {@link BankMirrors.Kind#ROM_IDENTIFYING} ANSWERS, AND ONLY PER WINDOW.</b> This
	 * mechanism is the one shipped strategy that tracks SEVERAL switchable windows through
	 * separate registers -- on MMC3, {@code $A000-$BFFF} is R7 while {@code $8000-$9FFF} is R6
	 * (prg_mode 0) or fixed (prg_mode 1). "The bank" is therefore ambiguous until you know
	 * WHICH window the identifying byte was read from, and the single-field reasoning
	 * {@code MemoryLatchBankSwitchStrategy.mirroredByte} and
	 * {@code SerialShiftBankSwitchStrategy.mirroredByte} get away with does not transfer. The
	 * derivation records the window's bank field beside each offset
	 * ({@link BankMirrors#identifyingField}), and the answer here is that field's tracked value
	 * -- not the field the byte is about to be STORED to, which is a different question the
	 * program is free to answer any way it likes (copying R7's bank into R6 is a legal program).
	 * Every refusal below is a case where that proof is missing:
	 * <ul>
	 * <li>the offset carries no field (a derivation that did not attribute its window);</li>
	 * <li>the field is not one of this mechanism's {@code targets} by name (a window banked by a
	 * register another mechanism owns);</li>
	 * <li>the field's width disagrees with the target's (a descriptor inconsistency).</li>
	 * </ul>
	 * Mode needs no check, and that is a property of the DERIVATION rather than an assumption
	 * made here: only mode-invariant computed windows are content-scanned, so a recorded field
	 * selects its window's bank under every mode -- MMC3's {@code WA000} is R7 in both prg_modes,
	 * and its mode-varying {@code W8000}/{@code WC000} never produce an offset. A load of
	 * {@code $8100} on a cartridge whose every bank holds its number at offset {@code $100} still
	 * declines, correctly: which register (or none) that window reads through depends on
	 * prg_mode, and nothing recorded says.
	 * <p>
	 * <b>Coordinates.</b> {@code inState} is this mechanism's field-local state; the answer is
	 * the raw byte the {@code LDA} yields, which {@link #computeDataWrite}'s
	 * {@code byteMask} extraction then narrows -- so the target's field is lifted back down to
	 * bit 0 and handed to {@link BankMirrors.IdentifyingEncoding#byteFor}, which applies whatever
	 * formula (bead grm-km4f) {@link BankMirrors#romIdentifyingOffsets} actually proved for this
	 * offset -- {@code byte == bank} on an ordinary board, {@code byte == bank >> 1} on odd banks
	 * for River City Ransom's MMC3 {@code WA000} -- and refuses outright for a bank that formula
	 * was never proved against. Every bit above the field the formula covers is a PROVED zero,
	 * which is what makes the answer a whole byte rather than a field.
	 * <p>
	 * <b>{@link BankMirrors.Kind#WRITE_THROUGH} DECLINES on this strategy, deliberately, and it is
	 * a decision rather than an omission.</b> On a single-register mechanism a write-through
	 * cell holds a copy of THE bank byte. Here a mechanism write is one of two very different
	 * bytes -- the select/mode byte ({@code $8000}) or a bank byte ({@code $8001}) whose register
	 * is whatever select was live at that site -- and {@link BankMirrors} carries no per-cell
	 * record of which, so "resolve from in-state" would first have to classify the cell's
	 * paired sites by parity and, for a data byte, recover the select at each. That is a new
	 * inference, not a derivation. The one shipped instance (smb3's {@code f8ca LDA $0721 /
	 * f8cd STA $8000}, the select-latch shadow restored in an interrupt epilogue) is also the
	 * shape the answer would be WRONG for: the IRQ body switches CHR banks through direct
	 * {@code $8000} writes that never touch {@code $0721}, so the tracked select at the load is
	 * the IRQ's last CHR select, not the interrupted mainline's value the cell actually holds
	 * -- exactly the grm-p9y stale-shadow defect. A coherence walk would decline it, and the
	 * bead's own caveat is that the site would gain a classification and no annotation. That
	 * site is retired by recognising a restore-shaped write instead (grm-sen5's second comment),
	 * which needs no value at all and is filed separately. {@code SAVE_SLOT} and {@code INPUT}
	 * decline as they do everywhere (H2).
	 */
	private BankState mirroredByte(Address target, BankState inState) {
		if (target == null || mirrors.isEmpty()) {
			return null;
		}
		BoardDescriptorModel.FieldSpec windowField = mirrors.identifyingField(target);
		if (windowField == null) {
			return null; // not ROM_IDENTIFYING, or its window was not attributed -- refuse
		}
		FieldPos pos = targetsByName.get(windowField.name());
		if (pos == null || pos.width() != windowField.width()) {
			return null; // banked by a register this mechanism does not track -- refuse
		}
		BankMirrors.IdentifyingEncoding encoding = mirrors.identifyingEncoding(target);
		if (encoding == null) {
			return null; // defensive: a ROM_IDENTIFYING offset always carries one once derived
		}
		int byteMask = (1 << pos.width()) - 1;
		int known = (inState.knownMask() >>> pos.lsb()) & byteMask;
		int bits = (inState.bits() >>> pos.lsb()) & byteMask;
		return encoding.byteFor(known, bits, byteMask);
	}

	/**
	 * <b>No site of this mechanism imposes a bank-known-on-entry requirement that the
	 * requirement derivation is able to express</b> (grm-vgod). This is the same defect
	 * grm-mej.2 §2d fixed on {@link MemoryLatchBankSwitchStrategy}, recurring here because
	 * this strategy inherits {@link #cacheable()}{@code == false} from the interface (the
	 * class javadoc above explains why it must) and so inherited
	 * {@code effectDependsOnPriorState() == !cacheable() == true} with it -- unconditionally,
	 * at every MMC3 switch site.
	 * <p>
	 * {@code BankAnnotationAdapter.annotateBankRequirementViolations} derives the required mask
	 * from the site's own {@code effectMask}. Take the three shapes {@link #computeSwitch}
	 * dispatches to and ask, of each, whether knowing those {@code effectMask} bits on entry
	 * would have changed the outcome:
	 * <ul>
	 * <li>{@link #computeSelectWrite} deposits the recovered byte into {@code selectField}
	 *     (and {@code modeField}). Both are a pure function of the byte written; neither
	 *     consults its own prior value. <b>No.</b></li>
	 * <li>{@link #computeDataWrite} with a KNOWN select and a tracked target deposits the
	 *     recovered byte into that target field alone. Also a pure function of the byte.
	 *     When it comes out unknown it is because {@code resolveStoredValue} could not pin
	 *     the DATA down -- the unresolved-value case, not a missing state bit. <b>No.</b></li>
	 * <li>{@link #computeDataWrite} with an UNKNOWN select poisons every target. This one
	 *     genuinely does depend on prior state -- but on {@code selectField}, which is never
	 *     in a data write's {@code effectMask}. Knowing {@code r6}/{@code r7} on entry would
	 *     not help; they get poisoned regardless. <b>No</b> -- and see the caveat below.</li>
	 * </ul>
	 * The interface's own stated condition for overriding to {@code false} is that "the
	 * mechanism's registers are genuinely write-only and never resolved back to tracked
	 * state". The registers are; but since bead grm-sen5 a load of a bank-identifying ROM
	 * offset IS resolved back to tracked state ({@link #mirroredByte}), so the clause "never
	 * resolved back" stopped being true at exactly the sites that read one. The strategy-wide
	 * answer therefore stays {@code false} -- still right for every site that does not read a
	 * mirror, which on a real cartridge is nearly all of them -- and the per-site overload
	 * {@link #effectDependsOnPriorState(Program, Instruction, BankState)} below answers the
	 * sites where it is not. That is grm-mej.2 §2d's precedent followed exactly, from the same
	 * direction {@code SerialShiftBankSwitchStrategy} arrived at it: a hardcoded {@code false}
	 * that would now UNDER-report, with the override stopping a real requirement from being
	 * silently dropped (memory-latch's override runs the other way, stopping a {@code true}
	 * default from over-reporting).
	 * <p>
	 * <b>Measured</b> (grm-vgod, 2026-08-23), by a rebuilt A/B over all 31 rows of both
	 * real-ROM manifests: this removed 29 violation WARNINGs and moved nothing else -- 17 on
	 * smb3, 10 on rcransom, 2 on smb2, and zero lines of any other kind on any row. That is
	 * the entire population of the class in the corpus. Not one bankComment, reference,
	 * instruction or symbol moved anywhere, which is the expected shape: this predicate is
	 * read at exactly one place ({@code BankAnnotationAdapter.annotateBankRequirementViolations}),
	 * in phase 3, never inside the dataflow fixpoint.
	 * <p>
	 * Twenty-eight of the 29 named {@code r6,r7} -- target registers a data write DEPOSITS
	 * into rather than reads -- and every site involved had a KNOWN select, making them the
	 * second bullet above: purely spurious, the unresolved-DATA case. The 29th is smb3's
	 * {@code 89c2}, "requires select,prg_mode,r6,r7", which comes from an unresolvable SELECT
	 * write and so falls under the first bullet: {@code computeSelectWrite} deposits the
	 * written byte into {@code selectField}/{@code modeField} without consulting either's
	 * prior value, so its failure is likewise about a value it could not recover, not about
	 * state it needed. Same verdict, different route -- worth stating because it is the one
	 * line that does mention {@code select}, and it is NOT the third bullet.
	 * <p>
	 * <b>The caveat, so the third bullet is not silently lost:</b> an unknown-select data
	 * write IS a real entry requirement, on {@code selectField}. It cannot be reported through
	 * this predicate, whose mask comes from {@code effectMask}, so it needs a diagnostic of
	 * its own rather than a different answer here -- filed as grm-vgod's follow-up. No real
	 * ROM in either manifest currently exhibits it; nesmmc3test2's CallerB ($E128) does, and
	 * is already masked by the helper-argument warning there (grm-mlp2).
	 * <p>
	 * <b>Guarded by</b> nesmmc3test2's G11/G12/G13 (CallerH/Worker/H4, $E2C0-$E2D6), the MMC3
	 * analogue of nesmirrortest's M8. G11 was confirmed to FAIL on the pre-fix strategy with
	 * "call to FUN_e2d0 requires r6 known on entry" -- two earlier drafts of that fixture
	 * passed on unfixed code for two different reasons, so do not weaken its shape without
	 * re-running that check; the criteria comments record both traps. nesmmc3test2 has no
	 * mirrors, so it never reaches the per-site probe; nesmmc3mirrortest's MM12/MM13 (the
	 * probe reporting a real mirror-derived requirement) and MM14 (the probe staying silent for
	 * an unrelated failure with the mirror set non-empty) guard the overload below.
	 */
	/** Returns whether the strategy's effect depends on prior state in general. */
	@Override
	public boolean effectDependsOnPriorState() {
		return false;
	}

	/**
	 * The per-site question (grm-mej.2 §2d), answered by re-running this site's own value scan
	 * under an instrumented hook and reporting whether a MIRROR load was actually resolved
	 * (bead grm-sen5). Same shape as {@code SerialShiftBankSwitchStrategy}'s override and for
	 * the same reason: the strategy-wide {@code false} above would now under-report a site
	 * whose byte came from an identifying read-back with the bank unknown -- that site
	 * genuinely needed the bank on entry, and dropping it is how a real bank-requirement
	 * violation goes unreported.
	 * <p>
	 * Mirrors the two scans {@link #computeSwitchOutcomeValue} runs, because which scan (if
	 * any) a site performs is what decides whether a mirror could have been consulted:
	 * <ul>
	 * <li>an even (select) write scans its stored register under {@code 0xFF};</li>
	 * <li>an odd (data) write scans only when the tracked select is fully known and names a
	 * tracked target -- an unknown select poisons without scanning, and an untracked (CHR)
	 * select deposits nothing. Neither consults a mirror, so neither can answer {@code true};
	 * the unknown-select case's genuine requirement on {@code selectField} remains the
	 * unexpressible third bullet above, unchanged by this.</li>
	 * </ul>
	 * {@code siteInState} is the real field-local in-state, never {@link BankState#unknown()}:
	 * the sites this exists to find are those that consulted a mirror AND came up unknown, and
	 * {@link #mirroredByte} answers non-null even when wholly unknown for that reason. Cheap by
	 * construction -- the mirror set is empty on every board without one and the whole probe
	 * short-circuits. Called once per site in phase 3, never inside the fixpoint.
	 */
	/** Returns whether this switch site consulted prior bank state. */
	@Override
	public boolean effectDependsOnPriorState(Program program, Instruction site,
			BankState siteInState) {
		if (mirrors.isEmpty() || site == null || siteInState == null) {
			return false;
		}
		Long offset = writesInRange(site);
		Character reg = offset == null ? null : StoredValueScanner.storeRegister(site);
		if (reg == null) {
			return false;
		}
		int mask;
		if ((offset & 1) == 0) {
			mask = 0xFF;
		}
		else {
			Integer selectValue = fieldValueIfFullyKnown(siteInState, selectField);
			FieldPos target = selectValue == null ? null : targets.get(selectValue);
			if (target == null) {
				return false; // poisons or deposits nothing -- no scan, no mirror
			}
			mask = (1 << target.width()) - 1;
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
				BankState mirrored = hooks.resolveMirrorLoad(loadInstr, resolvedTarget,
					inStateAtStore);
				if (mirrored != null) {
					consulted[0] = true;
				}
				return mirrored;
			}
		};
		StoredValueScanner.resolveStoredValue(program, site, reg, siteInState, mask, probe);
		return consulted[0];
	}

	/** Computes the state effect of a select or data write. */
	@Override
	public SwitchOutcome computeSwitchOutcome(Program program, Instruction instr,
			BankState inState) {
		// The recovery body classifies its own outcome: SwitchOutcome.of derives the
		// conservative stop reason from the recovered value, except at the untracked-target
		// data write, which deposits nothing by design and says so (bead grm-pdd6).
		return computeSwitchOutcomeValue(program, instr, inState);
	}

	/**
	 * Increment 3 (bead {@code grm-3ou} part 1): whether an unresolved value here is this
	 * helper's ARGUMENT. Mirrors {@link #computeSwitchOutcomeValue}'s fork, because which
	 * register scan
	 * failed -- and whether a scan is even what failed -- depends on which side of it we are on.
	 * <p>
	 * The odd-address branch is the interesting one, and the reason this is not a one-liner. A
	 * data write's value gap has TWO possible causes and only one of them is the argument:
	 * <ul>
	 * <li>the SELECT is unknown, so we cannot tell which target register this write commits to.
	 * That is a gap in tracked STATE, not in a register scan -- the byte being stored may well
	 * be a resolved constant. {@code ANALYZER_LIMIT}, and deliberately so;</li>
	 * <li>the select is known and names a tracked target, but the stored BYTE did not resolve.
	 * That is the register scan, and the only place a caller's argument can be the answer.</li>
	 * </ul>
	 * A select value naming no tracked target (MMC3's CHR registers) is not a gap at all -- that
	 * branch returns {@code inState} verbatim and never warns -- so it cannot reach here, and
	 * answering {@code ANALYZER_LIMIT} for it is inert either way.
	 */
	/** Classifies an unresolved select/data write in a helper body. */
	@Override
	public ValueStop classifyHelperBodyGap(Program program, Instruction switchSite,
			BankState inState, Address helperEntry) {
		Long offset = writesInRange(switchSite);
		if (offset == null) {
			return ValueStop.ANALYZER_LIMIT;
		}
		Character reg = StoredValueScanner.storeRegister(switchSite);
		if (reg == null) {
			// No identifiable stored register means nothing was scanned, so there is no scan to
			// re-run and no argument to attribute -- same reasoning as the two converted
			// strategies' null-register guards.
			return ValueStop.ANALYZER_LIMIT;
		}

		int mask;
		if ((offset & 1) == 0) {
			mask = 0xFF;
		}
		else {
			Integer selectValue = fieldValueIfFullyKnown(inState, selectField);
			if (selectValue == null) {
				return ValueStop.ANALYZER_LIMIT;
			}
			FieldPos target = targets.get(selectValue);
			if (target == null) {
				return ValueStop.ANALYZER_LIMIT;
			}
			mask = (1 << target.width()) - 1;
		}

		// Same scan, differing only in the entry stop; the value is discarded, so this can only
		// reclassify. See BankSwitchStrategy.classifyHelperBodyGap for the soundness argument.
		StoredValueScanner.Scan atEntry = StoredValueScanner.resolveStoredValueScan(program,
			switchSite, reg, inState, mask, hooks, RegisterEnv.entryStopOnly(helperEntry));
		return atEntry.stop() == ValueStop.HELPER_ARGUMENT ? ValueStop.HELPER_ARGUMENT
				: ValueStop.ANALYZER_LIMIT;
	}

	private SwitchOutcome computeSwitchOutcomeValue(Program program, Instruction instr,
			BankState inState) {
		Long offset = writesInRange(instr);
		if (offset == null) {
			return null;
		}
		Character reg = StoredValueScanner.storeRegister(instr);
		boolean even = (offset & 1) == 0;
		return even ? SwitchOutcome.of(computeSelectWrite(program, instr, reg, inState))
				: computeDataWrite(program, instr, reg, inState);
	}

	/**
	 * An even-address (bank-select) write: deposits the recovered byte's select-index
	 * bits into {@code selectField} and (when this board tracks one) its mode bit into
	 * {@code modeField} -- both from the SAME recovered byte, MMC3's actual co-emission
	 * shape. Every target field is left untouched (the result starts from {@code inState}
	 * and only these two fields are ever overwritten).
	 */
	private BankState computeSelectWrite(Program program, Instruction instr, Character reg,
			BankState inState) {
		BankState stored = reg == null ? BankState.unknown()
				: StoredValueScanner.resolveStoredValue(program, instr, reg, inState, 0xFF, hooks);

		BankState result =
			setFieldFromByte(inState, selectField, extractByteField(stored, selectByteMask, selectByteShift));
		if (modeField != null) {
			result =
				setFieldFromByte(result, modeField, extractByteField(stored, modeByteMask, modeByteShift));
		}
		return result;
	}

	/**
	 * An odd-address (bank-data) write: dispatches on the currently tracked
	 * {@code selectField} value (in-state at this instruction, not the byte being written
	 * here). Unknown select poisons every configured target (any of them could have been
	 * the one last selected); a select value with no {@code targets} entry (MMC3 CHR) is
	 * the no-poison case -- {@code inState} returned verbatim, and reported as
	 * {@link ValueStop#NO_DEPOSIT} rather than as a failed value recovery (bead grm-pdd6);
	 * a select value that IS a tracked target recovers the written byte and overwrites only
	 * that target field.
	 */
	private SwitchOutcome computeDataWrite(Program program, Instruction instr, Character reg,
			BankState inState) {
		Integer selectValue = fieldValueIfFullyKnown(inState, selectField);
		if (selectValue == null) {
			BankState result = inState;
			for (FieldPos target : targets.values()) {
				result = setUnknownField(result, target);
			}
			return SwitchOutcome.of(result);
		}

		FieldPos target = targets.get(selectValue);
		if (target == null) {
			// Untracked register (e.g. MMC3 CHR banks R0-R5): no poison -- see class javadoc.
			// Nothing is deposited here and nothing was attempted, so this is NOT the
			// "undeterminable value" population (bead grm-pdd6).
			return SwitchOutcome.noDeposit(inState);
		}

		int byteMask = (1 << target.width()) - 1;
		BankState stored = reg == null ? BankState.unknown()
				: StoredValueScanner.resolveStoredValue(program, instr, reg, inState, byteMask, hooks);
		return SwitchOutcome.of(setFieldFromByte(inState, target, stored));
	}

	/**
	 * Converts a bare helper call site's recovered data-argument byte into this mechanism's
	 * field-local deposit, routing it by the CALLER'S TRACKED SELECT VALUE rather than by
	 * {@code switchSite}'s own address -- select-data's mirror image of
	 * {@link SerialShiftBankSwitchStrategy}'s override, and the reason the interface grew
	 * an {@code inState} parameter in the first place. Unlike serial-shift, one select-data
	 * switch-site SHAPE (an even-address select write, or an odd-address data write) does
	 * NOT by itself say which target register a data write commits to -- MMC3 helpers
	 * commonly amortize one select write across several data-write-only calls (see the
	 * class javadoc's example and {@code nesmmc3test2}'s fixture), so the routing decision
	 * has to come from the tracked select field at the call site instead.
	 * <p>
	 * Dispatches on {@code switchSite}'s own write-address parity first, exactly like
	 * {@link #computeSwitch}:
	 * <ul>
	 * <li><b>Even (select-write helper):</b> {@code argValue} IS the select byte -- mirrors
	 * {@link #computeSelectWrite}'s extraction (select field, and mode field when this board
	 * tracks one) deposited into an empty state; {@code ownedMask} is the union of those
	 * fields' masks. {@code inState} is irrelevant here (a select write's routing is fixed,
	 * not state-dependent) and is ignored.</li>
	 * <li><b>Odd (data-write helper):</b> dispatches on
	 * {@code fieldValueIfFullyKnown(inState, selectField)}, mirroring
	 * {@link #computeDataWrite}'s three-way split:
	 * <ul>
	 * <li>select known and a tracked target (MMC3 R6/R7): {@code ownedMask} is that target
	 * field's mask ALONE (never select/prg_mode -- a data write never touches them); value
	 * is {@code argValue} deposited into that field (partial per-bit knowledge of the
	 * argument byte preserved, same as {@link #computeDataWrite}).</li>
	 * <li>select known and untracked (MMC3 CHR 0-5): {@code ownedMask = 0} -- a verified
	 * no-op, same no-poison contract as {@link #computeDataWrite}'s CHR case and
	 * {@link SerialShiftBankSwitchStrategy}'s CHR-target override.</li>
	 * <li>select unknown: this call could have hit ANY tracked target, so honest poison
	 * covers the union of every configured target field's mask (never select/prg_mode,
	 * which a data write cannot touch regardless of which target was picked); the value
	 * itself is left wholly unknown, since which field the (known) argument byte would even
	 * land in is itself unresolved.</li>
	 * </ul>
	 * </li>
	 * </ul>
	 */
	/**
	 * {@code true}: this mechanism's writes are independent deposits, not instalments of one
	 * (bead grm-4bgh.5). Each recognized site of a select-data helper routes ITSELF -- an even
	 * address deposits the select (and mode) field, an odd one deposits whichever target
	 * register {@link #selectSuppliedInsideHelper} or the caller's tracked select says it
	 * commits through -- so a helper that writes several of them writes several fields, and
	 * summarizing it by one site loses the rest. rcransom's {@code FUN_fed1} is the shape:
	 * select R6, data R6 = A*2, select R7, data R7 = A*2+1, from one argument byte.
	 * <p>
	 * Contrast {@link SerialShiftBankSwitchStrategy}, which keeps the default {@code false}
	 * because its five writes ARE one value -- see {@link BankSwitchStrategy#depositsPerSite}.
	 */
	/** Returns whether deposits are evaluated independently for each site. */
	@Override
	public boolean depositsPerSite() {
		return true;
	}

	/** Recovers a helper argument using the selector/data state model. */
	@Override
	public HelperDeposit depositHelperArgument(Program program, Instruction switchSite,
			BankState argValue, BankState inState, int stateMask) {
		Long offset = writesInRange(switchSite);
		if (offset == null) {
			// switchSite isn't a shape this strategy itself recognizes as a mechanism
			// write -- can't happen for a genuine HelperModel.switchSite (it was recorded
			// because THIS strategy matched it), but stay conservative: own nothing rather
			// than guess (same stance as SerialShiftBankSwitchStrategy's override).
			return new HelperDeposit(0, new BankState(0, 0));
		}

		if ((offset & 1) == 0) {
			BankState empty = new BankState(0, 0);
			BankState stored = new BankState(argValue.knownMask() & 0xFF, argValue.bits() & 0xFF);
			BankState value =
				setFieldFromByte(empty, selectField, extractByteField(stored, selectByteMask, selectByteShift));
			int owned = selectField.mask();
			if (modeField != null) {
				value =
					setFieldFromByte(value, modeField, extractByteField(stored, modeByteMask, modeByteShift));
				owned |= modeField.mask();
			}
			return new HelperDeposit(owned, value);
		}

		// A helper that establishes its OWN select on the straight-line path into this data
		// write has already answered the routing question, and answered it for every caller at
		// once; the caller's tracked select is stale by construction there (grm-qd0u). Only
		// when the helper supplies none -- the amortized shape, one caller select across
		// several data-write-only calls -- does the caller's in-state get a say.
		Integer selectValue = selectSuppliedInsideHelper(program, switchSite);
		if (selectValue == null) {
			selectValue = fieldValueIfFullyKnown(inState, selectField);
		}
		if (selectValue == null) {
			int owned = 0;
			for (FieldPos target : targets.values()) {
				owned |= target.mask();
			}
			return new HelperDeposit(owned, new BankState(0, 0));
		}

		FieldPos target = targets.get(selectValue);
		if (target == null) {
			// Untracked register (e.g. MMC3 CHR banks R0-R5): verified no-op -- see method
			// javadoc.
			return new HelperDeposit(0, new BankState(0, 0));
		}

		BankState value = setFieldFromByte(new BankState(0, 0), target, argValue);
		return new HelperDeposit(target.mask(), value);
	}

	/**
	 * {@link #depositHelperArgument(Program, Instruction, BankState, BankState, int)} above, with
	 * one additive FALLBACK: when {@code argValue} came back with nothing pinned down at all
	 * ({@code knownMask() == 0}) -- the shape {@code HelperArgumentRecovery} produces for a
	 * helper whose prologue transforms or clobbers its argument register rather than merely
	 * relaying it -- re-evaluate the switch site's own store under the CALLER's registers
	 * ({@code callerRegs}) via {@link StoredValueScanner#resolveStoredValue(Program, Instruction,
	 * char, BankState, int, StoredValueScanner.Hooks, RegisterEnv)} before falling through to the
	 * 5-arg method (bead grm-4bgh increment 4).
	 * <p>
	 * <b>This is a fallback, never a substitution.</b> Unlike
	 * {@code MemoryLatchBankSwitchStrategy}'s override, which ignores {@code argValue} entirely
	 * and always re-derives its answer from {@code callerRegs}, this body still tries
	 * {@code argValue} FIRST and only reaches for {@code callerRegs} when that attempt produced
	 * nothing -- so every call site that already resolves via {@code argValue} today is
	 * byte-identical, and the new path only ever turns an existing decline into an answer.
	 * <p>
	 * {@code 0xFF} matches the 5-arg method's own treatment of {@code argValue} as a raw byte
	 * (masked to {@code 0xFF} before any field extraction happens there): the evaluated
	 * replacement must be the same coordinate space the fallthrough call expects.
	 * <p>
	 * <b>{@link #consumesHelperArgument()} stays {@code true} here</b>, and deliberately so --
	 * see its own override (there is none: this strategy keeps the default) and its javadoc's
	 * instruction to re-check the two together on any change to this body. This override still
	 * reads {@code argValue} as its PRIMARY answer, falling back to evaluation only when that
	 * answer is empty, so the grm-mu7 stale-argument guard is exactly the protection this
	 * strategy still needs on the path that does not fall back.
	 */
	@Override
	public HelperDeposit depositHelperArgument(Program program, Instruction switchSite,
			BankState argValue, BankState inState, int stateMask, RegisterEnv callerRegs) {
		BankState effective = argValue;
		if (argValue.knownMask() == 0) {
			Character reg = StoredValueScanner.storeRegister(switchSite);
			if (reg != null) {
				BankState evaluated = StoredValueScanner.resolveStoredValue(program, switchSite,
					reg, inState, 0xFF, hooks, callerRegs);
				if (evaluated.knownMask() != 0) {
					effective = evaluated;
				}
			}
		}
		return depositHelperArgument(program, switchSite, effective, inState, stateMask);
	}

	/**
	 * How many instructions {@link #selectSuppliedInsideHelper} walks back from a data write
	 * looking for the helper's own select write. smb3's {@code FUN_ffc2} needs two steps; a
	 * select write further away than this is not the co-located pair this models.
	 */
	private static final int MAX_OWN_SELECT_SCAN = 8;

	/**
	 * The select value THIS HELPER establishes for itself on the straight-line path into its own
	 * data write, or {@code null} when it establishes none and the caller's tracked select is
	 * therefore the only answer available (bead grm-qd0u).
	 * <p>
	 * <b>The defect this fixes.</b> {@link #depositHelperArgument} routed a data-write helper's
	 * argument using the select tracked AT THE CALL SITE, which is right for the amortized shape
	 * (one caller select across several data-write-only calls -- {@code nesmmc3test2}'s
	 * {@code H}/CallerA) and wrong for a helper that writes select itself. smb3's {@code FUN_ffc2}
	 * is the shipped example, and it is not marginal:
	 * <pre>
	 *   ffc2: LDA #$47        ; select 7, prg_mode 1 -- the helper's OWN constant
	 *   ffc4: STA $0721
	 *   ffc7: STA $8000       ; SELECT write            &lt;- what the hardware actually routes by
	 *   ffca: LDA $0720       ; the caller's argument cell
	 *   ffcd: STA $8001       ; DATA write              &lt;- switchSite
	 * </pre>
	 * Callers of {@code ffc2} do not write select, so the tracked value at their call sites is
	 * whatever unrelated earlier code left -- measured as 0 on smb3, which is CHR R0, an
	 * UNTRACKED target. The deposit therefore took its no-poison branch and returned
	 * {@code ownedMask = 0}: a "verified no-op" claim, silently discarding a fully recovered
	 * constant bank ({@code argKnown=ff argBits=1a}) with neither an annotation nor a warning.
	 * On smb3 that path was taken 172 times against 70 poisons and 12 correct resolutions.
	 * <b>The failure was silent, not noisy</b> -- which is why it survived so long and why the
	 * bead it was filed under described the wrong symptom.
	 * <p>
	 * <b>Why the helper's own select WINS rather than merely filling in.</b> A select write on the
	 * straight-line path into the data write is the last one the hardware sees before that write,
	 * whatever any caller did earlier. So this is consulted FIRST and the caller's in-state is the
	 * fallback, not the other way round.
	 * <p>
	 * <b>Why a straight-line walk, and what it refuses.</b> The claim being made is "select is
	 * THIS value on every path reaching the data write", and a wrong answer here is not a decline
	 * -- select 0 versus 7 is the whole difference between "CHR register, ignore" and "PRG R7,
	 * annotate", so a mis-recovery ships a confident wrong bank. The walk therefore abandons at
	 * anything that would make the claim conditional: a missing fall-through link, a control-flow
	 * join (some other path reaches here with a different select), or a call (which may write the
	 * register file itself). That is the same discipline
	 * {@code BankMirrors.Discovery.walkFromMechanismWrite} and
	 * {@code SaveRestoreTrampolines.restoresEntryBank} already use, and it makes "on every path" true
	 * by construction rather than by assumption.
	 * <p>
	 * An intervening ODD-address write is refused outright: a helper with two data writes commits
	 * twice, and which select governs which is exactly the question this walk cannot answer by
	 * looking backward from one of them.
	 * <p>
	 * <b>Why {@link BankState#unknown()} is the right in-state here</b>, unlike in
	 * {@code effectDependsOnPriorState} where stubbing it would over-report: the question is
	 * whether the select byte resolves WITHOUT depending on tracked state, since the answer must
	 * hold for every caller. Resolving under a wholly unknown in-state proves exactly that. A
	 * select write whose byte is state-dependent simply fails to resolve and the caller's
	 * in-state takes over -- the conservative direction.
	 */
	private Integer selectSuppliedInsideHelper(Program program, Instruction dataWrite) {
		Listing listing = program.getListing();
		Instruction cur = dataWrite;
		for (int i = 0; i < MAX_OWN_SELECT_SCAN; i++) {
			Instruction prev = listing.getInstructionBefore(cur.getMinAddress());
			if (prev == null || !fallsInto(prev, cur) ||
				StoredValueScanner.isControlFlowJoin(program, cur, prev) ||
				prev.getFlowType().isCall()) {
				return null;
			}
			Long offset = writesInRange(prev);
			if (offset != null) {
				if ((offset & 1) != 0) {
					return null; // an earlier DATA write -- see the two-data-writes note above
				}
				Character reg = StoredValueScanner.storeRegister(prev);
				if (reg == null) {
					return null;
				}
				BankState stored = StoredValueScanner.resolveStoredValue(program, prev, reg,
					BankState.unknown(), 0xFF, hooks);
				BankState value = setFieldFromByte(new BankState(0, 0), selectField,
					extractByteField(stored, selectByteMask, selectByteShift));
				return fieldValueIfFullyKnown(value, selectField);
			}
			cur = prev;
		}
		return null;
	}

	/** Whether the fall-through path from {@code prev} is exactly {@code cur}. Same block-linkage
	 *  test {@code BankMirrors.Discovery.fallsInto} and both {@code StoredValueScanner} walks use;
	 *  duplicated rather than shared because that one is private to another class's nested type. */
	private static boolean fallsInto(Instruction prev, Instruction cur) {
		Address fallThrough = prev.getFallThrough();
		return fallThrough != null && fallThrough.equals(cur.getMinAddress());
	}

	/**
	 * {@code false}: read the helper's own supplied value at {@code switchSite}, not
	 * {@code firstSite} (bead grm-67g). Unique to this strategy among those shipped, because it
	 * is the only one whose helper can carry TWO mechanism writes holding DIFFERENT values --
	 * the {@code $8000} register-select byte and the {@code $8001} bank byte. See the interface
	 * javadoc for smb3's {@code FUN_ffc2}, the case where reading {@code firstSite} deposited the
	 * select byte into a bank field.
	 */
	/** Supplies a helper value at its first recognized site when applicable. */
	@Override
	public boolean suppliesHelperValueAtFirstSite() {
		return false;
	}

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

	/** Extracts the sub-bits {@code byteMask} (already shifted to {@code byteShift}) out of
	 *  a byte-space {@link BankState}, repositioned to bit 0 -- same convention as
	 *  {@link MemoryLatchBankSwitchStrategy}'s final field deposit. */
	private static BankState extractByteField(BankState byteState, int byteMask, int byteShift) {
		int widthMask = byteMask >>> byteShift;
		return new BankState((byteState.knownMask() >>> byteShift) & widthMask,
			(byteState.bits() >>> byteShift) & widthMask);
	}

	/** Fully known iff every bit of {@code field}'s mask is known in {@code state}; returns
	 *  that field's value (right-shifted to bit 0), or null when any bit is unknown -- a
	 *  dispatch decision (e.g. which register a data write targets) cannot be made from a
	 *  partially known field. */
	private static Integer fieldValueIfFullyKnown(BankState state, FieldPos field) {
		int mask = field.mask();
		if ((state.knownMask() & mask) != mask) {
			return null;
		}
		return (state.bits() & mask) >>> field.lsb();
	}

	/** Returns {@code base} with {@code field}'s bits marked unknown, leaving every other
	 *  bit of {@code base} exactly as it was. */
	private static BankState setUnknownField(BankState base, FieldPos field) {
		int mask = field.mask();
		return new BankState(base.knownMask() & ~mask, base.bits() & ~mask);
	}

	/** Returns {@code base} with {@code field}'s bits replaced by {@code fieldValue} (a
	 *  {@link BankState} already reduced to {@code [0, field.width())}, possibly only
	 *  partially known -- e.g. mask-algebra partial knowledge from
	 *  {@link StoredValueScanner}), leaving every other bit of {@code base} exactly as it
	 *  was. Generalizes {@link #setUnknownField} to fully- and partially-known values alike. */
	private static BankState setFieldFromByte(BankState base, FieldPos field, BankState fieldValue) {
		int mask = field.mask();
		int knownBits = (fieldValue.knownMask() << field.lsb()) & mask;
		int valueBits = (fieldValue.bits() << field.lsb()) & mask;
		return new BankState((base.knownMask() & ~mask) | knownBits,
			(base.bits() & ~mask) | valueBits);
	}
}
