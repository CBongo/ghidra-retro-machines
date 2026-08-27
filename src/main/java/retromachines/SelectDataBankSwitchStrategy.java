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
 * {@link BoardBankAnalyzer#configureStrategies} injects for every mechanism from the
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

	@Override
	public String strategyName() {
		return "select-data";
	}

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
		if (params.has("targets")) {
			for (Map.Entry<String, JsonElement> e : params.getAsJsonObject("targets").entrySet()) {
				targets.put(Integer.valueOf(e.getKey()), fieldPos(fieldLayout, e.getValue().getAsString()));
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
			// MMC3-style select/data registers are write-only -- nothing reads them back,
			// at any resolvedTarget.
			return null;
		}
	};

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
	 * state". That is this mechanism exactly, and {@link #hooks}' {@code resolveLoad} above
	 * already says so in as many words: it returns {@code null} at every {@code
	 * resolvedTarget} because nothing reads an MMC3 select/data register back.
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
	 * re-running that check; the criteria comments record both traps.
	 */
	@Override
	public boolean effectDependsOnPriorState() {
		return false;
	}

	@Override
	public BankState computeSwitch(Program program, Instruction instr, BankState inState) {
		Long offset = writesInRange(instr);
		if (offset == null) {
			return null;
		}
		Character reg = StoredValueScanner.storeRegister(instr);
		boolean even = (offset & 1) == 0;
		return even ? computeSelectWrite(program, instr, reg, inState)
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
	 * the no-poison case -- {@code inState} returned verbatim; a select value that IS a
	 * tracked target recovers the written byte and overwrites only that target field.
	 */
	private BankState computeDataWrite(Program program, Instruction instr, Character reg,
			BankState inState) {
		Integer selectValue = fieldValueIfFullyKnown(inState, selectField);
		if (selectValue == null) {
			BankState result = inState;
			for (FieldPos target : targets.values()) {
				result = setUnknownField(result, target);
			}
			return result;
		}

		FieldPos target = targets.get(selectValue);
		if (target == null) {
			// Untracked register (e.g. MMC3 CHR banks R0-R5): no poison -- see class javadoc.
			return inState;
		}

		int byteMask = (1 << target.width()) - 1;
		BankState stored = reg == null ? BankState.unknown()
				: StoredValueScanner.resolveStoredValue(program, instr, reg, inState, byteMask, hooks);
		return setFieldFromByte(inState, target, stored);
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
	 * {@code BoardBankAnalyzer.restoresEntryBank} already use, and it makes "on every path" true
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
