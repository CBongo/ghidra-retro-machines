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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import retromachines.BankStrategyRegistry.ConfiguredMechanism;
import retromachines.BoardDescriptorModel.FieldSpec;
import retromachines.DescriptorSupport.BankStack;
import retromachines.DescriptorSupport.PairedFields;

/**
 * RAM bank-stack brackets (bead grm-mej.10): a function that PUSHES the live bank onto a RAM
 * bank stack, makes inner calls, and POPS it again restores the fields the pop writes to the
 * value they held at the push -- so the pop call is not an unknown bank switch.
 * <p>
 * tmnt3 is the shape (a game that keeps {@code $F2} as a stack pointer and {@code $00F3,Y} as
 * its slots):
 * <pre>
 *   push (86F9): PHA / LDA $A000 / LDY $F2 / INC $F2 / STA $00F3,Y / PLA / R7 = A, R6 = A+1
 *   pop  (871C): DEC $F2 / LDY $F2 / LDA $00F3,Y / R7 = A / CLC / ADC #1 / R6 = A / RTS
 *   caller     : JSR 86A5 (stub: LDA #$20 / BNE 86F9) / JSR A001 / JMP 871C
 * </pre>
 * <b>Everything the descriptor must state, it states.</b> {@code banking.bank_stacks} names the
 * pointer and slot cells; the walk finds push and pop helpers by their SHAPE over those cells
 * (never by address). The owner's fact, per the descriptor's provenance, is that inner calls
 * are stack-balanced -- what a verified bracket assumes of everything between the push and the
 * pop, and the one premise this class cannot prove. {@code banking.paired_fields} states
 * {@code high == low + offset} (r6 == r7 + 1), which is what lets a pop's {@code A+1} commit
 * count as restoring the high field.
 * <p>
 * <b>The claim is FIELD-SCOPED and LOCAL.</b> A pop restores exactly the fields whose last data
 * commit in the pop's own body is the slot byte (plus a stated pairing offset); the select/mode
 * writes it makes are untouched. And the push and the pop must be one bracket of one function:
 * a forward dataflow over the function's CFG, tracking the one open push, requires every path to
 * the pop to arrive with that same push open and no other push/pop between them, and refuses
 * when anything outside the walked set can jump into the open region, or any instruction in the
 * function writes the stack cells directly. The engine then deposits, at the pop, the tracked
 * state AT THE PUSH for the restored fields (never a fixed value), so a bracket whose entry
 * bank was unknown stays unknown rather than being invented.
 */
final class BankStackBrackets {

	private BankStackBrackets() {
	}

	/**
	 * A verified pop: the call site it pairs with, and the positioned fields it restores to
	 * their value at that push.
	 */
	record Pop(Address pushSite, Restore restore) {
		int restoredMask() {
			return restore.restoredMask();
		}
	}

	/**
	 * What a verified restore puts back, and how to COMPUTE it. {@code lowMask} is the identity
	 * cell field; {@code encoding} says which of its banks actually carry an identity byte;
	 * {@code highs} are the stated {@code high == low + offset} pairings over that low field.
	 * The restored low field takes its pre-bracket value only when that value is a bank the
	 * encoding verified (tmnt3: even banks); each restored high field is the low value plus
	 * the offset, masked to the field width -- NEVER the high field's own pre-bracket value,
	 * which equals it only if the pairing already held in the tracked state.
	 */
	record Restore(int restoredMask, int lowMask, BankMirrors.IdentifyingEncoding encoding,
			List<SaveRestoreTrampolines.FieldPairing> highs) {
	}

	/**
	 * Folds {@code restore} into {@code effect}, given the tracked state {@code at} the start of
	 * the bracket (the push, or the call to a self-contained restoring helper). A restored field
	 * whose value cannot be established is owned and UNKNOWN.
	 */
	static HelperArgumentRecovery.CallEffect fold(HelperArgumentRecovery.CallEffect effect,
			Restore restore, BankState at) {
		int lowMask = restore.lowMask();
		int lowLsb = Integer.numberOfTrailingZeros(lowMask);
		Integer v = null;
		if (at != null && (at.knownMask() & lowMask) == lowMask) {
			int val = (at.bits() & lowMask) >>> lowLsb;
			if (restore.encoding().isIdentity() || restore.encoding().verified().contains(val)) {
				v = val;
			}
		}
		int known = 0;
		int bits = 0;
		int restored = restore.restoredMask();
		if ((restored & lowMask) != 0 && v != null) {
			known |= lowMask;
			bits |= v << lowLsb;
		}
		for (SaveRestoreTrampolines.FieldPairing h : restore.highs()) {
			if ((restored & h.highMask()) != 0 && v != null) {
				int lsb = Integer.numberOfTrailingZeros(h.highMask());
				int hv = (v + h.offset()) & (h.highMask() >>> lsb);
				known |= h.highMask();
				bits |= hv << lsb;
			}
		}
		BankState state = effect.state();
		BankState folded = new BankState((state.knownMask() & ~restored) | known,
			(state.bits() & ~restored & state.knownMask()) | bits);
		boolean resolved = effect.argumentResolved() ||
			(effect.ownedMask() & ~restored & ~state.knownMask()) == 0;
		return new HelperArgumentRecovery.CallEffect(folded, effect.ownedMask() | restored,
			resolved, effect.noInboundArgument(), effect.secondTierRelay(), effect.restoreCell(),
			effect.readBack());
	}

	/**
	 * The proven brackets. {@code privatePushes} maps a push call site that belongs to at
	 * least one verified bracket to the positioned fields the push helper's data commits write,
	 * so the engine can treat the push's own (caller-supplied, possibly unrecoverable) bank
	 * argument as private to the bracket.
	 */
	record Claims(Map<Address, Pop> pops, Map<Address, Integer> privatePushes,
			Map<ghidra.program.model.listing.Function, Restore> helperRestores) {

		static final Claims NONE = new Claims(Map.of(), Map.of(), Map.of());

		/** These claims plus the self-contained helpers whose restore is computed per call. */
		Claims withHelperRestores(Map<ghidra.program.model.listing.Function, Restore> restores) {
			return new Claims(pops, privatePushes, restores);
		}

		boolean isEmpty() {
			return pops.isEmpty() && helperRestores.isEmpty();
		}
	}

	// ------------------------------------------------------------------
	// Helper shapes
	// ------------------------------------------------------------------

	/** What the abstract value in A (or the stack) is, as far as the shape walk cares. */
	private record Val(int kind, Address source, int plus) {
		static final int NONE = 0, IDENT = 1, SLOT = 2;
		static final Val NO = new Val(NONE, null, 0);
	}

	/**
	 * A recognized push or pop helper entry. {@code source}: the identity cell a push stores.
	 * {@code lastPlus}: per positioned field mask, the offset from the slot byte that the LAST
	 * data commit to the field carried, or -1 when the last commit was some other value.
	 * {@code dataFields}: every field a data commit in the body writes.
	 */
	private record Shape(boolean push, Address source, int dataFields, Map<Integer, Integer> lastPlus) {
	}

	private static final int MAX_SHAPE_STEPS = 48;

	private record Context(Program program, BankMirrors mirrors, List<ConfiguredMechanism> mechanisms,
			Set<Address> switchSites, BankStack stack, Map<Address, Shape> cache) {
	}

	/** Cell address a plain operand names, or -1. */
	private static long plainOffset(Instruction instr) {
		Address a = StoredValueScanner.plainAbsoluteTarget(instr);
		return a == null ? -1 : a.getOffset();
	}

	/**
	 * The base of an absolute,{@code reg}-indexed operand ({@code LDA $00F3,Y}), or -1 when the
	 * operand is not of that form.
	 */
	private static long indexedBase(Instruction instr, String reg) {
		boolean indexed = false;
		long base = -1;
		for (Object o : instr.getOpObjects(0)) {
			if (o instanceof Register r) {
				if (!r.getName().equalsIgnoreCase(reg)) {
					return -1;
				}
				indexed = true;
			}
			else if (o instanceof Address a) {
				base = a.getOffset();
			}
			else if (o instanceof Scalar s) {
				base = s.getUnsignedValue();
			}
		}
		return indexed ? base : -1;
	}

	private static boolean inSlots(Context c, long offset) {
		return offset >= c.stack().slots() && offset <= c.stack().slots() + 0xFF;
	}

	/** Positioned field mask a mechanism write commits a bank value into; 0: none; -1: unknown. */
	private static int committedField(Context c, Instruction instr) {
		for (ConfiguredMechanism cm : c.mechanisms()) {
			int r = cm.strategy().bankFieldCommittedBySite(c.program(), instr);
			if (r >= 0) {
				return r == 0 ? 0 : cm.placement().positionMask(r);
			}
		}
		return -1;
	}

	/**
	 * Walks the helper entered at {@code entry} (following a jump, or a conditional branch that
	 * directly follows an {@code LDA #imm} that decides it -- the entry-stub idiom
	 * {@code LDA #$20 / BNE push}) and classifies it as a bank-stack push, a pop, or neither.
	 */
	private static Shape shapeAt(Context c, Address entry) {
		Listing listing = c.program().getListing();
		Register stackPointer = c.program().getCompilerSpec().getStackPointer();
		if (stackPointer == null) {
			return null;
		}
		Deque<Val> saved = new ArrayDeque<>();
		Val a = Val.NO;
		int y = 0; // 0 unknown, 1 = the pointer before any inc/dec, 2 = the pointer after one DEC
		int incs = 0;
		int decs = 0;
		boolean sawMechanismWrite = false;
		boolean prevClc = false;
		Integer lastImmA = null;
		Address pushed = null;
		boolean popLoaded = false;
		int dataFields = 0;
		Map<Integer, Integer> lastPlus = new LinkedHashMap<>();
		Address cursor = entry;
		for (int step = 0; step < MAX_SHAPE_STEPS; step++) {
			Instruction instr = listing.getInstructionAt(cursor);
			if (instr == null) {
				return null;
			}
			String mnem = instr.getMnemonicString().toUpperCase();
			boolean clcBefore = prevClc;
			prevClc = false;
			Integer immBefore = lastImmA;
			lastImmA = null;
			Address next = instr.getFallThrough();
			switch (mnem) {
				case "RTS" -> {
					if (pushed != null && incs == 1 && decs == 0) {
						return new Shape(true, pushed, dataFields, lastPlus);
					}
					if (popLoaded && decs == 1 && incs == 0 && lastPlus.containsValue(0)) {
						return new Shape(false, null, dataFields, lastPlus);
					}
					return null;
				}
				case "PHA" -> saved.push(a);
				case "PHP" -> saved.push(Val.NO);
				case "PLA" -> {
					if (saved.isEmpty()) {
						return null;
					}
					a = saved.pop();
				}
				case "PLP" -> {
					if (saved.isEmpty()) {
						return null;
					}
					saved.pop();
				}
				case "CLC" -> prevClc = true;
				case "ADC" -> {
					Integer imm = StoredValueScanner.isImmediate(instr)
							? StoredValueScanner.immediateOperandValue(instr) : null;
					a = clcBefore && imm != null && a.kind() == Val.SLOT
							? new Val(Val.SLOT, null, a.plus() + imm) : Val.NO;
				}
				case "INC", "DEC" -> {
					long target = plainOffset(instr);
					if (target < 0) {
						return null; // an indexed read-modify-write might be the stack
					}
					if (target == c.stack().pointer()) {
						if (mnem.equals("INC")) {
							incs++;
						}
						else {
							decs++;
						}
					}
					else if (inSlots(c, target)) {
						return null;
					}
				}
				case "LDA", "LDX", "LDY" -> {
					char reg = mnem.charAt(2);
					if (StoredValueScanner.isImmediate(instr)) {
						if (reg == 'A') {
							lastImmA = StoredValueScanner.immediateOperandValue(instr);
							a = Val.NO;
						}
						else if (reg == 'Y') {
							y = 0;
						}
					}
					else {
						long target = plainOffset(instr);
						if (target >= 0) {
							if (reg == 'Y') {
								y = target != c.stack().pointer() ? 0
										: incs == 0 && decs == 0 ? 1 : decs == 1 && incs == 0 ? 2 : 0;
							}
							else if (reg == 'A') {
								Address from = StoredValueScanner.plainAbsoluteTarget(instr);
								a = !sawMechanismWrite && SaveRestoreTrampolines
									.isLiveBankMirror(c.mirrors(), from) &&
									c.mirrors().identifyingField(from) != null
											? new Val(Val.IDENT, from, 0) : Val.NO;
							}
						}
						else {
							long base = indexedBase(instr, "Y");
							if (reg == 'A') {
								if (base == c.stack().slots() && y == 2) {
									a = new Val(Val.SLOT, null, 0);
									popLoaded = true;
								}
								else {
									a = Val.NO;
								}
							}
							else if (reg == 'Y') {
								y = 0;
							}
						}
					}
				}
				case "STA", "STX", "STY" -> {
					if (c.switchSites().contains(instr.getMinAddress())) {
						sawMechanismWrite = true;
						int field = committedField(c, instr);
						if (field < 0) {
							return null; // cannot say which field this commit writes
						}
						if (field != 0) {
							dataFields |= field;
							lastPlus.put(field, mnem.equals("STA") && a.kind() == Val.SLOT
									? a.plus() : -1);
						}
					}
					else {
						long target = plainOffset(instr);
						if (target < 0) {
							long base = indexedBase(instr, "Y");
							if (mnem.equals("STA") && base == c.stack().slots() && y == 1 &&
								a.kind() == Val.IDENT) {
								pushed = a.source();
							}
							else {
								return null; // some other indexed/indirect store: might be the stack
							}
						}
						else if (target == c.stack().pointer() || inSlots(c, target)) {
							return null;
						}
					}
				}
				default -> {
					if (instr.getFlowType().isCall() || instr.getFlowType().isTerminal()) {
						return null;
					}
					if (instr.getFlowType().isJump() && !instr.getFlowType().isConditional() &&
						!instr.getFlowType().isComputed() && instr.getFlows().length == 1) {
						next = instr.getFlows()[0];
					}
					else if (instr.getFlowType().isConditional() && !instr.getFlowType().isComputed() &&
						instr.getFlows().length == 1 && immBefore != null) {
						Boolean taken = switch (mnem) {
							case "BNE" -> immBefore != 0;
							case "BEQ" -> immBefore == 0;
							case "BPL" -> immBefore < 0x80;
							case "BMI" -> immBefore >= 0x80;
							default -> null;
						};
						if (taken == null) {
							return null;
						}
						next = taken ? instr.getFlows()[0] : instr.getFallThrough();
					}
					else if (instr.getFlows().length > 0) {
						return null;
					}
					else {
						if (StoredValueScanner.modifiesRegister(instr, 'A')) {
							a = Val.NO;
						}
						if (StoredValueScanner.modifiesRegister(instr, 'Y')) {
							y = 0;
						}
					}
				}
			}
			if (next == null) {
				return null;
			}
			cursor = next;
		}
		return null;
	}

	private static Shape cachedShape(Context c, Address entry) {
		if (c.cache().containsKey(entry)) {
			return c.cache().get(entry);
		}
		Shape s = shapeAt(c, entry);
		c.cache().put(entry, s);
		return s;
	}

	// ------------------------------------------------------------------
	// Brackets
	// ------------------------------------------------------------------

	/**
	 * The positioned fields a pop restores, given the push whose slot byte it reloads: the field
	 * the push's identity cell belongs to when committed with the slot byte as is, and each
	 * stated {@code high == low + offset} field when committed with slot + offset.
	 */
	private static Restore restoredFields(Context c, Shape pop, Shape push,
			List<SaveRestoreTrampolines.FieldPairing> pairs) {
		FieldSpec low = c.mirrors().identifyingField(push.source());
		if (low == null || !c.mirrors().restoreAliasesLiveBank(push.source())) {
			return null;
		}
		int mask = 0;
		List<SaveRestoreTrampolines.FieldPairing> highs = new java.util.ArrayList<>();
		for (SaveRestoreTrampolines.FieldPairing p : pairs) {
			if (p.lowMask() == low.positionedMask()) {
				highs.add(p);
			}
		}
		for (Map.Entry<Integer, Integer> commit : pop.lastPlus().entrySet()) {
			int field = commit.getKey();
			int plus = commit.getValue();
			if (plus == 0 && field == low.positionedMask()) {
				mask |= field;
			}
			else if (plus > 0) {
				for (SaveRestoreTrampolines.FieldPairing p : highs) {
					if (p.offset() == plus && p.highMask() == field) {
						mask |= field;
					}
				}
			}
		}
		return mask == 0 ? null
				: new Restore(mask, low.positionedMask(),
					c.mirrors().identifyingEncoding(push.source()), highs);
	}

	/**
	 * Resolves the descriptor's stated pairings against the board's field names. A pairing that
	 * names a field the board does not have is dropped (it then simply licenses nothing).
	 */
	static List<SaveRestoreTrampolines.FieldPairing> resolvePairings(
			BoardDescriptorModel.BoardModel board, List<PairedFields> pairs) {
		Map<String, FieldSpec> fields = new HashMap<>();
		for (FieldSpec f : board.fieldSpecs()) {
			fields.put(f.name(), f);
		}
		List<SaveRestoreTrampolines.FieldPairing> out = new java.util.ArrayList<>();
		for (PairedFields p : pairs) {
			FieldSpec high = fields.get(p.high());
			FieldSpec low = fields.get(p.low());
			if (high != null && low != null) {
				out.add(new SaveRestoreTrampolines.FieldPairing(high.positionedMask(),
					low.positionedMask(), p.offset()));
			}
		}
		return out;
	}

	/** Most instructions one push's open region may span before the walk gives up. */
	private static final int MAX_REGION = 600;

	/**
	 * Finds every verified bank-stack bracket in {@code program}. Empty (and free) when the
	 * descriptor states no {@code bank_stacks}.
	 */
	static Claims find(Program program, BankMirrors mirrors, List<ConfiguredMechanism> mechanisms,
			Set<Address> switchSites, List<BankStack> stacks,
			List<SaveRestoreTrampolines.FieldPairing> pairs) {
		if (stacks.isEmpty() || mirrors.isEmpty() || mechanisms.isEmpty()) {
			return Claims.NONE;
		}
		Map<Address, Pop> pops = new LinkedHashMap<>();
		Map<Address, Integer> privatePushes = new LinkedHashMap<>();
		for (BankStack stack : stacks) {
			Context c = new Context(program, mirrors, mechanisms, switchSites, stack, new HashMap<>());
			findForStack(c, pairs, pops, privatePushes);
		}
		return pops.isEmpty() ? Claims.NONE : new Claims(pops, privatePushes, Map.of());
	}

	/**
	 * Every call site whose target is a push or pop helper, then for each PUSH the region of
	 * code it dominates up to the pops it reaches. The pairing is a property of the code between
	 * the two, not of any Ghidra function: tmnt3 has bracket code that no function owns.
	 */
	private static void findForStack(Context c, List<SaveRestoreTrampolines.FieldPairing> pairs, Map<Address, Pop> pops, Map<Address, Integer> privatePushes) {
		Listing listing = c.program().getListing();
		Map<Address, Shape> shapes = new LinkedHashMap<>();
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			if (!instr.getFlowType().isCall() || instr.getFlowType().isComputed() ||
				instr.getFlows().length != 1) {
				continue;
			}
			Shape s = cachedShape(c, instr.getFlows()[0]);
			if (s != null) {
				shapes.put(instr.getMinAddress(), s);
			}
		}
		for (Map.Entry<Address, Shape> pushEntry : shapes.entrySet()) {
			if (!pushEntry.getValue().push()) {
				continue;
			}
			Address pushSite = pushEntry.getKey();
			Set<Address> region = new HashSet<>();
			List<Address> reached = new java.util.ArrayList<>();
			String why = openRegion(c, listing, shapes, pushSite, region, reached);
			if (why == null) {
				why = closed(c, pushSite, region, reached);
			}
			if (why != null) {
				continue;
			}
			boolean used = false;
			for (Address popSite : reached) {
				Restore restore = restoredFields(c, shapes.get(popSite), pushEntry.getValue(), pairs);
				if (restore != null) {
					pops.put(popSite, new Pop(pushSite, restore));
					used = true;
				}
			}
			if (used) {
				privatePushes.put(pushSite, pushEntry.getValue().dataFields());
			}
		}
	}

	/**
	 * Walks forward from the push through everything it can reach before a pop, filling
	 * {@code region} (the instructions strictly between) and {@code reached} (the pop call
	 * sites that end a path). Returns a reason to refuse, or null.
	 */
	private static String openRegion(Context c, Listing listing, Map<Address, Shape> shapes,
			Address pushSite, Set<Address> region, List<Address> reached) {
		Instruction push = listing.getInstructionAt(pushSite);
		Deque<Address> work = new ArrayDeque<>();
		if (push.getFallThrough() != null) {
			work.add(push.getFallThrough());
		}
		Set<Address> seen = new HashSet<>();
		while (!work.isEmpty()) {
			Address at = work.poll();
			if (!seen.add(at)) {
				continue;
			}
			if (seen.size() > MAX_REGION) {
				return "region too large";
			}
			Instruction instr = listing.getInstructionAt(at);
			if (instr == null) {
				return "no instruction at " + at;
			}
			Shape sh = shapes.get(at);
			if (sh != null) {
				if (sh.push()) {
					return "another push at " + at + " before a pop";
				}
				reached.add(at);
				continue;
			}
			region.add(at);
			if (StoredValueScanner.writesMemory(instr) && touchesStack(c, instr)) {
				return "writes the stack cells at " + at;
			}
			if (!instr.getFlowType().isCall()) {
				for (Address flow : instr.getFlows()) {
					work.add(flow);
				}
			}
			if (instr.getFallThrough() != null) {
				work.add(instr.getFallThrough());
			}
		}
		return reached.isEmpty() ? "no pop reached" : null;
	}

	/**
	 * The push must DOMINATE everything it brackets: every flow into the region or into a pop it
	 * reaches comes from the region or from the push itself. Otherwise some path reaches the pop
	 * without the push (or with another one), and "restores the state at the push" is false.
	 */
	private static String closed(Context c, Address pushSite, Set<Address> region,
			List<Address> reached) {
		Listing listing = c.program().getListing();
		Set<Address> inside = new HashSet<>(region);
		inside.add(pushSite);
		Set<Address> toCheck = new HashSet<>(region);
		toCheck.addAll(reached);
		for (Address at : toCheck) {
			Instruction instr = listing.getInstructionAt(at);
			Instruction fallFrom = instr.getFallFrom() == null ? null
					: listing.getInstructionAt(instr.getFallFrom());
			if (fallFrom != null && !inside.contains(fallFrom.getMinAddress()) &&
				fallFrom.getFallThrough() != null && fallFrom.getFallThrough().equals(at)) {
				return "falls in from outside at " + at;
			}
			for (Reference ref : c.program().getReferenceManager().getReferencesTo(at)) {
				if (ref.getReferenceType().isFlow() && !inside.contains(ref.getFromAddress())) {
					return "entered from " + ref.getFromAddress() + " at " + at;
				}
			}
		}
		return null;
	}

	/** Whether {@code instr} writes the stack's pointer or slot cells in a way this analysis can see. */
	private static boolean touchesStack(Context c, Instruction instr) {
		long plain = plainOffset(instr);
		if (plain >= 0) {
			return plain == c.stack().pointer() || inSlots(c, plain);
		}
		for (String reg : new String[] { "X", "Y" }) {
			long base = indexedBase(instr, reg);
			if (base >= 0 && (inSlots(c, base) || inSlots(c, base + 0xFF) ||
				base <= c.stack().pointer() && c.stack().pointer() <= base + 0xFF)) {
				return true;
			}
		}
		return false;
	}
}
