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
import java.util.function.Supplier;

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * {@link ConstantSemantics} that answers by interpreting an instruction's OWN p-code (bead
 * grm-4wqd, design (b) of grm-as0m) rather than by a table of recognized mnemonics -- so a
 * CPU family {@link Mos6502ConstantSemantics} has never been taught about still folds, as long
 * as its language's p-code is straight-line enough for {@link #after} to follow.
 * <p>
 * <b>Scope: one instruction, not a window.</b> The backward walk that calls this lives in
 * {@link StoredValueScanner#constantValue} and is unchanged by this class -- every guard it
 * applies (fall-through linkage, {@code isControlFlowJoin}, the step budget, the call abort,
 * the {@link RegisterEnv} entry stop) fires exactly as it does for {@link Mos6502ConstantSemantics}.
 * This class only answers "what does THIS instruction's p-code leave in {@code loc}, given its
 * inputs" -- each input asked of {@link Inputs}, which is the walk asking itself the same
 * question one level back. That split is what makes interpreting real p-code cheap to bolt onto
 * the existing walk instead of a second, parallel evaluator.
 * <p>
 * <b>Demand-driven, on purpose.</b> An instruction's p-code routinely computes several outputs
 * (a result, N, Z, C, V, ...) from a shared prefix and then diverges. Asking for one of them
 * must not pay for the others: {@link #after} binds every p-code op's output to a memoized
 * thunk as it walks the op list forward, and forces (calls) a thunk only when some later,
 * actually-relevant computation demands it -- ultimately, only when the QUERIED location's
 * final value is forced. In particular a register read that happens before that register is
 * written within the instruction becomes a thunk over {@link Inputs#before}, which is expensive
 * (it recurses the whole walk one level deeper) and is invoked at all only if forced. The stock
 * {@code adcNmos}/{@code sbcNmos} in the class javadoc example: asking for {@code A} forces the
 * carry-in ({@code tmpC}, via {@code Inputs.before(C)}) because {@code A}'s own value depends on
 * it, but never forces anything {@code V} alone would need beyond what {@code A} already
 * required.
 * <p>
 * <b>Exact answers only.</b> Every op is evaluated with Ghidra's own
 * {@link ghidra.pcode.opbehavior.OpBehaviorFactory} -- the same behaviors the real p-code
 * emulator uses, with the same {@code sizein}/{@code sizeout} convention
 * ({@code op.getInput(0).getSize()}, mirroring {@code Emulate.executeCurrentOp} exactly) -- so
 * this is interpretation, not a hand-rolled re-derivation of arithmetic/logic/carry/extension/
 * {@code PIECE}/{@code SUBPIECE} semantics.
 * <p>
 * <b>Memory reads.</b> Never read from program memory directly -- always through
 * {@link Inputs#memoryOperand}, which is the scanner's OWN authority on what this instruction's
 * memory operand reads (it already applies {@link Inputs#effectiveTarget}'s resolution, a
 * strategy's {@code resolveLoad}, and a stack-relative-reload last resort, grm-4bgh.1). Exactly
 * ONE read per instruction may ever consult it: the LAST memory read (a {@code LOAD}, or -- the
 * common case for a compile-time-fixed address, which Ghidra represents as a direct
 * address-space operand with no {@code LOAD} at all, e.g. {@code AND $9000} compiles to
 * {@code INT_AND(A, (RAM,0x9000,1))} -- a direct address-space input to some other op) before
 * the first store-like event in the op array. Earlier reads (e.g. the two zero-page bytes an
 * indirect mode's pointer fetch reads) are pointer-fetch components, not the operand itself, and
 * are unconditionally unknown -- {@code memoryOperand} answers for the addressing-mode operand
 * the scanner models, not an arbitrary intermediate access. For the designated read,
 * {@code memoryOperand} is TRUSTED by default: it is declined only on a PROVEN disagreement,
 * where this evaluator's own address (a bare constant for the direct form; whatever the
 * {@code LOAD}'s address expression folds to for the computed form) is independently known AND
 * {@code effectiveTarget} is independently known AND the two differ. An address this evaluator
 * cannot resolve (e.g. an index register from an unmodeled {@code TSX}) is deliberately NOT a
 * reason to decline on its own -- {@code memoryOperand} may still answer through a path (the
 * stack-relative reload) that never needed that address in the first place. An internal branch
 * ({@code CBRANCH}/{@code BRANCH} to
 * the p-code constant space, i.e. a relative op index within this same instruction, exactly as
 * {@code Emulate.executeBranch} resolves it) is followed when its condition is known and
 * declines the whole answer when it is not, since which ops execute after it is then undecided.
 * An instruction-external branch (a machine-address target, or {@code CALL}/{@code CALLIND}/
 * {@code RETURN}/{@code BRANCHIND}) that is taken -- unconditionally, or a {@code CBRANCH} whose
 * known condition selects it -- stops interpretation there: register writes already recorded
 * stand, and nothing later in the op list is examined. A {@code CBRANCH} leaving the instruction
 * with an UNKNOWN condition does not stop anything -- whichever way it actually goes, no
 * register write happens at the branch itself, so execution is treated as continuing with the
 * next op, which is exactly the union of what "taken" and "not taken" have already committed to
 * at that point. {@code CALLOTHER} (or any other unhandled opcode) with an output makes that
 * output unknown but does not otherwise stop interpretation; one with NO output declines the
 * whole answer immediately, since it may have effects on registers this evaluator cannot see.
 * <p>
 * <b>{@code D} is assumed, not just declined, when unestablished</b> (owner ruling 2026-09-26,
 * grm-4wqd; see {@code Interp#assumedDecimalFlag}). A {@code D} read the backward walk cannot
 * pin -- an entry stop, a join, block start, budget exhaustion, a call, or a writer this
 * evaluator cannot read {@code D} from (e.g. {@code PLP}/{@code RTI}) -- is treated as
 * {@code assumedDecimalFlag(program)} (currently {@code 0}, binary mode, for every program)
 * rather than declined. A writer the walk DOES resolve -- {@code SED}, {@code CLD}, or any
 * p-code that pins {@code D} -- still wins over the assumption; only a genuinely unestablished
 * read falls back. The assumption lives ONLY in this class's read of {@code D} -- never in
 * {@link StoredValueScanner#constantValue}'s walk itself and never in
 * {@link Mos6502ConstantSemantics} (whose {@code ADC}/{@code SBC} make the same binary-mode
 * assumption unconditionally, for a different reason: it never reads {@code D} at all).
 * <p>
 * <b>Known blockers to this being the default</b> (recorded on grm-4wqd, not fixed here; see
 * {@code PcodeConstantSemanticsDifferentialTest} for the fixtures that pin each one):
 * <ul>
 * <li>NES's stock {@code 6502:LE:16:default} language computes {@code ADC}'s carry-out as a
 * single {@code carry(A, op1)} that drops a carry-out arising solely from the carry-in
 * (grm-o9k) -- under PCODE the resulting {@code A} is right but any DERIVED carry is wrong in
 * that edge case, where {@link Mos6502ConstantSemantics}'s two-step chain is correct.</li>
 * <li>The SAME stock language's {@code SBC} computes the carry (not-borrow) flag via a bit-7
 * trick in {@code subtraction_flags1} that comes out wrong on at least one measured input
 * ({@code A=$01, SBC #$02} with carry-in 1: real/TABLE answer carry {@code =0}, stock p-code
 * says {@code 1}) -- the flag POLARITY is inverted: the trick is the textbook borrow-out, and
 * the 6502's C is not-borrow. Already known (grm-ef46 defect (2), found by the 6502-vectors tier)
 * and already fixed in both the bundled {@code 6502core.sinc} and upstream PR
 * NationalSecurityAgency/ghidra#9656; PCODE inherits it on stock until that PR lands.</li>
 * <li>An undocumented opcode whose addressing bypasses the shared {@code OP1}/{@code OP2}
 * subtables -- {@code LAX} is the example -- never resolves a memory operand, under EITHER
 * evaluator, even though this class's own interpreter handles {@code LAX}'s p-code fine in
 * isolation: {@code instr.getOpObjects(0)} yields no {@code Address} for it, so
 * {@link StoredValueScanner#plainAbsoluteTarget} always declines, and {@code
 * WalkInputs.memoryOperand()} -- the one implementation either evaluator's
 * {@link Inputs#memoryOperand} ever calls -- uses that same resolution to decide what address
 * to hand a strategy's hook, so the hook is never even asked about the real address. Not
 * specific to PCODE (see the previous stack-relative-reload note's resolution, once a fix
 * grounded in that shared plumbing landed) -- a limit of the SHARED {@code memoryOperand}
 * machinery on non-standard addressing, not of this class's own {@code LOAD} handling.</li>
 * </ul>
 * <p>
 * <b>The stack-relative-reload idiom is NOT a blocker</b> ({@code PHA / TXA / PHA / TSX / LDA
 * $01nn,X}, grm-4bgh.1; the real-ROM case that surfaced the fix, {@code rcransom}'s
 * {@code FUN_fed1}, both this bead's and grm-4bgh.1's own motivating example): the memory-read
 * rule above trusts {@link Inputs#memoryOperand} whenever this evaluator's own address neither
 * resolves nor is independently confirmed WRONG, so an unresolved {@code X} (from an unmodeled
 * {@code TSX}) no longer blocks reaching {@code memoryOperand}'s stack-relative-reload last
 * resort, which needs no address at all. An earlier version of this evaluator required an
 * independently-confirmed address match before trusting the hook, which made this decline
 * under PCODE only; that requirement is gone.
 */
final class PcodeConstantSemantics implements ConstantSemantics {

	static final PcodeConstantSemantics INSTANCE = new PcodeConstantSemantics();

	/** Total p-code ops this evaluator will step through for one {@link #after} call before
	 * declining -- a loop guard for an internal branch that keeps re-entering itself. 6502
	 * instructions need at most a few dozen even through the decimal-mode paths; 256 is a wide
	 * margin, not a tuned budget. */
	private static final int MAX_OPS = 256;

	private PcodeConstantSemantics() {
	}

	@Override
	public boolean writes(Instruction instr, Loc loc) {
		return ConstantSemantics.pcodeWrites(instr, loc.name());
	}

	@Override
	public Integer after(Instruction instr, Loc loc, Inputs in) {
		PcodeOp[] ops;
		try {
			ops = instr.getPcode();
		}
		catch (RuntimeException e) {
			return null;
		}
		if (ops == null || ops.length == 0) {
			return null;
		}
		return new Interp(instr.getProgram(), in, ops).run(loc);
	}

	/** One forward interpretation of a single instruction's p-code, for one {@link #after} call. */
	private static final class Interp {

		private final Program program;
		private final Inputs in;
		private final PcodeOp[] ops;

		/** Every varnode this interpretation has written, to a memoized lazy value -- unique
		 * temporaries and register writes alike; {@link Varnode#equals} compares only
		 * (space, offset, size), so re-writing the same storage (e.g. a reused local) simply
		 * replaces the entry, matching ordinary mutable p-code state. */
		private final Map<Varnode, Supplier<Integer>> bindings = new HashMap<>();

		/** The most recent thunk bound to each {@link Loc}'s register, kept alongside
		 * {@link #bindings} purely so the final answer does not need to reconstruct a lookup
		 * varnode for the queried register. */
		private final Map<Loc, Supplier<Integer>> locBindings = new HashMap<>();

		/** Memoized {@link Inputs#before} calls, so a register read before being written is
		 * asked of the walk at most once per instruction even if read from more than one op. */
		private final Map<Loc, Supplier<Integer>> beforeCache = new HashMap<>();

		/**
		 * The most recent WRITE to each (space, offset), regardless of size -- keyed loosely
		 * (unlike {@link #bindings}, which requires an exact size match) so a narrower READ of
		 * the same storage can still see it. This is for a real, common sleigh idiom measured
		 * in the bundled {@code adcNmos}: {@code local sum:2; ... local mid:1 = sum:1;} reads
		 * the LOW byte of a 2-byte local via a plain {@code COPY} from a same-offset,
		 * smaller-size varnode -- not a {@code SUBPIECE} -- so without this, {@code mid} (and
		 * later, the final {@code A = sum:1}) would see an "unbound unique" and decline every
		 * decimal-mode {@code ADC}/{@code SBC}, which is not a real unknown: the WIDE value was
		 * always fully known, just written under a different-sized key. A narrower read masks
		 * the wide value to its own size (the low bytes) -- correct because Ghidra's
		 * unique/constant space addresses a value by its low-order byte regardless of the
		 * target architecture's endianness. A read WIDER than the most recent same-offset
		 * write is NOT handled (rare, unseen in this instruction set) and still declines.
		 */
		private final Map<OffsetKey, SizedThunk> byOffset = new HashMap<>();

		private record OffsetKey(int space, long offset) {}

		private record SizedThunk(int size, Supplier<Integer> thunk) {}

		/**
		 * The op index of THE instruction's memory operand read -- the LAST memory read (a
		 * {@code LOAD}, or a direct address-space input to some other op) before the first
		 * store-like event ({@code STORE}, or a direct address-space output), or {@code -1}
		 * if there is none. Computed ONCE, structurally, from the raw op array -- not
		 * tracked dynamically during interpretation -- because it is a property of the
		 * INSTRUCTION's addressing mode (which memory access is "the operand"), the same
		 * kind of fact {@link StoredValueScanner#plainAbsoluteTarget} answers structurally.
		 * Every read strictly before this index is a pointer-fetch component (e.g. the two
		 * zero-page bytes {@code readZpPointer} reads for an indirect mode) and is never
		 * treated as the operand: {@link Inputs#memoryOperand} answers for the single
		 * addressing-mode operand the scanner itself models, not for an arbitrary
		 * intermediate memory access, so only ONE read per instruction may ever consult it.
		 */
		private final int operandReadIndex;

		Interp(Program program, Inputs in, PcodeOp[] ops) {
			this.program = program;
			this.in = in;
			this.ops = ops;
			this.operandReadIndex = findOperandReadIndex(ops);
		}

		private static int findOperandReadIndex(PcodeOp[] ops) {
			int result = -1;
			for (int i = 0; i < ops.length; i++) {
				PcodeOp op = ops[i];
				Varnode out = op.getOutput();
				if (op.getOpcode() == PcodeOp.STORE || (out != null && out.isAddress())) {
					break; // a store-like event -- nothing at or after this index qualifies
				}
				if (op.getOpcode() == PcodeOp.LOAD) {
					result = i;
					continue;
				}
				for (Varnode input : op.getInputs()) {
					if (input.isAddress()) {
						result = i;
						break;
					}
				}
			}
			return result;
		}

		Integer run(Loc loc) {
			int pc = 0;
			int steps = 0;
			while (pc < ops.length) {
				if (++steps > MAX_OPS) {
					return null;
				}
				PcodeOp op = ops[pc];
				int opcode = op.getOpcode();
				Varnode out = op.getOutput();

				switch (opcode) {
					case PcodeOp.LOAD: {
						if (pc != operandReadIndex) {
							// A pointer-fetch component (e.g. one byte of an indirect mode's
							// zero-page pointer), not THE operand read -- see operandReadIndex's
							// javadoc. Nothing downstream may treat this as the instruction's
							// memory operand, so it is unconditionally unknown; cheap, since
							// nothing is forced to reach that answer.
							bind(out, UNKNOWN);
							pc++;
							continue;
						}
						// Snapshot the CURRENT binding for the address operand now, at this
						// op's position in the forward walk -- not a re-lookup by Varnode key
						// deferred to force time. Storage keys (space/offset/size) get REBOUND
						// as later ops write them, so a lazily-deferred `resolve(addrVn)` could
						// resolve to a LATER write to the same key (or, for a self-referential
						// op like `tmp = tmp << 1`, to itself) instead of the value that was
						// actually live when this LOAD read it.
						Supplier<Integer> addrThunk = resolve(op.getInput(1));
						int size = out.getSize();
						bind(out, memoize(() -> operandByte(addrThunk, size)));
						pc++;
						continue;
					}
					case PcodeOp.STORE: {
						pc++;
						continue;
					}
					case PcodeOp.CBRANCH: {
						Varnode destVn = op.getInput(0);
						Varnode condVn = op.getInput(1);
						boolean internal = isInternal(destVn);
						Integer cond = force(condVn);
						if (internal) {
							if (cond == null) {
								return null;
							}
							pc = cond != 0 ? internalTarget(destVn, pc) : pc + 1;
							if (pc < 0 || pc > ops.length) {
								return null;
							}
							continue;
						}
						// External target: a known taken branch stops here; not-taken or an
						// unknown condition both continue (see class javadoc).
						if (cond != null && cond != 0) {
							return finalValue(loc);
						}
						pc++;
						continue;
					}
					case PcodeOp.BRANCH: {
						Varnode destVn = op.getInput(0);
						if (isInternal(destVn)) {
							pc = internalTarget(destVn, pc);
							if (pc < 0 || pc > ops.length) {
								return null;
							}
							continue;
						}
						return finalValue(loc);
					}
					case PcodeOp.CALL:
					case PcodeOp.CALLIND:
					case PcodeOp.RETURN:
					case PcodeOp.BRANCHIND:
						return finalValue(loc);
					case PcodeOp.CALLOTHER: {
						if (out == null) {
							return null; // unseen side effects on registers -- decline entirely
						}
						bind(out, () -> null);
						pc++;
						continue;
					}
					default: {
						if (out == null) {
							pc++;
							continue; // no output, no result to bind -- nothing to decline either
						}
						if (!evaluate(op, out, pc)) {
							bind(out, () -> null);
						}
						pc++;
						continue;
					}
				}
			}
			return finalValue(loc);
		}

		/** Binds {@code out} to the result of evaluating {@code op} via
		 * {@link OpBehaviorFactory}, if it is a plain unary/binary arithmetic/logic op this
		 * evaluator can handle; returns false (leaving {@code out} for the caller to bind
		 * unknown) for anything else -- an unrecognized opcode, or one whose operand sizes this
		 * evaluator does not trust (over 8 bytes, never true for 6502 p-code). */
		private boolean evaluate(PcodeOp op, Varnode out, int opIndex) {
			OpBehavior behavior = OpBehaviorFactory.getOpBehavior(op.getOpcode());
			if (behavior instanceof UnaryOpBehavior u && op.getNumInputs() >= 1) {
				Varnode in0 = op.getInput(0);
				if (in0.getSize() > 8 || out.getSize() > 8) {
					return false;
				}
				int sizeout = out.getSize();
				int sizein = in0.getSize();
				// Snapshot the input's CURRENT binding now -- see the LOAD case's comment on
				// why a deferred re-lookup by Varnode key is wrong once the same key can be
				// rebound later (including by this very op, when in0 == out, e.g. `tmp =
				// tmp << 1`, which would otherwise resolve to itself and overflow the stack).
				Supplier<Integer> in0Thunk = resolveInput(in0, opIndex);
				bind(out, memoize(() -> {
					Integer v0 = in0Thunk.get();
					if (v0 == null) {
						return null;
					}
					long r = u.evaluateUnary(sizeout, sizein, Integer.toUnsignedLong(v0));
					return (int) (r & mask(sizeout));
				}));
				return true;
			}
			if (behavior instanceof BinaryOpBehavior b && op.getNumInputs() >= 2) {
				Varnode in0 = op.getInput(0);
				Varnode in1 = op.getInput(1);
				if (in0.getSize() > 8 || in1.getSize() > 8 || out.getSize() > 8) {
					return false;
				}
				int sizeout = out.getSize();
				int sizein = in0.getSize(); // matches Emulate.executeCurrentOp's convention
				Supplier<Integer> in0Thunk = resolveInput(in0, opIndex);
				Supplier<Integer> in1Thunk = resolveInput(in1, opIndex);
				bind(out, memoize(() -> {
					Integer v0 = in0Thunk.get();
					Integer v1 = in1Thunk.get();
					if (v0 == null || v1 == null) {
						return null;
					}
					long r = b.evaluateBinary(sizeout, sizein, Integer.toUnsignedLong(v0),
						Integer.toUnsignedLong(v1));
					return (int) (r & mask(sizeout));
				}));
				return true;
			}
			return false;
		}

		private Integer finalValue(Loc loc) {
			Supplier<Integer> s = locBindings.get(loc);
			return s == null ? null : s.get();
		}

		private static boolean isInternal(Varnode destVn) {
			AddressSpace space = destVn.getAddress().getAddressSpace();
			return space.isConstantSpace();
		}

		/** {@code offset + currentOpIndex}, exactly as {@code Emulate.executeBranch} resolves an
		 * intra-instruction relative branch; {@code ops.length} itself is a valid result (falls
		 * off the end of this instruction, i.e. an external exit). */
		private static int internalTarget(Varnode destVn, int currentOpIndex) {
			return (int) (destVn.getOffset() + currentOpIndex);
		}

		private void bind(Varnode vn, Supplier<Integer> thunk) {
			bindings.put(vn, thunk);
			byOffset.put(new OffsetKey(vn.getSpace(), vn.getOffset()), new SizedThunk(vn.getSize(), thunk));
			Register r = safeGetRegister(vn);
			if (r != null) {
				Loc l = locFor(r);
				if (l != null) {
					locBindings.put(l, thunk);
				}
			}
		}

		private Supplier<Integer> resolve(Varnode vn) {
			if (vn.isConstant()) {
				int size = vn.getSize();
				long value = vn.getOffset() & mask(size);
				int boxed = (int) value;
				return () -> boxed;
			}
			Supplier<Integer> bound = bindings.get(vn);
			if (bound != null) {
				return bound;
			}
			if (vn.isUnique()) {
				SizedThunk wide = byOffset.get(new OffsetKey(vn.getSpace(), vn.getOffset()));
				if (wide != null && wide.size() > vn.getSize()) {
					int narrowSize = vn.getSize();
					Supplier<Integer> wideThunk = wide.thunk();
					return memoize(() -> {
						Integer w = wideThunk.get();
						return w == null ? null : (int) (w & mask(narrowSize));
					});
				}
				return UNKNOWN;
			}
			Register r = safeGetRegister(vn);
			if (r != null) {
				Loc l = locFor(r);
				if (l == null) {
					return UNKNOWN;
				}
				return beforeThunk(l);
			}
			// A direct address-space varnode (a fixed memory read/write with no LOAD/STORE op
			// -- see operandReadIndex's javadoc) reaches here only when a call site did NOT
			// already route it through resolveInput (which is where the operand-read rule
			// lives), or from any other varnode kind this evaluator does not model. Either
			// way, plain resolve() never treats it as the instruction's operand.
			return UNKNOWN;
		}

		/**
		 * Resolves an INPUT varnode to the op at {@code opIndex}, applying the operand-read
		 * rule (see {@link #operandReadIndex}'s javadoc) when {@code vn} is a direct
		 * address-space read -- the no-{@code LOAD} form of a fixed memory access (e.g.
		 * {@code AND $9000} compiles to {@code INT_AND(A, (RAM,0x9000,1))} with no
		 * {@code LOAD} at all). If this op is not the designated operand read, the value is
		 * unconditionally unknown -- cheap, no address ever computed. If it IS,
		 * {@link #operandByteAtFixedAddress} answers it. Every other kind of varnode
		 * (constant, register, unique, register-computed) goes through the ordinary
		 * {@link #resolve}.
		 */
		private Supplier<Integer> resolveInput(Varnode vn, int opIndex) {
			if (vn.isAddress()) {
				if (opIndex != operandReadIndex) {
					return UNKNOWN;
				}
				Address fixedAddress = vn.getAddress();
				int size = vn.getSize();
				return memoize(() -> operandByteAtFixedAddress(fixedAddress, size));
			}
			return resolve(vn);
		}

		/**
		 * THE operand byte for a direct (no-{@code LOAD}) fixed-address read, where the
		 * address is always known (it IS {@code fixedAddress}, by construction of the
		 * varnode). Declines only when {@link Inputs#effectiveTarget} is ALSO known and
		 * disagrees; otherwise trusts {@link Inputs#memoryOperand} -- see the class
		 * javadoc's "Memory reads" section for why an inability to independently confirm the
		 * address is no longer, by itself, a reason to decline.
		 */
		private Integer operandByteAtFixedAddress(Address fixedAddress, int size) {
			if (size != 1) {
				return null;
			}
			Address target = in.effectiveTarget();
			if (target != null && !target.equals(fixedAddress)) {
				return null; // known disagreement
			}
			return in.memoryOperand();
		}

		/**
		 * THE operand byte for a {@code LOAD} whose address is COMPUTED (a register/unique
		 * expression, not a bare constant): declines only when BOTH the computed address and
		 * {@link Inputs#effectiveTarget} resolve and disagree; otherwise trusts
		 * {@link Inputs#memoryOperand}. An address that fails to resolve (e.g. an index
		 * register the walk cannot pin, such as {@code X} from an unmodeled {@code TSX}) is
		 * NO LONGER, by itself, a reason to decline: {@code memoryOperand} is the scanner's
		 * own authority on this instruction's operand and already applies its own
		 * resolution, including a last resort (the stack-relative reload, grm-4bgh.1) that
		 * does not need the address either -- see the class javadoc's "Memory reads"
		 * section.
		 */
		private Integer operandByte(Supplier<Integer> addressThunk, int size) {
			if (size != 1) {
				return null;
			}
			Address target = in.effectiveTarget();
			// Our own address is forced ONLY when there is a target to disagree with (bead
			// grm-om3i): with no target, a disagreement is impossible and memoryOperand() is the
			// answer either way, so forcing it would only spend budget on the index register's
			// walk that TABLE never spends. The target itself is memoized by the Inputs, so the
			// memoryOperand() below does not recompute it.
			if (target != null) {
				Integer addrVal = addressThunk.get();
				if (addrVal != null &&
					target.getUnsignedOffset() != Integer.toUnsignedLong(addrVal)) {
					return null; // known disagreement
				}
			}
			return in.memoryOperand();
		}

		private Integer force(Varnode vn) {
			return resolve(vn).get();
		}

		private Supplier<Integer> beforeThunk(Loc l) {
			if (l == Loc.D) {
				// Owner ruling 2026-09-26 (grm-4wqd), overriding this class's original "never
				// default D" stance: when the WALK cannot establish D -- entry stop, a join,
				// block start, budget exhaustion, a call, or a writer whose D this evaluator
				// cannot pin (PLP/RTI) -- assume assumedDecimalFlag(program) rather than
				// decline. A writer the walk DOES resolve (SED/CLD, or p-code that pins D) still
				// wins: this fallback only fires when in.before(D) itself returns null, never
				// overriding an actual answer. See assumedDecimalFlag's javadoc for the
				// assumption itself and its future per-game override seam.
				return beforeCache.computeIfAbsent(l,
					k -> memoize(() -> {
						Integer d = in.before(k);
						return d != null ? d : assumedDecimalFlag(program);
					}));
			}
			return beforeCache.computeIfAbsent(l, k -> memoize(() -> in.before(k)));
		}

		/**
		 * The decimal (D) flag value this evaluator assumes when the backward walk cannot
		 * establish it (owner ruling 2026-09-26, grm-4wqd) -- currently always {@code 0}
		 * (binary mode) for every program, regardless of platform.
		 * <p>
		 * On NES the 2A03 has no decimal mode at all (and the stock {@code 6502:LE:16:default}
		 * language never reads {@code D} in the first place, so this seam is never consulted
		 * there). On the C64 languages, where {@code D} is a real, settable flag, {@code 0} is
		 * the same assumption {@link Mos6502ConstantSemantics}'s {@code ADC}/{@code SBC}
		 * already make unconditionally: decimal mode in banking-relevant code is rare, and
		 * assuming binary is what let the TABLE evaluator resolve these at all before this
		 * class existed.
		 * <p>
		 * This is a single, per-program seam and nothing else: a future per-game or per-region
		 * override (a program that is KNOWN to run in decimal mode at a query site) plugs in
		 * here, by making this a real function of {@code program} instead of a constant --
		 * that override is not built yet. Deliberately not a per-query parameter and not a
		 * field: every {@link Interp} for the same program must assume the same thing, so a
		 * later per-program override composes without threading a new argument through
		 * {@link ConstantSemantics.Inputs}.
		 */
		private static int assumedDecimalFlag(Program program) {
			return 0;
		}

		private Register safeGetRegister(Varnode vn) {
			try {
				return program.getRegister(vn);
			}
			catch (RuntimeException e) {
				return null;
			}
		}

		private static Loc locFor(Register r) {
			return switch (r.getName().toUpperCase()) {
				case "A" -> Loc.A;
				case "X" -> Loc.X;
				case "Y" -> Loc.Y;
				case "C" -> Loc.C;
				case "D" -> Loc.D;
				default -> null;
			};
		}

		private static final Supplier<Integer> UNKNOWN = () -> null;

		private static long mask(int sizeBytes) {
			return sizeBytes >= 8 ? -1L : (1L << (8 * sizeBytes)) - 1;
		}

		private static Supplier<Integer> memoize(Supplier<Integer> s) {
			Object[] cache = new Object[1]; // cache[0]: null = not yet computed, else holder
			return () -> {
				if (cache[0] == null) {
					cache[0] = new Holder(s.get());
				}
				return ((Holder) cache[0]).value;
			};
		}

		/** Distinguishes "not yet computed" from "computed, and the answer was null" in
		 * {@link #memoize}, since the memoized value itself is allowed to be null. */
		private static final class Holder {
			final Integer value;

			Holder(Integer value) {
				this.value = value;
			}
		}
	}
}
