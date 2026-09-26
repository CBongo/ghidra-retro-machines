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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

/**
 * The per-instruction half of {@link StoredValueScanner#constantRegisterValue}'s all-or-nothing
 * constant evaluator (bead grm-as0m): which {@link Loc locations} an instruction writes, and
 * the exact value it leaves in one, given exact values for its inputs.
 * <p>
 * <b>The split is the point.</b> The backward walk -- and with it every guard the evaluator
 * carries (the {@link RegisterEnv} entry stop, the join guard and its licensed exception,
 * fall-through linkage, the step budget, the decline at a call) -- lives once, in the scanner,
 * and asks only "does this instruction write the location I want?" and "what does it leave
 * there?". An implementation never walks: it asks {@link Inputs} for what it reads, and the
 * scanner answers each of those with another walk under the same guards. "Fold when every
 * input is constant" is therefore structural rather than repeated per mnemonic, and a
 * different source of semantics (a p-code interpreter, another CPU family) replaces this
 * interface and nothing else.
 * <p>
 * Contract, all of it load-bearing:
 * <ul>
 * <li>{@link #writes} must be CONSERVATIVE: {@code true} for any instruction that may change
 * the location, including ones {@link #after} cannot evaluate. A false {@code false} lets the
 * walk step over a write and answer with a value from before it -- a confident wrong bank.</li>
 * <li>{@link #after} answers only with an EXACT value, or {@code null}. There is no partial
 * answer: a location with any unknown bit is a decline.</li>
 * </ul>
 */
interface ConstantSemantics {

	/**
	 * A location the evaluator can hold an exact value for: the three registers, carry, and
	 * (bead grm-4wqd) decimal mode -- added because the bundled {@code 6502core.sinc}
	 * {@code adcNmos}/{@code sbcNmos} branch on {@code D}, so a p-code interpreter needs a Loc
	 * for it to answer that branch at all (never to default it -- see {@link PcodeConstantSemantics}).
	 */
	enum Loc {
		A, X, Y, C, D;

		/**
		 * Whether this location is a numbered CPU register that {@link #register()} and
		 * {@link RegisterEnv#get(char)} can name. {@code false} for the flags {@code C} and
		 * {@code D}: a {@link RegisterEnv} carries no flags, and {@link #register()} must never
		 * be called for one.
		 */
		boolean isRegister() {
			return this == A || this == X || this == Y;
		}

		/** The register letter {@link RegisterEnv#get(char)} takes. Only valid when {@link #isRegister()}. */
		char register() {
			if (!isRegister()) {
				throw new IllegalStateException("not a register: " + this);
			}
			return name().charAt(0);
		}

		/** The location for a register letter the scanner's public entry point takes. */
		static Loc ofRegister(char reg) {
			return switch (reg) {
				case 'A' -> A;
				case 'X' -> X;
				case 'Y' -> Y;
				default -> throw new IllegalArgumentException("not a register: " + reg);
			};
		}
	}

	/** What an instruction reads, answered by the scanner under the walk's own guards. */
	interface Inputs {

		/** The exact value of {@code loc} immediately before the instruction, or null. */
		Integer before(Loc loc);

		/**
		 * The exact byte the instruction's memory operand reads, or null -- resolved the way
		 * the scanner resolves a load (effective target, then the strategy's
		 * {@code resolveLoad}, then a stack-relative reload), never from a caller's in-state.
		 */
		Integer memoryOperand();

		/**
		 * The single address the scanner resolves as this instruction's addressing-mode target
		 * (plain absolute/zero-page, or absolute-indexed with a constant-resolvable index), or
		 * {@code null} when that is not statically certain -- the same resolution
		 * {@link #memoryOperand} uses to find the address it reads. Exposed (bead grm-4wqd) so a
		 * p-code interpreter can check a {@code LOAD}'s own computed address against it before
		 * trusting {@link #memoryOperand} for that {@code LOAD}'s byte.
		 */
		Address effectiveTarget();
	}

	/**
	 * Whether {@code instr}'s p-code writes any part of the register named {@code name} (or a
	 * register containing it). Shared by {@link Mos6502ConstantSemantics} (as one half of its
	 * writes-union) and {@link PcodeConstantSemantics} (as its entire {@link #writes} answer).
	 * The 6502 languages define each flag as its own byte register, so {@code C}/{@code D} are
	 * not slices of a status register here, but containment either way is the safe test.
	 */
	static boolean pcodeWrites(Instruction instr, String name) {
		Register target = instr.getProgram().getRegister(name);
		if (target == null) {
			return false;
		}
		for (Object result : instr.getResultObjects()) {
			if (result instanceof Register r && (r.contains(target) || target.contains(r))) {
				return true;
			}
		}
		return false;
	}

	/** Whether {@code instr} may change {@code loc}. Conservative -- see the class javadoc. */
	boolean writes(Instruction instr, Loc loc);

	/**
	 * The exact value {@code instr} leaves in {@code loc}, or null to decline. Asked only when
	 * {@link #writes} said yes.
	 */
	Integer after(Instruction instr, Loc loc, Inputs in);
}
