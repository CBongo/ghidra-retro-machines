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

	/** A location the evaluator can hold an exact value for: the three registers and carry. */
	enum Loc {
		A, X, Y, C;

		/** The register letter {@link RegisterEnv#get(char)} takes; {@code C} has none. */
		char register() {
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
	}

	/** Whether {@code instr} may change {@code loc}. Conservative -- see the class javadoc. */
	boolean writes(Instruction instr, Loc loc);

	/**
	 * The exact value {@code instr} leaves in {@code loc}, or null to decline. Asked only when
	 * {@link #writes} said yes.
	 */
	Integer after(Instruction instr, Loc loc, Inputs in);
}
