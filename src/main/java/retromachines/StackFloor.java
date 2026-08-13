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
import ghidra.program.model.listing.Program;

/**
 * How deep the 6502 stack is assumed to run, and therefore which cells of the stack page
 * ({@code $0100-$01FF}) a dataflow walk may treat as ordinary scratch memory.
 * <p>
 * <b>Why this exists.</b> Three walks in this extension attribute a value to a memory cell
 * across instructions that push onto the stack -- {@code PHA}, {@code PHP}, and a caller's
 * {@code JSR} return address. None of those names an address any of this extension's write
 * detectors ({@code StoredValueScanner.writesMemory}, {@code writesAddress}) can see, because
 * the address is {@code $0100 + S} and {@code S} is not tracked. Each walk therefore steps
 * over a push without noticing it, and if the cell being attributed happens to live in the
 * stack page, the push may have silently overwritten it.
 * <p>
 * Refusing the whole page is not the answer: real switching code parks scratch bytes low in
 * it. Dodgeball's {@code FUN_ff08} keeps its bank argument at {@code $0103} across an
 * unrelated {@code PHA}, and Castlevania 2's {@code FUN_c187} does the same at the same cell.
 * Refusing {@code $0103} costs those titles their whole overlay recovery to guard against a
 * push that would have to run the stack ~253 bytes deep to reach it.
 * <p>
 * <b>The ruling</b> (project owner, 2026-08-12) is to draw the line with a number instead of
 * measuring it: assume {@code S} never descends below {@link #DEFAULT_FLOOR}, so the stack
 * occupies at most {@code $0140-$01FF} and {@code $0100-$013F} is fair game for finding
 * shadows and stashed arguments. The alternative -- a min-{@code S} watchpoint in an emulator
 * over every pinned title -- was priced and declined; it is a real measurement but it answers
 * only for the titles measured, and a threshold that can be moved covers the corpus and every
 * future title at once. The residual risk is unchanged in kind from what {@code grm-mej.3}
 * increment 2 already accepted, but it is now bounded and named rather than implicit.
 * <p>
 * <b>The endpoints reproduce both historical behaviors exactly</b>, which is the cheapest way
 * to be sure the knob is the only thing that changed: a floor of {@code 0x100} refuses the
 * entire page (the blanket guard increment 2 removed), and a floor of {@code 0} accepts the
 * entire page (increment 2 as shipped). {@link #DEFAULT_FLOOR} sits between them.
 * <p>
 * <b>Overriding it.</b> Resolution order, first match wins:
 * <ol>
 * <li>the program-info property {@link #PROPERTY} -- per program, and the seam the per-game
 * descriptor tier ({@code grm-hb6}) is expected to write when a game {@code .yaml} grows a
 * field for it. Nothing sets it today; that is deliberate, since a title that needs it has
 * not been found yet and inventing the YAML key before the tier exists would fix the schema
 * around a guess. A loader or a script setting this string is enough to move the line now.</li>
 * <li>the JVM system property {@link #SYSTEM_PROPERTY} -- per run, for a headless
 * bisect ("does this warning come back if I refuse the whole page?") without a rebuild.</li>
 * <li>{@link #DEFAULT_FLOOR}.</li>
 * </ol>
 * Both accept decimal or hex ({@code 0x40}, {@code $40}, {@code 64}). An unparseable or
 * out-of-range value falls through to the next source rather than failing the analysis: this
 * is a tuning knob, and a typo in it must not cost a user their import.
 */
final class StackFloor {

	/** First address of the 6502 stack page. The whole family (6502/6510/8502) shares it. */
	static final int STACK_PAGE = 0x0100;

	/**
	 * The lowest value {@code S} is assumed ever to reach, so cells below
	 * {@code STACK_PAGE + DEFAULT_FLOOR} are assumed never to be written by a push.
	 * <p>
	 * {@code $40} is an estimate, not a measurement -- see the class javadoc. It leaves 192
	 * bytes of stack, which is far past the depth any 6502 game code plausibly reaches, while
	 * still clearing the low-page scratch cells that are actually used in the corpus (the
	 * deepest measured one is {@code $0103}).
	 */
	static final int DEFAULT_FLOOR = 0x40;

	/** Program-info property overriding {@link #DEFAULT_FLOOR} for one program. */
	static final String PROPERTY = "Retro Machines.Stack Floor";

	/** JVM system property overriding {@link #DEFAULT_FLOOR} for one run. */
	static final String SYSTEM_PROPERTY = "retromachines.stackFloor";

	private StackFloor() {
	}

	/**
	 * The assumed minimum value of {@code S} for {@code program}, in {@code [0, 0x100]}.
	 * Resolution order is the class javadoc's.
	 */
	static int floor(Program program) {
		Integer fromProgram = program == null ? null
				: parse(program.getOptions(Program.PROGRAM_INFO).getString(PROPERTY, null));
		if (fromProgram != null) {
			return fromProgram;
		}
		Integer fromRun = parse(System.getProperty(SYSTEM_PROPERTY));
		return fromRun != null ? fromRun : DEFAULT_FLOOR;
	}

	/**
	 * Whether a push could have written {@code cell} under {@code program}'s floor -- the
	 * question every consumer actually asks. True for anything in the stack page at or above
	 * the floor; false for a low-page scratch cell, and false for every address outside the
	 * page.
	 * <p>
	 * Deliberately keyed on the raw offset rather than on the address space: over-reporting
	 * costs a forfeited forward, which is this extension's failure mode everywhere else, and
	 * no board in the corpus overlays the stack page. A null {@code cell} reads as unsafe for
	 * the same reason -- an unplaceable cell is not a cell known to be clear of the stack.
	 */
	static boolean mayAliasStack(Program program, Address cell) {
		if (cell == null) {
			return true;
		}
		long offset = cell.getOffset();
		if (offset < STACK_PAGE || offset > STACK_PAGE + 0xFF) {
			return false;
		}
		return offset - STACK_PAGE >= floor(program);
	}

	/**
	 * {@code text} as a floor in {@code [0, 0x100]}, or null when it is absent, malformed, or
	 * out of range -- all of which mean "this source has no opinion", never "fail".
	 */
	private static Integer parse(String text) {
		if (text == null) {
			return null;
		}
		String trimmed = text.trim();
		int radix = 10;
		if (trimmed.startsWith("$")) {
			trimmed = trimmed.substring(1);
			radix = 16;
		}
		else if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
			trimmed = trimmed.substring(2);
			radix = 16;
		}
		try {
			int value = Integer.parseInt(trimmed, radix);
			return value >= 0 && value <= 0x100 ? value : null;
		}
		catch (NumberFormatException e) {
			return null;
		}
	}
}
