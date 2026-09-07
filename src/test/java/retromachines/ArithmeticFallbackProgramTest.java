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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pins the ARITHMETIC FALLBACK bridge between {@link StoredValueScanner}'s two evaluators
 * (bead grm-4bgh.6): when the per-bit mask algebra of {@code resolveStoredValue} meets an
 * instruction it cannot decompose per bit -- a shift, an {@code ADC}, a transfer -- it now asks
 * the all-or-nothing {@code constantRegisterValue} for the same register at the same point
 * before declining, and adopts a non-null answer as a fully known base.
 * <p>
 * <b>Why this file exists at all.</b> grm-4bgh.1 (the stack-relative reload) and grm-4bgh.2
 * ({@code CLC}/{@code ADC #imm}) both landed in {@code constantRegisterValue}, which
 * <em>only</em> effective-address resolution called. A STORED VALUE -- which is what a
 * bank-switch deposit needs -- went through the mask algebra instead, and died on the very
 * {@code ASL} those increments were built to model. River City Ransom's {@code FUN_fed1}
 * ({@code TSX / LDA $0102,X / ASL A / STA $8001}, computing {@code r6 = A*2}) is the measured
 * case, reproduced in {@link #fed1ShapeStackReloadThenAslResolvesToTwiceTheArgument}.
 * <p>
 * <b>What must NOT change, and is pinned here too.</b> The fallback is strictly additive: it is
 * consulted only on the path already returning wholly unknown, so anything the exact evaluator
 * also declines stays exactly as unresolved as it was
 * ({@link #rolStillDeclinesBecauseCarryIsNotModeled},
 * {@link #anUndefinedSourceRegisterStillWallsTheScan} -- the latter being the property
 * {@code MultiDepositHelperProgramTest}'s {@code TXA} wall rests on). And the mask algebra keeps
 * composing OVER a fallback answer rather than being short-circuited by it
 * ({@link #maskAlgebraStillComposesOverAFallbackResolvedBase}).
 * <p>
 * Fixture note inherited from {@link StackRelativeReloadProgramTest}: {@link ProgramBuilder}
 * blocks are created read-only, so every RAM block must be made writable explicitly.
 */
public class ArithmeticFallbackProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		MemoryBlock ram = builder.createMemory(".ram", "0x100", 0x700);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		makeWritable(zp);
		makeWritable(ram);
	}

	private void makeWritable(MemoryBlock block) {
		int tx = program.startTransaction("set block write permission");
		try {
			block.setWrite(true);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	/**
	 * A latch over the whole ROM area with a 4-bit field -- one bit wider than
	 * {@link StackRelativeReloadProgramTest}'s AxROM shape, so that DOUBLING a small argument
	 * stays inside the tracked field instead of being truncated by the mask (a 3-bit field would
	 * report {@code 5 * 2 == 2} and make every assertion below unreadable).
	 */
	private MemoryLatchBankSwitchStrategy latch() {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.addProperty("mask", 0x0F);
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, 0x0F);
		return strategy;
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	private void assertBank(int expected, BankState actual) {
		assertEquals("tracked bits not fully known: " + actual, 0x0F, actual.knownMask());
		assertEquals(expected, actual.bits());
	}

	private void assertUnresolved(BankState actual) {
		assertEquals("expected no tracked bit to be pinned down, got " + actual, 0,
			actual.knownMask());
	}

	private BankState switchAt(String address) {
		return latch().computeSwitch(program, instructionAt(address), BankState.unknown());
	}

	// ------------------------------------------------------------------
	// 1. The plain shift: the mask algebra's oldest wall
	// ------------------------------------------------------------------

	/**
	 * {@code LDA #$03 / ASL A / STA $8000}. Before grm-4bgh.6 the walk met {@code ASL} -- a
	 * member of {@code A_MODIFIERS} with no mask-algebra rule -- and returned wholly unknown one
	 * instruction short of the immediate that determines the answer.
	 * {@code constantRegisterValue} has modeled {@code ASL A} since grm-hum; it was simply never
	 * asked from here.
	 */
	@Test
	public void aslAfterAnImmediateResolvesToTwiceTheImmediate() throws Exception {
		builder.setBytes("0x8000", "a9 03", true); // LDA #$03
		builder.setBytes("0x8002", "0a", true); // ASL A
		builder.setBytes("0x8003", "8d 00 80", true); // STA $8000

		assertBank(6, switchAt("0x8003"));
	}

	// ------------------------------------------------------------------
	// 2. The motivating shape: grm-4bgh.1's stack reload, reached through the shift
	// ------------------------------------------------------------------

	/**
	 * River City Ransom's {@code FUN_fed1} body, minus the mechanism writes:
	 * {@code LDA #$05 / PHA / TXA / PHA / TSX / LDA $0102,X / ASL A / STA $8000} -- the argument
	 * is pushed, read back WITHOUT popping via a stack-relative reload, doubled, and stored.
	 * Expect {@code 5 * 2 == 10}.
	 * <p>
	 * This is the test that would have failed with grm-4bgh.1 through .5 all landed:
	 * {@link StackRelativeReloadProgramTest#funFed1ShapeResolvesTheFirstPushNotTheSecond} pins
	 * the same reload WITHOUT the {@code ASL}, and passed throughout -- the reload works, and the
	 * shift in front of it is what the stored-value path could not get past.
	 */
	@Test
	public void fed1ShapeStackReloadThenAslResolvesToTwiceTheArgument() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05    -- the bank argument
		builder.setBytes("0x8002", "48", true); // PHA         -- push 1: the argument
		builder.setBytes("0x8003", "8a", true); // TXA
		builder.setBytes("0x8004", "48", true); // PHA         -- push 2: X
		builder.setBytes("0x8005", "ba", true); // TSX
		builder.setBytes("0x8006", "bd 02 01", true); // LDA $0102,X -- reloads push 1
		builder.setBytes("0x8009", "0a", true); // ASL A       -- r6 = A*2
		builder.setBytes("0x800a", "8d 00 80", true); // STA $8000

		assertBank(10, switchAt("0x800a"));
	}

	// ------------------------------------------------------------------
	// 3. grm-4bgh.2's ADC, likewise reached for the first time
	// ------------------------------------------------------------------

	/**
	 * {@code LDA #$03 / ASL A / CLC / ADC #$01 / STA $8000} -- {@code FUN_fed1}'s
	 * {@code r7 = A*2+1} arithmetic verbatim, expecting {@code 3 * 2 + 1 == 7}. Both the
	 * {@code ADC} and the {@code ASL} behind it are opaque to the mask algebra, so this resolves
	 * only if the fallback answers the whole chain at once rather than a single instruction.
	 */
	@Test
	public void clcAdcOverAShiftResolvesTheWholeChain() throws Exception {
		builder.setBytes("0x8000", "a9 03", true); // LDA #$03
		builder.setBytes("0x8002", "0a", true); // ASL A
		builder.setBytes("0x8003", "18", true); // CLC
		builder.setBytes("0x8004", "69 01", true); // ADC #$01
		builder.setBytes("0x8006", "8d 00 80", true); // STA $8000

		assertBank(7, switchAt("0x8006"));
	}

	// ------------------------------------------------------------------
	// 4. The mask algebra is bridged, not bypassed
	// ------------------------------------------------------------------

	/**
	 * {@code LDA #$06 / ASL A / AND #$0E / ORA #$01 / STA $8000}. The {@code AND}/{@code ORA} are
	 * consumed by the mask algebra on the way back, and only then does the walk meet the
	 * {@code ASL} and fall back. The answer must be the accumulators applied to the fallback's
	 * base -- {@code ((6 * 2) & $0E) | $01 == $0D} -- which is what proves the fallback returns a
	 * BASE into {@code combine()} rather than short-circuiting the composition that preceded it.
	 */
	@Test
	public void maskAlgebraStillComposesOverAFallbackResolvedBase() throws Exception {
		builder.setBytes("0x8000", "a9 06", true); // LDA #$06
		builder.setBytes("0x8002", "0a", true); // ASL A      -- 12 = $0C
		builder.setBytes("0x8003", "29 0e", true); // AND #$0E -- $0C
		builder.setBytes("0x8005", "09 01", true); // ORA #$01 -- $0D
		builder.setBytes("0x8007", "8d 00 80", true); // STA $8000

		assertBank(0x0D, switchAt("0x8007"));
	}

	// ------------------------------------------------------------------
	// 5. Strictly additive: what the exact evaluator declines stays unresolved
	// ------------------------------------------------------------------

	/**
	 * {@code LDA #$03 / ROL A / STA $8000}. {@code constantRegisterValue} declines {@code ROL}
	 * and {@code ROR} deliberately -- carry is modeled only as the constant a
	 * {@code CLC}/{@code SEC} leaves, and the bit rotated in here comes from whatever set the
	 * flag last. The fallback must therefore leave this exactly as unresolved as it was, not
	 * guess a low bit.
	 */
	@Test
	public void rolStillDeclinesBecauseCarryIsNotModeled() throws Exception {
		builder.setBytes("0x8000", "a9 03", true); // LDA #$03
		builder.setBytes("0x8002", "2a", true); // ROL A
		builder.setBytes("0x8003", "8d 00 80", true); // STA $8000

		assertUnresolved(switchAt("0x8003"));
	}

	/**
	 * The SAME shape as {@link #fed1ShapeStackReloadThenAslResolvesToTwiceTheArgument} with one
	 * instruction added -- a {@code STA $8000} between the pushes and the {@code TSX} -- and it
	 * must go back to UNRESOLVED. This is not a limitation of the fallback; it is the mid-scan
	 * mechanism-write abort, applied by {@code findMatchingPush} (which the stack reload hands
	 * off to) exactly as it is by every other backward walk here.
	 * <p>
	 * <b>This is the real fed1 layout, and the reason grm-4bgh.6 did not move rcransom.</b> The
	 * bead's description reconstructed {@code FUN_fed1} as {@code TSX / LDA $0102,X / ASL A /
	 * STA $FC / STA $8001} and concluded the {@code ASL} was the only thing in the way. The
	 * cartridge's actual bytes put an MMC3 SELECT write in the middle of that chain:
	 * <pre>
	 *   FED1  PHA          ; the caller's bank argument
	 *   FED2  TXA
	 *   FED3  PHA
	 *   FED4  LDA #$06
	 *   FED6  STA $FB
	 *   FED8  STA $8000    ; select R6 -- A RECOGNIZED SITE, and the abort fires here
	 *   FEDB  TSX
	 *   FEDC  LDA $0102,X  ; the reload, which must reach back past FED8 to find FED1
	 *   FEDF  ASL A        ; r6 = A*2
	 *   FEE0  STA $FC
	 *   FEE2  STA $8001    ; the deposit
	 * </pre>
	 * So {@code r6} was blocked by TWO independent walls stacked in series, and grm-4bgh.6
	 * removed only the outer one.
	 * <p>
	 * <b>UPDATED BY grm-4bgh.7, WHICH REMOVED THE INNER WALL TOO.</b> This test asserted
	 * {@code assertUnresolved} when it was written, one increment ago; it now asserts the value.
	 * Crossing a mechanism write no longer ends a walk -- it WITHDRAWS the in-state, because that
	 * is the whole of what the crossing invalidates, and a byte sitting on the stack is not the
	 * in-state. The pushed {@code $05} is therefore still reachable, and {@code 5 * 2 == 10}
	 * exactly as in the sibling fixture without the {@code STA}.
	 * <p>
	 * The fixture is deliberately left in place rather than deleted: it is the ONE-INSTRUCTION
	 * DIFFERENCE that distinguishes the two increments, and a regression that reinstated either
	 * abort would show up here first.
	 */
	@Test
	public void aStackReloadNowSurvivesAnInterveningMechanismWrite() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05    -- the bank argument
		builder.setBytes("0x8002", "48", true); // PHA         -- push 1: the argument
		builder.setBytes("0x8003", "8a", true); // TXA
		builder.setBytes("0x8004", "48", true); // PHA         -- push 2: X
		builder.setBytes("0x8005", "8d 00 90", true); // STA $9000 -- a mechanism write (fed1's FED8)
		builder.setBytes("0x8008", "ba", true); // TSX
		builder.setBytes("0x8009", "bd 02 01", true); // LDA $0102,X
		builder.setBytes("0x800c", "0a", true); // ASL A
		builder.setBytes("0x800d", "8d 00 80", true); // STA $8000

		assertBank(10, switchAt("0x800d"));
	}

	/**
	 * {@code TXA / STA $8000} with X never defined anywhere reachable. The fallback follows the
	 * transfer into X and finds nothing, so the answer stays unresolved.
	 * <p>
	 * Pinned deliberately rather than incidentally: {@code MultiDepositHelperProgramTest}'s
	 * {@code FUN_fed1} fixture uses exactly this {@code TXA} as a value-resolution WALL, and its
	 * whole point (that a data write's value can go honestly unresolved while its field is still
	 * owned) collapses if a future change teaches the exact evaluator to answer for an undefined
	 * register.
	 */
	@Test
	public void anUndefinedSourceRegisterStillWallsTheScan() throws Exception {
		builder.setBytes("0x8000", "ea", true); // NOP
		builder.setBytes("0x8001", "8a", true); // TXA -- X is never assigned
		builder.setBytes("0x8002", "8d 00 80", true); // STA $8000

		assertUnresolved(switchAt("0x8002"));
	}
}
