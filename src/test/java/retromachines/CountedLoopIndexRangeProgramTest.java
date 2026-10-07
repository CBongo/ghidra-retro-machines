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
import static org.junit.Assert.assertNull;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;

/**
 * {@code ProgramBuilder} coverage of bead grm-mej.15, {@link LoopIdioms#countedLoopIndexRange}:
 * the index range an indexed store inside a counted loop provably sees. Each test names the
 * loop it builds; the seed evaluator is the scanner's own state-free constant walk, as in
 * production.
 */
public class CountedLoopIndexRangeProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	private void put(String address, String hex) throws Exception {
		builder.setBytes(address, hex, true);
	}

	private LoopIdioms.IndexRange rangeAt(String address) {
		Instruction access = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, access);
		char reg = Character.toUpperCase(LoopIdioms.indexReg(access).getName().charAt(0));
		return LoopIdioms.countedLoopIndexRange(program, access,
			p -> StoredValueScanner.constantRegisterValue(program, p, reg,
				new StoredValueScanner.Hooks() {
					@Override
					public boolean isMechanismWrite(Instruction instr) {
						return false;
					}

					@Override
					public BankState resolveLoad(Instruction loadInstr,
							ghidra.program.model.address.Address resolvedTarget,
							BankState inStateAtStore) {
						return null;
					}
				}, RegisterEnv.NONE, new StoredValueScanner.Budget(1000)));
	}

	private static void assertRange(int lo, int hi, LoopIdioms.IndexRange r) {
		assertNotNull("expected a range", r);
		assertEquals("lo", lo, r.lo());
		assertEquals("hi", hi, r.hi());
	}

	// ==================================================================
	// 1. The modeled shapes
	// ==================================================================

	/** blmaster e6fe/ce02: {@code LDX #$1F / LDA #0 / L: STA $58,X / DEX / BPL L} -- the seed
	 *  comes through a non-writing predecessor ({@code LDA #0}), so the walk proves it. */
	@Test
	public void dexBplCountsDownToZero() throws Exception {
		put("0xc000", "a2 1f"); // LDX #$1F
		put("0xc002", "a9 00"); // LDA #0
		put("0xc004", "95 58"); // L: STA $58,X
		put("0xc006", "ca"); // DEX
		put("0xc007", "10 fb"); // BPL L
		put("0xc009", "60"); // RTS
		assertRange(0, 0x1f, rangeAt("0xc004"));
	}

	/** {@code DEX / BNE} stops before 0. */
	@Test
	public void dexBneStopsAtOne() throws Exception {
		put("0xc000", "a2 05"); // LDX #5
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "ca"); // DEX
		put("0xc005", "d0 fb"); // BNE L
		put("0xc007", "60");
		assertRange(1, 5, rangeAt("0xc002"));
	}

	/** {@code DEX / BNE} entered at 0 runs all 256 values. */
	@Test
	public void dexBneFromZeroIsEverything() throws Exception {
		put("0xc000", "a2 00"); // LDX #0
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "ca"); // DEX
		put("0xc005", "d0 fb"); // BNE L
		put("0xc007", "60");
		assertRange(0, 0xff, rangeAt("0xc002"));
	}

	/** {@code INX / CPX #4 / BNE}: 0..3. */
	@Test
	public void inxCpxBneCountsUpToTheBound() throws Exception {
		put("0xc000", "a2 00"); // LDX #0
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "e8"); // INX
		put("0xc005", "e0 04"); // CPX #4
		put("0xc007", "d0 f9"); // BNE L
		put("0xc009", "60");
		assertRange(0, 3, rangeAt("0xc002"));
	}

	/** {@code DEX / CPX #3 / BNE} from 9: 9 down to 4. */
	@Test
	public void dexCpxBneCountsDownToTheBound() throws Exception {
		put("0xc000", "a2 09"); // LDX #9
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "ca"); // DEX
		put("0xc005", "e0 03"); // CPX #3
		put("0xc007", "d0 f9"); // BNE L
		put("0xc009", "60");
		assertRange(4, 9, rangeAt("0xc002"));
	}

	/** Absolute,Y with {@code INY / BNE}: $F0..$FF. */
	@Test
	public void inyBneRunsToTheTop() throws Exception {
		put("0xc000", "a0 f0"); // LDY #$F0
		put("0xc002", "99 00 03"); // L: STA $0300,Y
		put("0xc005", "c8"); // INY
		put("0xc006", "d0 fa"); // BNE L
		put("0xc008", "60");
		assertRange(0xf0, 0xff, rangeAt("0xc002"));
	}

	/** {@code INX / BPL} from $70: $70..$7F. */
	@Test
	public void inxBplStopsAtTheSignBit() throws Exception {
		put("0xc000", "a2 70"); // LDX #$70
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "e8"); // INX
		put("0xc005", "10 fb"); // BPL L
		put("0xc007", "60");
		assertRange(0x70, 0x7f, rangeAt("0xc002"));
	}

	/** A forward exit out of the body only cuts the sequence short: still bounded. */
	@Test
	public void forwardExitIsAllowed() throws Exception {
		put("0xc000", "a2 07"); // LDX #7
		put("0xc002", "b5 40"); // L: LDA $40,X
		put("0xc004", "f0 05"); // BEQ $C00B (exit)
		put("0xc006", "95 58"); // STA $58,X
		put("0xc008", "ca"); // DEX
		put("0xc009", "10 f7"); // BPL L
		put("0xc00b", "60");
		assertRange(0, 7, rangeAt("0xc006"));
	}

	// ==================================================================
	// 2. Declines
	// ==================================================================

	/** A second write of X in the body ({@code TAX}). */
	@Test
	public void secondIndexWriterDeclines() throws Exception {
		put("0xc000", "a2 05"); // LDX #5
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "aa"); // TAX
		put("0xc005", "ca"); // DEX
		put("0xc006", "10 fa"); // BPL L
		put("0xc008", "60");
		assertNull(rangeAt("0xc002"));
	}

	/** A call in the body may change X. */
	@Test
	public void callInBodyDeclines() throws Exception {
		put("0xc000", "a2 05"); // LDX #5
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "20 40 c0"); // JSR $C040
		put("0xc007", "ca"); // DEX
		put("0xc008", "10 f8"); // BPL L
		put("0xc00a", "60");
		put("0xc040", "60");
		assertNull(rangeAt("0xc002"));
	}

	/** Another branch into the middle of the body is a second way in, with any X. */
	@Test
	public void sideEntryDeclines() throws Exception {
		put("0xbff0", "4c 04 c0"); // JMP $C004 -- into the body, past the store
		put("0xc000", "a2 05"); // LDX #5
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "ca"); // DEX
		put("0xc005", "10 fb"); // BPL L
		put("0xc007", "60");
		assertNull(rangeAt("0xc002"));
	}

	/** The loop head reached by a branch other than the back edge. */
	@Test
	public void secondEntryToHeadDeclines() throws Exception {
		put("0xbff0", "4c 02 c0"); // JMP $C002 -- straight to L with an unknown X
		put("0xc000", "a2 05"); // LDX #5
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "ca"); // DEX
		put("0xc005", "10 fb"); // BPL L
		put("0xc007", "60");
		assertNull(rangeAt("0xc002"));
	}

	/** An unprovable seed. */
	@Test
	public void unknownSeedDeclines() throws Exception {
		put("0xc000", "a6 20"); // LDX $20
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "ca"); // DEX
		put("0xc005", "10 fb"); // BPL L
		put("0xc007", "60");
		assertNull(rangeAt("0xc002"));
	}

	/** A back edge that is not one of the modeled branches. */
	@Test
	public void beqBackEdgeDeclines() throws Exception {
		put("0xc000", "a2 05"); // LDX #5
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "ca"); // DEX
		put("0xc005", "f0 fb"); // BEQ L
		put("0xc007", "60");
		assertNull(rangeAt("0xc002"));
	}

	/** {@code DEX / CPX #5 / BNE} from 2 wraps through $FF: two ranges, declined. */
	@Test
	public void wrappingSequenceDeclines() throws Exception {
		put("0xc000", "a2 02"); // LDX #2
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "ca"); // DEX
		put("0xc005", "e0 05"); // CPX #5
		put("0xc007", "d0 f9"); // BNE L
		put("0xc009", "60");
		assertNull(rangeAt("0xc002"));
	}

	/** The flags BPL tests are not the step's ({@code LDA} after {@code DEX}). */
	@Test
	public void flagsNotFromTheStepDecline() throws Exception {
		put("0xc000", "a2 05"); // LDX #5
		put("0xc002", "95 58"); // L: STA $58,X
		put("0xc004", "ca"); // DEX
		put("0xc005", "a5 30"); // LDA $30
		put("0xc007", "10 f9"); // BPL L
		put("0xc009", "60");
		assertNull(rangeAt("0xc002"));
	}
}
