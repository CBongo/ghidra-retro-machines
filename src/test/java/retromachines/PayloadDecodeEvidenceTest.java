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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;

/**
 * Pins {@link PayloadDecodeEvidence#decodesAsSubroutine}, the weakest leg of
 * {@link CopyLoopAnalyzer}'s evidence gate (grm-k5m): what counts as "these bytes are a
 * subroutine" and, more importantly, what does not. The positive rows are the three Wizards
 * &amp; Warriors bank-switch stubs byte for byte (ROM offsets {@code ce38/ce4b/ce5b} of bank 0,
 * hand-decoded in the bead); the negative rows are the shapes the grm-1.7.6 data-copy rule was
 * written for, plus the two of wizwarr's own data copies whose bytes fall closest to code.
 */
public class PayloadDecodeEvidenceTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	private boolean decodes(String hex) throws Exception {
		builder.setBytes("0xc000", hex, false);
		int len = hex.trim().split("\\s+").length;
		return PayloadDecodeEvidence.decodesAsSubroutine(program, builder.addr("0xc000"), len);
	}

	// ---- wizwarr's three copied stubs: every one must be admitted -------------------------

	@Test
	public void farReadStubWithSaveRestoreDecodes() throws Exception {
		// ce38 -> $033d: LDA $00 / PHA / AND #$F8 / ORA #$02 / STA $8000 / LDA ($9D),Y / TAY /
		// PLA / STA $8000 / TYA / RTS
		assertTrue(decodes("a5 00 48 29 f8 09 02 8d 00 80 b1 9d a8 68 8d 00 80 98 60"));
	}

	@Test
	public void ppuUploadStubWithBackwardBranchDecodes() throws Exception {
		// ce4b -> $032d: STA $8000 / LDA ($64),Y / STA $2007 / INY / DEX / BNE -9 / STX $8000 / RTS
		assertTrue(decodes("8d 00 80 b1 64 8d 07 20 c8 ca d0 f7 8e 00 80 60"));
	}

	@Test
	public void switchAndExitOnBank3StubDecodes() throws Exception {
		// ce5b -> $0300: two nested loops, then LDA #3 / STA $00 / STA $8000 / RTS
		assertTrue(decodes("85 00 8d 00 80 a0 00 b1 64 8d 07 20 c8 c0 10 d0 f6 a5 64 18 69 10 " +
			"85 64 a5 65 69 00 85 65 ca d0 e4 a9 03 85 00 8d 00 80 60"));
	}

	// ---- the data shapes that must stay out -----------------------------------------------

	@Test
	public void zeroRunIsNotCode() throws Exception {
		// A cleared buffer. BRK is a computed flow; Ghidra's own isValidSubroutine would count
		// it as "terminates".
		assertFalse(decodes("00 00 00 00 00 00 00 00"));
	}

	@Test
	public void leadingByteThenBrkIsNotCode() throws Exception {
		// wizwarr ce1b -> $0369, the closest of its data copies: TAY then BRK.
		assertFalse(decodes("a8 00 00 00 a4 fc fc 00 a5 fc 04 00 a6 04 fc 00 a7 04 04 00 00"));
	}

	@Test
	public void undefinedOpcodeIsNotCode() throws Exception {
		// wizwarr ce30 -> $0361: CPX #0 / ASL $F0 / $12 -- undefined on the stock 6502.
		assertFalse(decodes("e0 00 06 f0 12 f0 15 00"));
	}

	@Test
	public void codeThatRunsOffTheEndIsNotCode() throws Exception {
		// Valid instructions to the last byte, but no return inside the payload: a table of
		// small opcodes-by-coincidence, or a stub whose tail was not copied.
		assertFalse(decodes("a9 01 8d 00 80 a2 10"));
	}

	@Test
	public void branchOutOfThePayloadIsNotAnExit() throws Exception {
		// LDA #1 / BNE +$40 (leaves the range) / nothing after: no return reached.
		assertFalse(decodes("a9 01 d0 40"));
	}

	@Test
	public void computedJumpIsNotCode() throws Exception {
		// LDA #1 / JMP ($0200): a dispatcher shape, but in a copied stub that is data.
		assertFalse(decodes("a9 01 6c 00 02"));
	}

	@Test
	public void singleReturnIsTooShort() throws Exception {
		assertFalse(decodes("60"));
	}

	// ---- exits other than RTS -------------------------------------------------------------

	@Test
	public void tailJumpOutOfThePayloadIsAnExit() throws Exception {
		// LDA #1 / STA $8000 / JMP $c100 -- switch and jump into the new bank.
		assertTrue(decodes("a9 01 8d 00 80 4c 00 c1"));
	}

	@Test
	public void callIsNotFollowedButItsFallThroughIs() throws Exception {
		// JSR $c100 (a sibling stub, uninitialized RAM in real life) / RTS
		assertTrue(decodes("20 00 c1 60"));
	}

	@Test
	public void uninitializedSourceIsNotEvidence() throws Exception {
		// $0300 lies in no block at all: the materializer's gate 0 would refuse such a source
		// anyway, and this must not claim evidence it cannot read.
		assertFalse(PayloadDecodeEvidence.decodesAsSubroutine(program, builder.addr("0x0300"), 8));
	}
}
