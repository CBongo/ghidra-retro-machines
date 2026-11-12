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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * Coverage for grm-ed6h: 6502 pop-return helpers. Hand-built minimal shapes after Metroid
 * {@code c376} ({@code LDA #$00 / STA $07a1,X / PLA / PLA / RTS}) and {@code c36b} (the same tail
 * behind a {@code BCC} to the shared RTS); no ROM bytes are copied.
 */
public class PopReturnHelperAnalyzerTest extends AbstractBundledLanguageTest {

	private static final String LANG = "6502:LE:16:default";

	private ProgramBuilder builder;

	private Address addr(long offset) {
		return builder.addr(String.format("0x%x", offset));
	}

	private ProgramDB freshProgram() throws Exception {
		builder = newBuilder("Test", LANG);
		uninitializedRam(builder, ".zp", "0x0", 0x800);
		builder.createMemory(".text", "0x8000", 0x8000);
		return builder.getProgram();
	}

	private Boolean recognize(String bytes) throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc000", bytes, true);
		return PopReturnHelper.recognize(program, addr(0xc000));
	}

	@Test
	public void recognizesMetroidC376Shape() throws Exception {
		// LDA #$00 / STA $07a1,X / PLA / PLA / RTS
		assertEquals(Boolean.TRUE, recognize("a9 00 9d a1 07 68 68 60"));
	}

	@Test
	public void recognizesTsxInxInxTxs() throws Exception {
		// TSX / INX / INX / TXS / RTS
		assertEquals(Boolean.TRUE, recognize("ba e8 e8 9a 60"));
	}

	@Test
	public void recognizesBothArmsPopping() throws Exception {
		// BEQ +3 / PLA / PLA / RTS / PLA / PLA / RTS
		assertEquals(Boolean.TRUE, recognize("f0 03 68 68 60 68 68 60"));
	}

	@Test
	public void recognizesAJmpToASharedPopTail() throws Exception {
		// $c000: JMP $c010 ; $c010: PLA / PLA / RTS
		ProgramDB program = freshProgram();
		builder.setBytes("0xc010", "68 68 60", true);
		builder.setBytes("0xc000", "4c 10 c0", true);
		assertEquals(Boolean.TRUE, PopReturnHelper.recognize(program, addr(0xc000)));
	}

	@Test
	public void declinesMetroidC36bConditionalReturn() throws Exception {
		// STA $07a1,X / INX / CPX #$4f / BCC rts / LDA #$00 / PLA / PLA / rts: RTS
		// the BCC lands on the RTS with nothing popped: that path returns normally
		assertEquals(Boolean.FALSE, recognize("9d a1 07 e8 e0 4f 90 04 a9 00 68 68 60"));
	}

	@Test
	public void declinesAnOrdinaryRts() throws Exception {
		assertEquals(Boolean.FALSE, recognize("a9 00 60"));
	}

	@Test
	public void declinesBalancedPushPull() throws Exception {
		// PHA / PHA / PLA / PLA / RTS
		assertEquals(Boolean.FALSE, recognize("48 48 68 68 60"));
	}

	@Test
	public void declinesTheJumpEngineIndirectJump() throws Exception {
		// PLA / STA $04 / PLA / STA $05 / JMP ($0006)
		assertEquals(Boolean.FALSE, recognize("68 85 04 68 85 05 6c 06 00"));
	}

	@Test
	public void declinesAnUntrackedTxs() throws Exception {
		// LDX #$ff / TXS / RTS (a stack reset, not a pop)
		assertEquals(Boolean.FALSE, recognize("a2 ff 9a 60"));
	}

	/** The dodge/smb3 regression: base-space bytes of a banked window are not trusted. */
	@Test
	public void declinesAHelperInTheBaseCopyOfABankedWindow() throws Exception {
		builder = newBuilder("Banked", LANG);
		builder.createMemory("PRG_LO", "0x8000", 0x4000);
		builder.createMemory("PRG_FIXED", "0xc000", 0x4000);
		builder.createOverlayMemory("PRG_LO_B1", "0x8000", 0x4000);
		ProgramDB program = builder.getProgram();
		builder.setBytes("0x8100", "68 68 60", true);
		assertEquals(Boolean.FALSE, PopReturnHelper.recognize(program, addr(0x8100)));
		// the fixed part of the same map is still trusted
		builder.setBytes("0xc100", "68 68 60", true);
		assertEquals(Boolean.TRUE, PopReturnHelper.recognize(program, addr(0xc100)));
	}

	@Test
	public void inconclusiveWhenAPathIsNotYetDisassembled() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc000", "4c 10 c0", true);
		builder.setBytes("0xc010", "68 68 60", false);
		inTx(program, "clear", () -> program.getListing()
				.clearCodeUnits(addr(0xc010), addr(0xc012), false));
		assertNull(PopReturnHelper.recognize(program, addr(0xc000)));
	}

	/** The bead's acceptance shape: e5dd JSR $c376, then data that decodes as JSR $A29E. */
	@Test
	public void analyzerStopsFallThroughAndClearsTheFalseDecode() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc376", "a9 00 9d a1 07 68 68 60", true);
		builder.setBytes("0xe5dd", "20 76 c3 20 9e a2 60", true);
		builder.setBytes("0xa29e", "60", true);
		assertNotNull("precondition: the false decode exists", instrAt(program, 0xe5e0));

		PopReturnHelperAnalyzer analyzer = new PopReturnHelperAnalyzer();
		assertTrue(analyzer.canAnalyze(program));
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0xe5dd), addr(0xe5e3)), TaskMonitor.DUMMY, new MessageLog()));

		assertNull("no instruction at e5e0", instrAt(program, 0xe5e0));
		for (Reference ref : program.getReferenceManager().getReferencesTo(addr(0xa29e))) {
			assertFalse("no A29E ref from e5e0", ref.getFromAddress().equals(addr(0xe5e0)));
		}
		Function helper = program.getFunctionManager().getFunctionAt(addr(0xc376));
		assertNotNull(helper);
		assertTrue(helper.hasNoReturn());
		assertNull(instrAt(program, 0xe5dd).getFallThrough());
	}

	/** Code after the JSR that something else branches into is real and must stay. */
	@Test
	public void analyzerKeepsAFallThroughThatIsABranchTarget() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc376", "68 68 60", true);
		// e000: BEQ $e005 / JSR $c376 / e005: RTS
		builder.setBytes("0xe000", "f0 03 20 76 c3 60", true);

		PopReturnHelperAnalyzer analyzer = new PopReturnHelperAnalyzer();
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0xe000), addr(0xe005)), TaskMonitor.DUMMY, new MessageLog()));

		assertNull(instrAt(program, 0xe002).getFallThrough());
		assertNotNull("branch target kept", instrAt(program, 0xe005));
	}

	/** A conditional pop-return helper is left alone: its JSR keeps its fall-through. */
	@Test
	public void analyzerLeavesConditionalHelpersAlone() throws Exception {
		ProgramDB program = freshProgram();
		builder.setBytes("0xc36b", "9d a1 07 e8 e0 4f 90 04 a9 00 68 68 60", true);
		builder.setBytes("0xe000", "20 6b c3 60", true);

		PopReturnHelperAnalyzer analyzer = new PopReturnHelperAnalyzer();
		inTx(program, "analyze", () -> analyzer.added(program,
			new AddressSet(addr(0xe000), addr(0xe003)), TaskMonitor.DUMMY, new MessageLog()));

		assertNotNull(instrAt(program, 0xe000).getFallThrough());
		assertNotNull(instrAt(program, 0xe003));
	}

	private ghidra.program.model.listing.Instruction instrAt(ProgramDB program, long a) {
		return program.getListing().getInstructionAt(addr(a));
	}
}
