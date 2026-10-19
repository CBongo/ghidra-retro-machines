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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.symbol.SourceType;

/**
 * Exact comment provenance for {@link GameDescriptorExporter} (bead grm-hb6.18):
 * {@link AnalyzerCommentRecord} and the exporter's record-based filtering, with the legacy
 * prefix heuristic as the fallback for programs that predate it.
 */
public class GameDescriptorCommentProvenanceTest extends AbstractBundledLanguageTest {

	private static final String PRG =
		"f4130ba655229d9999fa3b2c59984165810c9b9b125c43b1ff899872e7fedff4";
	private static final String FILE =
		"4377a7f5e6eb50bdd2ac6f249bf1a7085500aca8eb41f38545c3a2731c51a579";

	private static final String MIRROR = "bank mirror: ROM_IDENTIFYING established at 8000";
	private static final String BOUND = "[JumpTableBound] table at 9000 bounded 9 -> 4 entries (x)";

	private ProgramBuilder newBuilder() throws Exception {
		ProgramBuilder b = newBuilder("Test", "6502:LE:16:default");
		uninitializedRam(b, "RAM", "0x1000", 0x100);
		return b;
	}

	private static void label(ProgramDB p, Address a, String name) {
		inTx(p, "label", () -> {
			try {
				p.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
	}

	private static void setComment(ProgramDB p, Address a, CommentType t, String text) {
		inTx(p, "comment", () -> p.getListing().setComment(a, t, text));
	}

	private static void append(ProgramDB p, Address a, CommentType t, String text,
			String... markers) {
		inTx(p, "append", () -> AnalyzerCommentRecord.append(p, a, t, text, markers));
	}

	private static GameDescriptorExporter.Result export(ProgramDB p) {
		return GameDescriptorExporter.export(p, new GameDescriptorExporter.Request("t", "T (U)",
			"nes_mmc1", "test", PRG, FILE, null));
	}

	@Test
	public void humanBankArrowSurvivesWhenNotRecorded() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		Address a = b.addr("0x1000");
		label(p, a, "user_main");
		setComment(p, a, CommentType.EOL, "bank -> 5");
		inTx(p, "maps", () -> AnalyzerCommentRecord.openAll(p));
		GameDescriptorExporter.Result r = export(p);
		assertEquals(1, r.comments());
		assertTrue(r.yaml(), r.yaml().contains("bank -> 5"));
		assertTrue(r.skipped().toString(), r.skipped().isEmpty());
	}

	@Test
	public void recordedBankMirrorAndJumpTableBoundAreDroppedExactly() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		Address a = b.addr("0x1000");
		label(p, a, "user_main");
		setComment(p, a, CommentType.EOL, "my note");
		append(p, a, CommentType.EOL, MIRROR, "bank mirror:");
		append(p, a, CommentType.EOL, BOUND, BOUND);
		GameDescriptorExporter.Result r = export(p);
		assertEquals(1, r.comments());
		assertTrue(r.yaml(), r.yaml().contains("my note"));
		assertFalse(r.yaml(), r.yaml().contains("bank mirror"));
		assertFalse(r.yaml(), r.yaml().contains("JumpTableBound"));
		assertTrue(r.skipped().toString(), r.skipped().isEmpty());
	}

	@Test
	public void aHumanEditedSegmentIsNoLongerRecognizedAndIsKept() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		Address a = b.addr("0x1000");
		append(p, a, CommentType.EOL, MIRROR, "bank mirror:");
		setComment(p, a, CommentType.EOL, MIRROR + " (checked by hand)");
		assertEquals(MIRROR + " (checked by hand)",
			GameDescriptorExporter.userComment(p, a, CommentType.EOL, MIRROR + " (checked by hand)"));
	}

	@Test
	public void helperWorksForAnyCommentTypeAndReturnsNullWhenNothingLeft() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		Address a = b.addr("0x1000");
		inTx(p, "set", () -> AnalyzerCommentRecord.set(p, a, CommentType.PLATE, "SYS target"));
		assertNull(GameDescriptorExporter.userComment(p, a, CommentType.PLATE, "SYS target"));
		assertEquals("human; later", GameDescriptorExporter.userComment(p, a, CommentType.PLATE,
			"human; SYS target; later"));
		// the PLATE record does not leak into EOL
		assertEquals("SYS target",
			GameDescriptorExporter.userComment(p, a, CommentType.EOL, "SYS target"));
	}

	@Test
	public void segmentsContainingTheJoinSeparatorAreRemovedWhole() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		Address a = b.addr("0x1000");
		String basic = "10 PRINT \"A; B\"";
		append(p, a, CommentType.PRE, basic, basic);
		setComment(p, a, CommentType.PRE, basic + "; mine");
		assertEquals("mine", GameDescriptorExporter.userComment(p, a, CommentType.PRE,
			basic + "; mine"));
	}

	@Test
	public void fallbackUsesPrefixListAndNotesIt() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		Address a = b.addr("0x1000");
		label(p, a, "user_main");
		setComment(p, a, CommentType.EOL, "mine; bank -> 3; " + MIRROR + "; " + BOUND);
		assertFalse(AnalyzerCommentRecord.hasAnyMap(p));
		GameDescriptorExporter.Result r = export(p);
		assertTrue(r.yaml(), r.yaml().contains("mine"));
		assertFalse(r.yaml(), r.yaml().contains("bank"));
		assertFalse(r.yaml(), r.yaml().contains("JumpTableBound"));
		assertEquals(r.skipped().toString(), 1, r.skipped().size());
		assertTrue(r.skipped().get(0), r.skipped().get(0).contains("predates comment provenance"));
	}

	@Test
	public void recorderIsWriteFreeOnASettledRerun() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		Address a = b.addr("0x1000");
		boolean[] first = new boolean[1];
		inTx(p, "first", () -> first[0] =
			AnalyzerCommentRecord.append(p, a, CommentType.EOL, BOUND, BOUND));
		assertTrue(first[0]);
		inTx(p, "set", () -> AnalyzerCommentRecord.set(p, a, CommentType.PLATE, "plate"));
		long before = p.getModificationNumber();
		boolean[] again = new boolean[3];
		inTx(p, "again", () -> {
			again[0] = AnalyzerCommentRecord.append(p, a, CommentType.EOL, BOUND, BOUND);
			again[1] = AnalyzerCommentRecord.set(p, a, CommentType.PLATE, "plate");
		});
		assertFalse(again[0]);
		assertFalse(again[1]);
		assertEquals("a settled re-run must not mutate the program", before,
			p.getModificationNumber());
		assertEquals(List.of(BOUND), AnalyzerCommentRecord.recorded(p, a, CommentType.EOL));
		assertEquals(BOUND, p.getListing().getComment(CommentType.EOL, a));
	}

	@Test
	public void severalSegmentsAreRecordedSeparately() throws Exception {
		ProgramBuilder b = newBuilder();
		ProgramDB p = b.getProgram();
		Address a = b.addr("0x1000");
		append(p, a, CommentType.EOL, MIRROR, "bank mirror:");
		append(p, a, CommentType.EOL, BOUND, BOUND);
		assertEquals(List.of(MIRROR, BOUND), AnalyzerCommentRecord.recorded(p, a, CommentType.EOL));
	}
}
