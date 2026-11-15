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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 coverage of emission under {@code banking.live_bank_sets} (bead grm-5tl.20.5, phase B):
 * {@link LiveBankExpansion} substitutes one fully-known state per candidate bank and
 * {@link BankAnnotationAdapter#retargetReferences} places a reference into each overlay.
 * <p>
 * The board is the UxROM shape of {@link BaseReferenceRetirementProgramTest}: a computed
 * {@code PRG_LO} window at {@code $8000-$BFFF} selected by a 4-bit {@code bank} field, home bank 0
 * in base space, a fixed {@code PRG_HI}. {@code JSR $8010} sits in {@code PRG_HI} (fixed code);
 * the target is {@code RTS} in banks 0-2 and a {@code BRK} run in bank 3.
 */
public class LiveBankExpansionProgramTest extends AbstractBundledLanguageTest {

	private static final int CALL_SITE = 0xC005;
	private static final int RESIDENT_SITE = 0x8100;
	private static final int TARGET = 0x8010;
	private static final String DESCRIPTOR = "games/test.gmap";
	private static final Map<String, Set<Integer>> UNIVERSE = Map.of("PRG_LO", Set.of(0, 1, 2, 3));

	private ProgramBuilder builder;
	private ProgramDB program;
	private ReferenceManager refMgr;
	private AddressSpace base;
	private BoardDescriptorModel.BoardModel board;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG_LO", "0x8000", 0x4000);
		builder.createMemory("PRG_HI", "0xC000", 0x4000);
		for (int b = 1; b <= 3; b++) {
			builder.createOverlayMemory("PRG_LO_B" + b, "0x8000", 0x4000);
		}
		program = builder.getProgram();
		refMgr = program.getReferenceManager();
		base = program.getAddressFactory().getDefaultAddressSpace();
		board = board();
		builder.setBytes("0x8010", "60", true); // RTS, home bank
		builder.setBytes("PRG_LO_B1::8010", "60", true);
		builder.setBytes("PRG_LO_B2::8010", "60", true);
		builder.setBytes("PRG_LO_B3::8010", "00 00 00 00 00 00 00 00 00 00", true); // BRK run
		builder.setBytes(String.format("0x%x", CALL_SITE), "20 10 80", true); // JSR $8010
		builder.setBytes(String.format("0x%x", RESIDENT_SITE), "20 10 80", true);
	}

	private BoardDescriptorModel.BoardModel board() {
		JsonObject map = JsonParser.parseString("""
				{
				  "physical": [ { "name": "PRG", "image": "prg_rom" } ],
				  "windows": [
				    { "name": "PRG_LO", "start": 32768, "end": 49151,
				      "maps": { "space": "PRG", "expr": "bank * 0x4000" },
				      "on_write": "mechanism" },
				    { "name": "PRG_HI", "start": 49152, "end": 65535,
				      "maps": { "space": "PRG", "expr": "last" },
				      "on_write": "mechanism" }
				  ],
				  "banking": {
				    "initial_state": 0,
				    "state": [ { "name": "bank", "bits": 4 } ],
				    "mechanisms": [ { "strategy": "memory-latch" } ]
				  }
				}
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel parsed = BoardDescriptorModel.BoardModel.parse(map,
			new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(parsed);
		return parsed;
	}

	private void publish(String valueset) {
		JsonObject doc = JsonParser.parseString("{\"banking\": {\"live_bank_sets\": [" +
			"{\"field\": \"bank\", \"valueset\": " + valueset + ", \"provenance\": \"unit test\"}]}}")
				.getAsJsonObject();
		String published = DescriptorHints.formatLiveBankSets(doc, DESCRIPTOR);
		inTx(program, "publish", () -> program.getOptions(Program.PROGRAM_INFO)
				.setString(DescriptorHints.LIVE_BANK_SETS_PROPERTY, published));
	}

	private void unpublish() {
		inTx(program, "unpublish", () -> program.getOptions(Program.PROGRAM_INFO)
				.removeOption(DescriptorHints.LIVE_BANK_SETS_PROPERTY));
	}

	private LiveBankSets.Plan plan() {
		return LiveBankSets.plan(program, board, UNIVERSE);
	}

	private Address addr(int a) {
		return base.getAddress(a);
	}

	private Instruction at(int a) {
		Instruction i = program.getListing().getInstructionAt(addr(a));
		assertNotNull(i);
		return i;
	}

	private LiveBankExpansion.Result expand(int site, BankState state, boolean prune) {
		return LiveBankExpansion.expand(program, board, UNIVERSE, Map.of(), plan(), at(site), base,
			List.of(state), prune);
	}

	private static List<Integer> values(LiveBankExpansion.Result r) {
		List<Integer> out = new ArrayList<>();
		for (BankState s : r.states()) {
			assertEquals("every expanded state is fully known", 0xF, s.knownMask() & 0xF);
			out.add(s.bits() & 0xF);
		}
		return out;
	}

	/** Overlay spaces (by name) holding a reference out of {@code site}'s instruction at TARGET. */
	private Set<String> overlayTargets(int site) {
		Set<String> out = new TreeSet<>();
		for (Reference r : at(site).getReferencesFrom()) {
			AddressSpace to = r.getToAddress().getAddressSpace();
			if (to.isOverlaySpace() && r.getToAddress().getOffset() == TARGET) {
				out.add(to.getName());
			}
		}
		return out;
	}

	private boolean hasBaseRef(int site) {
		for (Reference r : at(site).getReferencesFrom()) {
			if (r.getToAddress().getAddressSpace().equals(base) &&
				r.getToAddress().getOffset() == TARGET) {
				return true;
			}
		}
		return false;
	}

	/** One analysis round of the site, as BoardBankAnalyzer drives it. */
	private void round(int site, LiveBankSets.Plan plan, BankState state, boolean prune) {
		int tx = program.startTransaction("round");
		try {
			BankCommentProvenance comments = BankCommentProvenance.open(program);
			OverlayRefProvenance refsProv = OverlayRefProvenance.open(program);
			List<BankState> states = List.of(state);
			LiveBankExpansion.Result ex = LiveBankExpansion.expand(program, board, UNIVERSE,
				Map.of(), plan, at(site), base, states, prune);
			if (ex.comment() != null) {
				BankAnnotationAdapter.writeLiveBankSetComment(program.getListing(), addr(site),
					ex.comment(), comments);
			}
			BankAnnotationAdapter.retargetReferences(new NesBankingAnalyzer(), program, refMgr,
				base, at(site), board, UNIVERSE, ex.states(), Map.of(), TaskMonitor.DUMMY,
				new MessageLog(), comments, refsProv);
			comments.sweep(program.getListing());
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private String comment(int site) {
		return program.getListing().getComment(CommentType.EOL, addr(site));
	}

	// (a) unknown field -> a reference into each candidate overlay; base kept iff home is one

	@Test
	public void anUnknownFieldGetsOneReferencePerCandidateAndKeepsBaseWhenHomeIsACandidate() {
		publish("[0, 1, 2]");
		LiveBankExpansion.Result r = expand(CALL_SITE, BankState.unknown(), true);
		assertEquals(List.of(0, 1, 2), values(r));
		assertTrue(r.comment(), r.comment().startsWith("live bank set (game descriptor " +
			DESCRIPTOR + "): bank in {0,1,2}, refs for 0, 1, 2, pruned none"));
		assertNull(r.warning());

		round(CALL_SITE, plan(), BankState.unknown(), true);
		assertEquals(Set.of("PRG_LO_B1", "PRG_LO_B2"), overlayTargets(CALL_SITE));
		assertTrue("home bank 0 is a candidate: the base reference survives",
			hasBaseRef(CALL_SITE));
		assertTrue(comment(CALL_SITE), comment(CALL_SITE).contains("live bank set ("));

	}

	/** Without home in the set the stock base reference is retired (every state resolved away). */
	@Test
	public void theBaseReferenceIsRetiredWhenHomeIsNotACandidate() {
		publish("[1, 2]");
		round(CALL_SITE, plan(), BankState.unknown(), true);
		assertEquals(Set.of("PRG_LO_B1", "PRG_LO_B2"), overlayTargets(CALL_SITE));
		assertFalse("home is not a candidate: the stock base reference is retired",
			hasBaseRef(CALL_SITE));
	}

	// (b) known bits narrow the set

	@Test
	public void knownBitsNarrowTheSet() {
		publish("[0, 1, 2, 3]");
		// bit 1 known set: only 2 and 3 agree
		LiveBankExpansion.Result r = expand(CALL_SITE, new BankState(0b0010, 0b0010), false);
		assertEquals(List.of(2, 3), values(r));
		assertNull(r.warning());
	}

	// (c) a known value outside the set: the hint wins, with a warning

	@Test
	public void aKnownValueOutsideTheSetExpandsTheWholeSetAndWarns() {
		publish("[0, 1, 2]");
		LiveBankExpansion.Result r = expand(CALL_SITE, BankState.fullyKnown(0xF, 7), false);
		assertEquals(List.of(0, 1, 2), values(r));
		assertNotNull(r.warning());
		assertTrue(r.warning(), r.warning().contains("WINS"));
		assertTrue(r.warning(), r.warning().contains("bank = 7"));
		assertTrue(r.warning(), r.warning().contains("[0, 1, 2]"));
		// known bits that contradict every member are the same row
		LiveBankExpansion.Result bits = expand(CALL_SITE, new BankState(0b1000, 0b1000), false);
		assertEquals(List.of(0, 1, 2), values(bits));
		assertTrue(bits.warning(), bits.warning().contains("partly known"));
		// a known in-set value is left alone, with no comment and no warning
		LiveBankExpansion.Result known = expand(CALL_SITE, BankState.fullyKnown(0xF, 1), false);
		assertEquals(List.of(BankState.fullyKnown(0xF, 1)), known.states());
		assertNull(known.comment());
		assertNull(known.warning());
	}

	// (d) an instruction residing in the banked window is never expanded

	@Test
	public void codeInTheBankedWindowIsNotExpanded() {
		publish("[0, 1, 2]");
		LiveBankExpansion.Result r = expand(RESIDENT_SITE, BankState.unknown(), true);
		assertEquals(List.of(BankState.unknown()), r.states());
		assertNull(r.comment());
		assertNull(r.warning());
	}

	// (e) pruning drops a bank whose target is junk; with the option off it does not

	@Test
	public void pruningDropsABankWhoseTargetIsNotPlausibleCode() {
		publish("[0, 1, 2, 3]");
		LiveBankExpansion.Result pruned = expand(CALL_SITE, BankState.unknown(), true);
		assertEquals(List.of(0, 1, 2), values(pruned));
		assertTrue(pruned.comment(), pruned.comment().endsWith(
			"refs for 0, 1, 2, pruned 3 (target not plausible code there)"));
		LiveBankExpansion.Result kept = expand(CALL_SITE, BankState.unknown(), false);
		assertEquals(List.of(0, 1, 2, 3), values(kept));
		assertTrue(kept.comment(), kept.comment().endsWith("pruned none"));
	}

	@Test
	public void whenEveryCandidateIsPrunedNothingIsExpanded() {
		publish("[3]");
		LiveBankExpansion.Result r = expand(CALL_SITE, BankState.unknown(), true);
		assertEquals(List.of(BankState.unknown()), r.states());
		assertTrue(r.comment(), r.comment().contains("refs placed for none, pruned 3"));
	}

	// (f) re-analysis is write-free; removing the hint retracts the references and the comment

	@Test
	public void reanalysisIsWriteFreeAndRemovingTheHintRetractsEverything() {
		publish("[1, 2, 3]");
		round(CALL_SITE, plan(), BankState.unknown(), false);
		assertEquals(Set.of("PRG_LO_B1", "PRG_LO_B2", "PRG_LO_B3"), overlayTargets(CALL_SITE));
		String comment = comment(CALL_SITE);
		assertNotNull(comment);

		long before = program.getModificationNumber();
		round(CALL_SITE, plan(), BankState.unknown(), false);
		assertEquals("a settled round writes nothing", before, program.getModificationNumber());
		assertEquals(comment, comment(CALL_SITE));

		unpublish();
		round(CALL_SITE, plan(), BankState.unknown(), false);
		assertEquals("references the hint placed are retracted", Set.of(),
			overlayTargets(CALL_SITE));
		assertTrue("and the stock base reference is what dataflow alone leaves",
			hasBaseRef(CALL_SITE));
		assertNull("and so is the site comment", comment(CALL_SITE));
	}
}
