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

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Tier-2 {@code ProgramBuilder} coverage of {@link BankAnnotationAdapter#retargetReferences}'s
 * base-reference RETIREMENT (bead {@code grm-bfb}): once an overlay reference replaces the
 * disassembler's stock base-space reference at a site, the stock one is deleted -- unless some
 * live state resolves it to the home occupant, or a user pinned it by hand.
 * <p>
 * The E2E fixtures pin the same rule end to end ({@code nesbanktest} N6, {@code nesforktest} F9,
 * {@code nesforkhometest} H-criteria, {@code banktest} C9, {@code banktest4} D4). This class
 * exists for the two cases no fixture can reach -- a {@code USER_DEFINED} base reference, and a
 * second pass over an already-retired site -- and to state the fork-arm rule at the adapter's
 * own boundary, with the states handed in explicitly rather than recovered by dataflow.
 * <p>
 * The board is the UxROM shape ({@code data/machines/nes-uxrom.map}): a computed {@code PRG_LO}
 * window at {@code $8000-$BFFF} selected by a 4-bit {@code bank} field whose home bank is 0, so
 * a {@code JSR $8010} taken in bank 2 must reach {@code PRG_LO_B2::8010}, not the home bank's
 * bytes at {@code base:8010}. Per the {@code programbuilder-default-refs} memory,
 * {@code setBytes(.., true)} on a plain absolute operand DOES create the stock DEFAULT reference,
 * which is exactly the reference under test.
 */
public class BaseReferenceRetirementProgramTest extends AbstractBundledLanguageTest {

	private static final int CALL_SITE = 0xC005;
	private static final int TARGET = 0x8010;

	private ProgramBuilder builder;
	private ProgramDB program;
	private ReferenceManager refMgr;
	private AddressSpace base;
	private BoardDescriptorModel.BoardModel board;
	private Instruction call;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG_LO", "0x8000", 0x4000);
		builder.createMemory("PRG_HI", "0xC000", 0x4000);
		builder.createOverlayMemory("PRG_LO_B1", "0x8000", 0x4000);
		builder.createOverlayMemory("PRG_LO_B2", "0x8000", 0x4000);
		program = builder.getProgram();
		refMgr = program.getReferenceManager();
		base = program.getAddressFactory().getDefaultAddressSpace();
		board = board();

		// The call target is code in the home bank and in both overlays, so the retarget's
		// disassembly kick at the overlay target has real bytes to work on.
		builder.setBytes("0x8010", "60", true); // RTS (home bank, base space)
		for (String space : List.of("PRG_LO_B1", "PRG_LO_B2")) {
			builder.setBytes(space + "::8010", "60", true);
		}
		builder.setBytes(String.format("0x%x", CALL_SITE), "20 10 80", true); // JSR $8010
		call = program.getListing().getInstructionAt(addr(CALL_SITE));
		assertNotNull(call);
		assertEquals("the stock DEFAULT call reference is the fixture's subject", 1,
			baseRefsTo(TARGET).size());
		assertEquals(SourceType.DEFAULT, baseRefsTo(TARGET).get(0).getSource());
	}

	// ------------------------------------------------------------------
	// Fixture plumbing
	// ------------------------------------------------------------------

	private Address addr(int a) {
		return base.getAddress(a);
	}

	/** The UxROM shape: PRG_LO computed from {@code bank}, PRG_HI fixed, home bank 0. */
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
		assertNotNull("PRG_LO must parse as a computed window", parsed.computedWindows().get("PRG_LO"));
		return parsed;
	}

	private BankState bank(int value) {
		return BankState.fullyKnown(board.mask(), value);
	}

	private BankAnnotationAdapter.Retargeted retarget(BankState... states) {
		int tx = program.startTransaction("retarget");
		try {
			return BankAnnotationAdapter.retargetReferences(new NesBankingAnalyzer(), program,
				refMgr, base, call, board, Map.of("PRG_LO", Set.of(0, 1, 2, 3)), List.of(states),
				Map.of(), TaskMonitor.DUMMY, new MessageLog(), null);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private List<Reference> baseRefsTo(int offset) {
		return java.util.Arrays.stream(call.getReferencesFrom())
				.filter(r -> r.getToAddress().getAddressSpace().equals(base) &&
					r.getToAddress().getOffset() == offset)
				.toList();
	}

	private Reference overlayRef(String space) {
		for (Reference r : call.getReferencesFrom()) {
			AddressSpace to = r.getToAddress().getAddressSpace();
			if (to.isOverlaySpace() && to.getName().equals(space) &&
				r.getToAddress().getOffset() == TARGET) {
				return r;
			}
		}
		return null;
	}

	// ------------------------------------------------------------------
	// (a) The rule itself: a single non-home state retires the stock reference
	// ------------------------------------------------------------------

	@Test
	public void nonHomeStateRetiresTheStockBaseReference() throws Exception {
		BankAnnotationAdapter.Retargeted result = retarget(bank(2));

		assertEquals(new BankAnnotationAdapter.Retargeted(1, 1), result);
		Reference overlay = overlayRef("PRG_LO_B2");
		assertNotNull("JSR $8010 in bank 2 reaches PRG_LO_B2::8010", overlay);
		assertTrue(overlay.isPrimary());
		assertTrue(overlay.getReferenceType().isCall());
		assertTrue("the stock base:8010 reference is gone, not merely demoted",
			baseRefsTo(TARGET).isEmpty());
		assertEquals("getFlows() no longer names the home bank's bytes", 1, call.getFlows().length);
		assertEquals(overlay.getToAddress(), call.getFlows()[0]);
	}

	/** The home state places nothing and retires nothing -- the stock reference IS the answer. */
	@Test
	public void homeStateLeavesTheStockReferenceAlone() throws Exception {
		BankAnnotationAdapter.Retargeted result = retarget(bank(0));

		assertEquals(BankAnnotationAdapter.Retargeted.NONE, result);
		assertNull(overlayRef("PRG_LO_B2"));
		assertEquals(1, baseRefsTo(TARGET).size());
		assertTrue(baseRefsTo(TARGET).get(0).isPrimary());
	}

	// ------------------------------------------------------------------
	// (b) Fork arms: retirement is decided across ALL live states at the site
	// ------------------------------------------------------------------

	/**
	 * One arm resolves to home, so the base reference is right for that arm and survives --
	 * and since the home arm came first and consumed primacy without placing anything, it also
	 * stays primary; the second arm's overlay reference is a secondary. This is the
	 * {@code nesforkhometest} shape at the adapter boundary.
	 */
	@Test
	public void forkArmResolvingToHomeKeepsTheStockReference() throws Exception {
		BankAnnotationAdapter.Retargeted result = retarget(bank(0), bank(2));

		assertEquals(new BankAnnotationAdapter.Retargeted(1, 0), result);
		Reference overlay = overlayRef("PRG_LO_B2");
		assertNotNull(overlay);
		assertFalse("the first arm (home) took primacy; bank 2's reference is secondary",
			overlay.isPrimary());
		assertEquals(1, baseRefsTo(TARGET).size());
		assertTrue(baseRefsTo(TARGET).get(0).isPrimary());
	}

	/** Arm order does not change the survival decision, only which reference is primary. */
	@Test
	public void forkArmResolvingToHomeKeepsTheStockReferenceWhateverTheArmOrder()
			throws Exception {
		BankAnnotationAdapter.Retargeted result = retarget(bank(2), bank(0));

		assertEquals(new BankAnnotationAdapter.Retargeted(1, 0), result);
		Reference overlay = overlayRef("PRG_LO_B2");
		assertNotNull(overlay);
		assertTrue("bank 2 came first this time, so its reference is primary", overlay.isPrimary());
		assertEquals("...but the home arm still keeps the base reference alive", 1,
			baseRefsTo(TARGET).size());
		assertFalse(baseRefsTo(TARGET).get(0).isPrimary());
	}

	/** Both arms away from home: two overlay references, and the stock one goes. */
	@Test
	public void forkArmsBothAwayFromHomeRetireTheStockReference() throws Exception {
		BankAnnotationAdapter.Retargeted result = retarget(bank(1), bank(2));

		assertEquals(new BankAnnotationAdapter.Retargeted(2, 1), result);
		assertNotNull(overlayRef("PRG_LO_B1"));
		assertTrue(overlayRef("PRG_LO_B1").isPrimary());
		assertNotNull(overlayRef("PRG_LO_B2"));
		assertFalse(overlayRef("PRG_LO_B2").isPrimary());
		assertTrue(baseRefsTo(TARGET).isEmpty());
	}

	/**
	 * A PARTIALLY known state -- here only bit 1 of the 4-bit bank is known, and set -- is not a
	 * resolution. {@code valueIn(effective)} fills the unknown bits from the initial state and
	 * lands on bank 2, and this pass has always placed an overlay reference on that guess; the
	 * guess may add, but it must not delete the stock reference, which is still the only answer
	 * for the banks {@code {6, 10, 14, ...}} the state has not ruled out (grm-bfb's "a
	 * partially-known state must not be allowed to demote a correct default").
	 */
	@Test
	public void partiallyKnownStateAddsButDoesNotRetire() throws Exception {
		BankState bitOneSet = new BankState(0x2, 0x2);
		assertEquals("the fixture's premise: the guess resolves to bank 2", 2,
			bitOneSet.effective(board.initialState(), board.mask()));

		BankAnnotationAdapter.Retargeted result = retarget(bitOneSet);

		assertEquals(new BankAnnotationAdapter.Retargeted(1, 0), result);
		assertNotNull("the overlay reference is still placed, as before", overlayRef("PRG_LO_B2"));
		assertEquals("...but the stock reference survives the guess", 1, baseRefsTo(TARGET).size());
	}

	/**
	 * A base-space instruction referencing its OWN window keeps the stock reference whatever
	 * the state: the reference is the physical block's own flow graph, which helper lookup and
	 * join detection read through references (nesmmc1test's {@code JSR $C200} from
	 * {@code $C06C}). The overlay reference is still added, as it always was.
	 */
	@Test
	public void intraWindowReferenceFromBaseSpaceIsNeverRetired() throws Exception {
		builder.setBytes("0x8000", "20 10 80", true); // JSR $8010, from INSIDE PRG_LO
		Instruction inner = program.getListing().getInstructionAt(addr(0x8000));
		assertNotNull(inner);

		int tx = program.startTransaction("retarget");
		BankAnnotationAdapter.Retargeted result;
		try {
			result = BankAnnotationAdapter.retargetReferences(new NesBankingAnalyzer(), program,
				refMgr, base, inner, board, Map.of("PRG_LO", Set.of(0, 1, 2, 3)), List.of(bank(2)),
				Map.of(), TaskMonitor.DUMMY, new MessageLog(), null);
		}
		finally {
			program.endTransaction(tx, true);
		}

		assertEquals(new BankAnnotationAdapter.Retargeted(1, 0), result);
		boolean overlayPlaced = false;
		boolean baseKept = false;
		for (Reference r : inner.getReferencesFrom()) {
			AddressSpace to = r.getToAddress().getAddressSpace();
			if (to.isOverlaySpace() && to.getName().equals("PRG_LO_B2")) {
				overlayPlaced = true;
			}
			if (to.equals(base) && r.getToAddress().getOffset() == TARGET) {
				baseKept = true;
			}
		}
		assertTrue("the overlay reference is still added for an intra-window access", overlayPlaced);
		assertTrue("...but the block's own flow reference stays", baseKept);
		assertEquals("the cross-window call site is untouched by this", 1, baseRefsTo(TARGET).size());
	}

	// ------------------------------------------------------------------
	// (c) The guards: a hand-pinned reference, and a second pass
	// ------------------------------------------------------------------

	/**
	 * A {@code USER_DEFINED} base reference is the user's statement of where this call goes.
	 * {@link AnnotationGuard#mayDisplace} already keeps the overlay reference from taking
	 * primacy over it; retirement must honour the same line and leave it in place.
	 */
	@Test
	public void userDefinedBaseReferenceIsNeverRetired() throws Exception {
		int tx = program.startTransaction("pin by hand");
		try {
			refMgr.delete(baseRefsTo(TARGET).get(0));
			refMgr.addMemoryReference(call.getMinAddress(), addr(TARGET),
				RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
		}
		finally {
			program.endTransaction(tx, true);
		}
		assertEquals(SourceType.USER_DEFINED, baseRefsTo(TARGET).get(0).getSource());

		BankAnnotationAdapter.Retargeted result = retarget(bank(2));

		assertEquals(new BankAnnotationAdapter.Retargeted(1, 0), result);
		Reference overlay = overlayRef("PRG_LO_B2");
		assertNotNull("the overlay reference is still added, as a secondary", overlay);
		assertFalse(overlay.isPrimary());
		assertEquals(1, baseRefsTo(TARGET).size());
		assertEquals(SourceType.USER_DEFINED, baseRefsTo(TARGET).get(0).getSource());
		assertTrue(baseRefsTo(TARGET).get(0).isPrimary());
	}

	/**
	 * The analyzer re-runs to a whole-program fixpoint, so every site is visited again on a
	 * settled program. The second pass must confirm the overlay reference (it is reused, not
	 * duplicated) and find nothing left to retire -- a nonzero {@code retired} on a settled
	 * program would mean something keeps resurrecting the stock reference.
	 */
	/**
	 * The analyzer re-runs after a post-script or a later round discovers more code, and the
	 * state at a site can CHANGE between rounds -- {@code nesskiptest}'s {@code JSR $8010} at
	 * {@code c009} is bank 2 until {@code FixSkipInstructions} recovers the hidden entry that
	 * establishes bank 1. Round one retired the stock reference; round two must still find the
	 * banked access to resolve, seeded from the overlay reference round one left, and place bank
	 * 1's reference as the new primary. Bank 2's reference stays as a secondary: this pass has
	 * never removed an overlay reference an earlier round placed, and that is unchanged.
	 */
	@Test
	public void laterRoundWithADifferentBankStillRetargetsARetiredSite() throws Exception {
		assertEquals(new BankAnnotationAdapter.Retargeted(1, 1), retarget(bank(2)));
		assertTrue(baseRefsTo(TARGET).isEmpty());

		BankAnnotationAdapter.Retargeted roundTwo = retarget(bank(1));

		assertEquals(new BankAnnotationAdapter.Retargeted(1, 0), roundTwo);
		Reference bankOne = overlayRef("PRG_LO_B1");
		assertNotNull("round two placed bank 1's reference from the overlay-derived seed", bankOne);
		assertTrue(bankOne.isPrimary());
		assertNotNull(overlayRef("PRG_LO_B2"));
		assertFalse(overlayRef("PRG_LO_B2").isPrimary());
		assertTrue(baseRefsTo(TARGET).isEmpty());
	}

	@Test
	public void secondPassOverARetiredSiteIsWriteFree() throws Exception {
		assertEquals(new BankAnnotationAdapter.Retargeted(1, 1), retarget(bank(2)));

		BankAnnotationAdapter.Retargeted again = retarget(bank(2));

		assertEquals(new BankAnnotationAdapter.Retargeted(1, 0), again);
		assertEquals("one overlay reference, not two", 1, call.getReferencesFrom().length);
		assertTrue(overlayRef("PRG_LO_B2").isPrimary());
	}
}
