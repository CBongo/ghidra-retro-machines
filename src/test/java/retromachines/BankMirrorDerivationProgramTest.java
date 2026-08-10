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
import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pins {@link BankMirrors}' derivation (bead grm-mej.2, increment 1): which addresses on a program
 * mirror the live bank, and -- just as load-bearing -- which look like they do and must not be
 * admitted.
 * <p>
 * The two halves are independent facts about the same question:
 * <ul>
 * <li>a <b>bank-identifying ROM offset</b>, derived from image content. Contra and TMNT both hold
 * their own bank number at byte 0 of every bank; Mega Man's measured bytes
 * ({@code 00 00 00 00 00 00 06 00}) must fail, which is why the negative below uses those exact
 * bytes rather than an invented counterexample.</li>
 * <li>a <b>RAM shadow</b>, derived from code -- either written on the way into a mechanism write
 * (route (a)) or loaded into a wrapper's argument register at a call site (route (b)).</li>
 * </ul>
 * <p>
 * These drive {@link BankMirrors.Discovery} directly rather than through {@code BoardBankAnalyzer},
 * because the switch-site set and the helper-call set are exactly the two inputs the analyzer
 * supplies -- handing them over by hand isolates the derivation from helper classification, which
 * has its own tests. Nothing here CONSUMES a mirror: increment 1 lands the facts with no consumer,
 * and consumption arrives with its own fixture in increment 2.
 * <p>
 * Fixture note inherited from {@link MemoryLatchStrategyProgramTest}: {@link ProgramBuilder} blocks
 * are created read-only, so RAM must be made writable explicitly -- and here that is not a detail
 * but the actual mechanism under test, since "in writable memory" is how the pass expresses
 * "outside the latch range".
 */
public class BankMirrorDerivationProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private AddressSpace baseSpace;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		// Spans the stack page and ordinary RAM above it, so the stack-page refusal and the
		// "any RAM address, not just zero page" rule are both reachable.
		MemoryBlock ram = builder.createMemory(".ram", "0x100", 0x700);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		baseSpace = program.getAddressFactory().getDefaultAddressSpace();
		setWritable(zp, true);
		setWritable(ram, true);
	}

	private void setWritable(MemoryBlock block, boolean writable) {
		int tx = program.startTransaction("set block write permission");
		try {
			block.setWrite(writable);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private BankMirrors.Discovery discovery() {
		return new BankMirrors.Discovery(baseSpace);
	}

	private Address addr(String address) {
		return builder.addr(address);
	}

	private Set<BankMirrors.Kind> kindsAt(BankMirrors mirrors, String address) {
		return mirrors.kindsAt(addr(address));
	}

	// ------------------------------------------------------------------
	// The bank-identifying ROM offset (content)
	// ------------------------------------------------------------------

	/**
	 * Lays {@code banks-1} non-home bank overlays over the switchable window, following the
	 * {@code <window>_B<n>} naming contract {@link DescriptorSupport.OverlayNaming} defines and
	 * the loader realizes: bank 0 is home and lives in BASE space with no overlay of its own.
	 */
	private void layBankOverlays(int banks) {
		for (int bank = 1; bank < banks; bank++) {
			builder.createOverlayMemory("PRG_LO_B" + bank, "0x8000", 0x4000);
		}
	}

	/** Writes one byte at {@code offset} in the given bank's image (bank 0 = base space). */
	private void setBankByte(int bank, long offset, int value) throws Exception {
		AddressSpace space = bank == 0 ? baseSpace
				: program.getAddressFactory().getAddressSpace("PRG_LO_B" + bank);
		int tx = program.startTransaction("write bank image byte");
		try {
			program.getMemory().setBytes(space.getAddress(offset), new byte[] { (byte) value });
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private Set<Long> identifyingOffsets(int banks) {
		Set<Integer> realized = new java.util.LinkedHashSet<>();
		for (int bank = 0; bank < banks; bank++) {
			realized.add(bank);
		}
		return BankMirrors.romIdentifyingOffsets(program, "PRG_LO", 0x8000, 0xBFFF, realized);
	}

	/**
	 * The Contra/TMNT convention: byte 0 of bank N holds N. Four banks, so the
	 * {@link BankMirrors#MIN_IDENTIFYING_BANKS} floor is cleared.
	 */
	@Test
	public void byteHoldingItsOwnBankNumberInEveryBankIsIdentifying() throws Exception {
		layBankOverlays(4);
		for (int bank = 0; bank < 4; bank++) {
			setBankByte(bank, 0x8000, bank);
		}

		assertEquals(Set.of(0x8000L), identifyingOffsets(4));
	}

	/**
	 * <b>Mega Man's measured byte-0 values</b>, which the derivation must reject. Byte 0 of banks
	 * 0..7 is {@code 00 00 00 00 00 00 06 00}: bank 0 agrees by accident and bank 6 agrees by
	 * accident, and no rule may be satisfied by that. Using the real bytes rather than an invented
	 * counterexample is the point -- this is the game that proves the test is a test.
	 */
	@Test
	public void megaManByteZeroValuesAreNotIdentifying() throws Exception {
		layBankOverlays(8);
		int[] measured = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00 };
		for (int bank = 0; bank < 8; bank++) {
			setBankByte(bank, 0x8000, measured[bank]);
		}

		assertEquals(Set.of(), identifyingOffsets(8));
	}

	/**
	 * Two banks is a coincidence, not evidence: "the byte equals the bank" over a whole window of
	 * offsets will hit by chance long before it means anything. The image below would otherwise
	 * qualify, so this pins the floor itself rather than a program that happens not to reach it.
	 */
	@Test
	public void twoBanksCannotEstablishAnIdentifyingOffset() throws Exception {
		layBankOverlays(2);
		setBankByte(0, 0x8000, 0);
		setBankByte(1, 0x8000, 1);

		assertEquals(Set.of(), identifyingOffsets(2));
	}

	/**
	 * A window whose banks agree at byte 0 but disagree one byte later yields the one offset and
	 * not the other -- the test is per offset, not per window.
	 */
	@Test
	public void onlyTheAgreeingOffsetIsAdmitted() throws Exception {
		layBankOverlays(4);
		for (int bank = 0; bank < 4; bank++) {
			setBankByte(bank, 0x8000, bank);
			setBankByte(bank, 0x8001, bank == 2 ? 0x99 : bank);
		}

		assertEquals(Set.of(0x8000L), identifyingOffsets(4));
	}

	/**
	 * <b>Address-space normalization.</b> The offset is derived in base space, but the code that
	 * reads it back runs from inside a bank overlay and names it in THAT space. A membership test
	 * keyed on {@link Address} equality would silently decline here, and no non-overlay fixture
	 * would ever catch it -- which is why the set is keyed by raw offset and normalized through
	 * the physical space.
	 */
	@Test
	public void anOverlaySpaceQueryFindsABaseSpaceOffset() throws Exception {
		layBankOverlays(4);
		for (int bank = 0; bank < 4; bank++) {
			setBankByte(bank, 0x8000, bank);
		}
		BankMirrors.Discovery discovery = discovery();
		discovery.addRomIdentifying(identifyingOffsets(4));
		BankMirrors mirrors = discovery.build();

		Address inOverlay =
			program.getAddressFactory().getAddressSpace("PRG_LO_B1").getAddress(0x8000);

		assertTrue("an overlay-space read of the identifying offset must match",
			mirrors.is(inOverlay, BankMirrors.Kind.ROM_IDENTIFYING));
		assertTrue("and so must the base-space one",
			mirrors.is(addr("0x8000"), BankMirrors.Kind.ROM_IDENTIFYING));
	}

	// ------------------------------------------------------------------
	// Route (a): the write-through RAM shadow
	// ------------------------------------------------------------------

	private BankMirrors shadowsFrom(String... switchSites) {
		BankMirrors.Discovery discovery = discovery();
		discovery.scanWriteThroughShadows(program,
			List.of(switchSites).stream().map(this::addr).toList());
		return discovery.build();
	}

	/**
	 * <b>Mega Man's {@code $42}</b>: the bank is written to RAM and to the mechanism together, at
	 * every switch. Two distinct store sites, so the "one site is a coincidence" rule is satisfied
	 * without needing corroboration.
	 */
	@Test
	public void cellStoredAlongsideTwoDistinctMechanismWritesIsAWriteThroughShadow()
			throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 42", true); // STA $42
		builder.setBytes("0x8004", "8d 00 c0", true); // STA $C000   <- switch site
		builder.setBytes("0x8007", "a9 06", true); // LDA #$06
		builder.setBytes("0x8009", "85 42", true); // STA $42
		builder.setBytes("0x800b", "8d 00 c0", true); // STA $C000   <- switch site

		BankMirrors mirrors = shadowsFrom("0x8004", "0x800b");

		assertEquals(Set.of(BankMirrors.Kind.WRITE_THROUGH), kindsAt(mirrors, "0x42"));
	}

	/**
	 * <b>Castlevania 2's {@code $1C}</b>, the case the literal "two distinct sites" rule rejects
	 * and corroboration admits: the game has exactly ONE PRG mechanism chain, so one store site is
	 * all there will ever be -- but the very next instruction loads the cell back into the register
	 * the chain commits. Both evidences come out of a single backward walk, which is precisely what
	 * makes them corroboration rather than a second guess.
	 * <p>
	 * Note the walk must CONTINUE past the {@code LDA $1C}. Treating a load as a plain register
	 * modifier stops one instruction short of the store and loses the cell entirely.
	 */
	@Test
	public void oneStoreCorroboratedByALoadFeedingTheSwitchIsAShadow() throws Exception {
		builder.setBytes("0x8000", "85 1c", true); // STA $1C
		builder.setBytes("0x8002", "a5 1c", true); // LDA $1C
		builder.setBytes("0x8004", "8d 00 c0", true); // STA $C000   <- switch site

		BankMirrors mirrors = shadowsFrom("0x8004");

		assertEquals(Set.of(BankMirrors.Kind.WRITE_THROUGH), kindsAt(mirrors, "0x1c"));
	}

	/** One store, no corroboration, one site: not enough to believe. */
	@Test
	public void aSingleUncorroboratedStoreIsNotAShadow() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 42", true); // STA $42
		builder.setBytes("0x8004", "8d 00 c0", true); // STA $C000   <- switch site

		assertEquals(Set.of(), kindsAt(shadowsFrom("0x8004"), "0x42"));
	}

	/**
	 * A register clobber between the store and the mechanism write breaks the claim: whatever
	 * reached the latch is not what reached the cell, so the cell mirrors nothing.
	 */
	@Test
	public void aClobberBetweenStoreAndSwitchDisqualifiesTheCell() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 42", true); // STA $42
		builder.setBytes("0x8004", "a9 06", true); // LDA #$06     <- A no longer holds $42
		builder.setBytes("0x8006", "8d 00 c0", true); // STA $C000 <- switch site
		builder.setBytes("0x8009", "a9 07", true); // LDA #$07
		builder.setBytes("0x800b", "85 42", true); // STA $42
		builder.setBytes("0x800d", "a9 08", true); // LDA #$08
		builder.setBytes("0x800f", "8d 00 c0", true); // STA $C000 <- switch site

		assertEquals(Set.of(), kindsAt(shadowsFrom("0x8006", "0x800f"), "0x42"));
	}

	/**
	 * <b>"Outside the latch range" is enforced as "in writable memory".</b> A store into the
	 * cartridge's ROM window is another mechanism write, not a shadow, and it must not be admitted
	 * however many times it recurs.
	 */
	@Test
	public void aStoreIntoNonWritableMemoryIsNotAShadow() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "8d 00 90", true); // STA $9000  <- ROM, not RAM
		builder.setBytes("0x8005", "8d 00 c0", true); // STA $C000  <- switch site
		builder.setBytes("0x8008", "a9 06", true); // LDA #$06
		builder.setBytes("0x800a", "8d 00 90", true); // STA $9000
		builder.setBytes("0x800d", "8d 00 c0", true); // STA $C000  <- switch site

		assertEquals(Set.of(), kindsAt(shadowsFrom("0x8005", "0x800d"), "0x9000"));
	}

	/**
	 * The stack page is refused for {@code StoredValueScanner.inStackPage}'s reason: a {@code PHA}
	 * writes it without naming an address any detector here can see, so a value forwarded through
	 * it could be stale. Carrying a bank across a push/pull pair is grm-mej.3's domain.
	 */
	@Test
	public void aStackPageCellIsNotAShadow() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "8d 40 01", true); // STA $0140  <- stack page
		builder.setBytes("0x8005", "8d 00 c0", true); // STA $C000  <- switch site
		builder.setBytes("0x8008", "a9 06", true); // LDA #$06
		builder.setBytes("0x800a", "8d 40 01", true); // STA $0140
		builder.setBytes("0x800d", "8d 00 c0", true); // STA $C000  <- switch site

		assertEquals(Set.of(), kindsAt(shadowsFrom("0x8005", "0x800d"), "0x140"));
	}

	/**
	 * A shadow at an ABSOLUTE RAM address, not the zero page -- the same ruling grm-mej.1 made for
	 * store forwarding. Contra's save slots are {@code $07EC}/{@code $07ED}, so a zero-page
	 * restriction would exclude exactly the cells the follow-on beads need.
	 */
	@Test
	public void aShadowNeedNotBeInTheZeroPage() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "8d ec 07", true); // STA $07EC
		builder.setBytes("0x8005", "8d 00 c0", true); // STA $C000  <- switch site
		builder.setBytes("0x8008", "a9 06", true); // LDA #$06
		builder.setBytes("0x800a", "8d ec 07", true); // STA $07EC
		builder.setBytes("0x800d", "8d 00 c0", true); // STA $C000  <- switch site

		assertEquals(Set.of(BankMirrors.Kind.WRITE_THROUGH),
			kindsAt(shadowsFrom("0x8005", "0x800d"), "0x7ec"));
	}

	/**
	 * <b>TMNT's {@code $59} shape: a save slot must not be typed a write-through shadow.</b> The
	 * cell is filled from a bank READ-BACK, so it holds the bank that was live before the switch --
	 * by intent, since the game saved it precisely because it was about to change. Answering its
	 * reload from tracked in-state would ship a confidently wrong bank, so the kind has to survive
	 * discovery rather than be flattened into {@code WRITE_THROUGH} here and sorted out later.
	 */
	@Test
	public void aCellFilledFromABankReadBackIsASaveSlotNotAShadow() throws Exception {
		layBankOverlays(4);
		for (int bank = 0; bank < 4; bank++) {
			setBankByte(bank, 0x8000, bank);
		}
		builder.setBytes("0x9000", "ad 00 80", true); // LDA $8000   <- the identifying offset
		builder.setBytes("0x9003", "85 59", true); // STA $59
		builder.setBytes("0x9005", "8d 00 c0", true); // STA $C000   <- switch site
		builder.setBytes("0x9008", "ad 00 80", true); // LDA $8000
		builder.setBytes("0x900b", "85 59", true); // STA $59
		builder.setBytes("0x900d", "8d 00 c0", true); // STA $C000   <- switch site

		BankMirrors.Discovery discovery = discovery();
		discovery.addRomIdentifying(identifyingOffsets(4));
		discovery.scanWriteThroughShadows(program, List.of(addr("0x9005"), addr("0x900d")));
		BankMirrors mirrors = discovery.build();

		assertEquals(Set.of(BankMirrors.Kind.SAVE_SLOT), kindsAt(mirrors, "0x59"));
		assertFalse("a save slot must never resolve as a live-bank mirror",
			mirrors.is(addr("0x59"), BankMirrors.Kind.WRITE_THROUGH));
	}

	// ------------------------------------------------------------------
	// Route (b): the wrapper's argument cell
	// ------------------------------------------------------------------

	private BankMirrors argumentCellsFrom(Map<String, Character> callSites) {
		Map<Address, Character> sites = new LinkedHashMap<>();
		callSites.forEach((address, reg) -> sites.put(addr(address), reg));
		BankMirrors.Discovery discovery = discovery();
		discovery.scanArgumentCells(program, sites);
		return discovery.build();
	}

	/**
	 * <b>Blaster Master's {@code $D3}</b>, the cell route (a) structurally cannot find: it is
	 * written in five functions, none of which contains a mechanism write, so no backward scan from
	 * any mechanism write reaches it -- yet it feeds six of the twelve call sites into the switch
	 * wrapper. Route (b) starts from the CALL instead.
	 * <p>
	 * Typed {@link BankMirrors.Kind#INPUT}, not {@code WRITE_THROUGH}: it holds the bank the caller
	 * is asking for, which is the live bank only after the wrapper runs.
	 */
	@Test
	public void aCellLoadedIntoTheArgumentRegisterAtTwoCallSitesIsAnInputMirror() throws Exception {
		builder.setBytes("0x8000", "a5 d3", true); // LDA $D3
		builder.setBytes("0x8002", "20 00 90", true); // JSR $9000
		builder.setBytes("0x8010", "a5 d3", true); // LDA $D3
		builder.setBytes("0x8012", "20 00 90", true); // JSR $9000

		BankMirrors mirrors =
			argumentCellsFrom(Map.of("0x8002", 'A', "0x8012", 'A'));

		assertEquals(Set.of(BankMirrors.Kind.INPUT), kindsAt(mirrors, "0xd3"));
	}

	/** One call site is a coincidence here for the same reason one store site is in route (a). */
	@Test
	public void aSingleArgumentLoadIsNotAnInputMirror() throws Exception {
		builder.setBytes("0x8000", "a5 d3", true); // LDA $D3
		builder.setBytes("0x8002", "20 00 90", true); // JSR $9000

		assertEquals(Set.of(), kindsAt(argumentCellsFrom(Map.of("0x8002", 'A')), "0xd3"));
	}

	/**
	 * An immediate argument names no cell. This is the anti-overreach guard on route (b): the
	 * common case by far is {@code LDA #$05 / JSR wrapper}, and a route that nominated something
	 * for it would fill the mirror set with noise.
	 */
	@Test
	public void anImmediateArgumentNominatesNoCell() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "20 00 90", true); // JSR $9000
		builder.setBytes("0x8010", "a9 06", true); // LDA #$06
		builder.setBytes("0x8012", "20 00 90", true); // JSR $9000

		assertTrue(argumentCellsFrom(Map.of("0x8002", 'A', "0x8012", 'A')).isEmpty());
	}

	/**
	 * A cell carrying BOTH roles keeps both kinds. Blaster Master's {@code $D3} really is written
	 * as a bank request by three functions and read as a save slot by two others, at one address;
	 * a model that assumed one direction of information flow per cell would get it wrong. Neither
	 * kind resolves from in-state, but they are labelled differently and grm-mej.4 needs to tell
	 * them apart.
	 */
	@Test
	public void oneCellCanCarryBothAnInputAndAWriteThroughRole() throws Exception {
		builder.setBytes("0x8000", "a5 d3", true); // LDA $D3
		builder.setBytes("0x8002", "20 00 90", true); // JSR $9000
		builder.setBytes("0x8010", "a5 d3", true); // LDA $D3
		builder.setBytes("0x8012", "20 00 90", true); // JSR $9000
		builder.setBytes("0x8020", "a9 05", true); // LDA #$05
		builder.setBytes("0x8022", "85 d3", true); // STA $D3
		builder.setBytes("0x8024", "8d 00 c0", true); // STA $C000  <- switch site
		builder.setBytes("0x8027", "a9 06", true); // LDA #$06
		builder.setBytes("0x8029", "85 d3", true); // STA $D3
		builder.setBytes("0x802b", "8d 00 c0", true); // STA $C000  <- switch site

		Map<Address, Character> sites = new LinkedHashMap<>();
		sites.put(addr("0x8002"), 'A');
		sites.put(addr("0x8012"), 'A');
		BankMirrors.Discovery discovery = discovery();
		discovery.scanWriteThroughShadows(program, List.of(addr("0x8024"), addr("0x802b")));
		discovery.scanArgumentCells(program, sites);

		assertEquals(Set.of(BankMirrors.Kind.WRITE_THROUGH, BankMirrors.Kind.INPUT),
			kindsAt(discovery.build(), "0xd3"));
	}

	// ------------------------------------------------------------------
	// Route (c): a copy of an already-established mirror is a save slot
	// ------------------------------------------------------------------

	/**
	 * Establishes {@code $DB} as a {@link BankMirrors.Kind#WRITE_THROUGH} shadow the ordinary
	 * route (a) way -- two distinct store sites alongside two mechanism writes, Mega Man's
	 * {@code $42} shape -- so tests below can exercise route (c)'s forward walk against a source
	 * that genuinely qualifies without re-deriving that qualification each time. Placed at
	 * {@code $8100}-{@code $810B} so callers are free to lay their own copy-site code at
	 * {@code $8000}/{@code $9000} without collision.
	 */
	private BankMirrors.Discovery discoveryWithEstablishedShadow() throws Exception {
		builder.setBytes("0x8100", "a9 05", true); // LDA #$05
		builder.setBytes("0x8102", "85 db", true); // STA $DB
		builder.setBytes("0x8104", "8d 00 c0", true); // STA $C000  <- switch site
		builder.setBytes("0x8107", "a9 06", true); // LDA #$06
		builder.setBytes("0x8109", "85 db", true); // STA $DB
		builder.setBytes("0x810b", "8d 00 c0", true); // STA $C000  <- switch site

		BankMirrors.Discovery discovery = discovery();
		discovery.scanWriteThroughShadows(program, List.of(addr("0x8104"), addr("0x810b")));
		return discovery;
	}

	/**
	 * <b>Blaster Master's {@code $D3}, the headline case route (c) exists for.</b> {@code $DB} is
	 * established as a corroborated {@code WRITE_THROUGH} shadow the ordinary route (a) way, and
	 * separately, in two functions that contain no mechanism write at all, the game does
	 * {@code LDA $DB / STA $D3} -- stashing a copy of the live-tracking shadow. Route (a) cannot
	 * reach either copy site (no mechanism write nearby to walk back from); route (c) is the only
	 * one that can.
	 * <p>
	 * The negative assertion is the point of the test, not a formality: flattening {@code $D3}
	 * into {@code WRITE_THROUGH} would later answer its reload with the LIVE bank, when the whole
	 * reason the game stashed it was that the bank was about to change -- exactly the
	 * confidently-wrong-bank hazard {@link BankMirrors.Kind#SAVE_SLOT} exists to prevent.
	 */
	@Test
	public void aCopyOfAnEstablishedShadowIsASaveSlotNotAWriteThroughMirror() throws Exception {
		BankMirrors.Discovery discovery = discoveryWithEstablishedShadow();

		builder.setBytes("0x8010", "a5 db", true); // LDA $DB
		builder.setBytes("0x8012", "85 d3", true); // STA $D3   <- copy site 1, no switch nearby
		builder.setBytes("0x8020", "a5 db", true); // LDA $DB
		builder.setBytes("0x8022", "85 d3", true); // STA $D3   <- copy site 2, no switch nearby

		discovery.scanSaveSlotCopies(program);
		BankMirrors mirrors = discovery.build();

		assertEquals(Set.of(BankMirrors.Kind.WRITE_THROUGH), kindsAt(mirrors, "0xdb"));
		assertEquals(Set.of(BankMirrors.Kind.SAVE_SLOT), kindsAt(mirrors, "0xd3"));
		assertFalse("flattening the copy into WRITE_THROUGH is the exact failure this rule "
			+ "exists to prevent",
			mirrors.is(addr("0xd3"), BankMirrors.Kind.WRITE_THROUGH));
	}

	/**
	 * <b>TMNT's {@code $59} shape, reached via route (c) instead of route (a).</b> The existing
	 * {@code aCellFilledFromABankReadBackIsASaveSlotNotAShadow} test above pins this same shape
	 * when the {@code LDA $8000 / STA $59} sits on the walk back from a mechanism write; this test
	 * places two occurrences of the identical load/store pair with NO switch site anywhere nearby,
	 * so only route (c) -- which treats every {@code ROM_IDENTIFYING} offset as an unconditional
	 * mirror source via {@code liveMirrorOffsets} -- can classify it. Two occurrences, not one:
	 * {@code walkToCopyDestination} records only a store site, never a corroborating load, so
	 * {@code build()}'s corroboration rule needs a second copy site here exactly as it needs a
	 * second store site from route (a) -- see {@code aSingleUncorroboratedStoreIsNotAShadow} above
	 * for the identical rule on that route.
	 */
	@Test
	public void aCopyFromARomIdentifyingOffsetIsASaveSlotViaRouteC() throws Exception {
		layBankOverlays(4);
		for (int bank = 0; bank < 4; bank++) {
			setBankByte(bank, 0x8000, bank);
		}
		builder.setBytes("0x9000", "ad 00 80", true); // LDA $8000  <- the identifying offset
		builder.setBytes("0x9003", "85 59", true); // STA $59      <- copy site 1, no switch nearby
		builder.setBytes("0x9010", "ad 00 80", true); // LDA $8000
		builder.setBytes("0x9013", "85 59", true); // STA $59      <- copy site 2, no switch nearby

		BankMirrors.Discovery discovery = discovery();
		discovery.addRomIdentifying(identifyingOffsets(4));
		discovery.scanSaveSlotCopies(program);
		BankMirrors mirrors = discovery.build();

		assertEquals(Set.of(BankMirrors.Kind.SAVE_SLOT), kindsAt(mirrors, "0x59"));
	}

	/**
	 * <b>The anti-coincidence guard.</b> {@code $42} has exactly one store site and no
	 * corroborating load feeding a mechanism write, so it does not qualify as a mirror on its own
	 * evidence (the same corroboration rule route (a) itself enforces). A copy out of it must
	 * therefore NOT make its destination a save slot -- {@code liveMirrorOffsets} recomputes from
	 * raw evidence for exactly this reason, rather than trusting that "some cell got stored twice
	 * somewhere" is enough.
	 */
	@Test
	public void aCopyFromAnUncorroboratedCellIsNotASaveSlot() throws Exception {
		builder.setBytes("0x8000", "a9 05", true); // LDA #$05
		builder.setBytes("0x8002", "85 42", true); // STA $42   <- one store, no corroboration
		builder.setBytes("0x8004", "8d 00 c0", true); // STA $C000  <- switch site

		builder.setBytes("0x9000", "a5 42", true); // LDA $42
		builder.setBytes("0x9002", "85 99", true); // STA $99

		BankMirrors.Discovery discovery = discovery();
		discovery.scanWriteThroughShadows(program, List.of(addr("0x8004")));
		discovery.scanSaveSlotCopies(program);
		BankMirrors mirrors = discovery.build();

		assertEquals("an uncorroborated single store does not qualify as a mirror source",
			Set.of(), kindsAt(mirrors, "0x42"));
		assertEquals("so nothing copied from it may be typed a save slot",
			Set.of(), kindsAt(mirrors, "0x99"));
	}

	/**
	 * <b>A save slot cannot seed another save slot.</b> {@code $59} is filled from a bank
	 * READ-BACK (TMNT's shape) and so comes out {@code SAVE_SLOT} with
	 * {@code savedFromReadBack} set; {@code liveMirrorOffsets} excludes exactly that flag from its
	 * source set. A further {@code LDA $59 / STA $77} must therefore not propagate -- if it did,
	 * a chain of stashed copies would each certify the next as live-tracking, which is precisely
	 * backwards.
	 */
	@Test
	public void aSaveSlotCannotSeedAnotherSaveSlot() throws Exception {
		layBankOverlays(4);
		for (int bank = 0; bank < 4; bank++) {
			setBankByte(bank, 0x8000, bank);
		}
		builder.setBytes("0x9000", "ad 00 80", true); // LDA $8000
		builder.setBytes("0x9003", "85 59", true); // STA $59
		builder.setBytes("0x9005", "8d 00 c0", true); // STA $C000   <- switch site
		builder.setBytes("0x9008", "ad 00 80", true); // LDA $8000
		builder.setBytes("0x900b", "85 59", true); // STA $59
		builder.setBytes("0x900d", "8d 00 c0", true); // STA $C000   <- switch site

		builder.setBytes("0x9010", "a5 59", true); // LDA $59   <- $59 is a save slot, not a source
		builder.setBytes("0x9012", "85 77", true); // STA $77

		BankMirrors.Discovery discovery = discovery();
		discovery.addRomIdentifying(identifyingOffsets(4));
		discovery.scanWriteThroughShadows(program, List.of(addr("0x9005"), addr("0x900d")));
		discovery.scanSaveSlotCopies(program);
		BankMirrors mirrors = discovery.build();

		assertEquals(Set.of(BankMirrors.Kind.SAVE_SLOT), kindsAt(mirrors, "0x59"));
		assertEquals("a save slot must not itself seed another save slot", Set.of(),
			kindsAt(mirrors, "0x77"));
	}

	/**
	 * A register clobber between the load off the mirror source and the store into the candidate
	 * destination breaks the copy -- the same walk discipline route (a) enforces on its own
	 * backward scan, mirrored here on the forward one.
	 */
	@Test
	public void aRegisterClobberBetweenLoadAndStoreBreaksTheCopy() throws Exception {
		BankMirrors.Discovery discovery = discoveryWithEstablishedShadow();

		builder.setBytes("0x9000", "a5 db", true); // LDA $DB    <- source
		builder.setBytes("0x9002", "a9 00", true); // LDA #$00   <- clobbers A before the store
		builder.setBytes("0x9004", "85 d3", true); // STA $D3

		discovery.scanSaveSlotCopies(program);
		BankMirrors mirrors = discovery.build();

		assertEquals(Set.of(), kindsAt(mirrors, "0xd3"));
	}

	/**
	 * A control-flow join between the load and the store breaks the copy for the same reason
	 * route (a)'s backward walk refuses one: another path reaches the store with a register value
	 * this walk cannot vouch for. The {@code JMP $9002} makes {@code $9002} reachable other than
	 * by falling through from the load at {@code $9000}.
	 */
	@Test
	public void aControlFlowJoinBetweenLoadAndStoreBreaksTheCopy() throws Exception {
		BankMirrors.Discovery discovery = discoveryWithEstablishedShadow();

		builder.setBytes("0x9000", "a5 db", true); // LDA $DB   <- source
		builder.setBytes("0x9002", "85 d3", true); // STA $D3   <- also reachable from $9010
		builder.setBytes("0x9010", "4c 02 90", true); // JMP $9002

		discovery.scanSaveSlotCopies(program);
		BankMirrors mirrors = discovery.build();

		assertEquals(Set.of(), kindsAt(mirrors, "0xd3"));
	}

	/**
	 * A store into non-writable memory names no cell at all -- "outside the latch range" is
	 * enforced as "in writable memory", the identical rule route (a) applies to its own stores.
	 */
	@Test
	public void aStoreIntoNonWritableMemoryIsNotACopyDestination() throws Exception {
		BankMirrors.Discovery discovery = discoveryWithEstablishedShadow();

		builder.setBytes("0x9000", "a5 db", true); // LDA $DB
		builder.setBytes("0x9002", "8d 20 90", true); // STA $9020   <- ROM, not RAM

		discovery.scanSaveSlotCopies(program);
		BankMirrors mirrors = discovery.build();

		assertEquals(Set.of(), kindsAt(mirrors, "0x9020"));
	}

	/**
	 * The 6502 stack page is refused as a copy destination for {@code StoredValueScanner
	 * .inStackPage}'s reason: a {@code PHA} writes it without naming an address any detector here
	 * can see, so a value forwarded through it could be stale.
	 */
	@Test
	public void aStackPageDestinationIsRefusedAsACopyDestination() throws Exception {
		BankMirrors.Discovery discovery = discoveryWithEstablishedShadow();

		builder.setBytes("0x9000", "a5 db", true); // LDA $DB
		builder.setBytes("0x9002", "8d 40 01", true); // STA $0140   <- stack page

		discovery.scanSaveSlotCopies(program);
		BankMirrors mirrors = discovery.build();

		assertEquals(Set.of(), kindsAt(mirrors, "0x140"));
	}

	/**
	 * <b>One cell, both roles -- Blaster Master's {@code $D3} in full.</b> The same address is
	 * loaded as a bank ARGUMENT before two switch-helper calls (route (b), typed {@code INPUT})
	 * AND filled by copying the {@code $DB} shadow at TWO separate sites (route (c), typed
	 * {@code SAVE_SLOT} -- two sites because {@code walkToCopyDestination} records only a store,
	 * never a corroborating load, so {@code build()}'s corroboration rule needs the second site the
	 * same way it needs a second store site from route (a)). The bead's whole point about
	 * {@code $D3} is that provenance is carried, not flattened, so both kinds must survive at the
	 * one offset -- and route (c) must run after route (b) without disturbing what it found.
	 */
	@Test
	public void oneCellCanCarryBothAnInputAndASaveSlotRole() throws Exception {
		builder.setBytes("0x8000", "a5 d3", true); // LDA $D3
		builder.setBytes("0x8002", "20 00 90", true); // JSR $9000
		builder.setBytes("0x8010", "a5 d3", true); // LDA $D3
		builder.setBytes("0x8012", "20 00 90", true); // JSR $9000

		builder.setBytes("0x8020", "a9 05", true); // LDA #$05
		builder.setBytes("0x8022", "85 db", true); // STA $DB
		builder.setBytes("0x8024", "8d 00 c0", true); // STA $C000   <- switch site
		builder.setBytes("0x8027", "a9 06", true); // LDA #$06
		builder.setBytes("0x8029", "85 db", true); // STA $DB
		builder.setBytes("0x802b", "8d 00 c0", true); // STA $C000   <- switch site

		builder.setBytes("0x8030", "a5 db", true); // LDA $DB   <- copy site 1, into the SAME cell
		builder.setBytes("0x8032", "85 d3", true); // STA $D3      as the input
		builder.setBytes("0x8040", "a5 db", true); // LDA $DB   <- copy site 2
		builder.setBytes("0x8042", "85 d3", true); // STA $D3

		Map<Address, Character> sites = new LinkedHashMap<>();
		sites.put(addr("0x8002"), 'A');
		sites.put(addr("0x8012"), 'A');
		BankMirrors.Discovery discovery = discovery();
		discovery.scanWriteThroughShadows(program, List.of(addr("0x8024"), addr("0x802b")));
		discovery.scanArgumentCells(program, sites);
		// Route (c) LAST and deliberately so, exactly as BoardBankAnalyzer.deriveBankMirrors
		// orders it: "already established as mirroring" is only knowable once (a) and (b) ran.
		discovery.scanSaveSlotCopies(program);
		BankMirrors mirrors = discovery.build();

		assertEquals(Set.of(BankMirrors.Kind.WRITE_THROUGH), kindsAt(mirrors, "0xdb"));
		assertEquals(Set.of(BankMirrors.Kind.INPUT, BankMirrors.Kind.SAVE_SLOT),
			kindsAt(mirrors, "0xd3"));
	}

	// Note: "neither INPUT nor SAVE_SLOT resolves from tracked in-state" is a CONSUMPTION rule,
	// not a derivation one -- it is already pinned directly against MemoryLatchBankSwitchStrategy
	// by BankMirrorConsumptionProgramTest's saveSlotMirrorDeclinesEvenWithAFullyKnownInState and
	// inputMirrorDeclinesEvenWithAFullyKnownInState. Re-asserting it here, against a mirror set
	// this file never hands to a strategy, would not exercise anything those two do not already
	// cover, so it is intentionally left out of this file.

	// ------------------------------------------------------------------
	// The empty case
	// ------------------------------------------------------------------

	/** A board with nothing to find yields the shared empty set, which matches no address. */
	@Test
	public void aProgramWithNoMirrorsYieldsTheEmptySet() throws Exception {
		BankMirrors mirrors = discovery().build();

		assertTrue(mirrors.isEmpty());
		assertEquals(Set.of(), mirrors.kindsAt(addr("0x42")));
		assertEquals(BankMirrors.none().isEmpty(), mirrors.isEmpty());
	}
}
