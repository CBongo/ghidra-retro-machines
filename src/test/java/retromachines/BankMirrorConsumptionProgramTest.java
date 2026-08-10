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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Pins {@link MemoryLatchBankSwitchStrategy}'s CONSUMPTION of a {@link BankMirrors} set (bead
 * grm-mej.2, increment 2): given that some address is stated outright to mirror the live bank,
 * what does a load of it resolve to, and -- just as load-bearing -- when must it decline rather
 * than answer.
 * <p>
 * Mirror sets here are stated directly via the package-private {@link BankMirrors#of}, never
 * derived: derivation is {@link BankMirrors.Discovery}'s own concern, pinned separately by
 * {@link BankMirrorDerivationProgramTest}. Keeping the two apart is what stops a consumption
 * regression from hiding behind a derivation one, and vice versa.
 * <p>
 * Fixture note inherited from {@link MemoryLatchStrategyProgramTest}: {@link ProgramBuilder}
 * blocks are created read-only, so the zero page has to be made writable explicitly, and PRG has
 * to be told it is ROM explicitly too even though that already matches the default -- a test that
 * asserts a recovered ROM byte should not rest silently on an unstated default.
 */
public class BankMirrorConsumptionProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private MemoryBlock prg;
	private AddressSpace baseSpace;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		prg = builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		baseSpace = program.getAddressFactory().getDefaultAddressSpace();
		makeWritable(zp);
		romifyPrg();
	}

	// ------------------------------------------------------------------
	// Scaffolding -- copied in spirit from MemoryLatchStrategyProgramTest
	// ------------------------------------------------------------------

	/** A discrete-mapper latch (UxROM/Contra/Mega Man shape): {@code shift=0}, one nibble wide. */
	private MemoryLatchBankSwitchStrategy discreteLatch() {
		return latch(0x0F, 0);
	}

	/**
	 * A GxROM-shaped latch: the PRG field is 2 bits wide, sitting at bits 4-5 of the written byte
	 * ({@code shift=4}). This is the board the coordinate-conversion test below exists for.
	 */
	private MemoryLatchBankSwitchStrategy gxromLatch() {
		return latch(0x3, 4);
	}

	/** A latch whose field is the whole written byte -- what {@code ORA}-path tests need. */
	private MemoryLatchBankSwitchStrategy fullByteLatch() {
		return latch(0xFF, 0);
	}

	private MemoryLatchBankSwitchStrategy latch(int mask, int shift) {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.addProperty("mask", mask);
		params.addProperty("shift", shift);
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, 0xFF);
		return strategy;
	}

	/** States a mirror set outright -- see {@link BankMirrors#of}'s javadoc for why this route
	 *  exists rather than running {@link BankMirrors.Discovery}. */
	private BankMirrors mirrorsOf(long offset, BankMirrors.Kind... kinds) {
		return BankMirrors.of(baseSpace, Map.of(offset, Set.of(kinds)));
	}

	/** Redundant with {@link ProgramBuilder}'s own default (see {@link #setUp}), kept anyway so a
	 *  test asserting a recovered ROM byte does not rest silently on that default. */
	private void romifyPrg() {
		setWritable(prg, false);
	}

	private void makeWritable(MemoryBlock block) {
		setWritable(block, true);
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

	private Instruction instructionAt(String address) {
		return instructionAt(builder.addr(address));
	}

	private Instruction instructionAt(Address address) {
		Instruction instr = program.getListing().getInstructionAt(address);
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	// ------------------------------------------------------------------
	// 1. The coordinate conversion
	// ------------------------------------------------------------------

	/**
	 * <b>THE COORDINATE CONVERSION -- the single most important case in this increment.</b>
	 * {@link MemoryLatchBankSwitchStrategy#mirroredByte} receives {@code inStateAtStore} in
	 * FIELD-LOCAL {@code [0, width)} coordinates and must answer in RAW WRITTEN BYTE
	 * coordinates, because {@link StoredValueScanner} folds the {@code (byte >> shift) & mask}
	 * extraction back out afterward at {@code evaluateLatch}'s deposit step. GxROM
	 * ({@code shift=4}, {@code mask=0x3}) is the shape that makes a mistake here visible: with
	 * field-local {@code prg=2}, {@code LDA $42 / STA $8000} must resolve to field-local {@code 2}
	 * again, round trip intact.
	 * <p>
	 * <b>What omitting the {@code << shift} costs depends on the board's geometry</b>, and
	 * {@code mirroredByte}'s javadoc works both halves: the known bits would land at byte
	 * positions {@code [0, width)} while the deposit step reads back {@code [shift, shift+width)}.
	 * On GxROM those ranges are disjoint ({@code shift} 4, width 2), so the answer would degrade
	 * to wholly unknown -- lost recovery, but safe. On a board where they OVERLAP
	 * ({@code shift < width}) the surviving bits form a partially-known WRONG bank with no
	 * warning, which is the failure this conversion really exists to prevent. Pinning the round
	 * trip on GxROM catches both, because both start from the same missing shift.
	 */
	@Test
	public void writeThroughMirrorConvertsThroughTheLatchsShift() throws Exception {
		MemoryLatchBankSwitchStrategy latch = gxromLatch();
		latch.observeMirrors(mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH));

		builder.setBytes("0x8000", "a5 42", true); // LDA $42
		builder.setBytes("0x8002", "8d 00 80", true); // STA $8000

		BankState result = latch.computeSwitch(program, instructionAt("0x8002"),
			BankState.fullyKnown(0x3, 2)); // field-local prg=2

		assertNotNull(result);
		assertEquals("the field-local coordinate must round-trip through << shift and >> shift",
			0x3, result.knownMask());
		assertEquals(2, result.bits());
	}

	/**
	 * The other half of the conversion hazard, and the half that fails UNSAFELY: a field wider
	 * than its own shift ({@code shift=1}, 3 bits wide), where dropping the {@code << shift} leaves
	 * the two bit ranges OVERLAPPING instead of disjoint.
	 * <p>
	 * GxROM above cannot catch this on its own. There {@code shift >= width}, so a missing shift
	 * degrades to wholly unknown -- a decline, which is safe. Here the ranges overlap, so the
	 * surviving bits would come back as a partially-known bank that is simply WRONG: field-local 5
	 * would be reported as 2 with bits 0-1 marked KNOWN, no warning raised, references retargeted
	 * into the wrong overlay with confidence. Both cases start from the same missing shift, so
	 * either would catch a regression; only this one shows what the regression actually costs.
	 * <p>
	 * No shipped descriptor has this geometry today. It is pinned anyway because the conversion is
	 * written against {@code shift} in general, not against the two boards that currently use it.
	 */
	@Test
	public void writeThroughMirrorRoundTripsWhenTheFieldIsWiderThanItsShift() throws Exception {
		MemoryLatchBankSwitchStrategy latch = latch(0x7, 1); // 3-bit field at bits 1-3
		latch.observeMirrors(mirrorsOf(0x44, BankMirrors.Kind.WRITE_THROUGH));

		builder.setBytes("0x8000", "a5 44", true); // LDA $44
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000

		BankState result =
			latch.computeSwitch(program, instructionAt("0x8002"), BankState.fullyKnown(0x7, 5));

		assertNotNull(result);
		assertEquals("a missing shift here would report a partially-known WRONG bank, not decline",
			0x7, result.knownMask());
		assertEquals(5, result.bits());
	}

	// ------------------------------------------------------------------
	// 2. Plain WRITE_THROUGH resolution
	// ------------------------------------------------------------------

	/** On a {@code shift=0} board a {@code WRITE_THROUGH} mirror resolves straight to the tracked
	 *  in-state -- the base case every other test in this file is a variation on. */
	@Test
	public void writeThroughMirrorResolvesToTheTrackedBankOnAShiftZeroBoard() throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH));

		builder.setBytes("0x8000", "a5 42", true); // LDA $42
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000

		BankState result =
			latch.computeSwitch(program, instructionAt("0x8002"), BankState.fullyKnown(0x0F, 5));

		assertNotNull(result);
		assertEquals(0x0F, result.knownMask());
		assertEquals(5, result.bits());
	}

	// ------------------------------------------------------------------
	// 3. ROM_IDENTIFYING's byteShift asymmetry
	// ------------------------------------------------------------------

	/**
	 * {@code ROM_IDENTIFYING} always converts with {@code byteShift == 0} -- Contra's {@code $8000}
	 * reads {@code 00 01 02 ...} across banks 0..7, the bank number right-justified by cartridge
	 * convention, never shifted -- whereas {@code WRITE_THROUGH} converts at {@code byteShift ==
	 * shift}. That asymmetry is deliberate (see {@code mirroredByte}'s javadoc), and this pins both
	 * halves of it:
	 * <ul>
	 * <li>on a {@code shift=0} board the two byteShifts coincide, so {@code ROM_IDENTIFYING}
	 * resolves straight to the in-state value, indistinguishable from {@code WRITE_THROUGH} there
	 * (case 2 above);</li>
	 * <li>on a {@code shift!=0} board (GxROM) {@code ROM_IDENTIFYING} DECLINES OUTRIGHT, so a
	 * mirror load that resolves cleanly under {@code WRITE_THROUGH} (case 1 above, same in-state)
	 * comes back with nothing known at all.</li>
	 * </ul>
	 * <b>The decline is deliberate and the assertion below distinguishes it from the erasure it
	 * used to be</b> (grm-mej.2 increment 3). Before the identifying byte's upper bits were
	 * derived as known zero, this case came back unknown by accident: the known bits landed at
	 * byte positions {@code [0, width)} while the extraction read {@code [shift, shift+width)}, and
	 * the two ranges are disjoint on GxROM. Once the upper bits are PROVED zero (byte == bank),
	 * that same synthesis would put KNOWN ZEROES exactly where the extraction reads and report a
	 * confident {@code bank 0} -- valid-looking, unwarned, wrong overlay. So {@code mirroredByte}
	 * now refuses the combination explicitly. The extra
	 * {@code effectDependsOnPriorState} assertion is what tells the two apart: a declined mirror
	 * was never consulted, an erased one was.
	 * <p>
	 * No real cartridge is known to combine {@code shift != 0} with a bare
	 * {@code LDA <ident> / STA <latch>} -- a game on such a board must shift the number into place
	 * first, and the scan loses the value at that shift instruction anyway -- so this is a
	 * mechanical demonstration of the rule, not a reproduction.
	 */
	@Test
	public void romIdentifyingConvertsWithNoShiftUnlikeWriteThrough() throws Exception {
		MemoryLatchBankSwitchStrategy shiftZero = discreteLatch();
		shiftZero.observeMirrors(mirrorsOf(0x50, BankMirrors.Kind.ROM_IDENTIFYING));
		builder.setBytes("0x8000", "a5 50", true); // LDA $50
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000

		BankState onShiftZero = shiftZero.computeSwitch(program, instructionAt("0x8002"),
			BankState.fullyKnown(0x0F, 7));

		assertNotNull(onShiftZero);
		assertEquals("byteShift 0 coincides with the board's own shift 0", 0x0F,
			onShiftZero.knownMask());
		assertEquals(7, onShiftZero.bits());

		MemoryLatchBankSwitchStrategy gxrom = gxromLatch();
		gxrom.observeMirrors(mirrorsOf(0x51, BankMirrors.Kind.ROM_IDENTIFYING));
		builder.setBytes("0x8010", "a5 51", true); // LDA $51
		builder.setBytes("0x8012", "8d 00 80", true); // STA $8000

		BankState onGxrom = gxrom.computeSwitch(program, instructionAt("0x8012"),
			BankState.fullyKnown(0x3, 2)); // same field-local value as case 1's WRITE_THROUGH

		assertNotNull(onGxrom);
		assertEquals(
			"ROM_IDENTIFYING on a shift=4 board must NOT reproduce WRITE_THROUGH's clean round "
				+ "trip (case 1) under the identical in-state",
			0x0, onGxrom.knownMask());
		assertFalse(
			"and it must come back unknown because the mirror DECLINED, not because a synthesized "
				+ "byte was erased by the extraction -- with the upper bits proved zero, "
				+ "synthesizing here would report a confident bank 0",
			gxrom.effectDependsOnPriorState(program, instructionAt("0x8012"),
				BankState.fullyKnown(0x3, 2)));
	}

	// ------------------------------------------------------------------
	// 4 & 5. Kinds that must decline
	// ------------------------------------------------------------------

	/**
	 * {@code SAVE_SLOT} must decline wholly, never answering from in-state. TMNT's {@code cec0}
	 * does {@code LDA $8000 / STA $59} precisely BECAUSE it is about to change the bank -- so at
	 * the later reload, in-state already reflects the NEW bank while {@code $59} holds the OLD one
	 * being restored. Answering from in-state there would ship a confidently wrong bank, which
	 * this engine rates strictly worse than no bank at all.
	 */
	@Test
	public void saveSlotMirrorDeclinesEvenWithAFullyKnownInState() throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x59, BankMirrors.Kind.SAVE_SLOT));

		builder.setBytes("0x8000", "a5 59", true); // LDA $59
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000

		BankState result =
			latch.computeSwitch(program, instructionAt("0x8002"), BankState.fullyKnown(0x0F, 3));

		assertNotNull(result);
		assertEquals("a save slot must never resolve as a live-bank mirror", 0x00,
			result.knownMask());
	}

	/**
	 * {@code INPUT} must decline the same way. Blaster Master's {@code $D3} holds the bank a
	 * caller is ASKING for, out of five call sites across five functions with no mechanism write
	 * of their own -- it becomes the live bank only once the wrapper actually runs, so reading it
	 * back as "the current bank" before that point is the same confidently-wrong-bank hazard as
	 * {@code SAVE_SLOT}.
	 */
	@Test
	public void inputMirrorDeclinesEvenWithAFullyKnownInState() throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0xD3, BankMirrors.Kind.INPUT));

		builder.setBytes("0x8000", "a5 d3", true); // LDA $D3
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000

		BankState result =
			latch.computeSwitch(program, instructionAt("0x8002"), BankState.fullyKnown(0x0F, 4));

		assertNotNull(result);
		assertEquals("an input mirror holds the REQUESTED bank, not yet the live one", 0x00,
			result.knownMask());
	}

	// ------------------------------------------------------------------
	// 6. The control: not a mirror at all
	// ------------------------------------------------------------------

	/** An address the mirror set says nothing about declines exactly as it always did, before
	 *  mirrors existed at all -- the control every kind-specific case above is measured against. */
	@Test
	public void nonMirrorAddressDeclines() throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH)); // unrelated cell

		builder.setBytes("0x8000", "a5 60", true); // LDA $60 -- not a mirror
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000

		BankState result =
			latch.computeSwitch(program, instructionAt("0x8002"), BankState.fullyKnown(0x0F, 9));

		assertNotNull(result);
		assertEquals(0x00, result.knownMask());
	}

	// ------------------------------------------------------------------
	// 7. H1 ordering: local forwarding outranks the mirror
	// ------------------------------------------------------------------

	/**
	 * <b>H1: local store-to-load forwarding (grm-mej.1) OUTRANKS the mirror.</b> Castlevania 2's
	 * shape is exactly this:
	 * <pre>
	 *   LDA #$05    ; the NEW bank, only in A so far
	 *   STA $1C     ; shadow written -- $1C now holds the new bank
	 *   LDA $1C     ; &lt;-- reads the shadow back
	 *   STA $C000   ; commit
	 * </pre>
	 * In the gap between the {@code STA $1C} and the commit, the shadow holds the NEW bank while
	 * tracked in-state -- computed from everything that ran BEFORE this chain -- still holds the
	 * OLD one. {@link StoredValueScanner.Hooks#resolveMirrorLoad} is deliberately ranked below
	 * forwarding for this reason: answering the mirror first would preempt the correct forwarded
	 * value with a stale in-state. The in-state below is seeded with a bank (9) that disagrees with
	 * the forwarded value (5) precisely so a wrong precedence would be caught, not accidentally
	 * matched.
	 */
	@Test
	public void localForwardingOutranksTheMirror() throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x1C, BankMirrors.Kind.WRITE_THROUGH));

		builder.setBytes("0x8000", "a9 05", true); // LDA #$05     -- the new bank
		builder.setBytes("0x8002", "85 1c", true); // STA $1C      -- shadow write
		builder.setBytes("0x8004", "a5 1c", true); // LDA $1C      -- reload the shadow
		builder.setBytes("0x8006", "8d 00 c0", true); // STA $C000 -- commit

		BankState result = latch.computeSwitch(program, instructionAt("0x8006"),
			BankState.fullyKnown(0x0F, 9)); // stale in-state, deliberately disagreeing

		assertNotNull(result);
		assertEquals("the forwarded NEW value must win, not the stale in-state the mirror would "
			+ "have answered with", 0x0F, result.knownMask());
		assertEquals(5, result.bits());
	}

	// ------------------------------------------------------------------
	// 8. resolveLoad still outranks the mirror
	// ------------------------------------------------------------------

	/**
	 * A bank-invariant ROM byte still wins over a mirror answer at the SAME address, because
	 * {@link StoredValueScanner.Hooks#resolveLoad} is consulted first and short-circuits before
	 * forwarding or the mirror are ever asked: nothing can store to non-writable memory, so
	 * forwarding (and by the same argument, the mirror) can never have a better answer to preempt
	 * it with. The mirror kind here is chosen so that, were the ordering wrong, it would answer a
	 * DIFFERENT value than the ROM byte -- so a precedence bug would show up as a wrong number, not
	 * a coincidental match.
	 */
	@Test
	public void bankInvariantRomByteStillOutranksTheMirror() throws Exception {
		builder.setBytes("0x9000", "07"); // the bank-invariant ROM byte at $9000
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x9000, BankMirrors.Kind.WRITE_THROUGH));

		builder.setBytes("0x8000", "ad 00 90", true); // LDA $9000
		builder.setBytes("0x8003", "8d 00 c0", true); // STA $C000

		BankState result = latch.computeSwitch(program, instructionAt("0x8003"),
			BankState.fullyKnown(0x0F, 2)); // disagrees with the ROM byte on purpose

		assertNotNull(result);
		assertEquals("the ROM byte answers first -- the mirror is never consulted", 0x0F,
			result.knownMask());
		assertEquals(7, result.bits());
	}

	// ------------------------------------------------------------------
	// 9. A wholly-unknown in-state still yields a non-null mirror answer
	// ------------------------------------------------------------------

	/**
	 * A mirror load consulted under a WHOLLY UNKNOWN in-state must still produce a NON-NULL
	 * result -- wholly unknown, but not the Java {@code null} that means "this hook has nothing to
	 * say". {@link StoredValueScanner.Hooks#resolveMirrorLoad}'s javadoc calls this out
	 * explicitly: a non-null-but-unknown answer means "this site read the bank back and the bank
	 * was not known here", which is exactly the signal
	 * {@link MemoryLatchBankSwitchStrategy#effectDependsOnPriorState(ghidra.program.model.listing.Program,
	 * Instruction, BankState)} needs (pinned directly in case 12 below) to tell "needed the bank
	 * on entry and didn't have it" apart from "never consulted a mirror at all".
	 */
	@Test
	public void mirrorLoadUnderWhollyUnknownInStateIsNonNullAndUnknown() throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH));

		builder.setBytes("0x8000", "a5 42", true); // LDA $42
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000

		BankState result =
			latch.computeSwitch(program, instructionAt("0x8002"), BankState.unknown());

		assertNotNull("a consulted mirror must answer non-null even when wholly unknown", result);
		assertEquals(0x00, result.knownMask());
	}

	// ------------------------------------------------------------------
	// 10. Overlay-space normalization
	// ------------------------------------------------------------------

	/**
	 * <b>A mirror load executed from INSIDE an overlay block still resolves.</b> The mirror set is
	 * keyed by base-space offset ({@code BankMirrors}'s class javadoc), so a load whose operand
	 * address is expressed in a {@code PRG_LO_B<n>} overlay space -- as code physically running
	 * from inside that overlay produces -- has to be normalized through
	 * {@link AddressSpace#getPhysicalSpace()} before the lookup, exactly as
	 * {@code MemoryLatchBankSwitchStrategy.inLatchRange} already does for the mechanism-write side.
	 * <p>
	 * The failure mode if that normalization were dropped is a SILENT DECLINE: the load would
	 * simply come back unknown, indistinguishable from "not a mirror", and no NON-overlay fixture
	 * would ever exercise the code path that could catch it -- every synthetic and real-ROM
	 * fixture that doesn't specifically bank-switch into an overlay would stay green.
	 * <p>
	 * The identifying offset is placed at {@code $8000}, inside the switchable window, so this
	 * doubles as a reminder that {@code ROM_IDENTIFYING} offsets -- unlike RAM shadows -- actually
	 * live in the overlaid range and so are the kind most exposed to this bug.
	 */
	@Test
	public void mirrorLoadFromInsideAnOverlayStillResolves() throws Exception {
		MemoryBlock overlay = builder.createOverlayMemory("PRG_LO_B1", "0x8000", 0x4000);
		// configure() snapshots overlay-covered ranges at construction time, so the overlay
		// must exist before the strategy is built -- this also removes $8000 from
		// bankInvariantRomByte's reach, forcing resolveLoad to decline and the mirror path to
		// actually be exercised rather than preempted by the ROM-byte answer (case 8).
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x8000, BankMirrors.Kind.ROM_IDENTIFYING));

		Address site = overlay.getStart();
		builder.setBytes(site.toString(), "ad 00 80", true); // LDA $8000, from inside the overlay
		Address storeSite = site.getAddressSpace().getAddress(0x8003);
		builder.setBytes(storeSite.toString(), "8d 10 80", true); // STA $8010, also in the overlay

		Instruction store = instructionAt(storeSite);

		BankState result = latch.computeSwitch(program, store, BankState.fullyKnown(0x0F, 6));

		assertNotNull("a mirror load from inside the overlay must not silently decline", result);
		assertEquals(0x0F, result.knownMask());
		assertEquals(6, result.bits());
	}

	// ------------------------------------------------------------------
	// 11. cacheable() and the state-dependence it now admits
	// ------------------------------------------------------------------

	/**
	 * The positive half of {@code MemoryLatchStrategyProgramTest
	 * .computeSwitchIsIndependentOfInStateWithoutMirrors}: WITH a mirror actually observed and
	 * consulted, {@code computeSwitch} genuinely depends on {@code inState} -- two different
	 * in-states at the identical site give different answers -- so memoizing by address alone (as a
	 * {@code cacheable() == true} strategy would license) would be unsound. {@link
	 * MemoryLatchBankSwitchStrategy#cacheable()} must report {@code false} unconditionally, not
	 * merely when this particular board happens to have a mirror, since the strategy has no way to
	 * ask "does THIS query touch one" before running it.
	 */
	@Test
	public void computeSwitchDependsOnInStateWithAMirrorAndCacheableIsFalse() throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH));

		builder.setBytes("0x8000", "a5 42", true); // LDA $42
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000
		Instruction store = instructionAt("0x8002");

		BankState fromThree = latch.computeSwitch(program, store, BankState.fullyKnown(0x0F, 3));
		BankState fromNine = latch.computeSwitch(program, store, BankState.fullyKnown(0x0F, 9));

		assertNotEquals("two in-states at the same site must give different answers when a "
			+ "mirror is consulted -- memoizing either would be unsound", fromThree, fromNine);
		assertFalse(latch.cacheable());
	}

	// ------------------------------------------------------------------
	// 12. effectDependsOnPriorState(program, site, siteInState) -- the 2d guard
	// ------------------------------------------------------------------

	/**
	 * True at a site that actually resolved (or attempted, per case 9) a mirror load. This is the
	 * ordinary "needed the bank on entry" signal the per-site override exists to report.
	 */
	@Test
	public void effectDependsOnPriorStateIsTrueAtASiteThatConsultsAMirror() throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH));

		builder.setBytes("0x8000", "a5 42", true); // LDA $42
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000
		Instruction site = instructionAt("0x8002");

		assertTrue(latch.effectDependsOnPriorState(program, site, BankState.unknown()));
	}

	/**
	 * <b>False at a site that came out unknown for an UNRELATED reason.</b> Mega Man's
	 * {@code FUN_c39c} fails to resolve because it reads {@code $31}, a stateful counter -- not
	 * because it needed the bank on entry. The board here genuinely has a mirror ({@code $42}, an
	 * unrelated cell), so this is not the empty-mirror-set case (case below); it is specifically
	 * "this site's own load target is not one of them". Getting this wrong would make the flip to
	 * {@code cacheable() == false} emit a fresh violation WARNING at every such site across all
	 * twelve real-ROM goldens, none of which would be a real finding.
	 */
	@Test
	public void effectDependsOnPriorStateIsFalseWhenTheSiteFailsForAnUnrelatedReason()
			throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH)); // unrelated cell

		builder.setBytes("0x8000", "a5 31", true); // LDA $31 -- Mega Man's stateful counter
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000
		Instruction site = instructionAt("0x8002");

		assertFalse(latch.effectDependsOnPriorState(program, site, BankState.unknown()));
	}

	/** False when the observed mirror set is empty outright -- the cheap short-circuit that keeps
	 *  every board with no derivable mirror byte-identical to its pre-grm-mej.2 behavior. */
	@Test
	public void effectDependsOnPriorStateIsFalseWhenNoMirrorsAreObserved() throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch(); // observeMirrors never called

		builder.setBytes("0x8000", "a5 42", true); // LDA $42
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000
		Instruction site = instructionAt("0x8002");

		assertFalse(latch.effectDependsOnPriorState(program, site, BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 13. The operandByte (ORA) path
	// ------------------------------------------------------------------

	/**
	 * A mirror spliced in through an {@code ORA} operand resolves the same as a straight load does
	 * -- {@link StoredValueScanner}'s {@code operandByte} consults
	 * {@link StoredValueScanner.Hooks#resolveMirrorLoad} for exactly this reason (Ironsword's
	 * {@code STA $C3 ... ORA $C3 / STA $8000} splices a shadow back in rather than loading it).
	 * <b>The rule is all-or-nothing</b>: the mask algebra composing an {@code ORA} operand into the
	 * accumulator has no way to express "this bit was unknown", so only a FULL-BYTE mirror (a
	 * latch whose field spans the whole byte, {@code mask=0xFF}) can contribute at all -- a
	 * companion assertion below pins that a narrower field's mirror contributes nothing through
	 * {@code ORA}, declining the whole store rather than partially answering it.
	 */
	@Test
	public void orasOperandConsultsTheMirrorOnlyWhenItSpansTheWholeByte() throws Exception {
		MemoryLatchBankSwitchStrategy fullByte = fullByteLatch();
		fullByte.observeMirrors(mirrorsOf(0x42, BankMirrors.Kind.WRITE_THROUGH));

		builder.setBytes("0x8000", "a9 00", true); // LDA #$00
		builder.setBytes("0x8002", "05 42", true); // ORA $42
		builder.setBytes("0x8004", "8d 00 c0", true); // STA $C000

		BankState result = fullByte.computeSwitch(program, instructionAt("0x8004"),
			BankState.fullyKnown(0xFF, 0x0A));

		assertNotNull(result);
		assertEquals("a full-byte mirror must contribute through ORA", 0xFF, result.knownMask());
		assertEquals(0x0A, result.bits());

		// Companion: the identical shape, but the latch's field is one nibble wide (mask=0x0F).
		// mirroredByte can never report all 8 bits known on such a board, so operandByte's
		// all-or-nothing rule must refuse it -- the whole store declines rather than answering
		// with a partial byte.
		MemoryLatchBankSwitchStrategy narrow = discreteLatch();
		narrow.observeMirrors(mirrorsOf(0x43, BankMirrors.Kind.WRITE_THROUGH));

		builder.setBytes("0x8010", "a9 00", true); // LDA #$00
		builder.setBytes("0x8012", "05 43", true); // ORA $43
		builder.setBytes("0x8014", "8d 00 c0", true); // STA $C000

		BankState narrowResult = narrow.computeSwitch(program, instructionAt("0x8014"),
			BankState.fullyKnown(0x0F, 0x0A));

		assertNotNull(narrowResult);
		assertEquals("a mirror narrower than the whole byte must contribute nothing through ORA",
			0x00, narrowResult.knownMask());
	}
}
