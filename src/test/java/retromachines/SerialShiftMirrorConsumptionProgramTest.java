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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;

/**
 * Pins {@link SerialShiftBankSwitchStrategy}'s CONSUMPTION of a {@link BankMirrors} set
 * (bead grm-mej.2 increment 3): MMC1 commits a 5-bit value through five unrolled
 * {@code STA}/{@code LSR A} writes, and bit 7 of the byte {@link #computeSwitch} reconstructs
 * for the FIRST of those five is an out-of-band RESET signal on real hardware -- so
 * {@code computeSwitch} refuses to believe any byte whose bit 7 it cannot resolve and poisons
 * every tracked field instead ({@code bit7Known} in the class javadoc's "Chain-walk algorithm").
 * A chain's write 1 is not preceded by {@code LSR A}, so it takes the general backward value
 * scan -- and only {@link BankMirrors.Kind#ROM_IDENTIFYING} can supply a byte whose bit 7 is
 * PROVED zero (byte == bank, so everything above the bank's own field is a proved zero too).
 * {@link BankMirrors.Kind#WRITE_THROUGH} cannot, and is deliberately not admitted here -- see
 * {@link SerialShiftBankSwitchStrategy#mirroredByte}'s javadoc.
 * <p>
 * Mirror sets here are stated directly via the package-private {@link BankMirrors#of}, exactly
 * as {@link BankMirrorConsumptionProgramTest} does for memory-latch -- derivation is
 * {@link BankMirrors.Discovery}'s own concern and is not re-proved here.
 * <p>
 * <b>Fixture shape.</b> Every chain is the real unrolled shape: one pre-chain load, then five
 * {@code STA <target>} each but the first preceded by {@code LSR A}, all five writes landing on
 * the SAME address (which is what every surveyed commercial game does -- see the strategy class
 * javadoc). {@link #buildChain} lays this out and returns write 1's and write 5's addresses,
 * since the engine visits every write of the chain independently: a commit is asserted at write
 * 5 (where {@link SerialShiftBankSwitchStrategy#computeSwitch} actually deposits), while a
 * bit-7-gate failure is asserted at write 1 (where the gate that fails actually runs -- writes
 * 2-5 skip it entirely via the {@code precededByLsrA} shortcut, so probing write 5 directly for
 * a declined gate would show only that write 5's own OWN field failed to resolve, not that
 * every tracked field was poisoned).
 */
public class SerialShiftMirrorConsumptionProgramTest extends AbstractBundledLanguageTest {

	/** mirroring(2) | prg_mode(2) | prg_bank(5), matching machines/nes-mmc1.yaml. */
	private static final int STATE_MASK = 0x1FF;
	/** {@code prg_bank}'s field-local bit range: lsb 4, width 5. */
	private static final int PRG_BANK_MASK = 0x1F0;
	/** Control target's address (bits 14:13 = 0). */
	private static final int CONTROL_OFFSET = 0x8000;
	/** CHR0 target's address (bits 14:13 = 1) -- unconfigured in {@link #mmc1()}. */
	private static final int CHR0_OFFSET = 0xA000;
	/** PRG target's address (bits 14:13 = 3). */
	private static final int PRG_OFFSET = 0xE000;

	private ProgramBuilder builder;
	private ProgramDB program;
	private AddressSpace baseSpace;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		baseSpace = program.getAddressFactory().getDefaultAddressSpace();
	}

	// ------------------------------------------------------------------
	// Scaffolding -- copied in spirit from SerialShiftStrategyProgramTest
	// ------------------------------------------------------------------

	private static JsonObject pos(int lsb, int width) {
		JsonObject o = new JsonObject();
		o.addProperty("lsb", lsb);
		o.addProperty("width", width);
		return o;
	}

	private static JsonObject field(String name, int shift, int bits) {
		JsonObject o = new JsonObject();
		o.addProperty("name", name);
		o.addProperty("shift", shift);
		o.addProperty("bits", bits);
		return o;
	}

	private static JsonObject target(JsonObject... fields) {
		JsonArray arr = new JsonArray();
		for (JsonObject f : fields) {
			arr.add(f);
		}
		JsonObject o = new JsonObject();
		o.add("fields", arr);
		return o;
	}

	/** The real MMC1 mechanism: whole-range serial port, Control + PRG targets, bit-7 reset.
	 *  CHR0/CHR1 (targets 1 and 2) are deliberately left unconfigured, matching the shipped
	 *  descriptor. */
	private SerialShiftBankSwitchStrategy mmc1() {
		JsonObject layout = new JsonObject();
		layout.add("mirroring", pos(0, 2));
		layout.add("prg_mode", pos(2, 2));
		layout.add("prg_bank", pos(4, 5));

		JsonObject targets = new JsonObject();
		targets.add("0", target(field("mirroring", 0, 2), field("prg_mode", 2, 2)));
		targets.add("3", target(field("prg_bank", 0, 5)));

		JsonObject reset = new JsonObject();
		reset.addProperty("prg_mode", 3);

		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.add("_field_layout", layout);
		params.add("targets", targets);
		params.add("reset", reset);

		SerialShiftBankSwitchStrategy strategy = new SerialShiftBankSwitchStrategy();
		strategy.configure(program, params, STATE_MASK);
		return strategy;
	}

	/** States a mirror set outright -- see {@link BankMirrors#of}'s javadoc for why this route
	 *  exists rather than running {@link BankMirrors.Discovery}. */
	private BankMirrors mirrorsOf(long offset, BankMirrors.Kind... kinds) {
		return BankMirrors.of(baseSpace, Map.of(offset, Set.of(kinds)));
	}

	/** {@code prg_bank} known and equal to {@code bank}, every other field unknown -- the
	 *  in-state every PRG-target case below starts from, so a successful round trip is visible
	 *  as "the same bank comes back out". */
	private static BankState prgBankKnown(int bank) {
		return BankState.fullyKnown(PRG_BANK_MASK, (bank & 0x1F) << 4);
	}

	private static String hex(long addr) {
		return String.format("0x%x", addr);
	}

	private static String staAbs(int offset) {
		return String.format("8d %02x %02x", offset & 0xFF, (offset >>> 8) & 0xFF);
	}

	/** Write 1's and write 5's addresses of a built chain -- the two sites every test below
	 *  asserts at (see class javadoc). */
	private record ChainAddrs(String write1, String write5) {
	}

	/**
	 * Lays out one real-shaped unrolled chain: {@code preInstrBytes} (the pre-chain load, e.g.
	 * {@code "a5 50"} for {@code LDA $50}), then five {@code STA <writeOffset>}, each but the
	 * first preceded by {@code LSR A} -- straight-line, fall-through-linked, exactly the shape
	 * {@link SerialShiftBankSwitchStrategy#analyzeChain} requires.
	 */
	private ChainAddrs buildChain(long startAddr, String preInstrBytes, int writeOffset)
			throws Exception {
		long addr = startAddr;
		builder.setBytes(hex(addr), preInstrBytes, true);
		addr += preInstrBytes.split(" ").length;

		String write1 = null;
		String write5 = null;
		for (int i = 0; i < 5; i++) {
			if (i > 0) {
				builder.setBytes(hex(addr), "4a", true); // LSR A
				addr += 1;
			}
			String staAddr = hex(addr);
			if (i == 0) {
				write1 = staAddr;
			}
			write5 = staAddr;
			builder.setBytes(staAddr, staAbs(writeOffset), true);
			addr += 3;
		}
		return new ChainAddrs(write1, write5);
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	/**
	 * Runs {@code strategy} over the instruction at {@code address} and asserts it was
	 * recognized as a mechanism write at all -- if it was not, the fixture failed to produce a
	 * write reference and the test would otherwise pass vacuously.
	 */
	private BankState switchAt(SerialShiftBankSwitchStrategy strategy, String address,
			BankState inState) {
		BankState result = strategy.computeSwitch(program, instructionAt(address), inState);
		assertNotNull("fixture produced no mechanism write at " + address +
			" -- no write reference? the test would prove nothing", result);
		return result;
	}

	private void assertPoisoned(BankState result) {
		assertEquals("every tracked field should have been poisoned: " + result, 0,
			result.knownMask());
	}

	// ------------------------------------------------------------------
	// 1. The headline case: ROM_IDENTIFYING lets the chain survive the bit-7 gate and commit
	// ------------------------------------------------------------------

	/**
	 * <b>THE CASE THIS INCREMENT EXISTS FOR.</b> A 5-write chain commits to the PRG target
	 * ($E000-$FFFF), and its pre-chain load reads a {@code ROM_IDENTIFYING} mirror. With the
	 * bank already known in the in-state, {@code mirroredByte} reconstructs a byte whose field
	 * bits echo that known bank and whose bits above the field are PROVED zero -- bit 7 among
	 * them -- so the bit-7 gate at write 1 resolves clear, the chain survives to write 5, and
	 * the commit deposits exactly the bank that was already known. Before this increment, the
	 * unresolved {@code LDA} would have left bit 7 unknown and poisoned the whole mechanism at
	 * write 1, destroying the very state the commit would have read.
	 * <p>
	 * The result is asserted equal to the ORIGINAL in-state outright: {@code prg_bank} is the
	 * only field either the gate or the deposit ever touches, and both round-trip through the
	 * same known bank, so nothing should have moved at all.
	 */
	@Test
	public void romIdentifyingMirrorLetsTheChainSurviveAndCommitTheKnownBank() throws Exception {
		SerialShiftBankSwitchStrategy strategy = mmc1();
		strategy.observeMirrors(mirrorsOf(0x50, BankMirrors.Kind.ROM_IDENTIFYING));

		ChainAddrs chain = buildChain(0x9000, "a5 50", PRG_OFFSET); // LDA $50 (the mirror)

		BankState inState = prgBankKnown(11);
		BankState result = switchAt(strategy, chain.write5(), inState);

		assertEquals("the chain must survive the bit-7 gate and deposit the already-known bank "
			+ "unchanged", inState, result);

		// DISCRIMINATOR. "Result equals inState" is also what writes 1-4 return -- they echo
		// in-state and defer the commit -- so on its own the assertion above would still pass if
		// write5() were mis-identified as a mid-chain write and no deposit ever happened. Run the
		// IDENTICAL chain at the IDENTICAL address with no mirror observed: the pre-chain byte is
		// then unrecoverable, and write 5 must come back with prg_bank UNKNOWN. Getting a
		// different answer at the same site is what proves the commit is real.
		SerialShiftBankSwitchStrategy noMirrors = mmc1();
		BankState withoutMirror = switchAt(noMirrors, chain.write5(), inState);
		assertNotEquals("write 5 must be a COMMIT, not an echo -- the same site with no mirror "
			+ "observed has to produce a different answer", inState, withoutMirror);
	}

	// ------------------------------------------------------------------
	// 2. The bit-7 gate is what makes it work: WRITE_THROUGH is the anti-case
	// ------------------------------------------------------------------

	/**
	 * <b>The anti-case that proves case 1 isn't passing for some unrelated reason.</b> Identical
	 * fixture to the headline case, except the mirror is typed {@code WRITE_THROUGH} instead of
	 * {@code ROM_IDENTIFYING}. {@code mirroredByte} answers only {@code ROM_IDENTIFYING} -- a
	 * write-through shadow supplies only the field bits and nothing above them, so it can never
	 * prove bit 7, which is exactly why it is declined outright (see
	 * {@code SerialShiftBankSwitchStrategy.mirroredByte}'s javadoc). The mirror is therefore
	 * never consulted, the pre-chain byte stays wholly unknown, bit 7 stays unknown, and write
	 * 1's gate poisons every tracked field -- asserted at write 1 itself, the site where that
	 * gate actually runs (see class javadoc).
	 */
	@Test
	public void writeThroughMirrorCannotSupplyBit7AndTheGatePoisons() throws Exception {
		SerialShiftBankSwitchStrategy strategy = mmc1();
		strategy.observeMirrors(mirrorsOf(0x50, BankMirrors.Kind.WRITE_THROUGH));

		ChainAddrs chain = buildChain(0x9000, "a5 50", PRG_OFFSET); // LDA $50 (the mirror)

		BankState result = switchAt(strategy, chain.write1(), prgBankKnown(11));

		assertPoisoned(result);
	}

	// ------------------------------------------------------------------
	// 3. SAVE_SLOT and INPUT decline the same way
	// ------------------------------------------------------------------

	/**
	 * {@code SAVE_SLOT} and {@code INPUT} decline exactly like {@code WRITE_THROUGH}, for the
	 * same reason: {@code mirroredByte} only ever answers {@code ROM_IDENTIFYING}. Neither holds
	 * the live bank in the first place ({@code SAVE_SLOT} is the OLD bank, {@code INPUT} the
	 * REQUESTED one) -- so even the weaker question this method asks ("can bit 7 be proved
	 * zero") is moot; they never reach {@code mirroredByte}'s kind check with anything but a
	 * decline.
	 */
	@Test
	public void saveSlotAndInputMirrorsDeclineJustLikeWriteThrough() throws Exception {
		BankMirrors.Kind[] kinds = { BankMirrors.Kind.SAVE_SLOT, BankMirrors.Kind.INPUT };
		for (int i = 0; i < kinds.length; i++) {
			SerialShiftBankSwitchStrategy strategy = mmc1();
			strategy.observeMirrors(mirrorsOf(0x50, kinds[i]));

			// Each iteration gets its own, non-overlapping code region.
			ChainAddrs chain = buildChain(0x9000 + i * 0x100L, "a5 50", PRG_OFFSET); // LDA $50

			BankState result = switchAt(strategy, chain.write1(), prgBankKnown(11));

			assertPoisoned(result);
		}
	}

	// ------------------------------------------------------------------
	// 4. The control: a non-mirror address is unchanged
	// ------------------------------------------------------------------

	/**
	 * An address the mirror set says nothing about declines exactly as it always did before
	 * mirrors existed -- the control every kind-specific case above is measured against. The
	 * pre-chain load reads {@code $60}; the observed mirror set has an entry only for the
	 * unrelated {@code $50} (typed {@code ROM_IDENTIFYING}, so the assertion cannot pass merely
	 * because no kind ever qualifies), proving the decline is address-specific, not blanket.
	 */
	@Test
	public void nonMirrorAddressStillPoisonsUnaffectedByAnUnrelatedMirror() throws Exception {
		SerialShiftBankSwitchStrategy strategy = mmc1();
		strategy.observeMirrors(mirrorsOf(0x50, BankMirrors.Kind.ROM_IDENTIFYING)); // unrelated

		ChainAddrs chain = buildChain(0x9000, "a5 60", PRG_OFFSET); // LDA $60 -- not a mirror

		BankState result = switchAt(strategy, chain.write1(), prgBankKnown(11));

		assertPoisoned(result);
	}

	// ------------------------------------------------------------------
	// 5. The single-field-at-shift-0 restriction: Control must decline even with a good mirror
	// ------------------------------------------------------------------

	/**
	 * <b>A bank number is only coherent for a register that TAKES a bank number.</b> The chain
	 * here commits to Control (target 0), whose layout is {@code mirroring} at shift 0 width 2
	 * plus {@code prg_mode} at shift 2 width 2 -- two fields, not the single shift-0 field
	 * {@code mirroredByte} requires. Even with a genuine, otherwise-qualifying
	 * {@code ROM_IDENTIFYING} mirror on the pre-chain load, {@code mirroredByte} refuses outright
	 * ({@code fields.size() != 1}) before it ever inspects the mirror kind, so the byte stays
	 * unknown, bit 7 stays unknown, and write 1's gate poisons -- exactly the same refusal
	 * {@code MemoryLatchBankSwitchStrategy.mirroredByte} makes when its {@code shift != 0}.
	 */
	@Test
	public void controlTargetDeclinesEvenWithARomIdentifyingMirror() throws Exception {
		SerialShiftBankSwitchStrategy strategy = mmc1();
		strategy.observeMirrors(mirrorsOf(0x50, BankMirrors.Kind.ROM_IDENTIFYING));

		ChainAddrs chain = buildChain(0x9100, "a5 50", CONTROL_OFFSET); // LDA $50, commits to
																			// Control

		BankState result = switchAt(strategy, chain.write1(), prgBankKnown(11));

		assertPoisoned(result);
	}

	// ------------------------------------------------------------------
	// 6. CHR owns nothing: a mirror's presence must not make it deposit
	// ------------------------------------------------------------------

	/**
	 * CHR0 (target 1) has no configured fields, so {@code hooksFor} degrades to the plain,
	 * non-mirror-consulting hooks for every write in this chain -- structurally, not because no
	 * mirror happens to be observed: a {@code ROM_IDENTIFYING} mirror IS observed here (at
	 * {@code $50}), just never consulted, because there is no field list to ask
	 * {@code mirroredByte} about. The pre-chain load is a plain immediate ({@code LDA #$05}) so
	 * the bit-7 gate resolves without needing any hook at all (bit 7 of an immediate is read
	 * directly off the operand), which isolates the thing under test: even once the chain
	 * reaches write 5's target decode, the CHR target must still ECHO {@code inState} unchanged
	 * -- the same no-deposit contract as {@link SelectDataBankSwitchStrategy}'s untracked-select
	 * case -- rather than depositing anything, mirror or no mirror.
	 */
	@Test
	public void chrTargetEchoesInStateUnchangedEvenWithAMirrorObserved() throws Exception {
		SerialShiftBankSwitchStrategy strategy = mmc1();
		strategy.observeMirrors(mirrorsOf(0x50, BankMirrors.Kind.ROM_IDENTIFYING));

		ChainAddrs chain = buildChain(0x9000, "a9 05", CHR0_OFFSET); // LDA #$05, commits to CHR0

		BankState inState = BankState.fullyKnown(STATE_MASK, 0x155);
		BankState result = switchAt(strategy, chain.write5(), inState);

		assertEquals("an unconfigured target must echo inState, never deposit", inState, result);
	}

	// ------------------------------------------------------------------
	// 7. effectDependsOnPriorState(program, site, siteInState) -- the per-site guard
	// ------------------------------------------------------------------

	/**
	 * True at write 5 of a chain whose pre-chain load actually consults a {@code ROM_IDENTIFYING}
	 * mirror. {@code scanOriginFor} re-anchors the probe at the chain's start (write 1), which is
	 * exactly the instruction whose preceding load the commit itself reads -- so this reports the
	 * same "needed the bank on entry" fact the commit's own resolution depended on.
	 */
	@Test
	public void effectDependsOnPriorStateIsTrueAtASiteThatConsultsAMirror() throws Exception {
		SerialShiftBankSwitchStrategy strategy = mmc1();
		strategy.observeMirrors(mirrorsOf(0x50, BankMirrors.Kind.ROM_IDENTIFYING));

		ChainAddrs chain = buildChain(0x9000, "a5 50", PRG_OFFSET); // LDA $50 (the mirror)

		assertTrue(strategy.effectDependsOnPriorState(program, instructionAt(chain.write5()),
			BankState.unknown()));
	}

	/**
	 * False at a site whose chain failed for an UNRELATED reason: the pre-chain load reads
	 * {@code $60}, a plain RAM cell that is not in the observed mirror set at all ({@code $50}
	 * is, unrelated). The mirror set is genuinely non-empty, so this is not the empty-set case
	 * below -- it is specifically "this site's own pre-chain load is not one of them". Getting
	 * this wrong would make every ordinary poison across a real board's chains masquerade as a
	 * mirror-driven state requirement.
	 */
	@Test
	public void effectDependsOnPriorStateIsFalseWhenTheSiteFailsForAnUnrelatedReason()
			throws Exception {
		SerialShiftBankSwitchStrategy strategy = mmc1();
		strategy.observeMirrors(mirrorsOf(0x50, BankMirrors.Kind.ROM_IDENTIFYING)); // unrelated

		ChainAddrs chain = buildChain(0x9000, "a5 60", PRG_OFFSET); // LDA $60 -- not a mirror

		assertFalse(strategy.effectDependsOnPriorState(program, instructionAt(chain.write5()),
			BankState.unknown()));
	}

	/** False when the observed mirror set is empty outright -- the cheap short-circuit that
	 *  keeps every board with no derivable mirror byte-identical to its pre-grm-mej.2 behavior. */
	@Test
	public void effectDependsOnPriorStateIsFalseWhenNoMirrorsAreObserved() throws Exception {
		SerialShiftBankSwitchStrategy strategy = mmc1(); // observeMirrors never called

		ChainAddrs chain = buildChain(0x9000, "a5 50", PRG_OFFSET); // LDA $50

		assertFalse(strategy.effectDependsOnPriorState(program, instructionAt(chain.write5()),
			BankState.unknown()));
	}

	// ------------------------------------------------------------------
	// 8. An empty mirror set leaves computeSwitch byte-identical to pre-mirror behavior
	// ------------------------------------------------------------------

	/**
	 * A board with no derivable mirror must be unaffected: with {@code observeMirrors} never
	 * called, the default {@code BankMirrors.none()} makes {@code hooksFor} degrade to the plain
	 * hooks for every write, so the same unresolved {@code LDA $50} that case 1 turns into a
	 * clean commit here poisons exactly as it always did before this increment existed --
	 * pinned by asserting the SAME result as an explicit {@code observeMirrors(BankMirrors.none())}
	 * call, so this also proves the two are indistinguishable.
	 */
	@Test
	public void emptyMirrorSetLeavesComputeSwitchUnaffected() throws Exception {
		SerialShiftBankSwitchStrategy defaultStrategy = mmc1(); // observeMirrors never called
		ChainAddrs defaultChain = buildChain(0x9000, "a5 50", PRG_OFFSET);
		BankState defaultResult =
			switchAt(defaultStrategy, defaultChain.write1(), prgBankKnown(11));

		SerialShiftBankSwitchStrategy explicitStrategy = mmc1();
		explicitStrategy.observeMirrors(BankMirrors.none());
		ChainAddrs explicitChain = buildChain(0x9100, "a5 50", PRG_OFFSET);
		BankState explicitResult =
			switchAt(explicitStrategy, explicitChain.write1(), prgBankKnown(11));

		assertPoisoned(defaultResult);
		assertEquals("an explicit empty mirror set must behave identically to never observing "
			+ "one at all", defaultResult, explicitResult);
	}
}
