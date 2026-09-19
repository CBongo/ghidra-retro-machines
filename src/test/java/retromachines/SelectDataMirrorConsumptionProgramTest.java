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

import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;

import retromachines.BoardDescriptorModel.FieldSpec;

/**
 * Pins {@link SelectDataBankSwitchStrategy}'s CONSUMPTION of a {@link BankMirrors} set (bead
 * grm-sen5): until that bead the strategy never overrode {@code observeMirrors}, so no MMC3
 * board got bank-mirror read-back at all. What is different about this strategy, and what
 * every case below is really about, is that it tracks TWO switchable windows through separate
 * registers -- so "the bank" an identifying byte reads back is a function of WHICH window the
 * byte lives in, and the derivation's per-offset window field
 * ({@link BankMirrors#identifyingField}) is the proof the answer is narrowed with.
 * <p>
 * Mirror sets are stated outright via the package-private {@link BankMirrors#of} overloads,
 * exactly as {@link SerialShiftMirrorConsumptionProgramTest} does; derivation is
 * {@link BankMirrors.Discovery}'s own concern and is not re-proved here.
 * <p>
 * Layout is the shipped {@code machines/nes-mmc3.yaml}: {@code select(0,3) prg_mode(3,1)
 * r6(4,6) r7(10,6)}, one select-data mechanism over {@code $8000-$9FFF} with
 * {@code targets {6: r6, 7: r7}}. The identifying offset used throughout is {@code $A100} --
 * inside {@code WA000}, R7's window -- and every state below keeps R6 and R7 at DIFFERENT known
 * values so that answering from the wrong field is visible as the wrong number, not as a
 * coincidence.
 */
public class SelectDataMirrorConsumptionProgramTest extends AbstractBundledLanguageTest {

	private static final int STATE_MASK = 0xFFFF;
	private static final FieldSpec R6 = new FieldSpec("r6", 4, 6);
	private static final FieldSpec R7 = new FieldSpec("r7", 10, 6);
	private static final long IDENT = 0xA100;

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
	// Scaffolding
	// ------------------------------------------------------------------

	private static JsonObject pos(int lsb, int width) {
		JsonObject o = new JsonObject();
		o.addProperty("lsb", lsb);
		o.addProperty("width", width);
		return o;
	}

	/** The real MMC3 mechanism, field-local layout identical to the board's (mechanism lsb 0). */
	private SelectDataBankSwitchStrategy mmc3() {
		JsonObject layout = new JsonObject();
		layout.add("select", pos(0, 3));
		layout.add("prg_mode", pos(3, 1));
		layout.add("r6", pos(4, 6));
		layout.add("r7", pos(10, 6));

		JsonObject targets = new JsonObject();
		targets.addProperty("6", "r6");
		targets.addProperty("7", "r7");

		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0x9FFF);
		params.addProperty("select_field", "select");
		params.addProperty("select_mask", 0x07);
		params.addProperty("select_shift", 0);
		params.addProperty("mode_field", "prg_mode");
		params.addProperty("mode_mask", 0x40);
		params.addProperty("mode_shift", 6);
		params.add("targets", targets);
		params.add("_field_layout", layout);

		SelectDataBankSwitchStrategy strategy = new SelectDataBankSwitchStrategy();
		strategy.configure(program, params, STATE_MASK);
		return strategy;
	}

	/** {@code $A100} as an identifying offset of the window banked by {@code field}. */
	private BankMirrors identifyingIn(FieldSpec field) {
		return BankMirrors.of(baseSpace, Map.of(IDENT, Set.of(BankMirrors.Kind.ROM_IDENTIFYING)),
			Map.of(IDENT, field));
	}

	/** {@code $A100} typed {@code kind}, with R7 recorded as its window field regardless. */
	private BankMirrors typedAs(BankMirrors.Kind kind) {
		return BankMirrors.of(baseSpace, Map.of(IDENT, Set.of(kind)), Map.of(IDENT, R7));
	}

	/** select, prg_mode, r6 and r7 all fully known: select 6 / mode 0 / r6=2 / r7=4. */
	private static BankState allKnown(int select, int mode, int r6, int r7) {
		return BankState.fullyKnown(STATE_MASK,
			(select & 7) | ((mode & 1) << 3) | ((r6 & 0x3F) << 4) | ((r7 & 0x3F) << 10));
	}

	private static int r6Of(BankState s) {
		return (s.bits() >>> 4) & 0x3F;
	}

	private static boolean r6Known(BankState s) {
		return ((s.knownMask() >>> 4) & 0x3F) == 0x3F;
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	/** {@code LDA $A100 / STA $8001} at {@code $E000}; returns the data write. */
	private Instruction identifyingReadThenDataWrite() throws Exception {
		return identifyingReadThenDataWriteAt(0xE000);
	}

	private Instruction identifyingReadThenDataWriteAt(int start) throws Exception {
		builder.setBytes(String.format("0x%x", start), "ad 00 a1", true); // LDA $A100
		builder.setBytes(String.format("0x%x", start + 3), "8d 01 80", true); // STA $8001
		return instructionAt(String.format("0x%x", start + 3));
	}

	private BankState switchAt(SelectDataBankSwitchStrategy strategy, Instruction site,
			BankState inState) {
		BankState result = strategy.computeSwitch(program, site, inState);
		assertNotNull("fixture produced no mechanism write at " + site.getMinAddress() +
			" -- the test would prove nothing", result);
		return result;
	}

	// ------------------------------------------------------------------
	// 1. The headline case: the byte is R7's, whatever register it is stored to
	// ------------------------------------------------------------------

	/**
	 * <b>THE CASE THIS BEAD EXISTS FOR, in its per-window form.</b> The program reads R7's
	 * identifying byte and commits it through select 6 -- copying R7's bank into R6. The answer
	 * must be R7's tracked value (4): the window the byte was READ from decides, not the
	 * register it is about to be STORED to. Answering from the target field would deposit R6's
	 * own stale 2, a confidently wrong bank the fixture keeps distinct on purpose.
	 */
	@Test
	public void identifyingByteResolvesFromTheWindowsOwnFieldNotTheTarget() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(identifyingIn(R7));
		Instruction site = identifyingReadThenDataWrite();

		BankState result = switchAt(strategy, site, allKnown(6, 0, 2, 4));

		assertTrue("r6 must be fully known after the copy: " + result, r6Known(result));
		assertEquals("r6 takes R7's bank (4), not its own stale 2", 4, r6Of(result));
		assertEquals("every other field is untouched", allKnown(6, 0, 4, 4), result);
	}

	/**
	 * The DISCRIMINATOR for the case above: the identical site, with the identical in-state,
	 * declines without a mirror observed -- so the resolution really came through the mirror
	 * and not from some unrelated recovery.
	 */
	@Test
	public void withoutAMirrorTheSameSiteDeclines() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3(); // observeMirrors never called
		Instruction site = identifyingReadThenDataWrite();

		BankState result = switchAt(strategy, site, allKnown(6, 0, 2, 4));

		assertFalse("r6 must come out unknown with no mirror to answer: " + result,
			r6Known(result));
	}

	/**
	 * The mirror answers a WHOLE byte: {@code byte == bank} was verified against every realized
	 * bank, so the bits above the field are proved zero. A select write fed from the mirror
	 * therefore lands a fully-known {@code prg_mode} (bit 6 of the byte, a proved zero) as well
	 * as a select value -- which is what tells this apart from a field-only shadow answer.
	 */
	@Test
	public void bitsAboveTheBankFieldAreProvedZero() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(identifyingIn(R7));
		builder.setBytes("0xe000", "ad 00 a1", true); // LDA $A100
		builder.setBytes("0xe003", "8d 00 80", true); // STA $8000 -- a SELECT write

		BankState result = switchAt(strategy, instructionAt("0xe003"), allKnown(6, 1, 2, 4));

		assertEquals("select := R7's byte & 7 = 4, prg_mode := bit 6 = 0 (proved), r6/r7 kept",
			allKnown(4, 0, 2, 4), result);
	}

	// ------------------------------------------------------------------
	// 2. Every refusal: the proof is missing, so no bank is invented
	// ------------------------------------------------------------------

	/** An identifying offset whose window was NOT attributed to a field: refuse. */
	@Test
	public void identifyingOffsetWithoutAWindowFieldIsRefused() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(BankMirrors.of(baseSpace,
			Map.of(IDENT, Set.of(BankMirrors.Kind.ROM_IDENTIFYING)))); // no field map
		Instruction site = identifyingReadThenDataWrite();

		assertFalse(r6Known(switchAt(strategy, site, allKnown(6, 0, 2, 4))));
	}

	/** A window banked by a field this mechanism does not track (a CHR register): refuse. */
	@Test
	public void identifyingOffsetOwnedByAnUntrackedFieldIsRefused() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(identifyingIn(new FieldSpec("chr0", 16, 6)));
		Instruction site = identifyingReadThenDataWrite();

		assertFalse(r6Known(switchAt(strategy, site, allKnown(6, 0, 2, 4))));
	}

	/** A field whose width disagrees with the tracked target's: a descriptor inconsistency,
	 *  refused rather than reconciled. */
	@Test
	public void identifyingOffsetWithAWidthMismatchIsRefused() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(identifyingIn(new FieldSpec("r7", 10, 5)));
		Instruction site = identifyingReadThenDataWrite();

		assertFalse(r6Known(switchAt(strategy, site, allKnown(6, 0, 2, 4))));
	}

	/**
	 * {@code WRITE_THROUGH}, {@code SAVE_SLOT} and {@code INPUT} all decline on this strategy,
	 * even with a window field recorded -- only {@code ROM_IDENTIFYING} answers. See
	 * {@code SelectDataBankSwitchStrategy.mirroredByte} for why write-through is a decision
	 * here and not merely unimplemented.
	 */
	@Test
	public void everyNonIdentifyingKindDeclines() throws Exception {
		BankMirrors.Kind[] kinds = { BankMirrors.Kind.WRITE_THROUGH, BankMirrors.Kind.SAVE_SLOT,
			BankMirrors.Kind.INPUT };
		for (int i = 0; i < kinds.length; i++) {
			BankMirrors.Kind kind = kinds[i];
			SelectDataBankSwitchStrategy strategy = mmc3();
			strategy.observeMirrors(typedAs(kind));
			// Each iteration gets its own, non-overlapping code region.
			Instruction site = identifyingReadThenDataWriteAt(0xE000 + i * 0x100);

			assertFalse(kind + " must decline", r6Known(switchAt(strategy, site, allKnown(6, 0, 2, 4))));
		}
	}

	/** The R6-side control: an offset attributed to R6 answers R6's value, so the per-window
	 *  narrowing is symmetric and not "always R7". */
	@Test
	public void anOffsetAttributedToR6AnswersR6() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(identifyingIn(R6));
		builder.setBytes("0xe000", "ad 00 a1", true); // LDA $A100 (attributed to R6 here)
		builder.setBytes("0xe003", "8d 01 80", true); // STA $8001 under select 7 -> r7

		BankState result = switchAt(strategy, instructionAt("0xe003"), allKnown(7, 0, 2, 4));

		assertEquals("r7 := R6's bank (2)", allKnown(7, 0, 2, 2), result);
	}

	// ------------------------------------------------------------------
	// 3. The per-site effectDependsOnPriorState guard (grm-mej.2 §2d)
	// ------------------------------------------------------------------

	/** True at a data write whose byte came from the mirror with the bank UNKNOWN -- the
	 *  site that genuinely needed the bank on entry. */
	@Test
	public void effectDependsOnPriorStateIsTrueAtASiteThatConsultsTheMirror() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(identifyingIn(R7));
		Instruction site = identifyingReadThenDataWrite();

		BankState r7Unknown = new BankState(0x03FF, 6); // select=6, mode, r6 known; r7 unknown
		assertTrue(strategy.effectDependsOnPriorState(program, site, r7Unknown));
	}

	/** False when the load is not a mirror at all, with a real (unrelated) mirror observed. */
	@Test
	public void effectDependsOnPriorStateIsFalseWhenTheSiteFailsForAnUnrelatedReason()
			throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(identifyingIn(R7)); // $A100 -- unrelated to $A200 below
		builder.setBytes("0xe000", "ad 00 a2", true); // LDA $A200 -- not a mirror
		builder.setBytes("0xe003", "8d 01 80", true); // STA $8001

		assertFalse(strategy.effectDependsOnPriorState(program, instructionAt("0xe003"),
			new BankState(0x03FF, 6)));
	}

	/** False when select is unknown: the data write poisons without scanning, so no mirror is
	 *  consulted (its genuine requirement is on selectField, which this predicate cannot
	 *  express -- the documented third bullet). */
	@Test
	public void effectDependsOnPriorStateIsFalseWhenSelectIsUnknown() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(identifyingIn(R7));
		Instruction site = identifyingReadThenDataWrite();

		assertFalse(strategy.effectDependsOnPriorState(program, site, BankState.unknown()));
	}

	/** False with no mirrors observed -- the cheap short-circuit every mirrorless board takes. */
	@Test
	public void effectDependsOnPriorStateIsFalseWhenNoMirrorsAreObserved() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		Instruction site = identifyingReadThenDataWrite();

		assertFalse(strategy.effectDependsOnPriorState(program, site, new BankState(0x03FF, 6)));
	}

	/** The strategy-wide answer is unchanged: still {@code false} (grm-vgod). */
	@Test
	public void strategyWideAnswerStaysFalse() {
		assertFalse(mmc3().effectDependsOnPriorState());
	}

	// ------------------------------------------------------------------
	// 4. callerSideHooks: the same answer at a helper call site, with the mandatory
	//    mechanism-write detection
	// ------------------------------------------------------------------

	@Test
	public void callerSideHooksAnswerTheMirrorAndDetectMechanismWrites() throws Exception {
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(identifyingIn(R7));
		builder.setBytes("0xe000", "ad 00 a1", true); // LDA $A100
		builder.setBytes("0xe003", "8d 01 80", true); // STA $8001
		builder.setBytes("0xe006", "85 59", true);    // STA $59
		StoredValueScanner.Hooks hooks = strategy.callerSideHooks();

		assertTrue("a data write is a mechanism write",
			hooks.isMechanismWrite(instructionAt("0xe003")));
		assertFalse("a RAM store is not", hooks.isMechanismWrite(instructionAt("0xe006")));
		assertNull("scope discipline: resolveLoad answers nothing caller-side",
			hooks.resolveLoad(instructionAt("0xe000"), builder.addr("0xa100"), allKnown(6, 0, 2, 4)));

		BankState mirrored = hooks.resolveMirrorLoad(instructionAt("0xe000"),
			builder.addr("0xa100"), allKnown(6, 0, 2, 4));
		assertNotNull(mirrored);
		assertEquals("the raw byte is R7's bank, upper bits proved zero", 0xFF,
			mirrored.knownMask());
		assertEquals(4, mirrored.bits());
	}
}
