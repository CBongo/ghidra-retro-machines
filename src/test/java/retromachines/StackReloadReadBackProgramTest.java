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

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperArgumentRecovery.ReloadTransform;
import retromachines.HelperArgumentRecovery.StateOracle;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Pins bead grm-mej.7: a caller-side {@code RESTORED_BANK} read-back survives the grm-oj20
 * discard when the helper -- although its argument register does NOT survive to
 * {@code firstSite} -- saves the caller's A with an entry {@code PHA}, reads THAT slot back
 * stack-relative ({@code TSX} / {@code LDA $01nn,X}), and commits a fixed transform of it that
 * is exactly the read-back cell's own bank encoding. River City Ransom's {@code FUN_fed1} is the
 * shape, reproduced here byte for byte from the pinned ROM ({@code $FED1-$FEFA}, its
 * {@code CMP $BFFF} sanity tail replaced by {@code RTS}). The transform proof holds on fed1, but
 * only an IDENTITY encoding is accepted for now -- fed1's shift-encoded {@code $BFFF} read-back
 * is still dropped pending an owner ruling (see
 * {@link #fed1WithAShiftEncodedCellStillDropsTheReadBack}).
 * <p>
 * Two layers: {@link HelperArgumentRecovery#argumentReloadTransform} directly (the proof and
 * every strict refusal), and {@link HelperArgumentRecovery#recoverCallArgument} end to end (the
 * read-back is kept, and is still dropped when the transform is not the cell's encoding or the
 * field is not the cell's window). The grm-oj20 memory-latch case keeps its own pin in
 * {@code CallCrossingPushPullProgramTest}; a stack-reload variant of it is added here.
 */
public class StackReloadReadBackProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock ram = builder.createMemory("RAM", "0x0", 0x800);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		int tx = program.startTransaction("set block write permission");
		try {
			ram.setWrite(true);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private void put(String address, String hex) throws Exception {
		builder.setBytes(address, hex, true);
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	// ------------------------------------------------------------------
	// Fixtures
	// ------------------------------------------------------------------

	/** MMC3-shaped select/data over {@code $8000-$9FFF}: select[0,4), r6[4,8), r7[8,12). */
	private SelectDataBankSwitchStrategy mmc3() {
		JsonObject fieldLayout = new JsonObject();
		fieldLayout.add("select", layout(0, 4));
		fieldLayout.add("r6", layout(4, 4));
		fieldLayout.add("r7", layout(8, 4));
		JsonObject targets = new JsonObject();
		targets.addProperty("6", "r6");
		targets.addProperty("7", "r7");
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0x9FFF);
		params.addProperty("select_field", "select");
		params.add("targets", targets);
		params.add("_field_layout", fieldLayout);
		SelectDataBankSwitchStrategy strategy = new SelectDataBankSwitchStrategy();
		strategy.configure(program, params, 0xFFF);
		return strategy;
	}

	private static JsonObject layout(int lsb, int width) {
		JsonObject o = new JsonObject();
		o.addProperty("lsb", lsb);
		o.addProperty("width", width);
		return o;
	}

	/** {@code $BFFF} as a ROM-identifying byte with {@code encoding} on {@code field}. */
	private BankMirrors bfffMirror(BankMirrors.Kind kind, BankMirrors.IdentifyingEncoding encoding,
			BoardDescriptorModel.FieldSpec field) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		if (kind != BankMirrors.Kind.ROM_IDENTIFYING) {
			return BankMirrors.of(space, Map.of(0xBFFFL, Set.of(kind)));
		}
		return BankMirrors.of(space, Map.of(0xBFFFL, Set.of(kind)),
			Map.of(0xBFFFL, field), Map.of(0xBFFFL, encoding));
	}

	/** rcransom's encoding: {@code byte == (bank-1)/2} on odd banks, i.e. bank = 2*byte + 1. */
	private static BankMirrors.IdentifyingEncoding oddHalf() {
		return new BankMirrors.IdentifyingEncoding(1, 1, Set.of(1, 3, 5, 7), Set.of(1, 3, 5, 7));
	}

	private static final BoardDescriptorModel.FieldSpec R6 =
		new BoardDescriptorModel.FieldSpec("r6", 4, 4);
	private static final BoardDescriptorModel.FieldSpec R7 =
		new BoardDescriptorModel.FieldSpec("r7", 8, 4);

	/** The caller: {@code LDA $BFFF / JSR $FED1} -- a read-back handed straight to the helper. */
	private void caller() throws Exception {
		put("0xc000", "ad ff bf"); // LDA $BFFF -- bank-identifying ROM byte
		put("0xc003", "20 d1 fe"); // JSR $FED1
		put("0xc006", "60"); // RTS
		put("0xbfff", "01");
	}

	/**
	 * {@code FUN_fed1}, verbatim from River City Ransom (sha256 b95f8def...):
	 * <pre>
	 * FED1 PHA / TXA / PHA / LDA #6 / STA $FB / STA $8000 / TSX / LDA $0102,X / ASL A / STA $FC /
	 * FEE2 STA $8001 / LDA #7 / STA $FB / STA $8000 / LDA $0102,X / ASL A / CLC / ADC #1 /
	 * FEF3 STA $FD / FEF5 STA $8001 / PLA / TAX / PLA / RTS
	 * </pre>
	 */
	private static final String FED1 = "48 8a 48 a9 06 85 fb 8d 00 80 ba bd 02 01 0a 85 fc 8d 01 80 " +
		"a9 07 85 fb 8d 00 80 bd 02 01 0a 18 69 01 85 fd 8d 01 80 68 aa 68 60";

	private HelperModel fed1Model(SelectDataBankSwitchStrategy strategy) {
		return new HelperModel(null, builder.addr("0xfed1"), null, 'A', 0xFFF, 0, strategy,
			builder.addr("0xfef5"), builder.addr("0xfed8"), null,
			List.of(builder.addr("0xfed8"), builder.addr("0xfee2"), builder.addr("0xfee9"),
				builder.addr("0xfef5")));
	}

	private CallEffect recover(HelperModel helper) {
		StateOracle oracle = a -> BankState.unknown();
		return HelperArgumentRecovery.recoverCallArgument(program, instructionAt("0xc003"), helper,
			BankState.unknown(), new HashMap<>(), new HashSet<>(), RegisterEnv.NONE, oracle);
	}

	private ReloadTransform transform(String entry, String valueSite) {
		return HelperArgumentRecovery.argumentReloadTransform(program, builder.addr(entry),
			builder.addr(valueSite), 'A');
	}

	// ------------------------------------------------------------------
	// fed1 itself: the proof holds, the read-back still waits on an owner ruling
	// ------------------------------------------------------------------

	/** The proof on fed1 itself: R7's value site commits {@code 2*arg + 1}, R6's {@code 2*arg}. */
	@Test
	public void fed1ReloadIsProvedWithItsAffineTransform() throws Exception {
		put("0xfed1", FED1);
		assertEquals(new ReloadTransform(1, 1), transform("0xfed1", "0xfef5"));
		assertEquals(new ReloadTransform(1, 0), transform("0xfed1", "0xfee2"));
		assertFalse("survival to firstSite stays false -- A holds the select constant there",
			HelperArgumentRecovery.argumentSurvivesPrologue(program, builder.addr("0xfed1"),
				builder.addr("0xfed8"), 'A'));
	}

	/**
	 * PENDING OWNER RULING (grm-mej.7): fed1's transform matches $BFFF's shift encoding exactly,
	 * but the byte identifies a bank only on the encoding's congruent, verified banks, and
	 * nothing proves the live R7 is one of them at the read -- nesmmc3idtest's e28d/e2cd are the
	 * counter-examples. So a NON-identity encoding is refused and the read-back is still
	 * dropped. Flip this test if the owner rules the unproven premise acceptable.
	 */
	@Test
	public void fed1WithAShiftEncodedCellStillDropsTheReadBack() throws Exception {
		caller();
		put("0xfed1", FED1);
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(bfffMirror(BankMirrors.Kind.ROM_IDENTIFYING, oddHalf(), R7));
		CallEffect effect = recover(fed1Model(strategy));
		assertFalse(effect.argumentResolved());
		assertNull(effect.readBack());
	}

	// ------------------------------------------------------------------
	// Positive, end to end: an identity-encoded cell
	// ------------------------------------------------------------------

	/**
	 * fed1's prologue shape, without the transform: {@code PHA / TXA / PHA / LDA #7 / STA $8000
	 * (firstSite) / TSX / LDA $0102,X / STA $8001 (value site) / PLA / TAX / PLA / RTS}.
	 */
	private static final String IDENT = "48 8a 48 a9 07 8d 00 80 ba bd 02 01 8d 01 80 68 aa 68 60";

	private HelperModel identModel(SelectDataBankSwitchStrategy strategy) {
		return new HelperModel(null, builder.addr("0xfed1"), null, 'A', 0xFFF, 0, strategy,
			builder.addr("0xfedd"), builder.addr("0xfed6"), null,
			List.of(builder.addr("0xfed6"), builder.addr("0xfedd")));
	}

	/** The caller: {@code LDA $FD / JSR $FED1} -- a write-through bank shadow read back and
	 *  handed straight to the helper. */
	private void shadowCaller() throws Exception {
		put("0xc000", "a5 fd"); // LDA $FD -- write-through shadow
		put("0xc002", "20 d1 fe"); // JSR $FED1
		put("0xc005", "60"); // RTS
	}

	private BankMirrors shadowMirror() {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return BankMirrors.of(space, Map.of(0xFDL, Set.of(BankMirrors.Kind.WRITE_THROUGH)));
	}

	private CallEffect recoverShadow(HelperModel helper) {
		StateOracle oracle = a -> BankState.unknown();
		return HelperArgumentRecovery.recoverCallArgument(program, instructionAt("0xc002"), helper,
			BankState.unknown(), new HashMap<>(), new HashSet<>(), RegisterEnv.NONE, oracle);
	}

	/** The read-back is KEPT: A does not survive to firstSite (it holds the select constant),
	 *  yet the value site commits exactly the caller's byte, reloaded from the entry push -- the
	 *  read-back grm-oj20 used to drop. A write-through shadow holds the raw committed value, so
	 *  the identity transform re-commits exactly the bank read. */
	@Test
	public void stackReloadedArgumentKeepsTheReadBack() throws Exception {
		shadowCaller();
		put("0xfed1", IDENT);
		assertEquals(ReloadTransform.IDENTITY, transform("0xfed1", "0xfedd"));
		assertFalse(HelperArgumentRecovery.argumentSurvivesPrologue(program,
			builder.addr("0xfed1"), builder.addr("0xfed6"), 'A'));
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(shadowMirror());
		CallEffect effect = recoverShadow(identModel(strategy));
		assertFalse("the bank itself is not known -- only that it is restored",
			effect.argumentResolved());
		assertNotNull("the helper reloads the caller's A from its entry push: the read-back "
				+ "describes what R7 commits", effect.readBack());
		assertEquals(builder.addr("0x00fd"), effect.readBack().cell());
		assertEquals(builder.addr("0xc000"), effect.readBack().readAt());
	}

	/** The same caller and shadow, but fed1's {@code 2*A+1}: the committed bank is not the raw
	 *  value the shadow holds, so the read-back is dropped. */
	@Test
	public void shadowReadBackWithATransformIsDropped() throws Exception {
		shadowCaller();
		put("0xfed1", FED1);
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(shadowMirror());
		assertNull(recoverShadow(fed1Model(strategy)).readBack());
	}

	// ------------------------------------------------------------------
	// Negative, end to end: the transform or field is not the cell's
	// ------------------------------------------------------------------

	/** fed1 with its {@code ADC #1} replaced by two {@code NOP}s: R7 now receives {@code 2*A},
	 *  which is not the cell's {@code 2*byte+1} encoding either. */
	@Test
	public void encodingMismatchDropsTheReadBack() throws Exception {
		caller();
		put("0xfed1", FED1.replace("0a 18 69 01", "0a 18 ea ea"));
		assertEquals(new ReloadTransform(1, 0), transform("0xfed1", "0xfef5"));
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(bfffMirror(BankMirrors.Kind.ROM_IDENTIFYING, oddHalf(), R7));
		assertNull(recover(fed1Model(strategy)).readBack());
	}

	/** A write-through shadow holds the RAW committed value, so a non-identity transform commits
	 *  a different bank than the one read back. Not live on select-data in production (the
	 *  strategy declines write-through), pinned here as the rule. */
	@Test
	public void writeThroughCellWithATransformDropsTheReadBack() throws Exception {
		caller();
		put("0xfed1", FED1);
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(bfffMirror(BankMirrors.Kind.WRITE_THROUGH, null, null));
		assertNull(recover(fed1Model(strategy)).readBack());
	}

	/** The reload reads the wrong slot ($0101 = the saved X): the read-back is dropped. */
	@Test
	public void wrongSlotEndToEndDropsTheReadBack() throws Exception {
		shadowCaller();
		put("0xfed1", IDENT.replace("bd 02 01", "bd 01 01"));
		SelectDataBankSwitchStrategy strategy = mmc3();
		strategy.observeMirrors(shadowMirror());
		assertNull(recoverShadow(identModel(strategy)).readBack());
	}

	// ------------------------------------------------------------------
	// Negative, predicate level: every strict refusal
	// ------------------------------------------------------------------

	/** {@code $0101,X} names the most recent push (the saved X), not the argument. */
	@Test
	public void wrongSlotOffsetIsRefused() throws Exception {
		put("0x9000", "48 8a 48 ba bd 01 01 8d 01 80"); // PHA TXA PHA TSX LDA $0101,X STA $8001
		assertNull(transform("0x9000", "0x9007"));
		put("0x9100", "48 8a 48 ba bd 02 01 8d 01 80"); // ... LDA $0102,X -- the argument
		assertEquals(ReloadTransform.IDENTITY, transform("0x9100", "0x9107"));
	}

	/** An extra push between the argument's PHA and the TSX moves the argument one deeper, so the
	 *  unchanged $0102 operand now reads the wrong byte. */
	@Test
	public void depthChangeBetweenPushAndTsxIsRefused() throws Exception {
		put("0x9000", "48 8a 48 48 ba bd 02 01 8d 01 80"); // PHA TXA PHA PHA TSX LDA $0102,X
		assertNull(transform("0x9000", "0x9008"));
		// ...and a PLA between them shifts it the other way.
		put("0x9100", "48 8a 48 68 ba bd 02 01 8d 01 80"); // PHA TXA PHA PLA TSX LDA $0102,X
		assertNull(transform("0x9100", "0x9108"));
	}

	/** A push between the TSX and the load is refused outright by stackRelativePush. */
	@Test
	public void pushBetweenTsxAndReloadIsRefused() throws Exception {
		put("0x9000", "48 ba 48 bd 02 01 8d 01 80"); // PHA TSX PHA LDA $0102,X STA $8001
		assertNull(transform("0x9000", "0x9006"));
	}

	/** Any write into the stack page in the span is refused, indexed or plain. */
	@Test
	public void stackPageStoreIsRefused() throws Exception {
		// PHA TXA PHA TSX STA $0102,X LDA $0102,X STA $8001 -- overwrites the slot itself
		put("0x9000", "48 8a 48 ba 9d 02 01 bd 02 01 8d 01 80");
		assertNull(transform("0x9000", "0x900a"));
		// PHA TSX STA $01F0 LDA $0101,X STA $8001 -- a plain store into the page
		put("0x9100", "48 ba 8d f0 01 bd 01 01 8d 01 80");
		assertNull(transform("0x9100", "0x9108"));
		// PHA TSX STA ($10),Y LDA $0101,X STA $8001 -- an indirect store could land anywhere
		put("0x9200", "48 ba 91 10 bd 01 01 8d 01 80");
		assertNull(transform("0x9200", "0x9207"));
	}

	/** A was clobbered BEFORE the push, so the pushed byte is not the caller's argument. */
	@Test
	public void pushOfAClobberedRegisterIsRefused() throws Exception {
		put("0x9000", "a9 03 48 ba bd 01 01 8d 01 80"); // LDA #3 PHA TSX LDA $0101,X STA $8001
		assertNull(transform("0x9000", "0x9007"));
	}

	/** A branch anywhere in the span: not straight-line, refused. */
	@Test
	public void branchInTheSpanIsRefused() throws Exception {
		put("0x9000", "48 ba f0 00 bd 01 01 8d 01 80"); // PHA TSX BEQ +0 LDA $0101,X STA $8001
		assertNull(transform("0x9000", "0x9007"));
	}

	/** TXS moves the stack pointer under the model: refused. */
	@Test
	public void txsInTheSpanIsRefused() throws Exception {
		put("0x9000", "48 ba 9a bd 01 01 8d 01 80"); // PHA TSX TXS LDA $0101,X STA $8001
		assertNull(transform("0x9000", "0x9006"));
	}

	/** A is overwritten after the reload and before the value site: the site commits that. */
	@Test
	public void overwriteAfterReloadIsRefused() throws Exception {
		put("0x9000", "48 ba bd 01 01 a9 05 8d 01 80"); // PHA TSX LDA $0101,X LDA #5 STA $8001
		assertNull(transform("0x9000", "0x9007"));
	}

	/** ADC with the carry not provably known is not a fixed transform. */
	@Test
	public void adcWithUnknownCarryIsRefused() throws Exception {
		put("0x9000", "48 ba bd 01 01 0a 69 01 8d 01 80"); // ... ASL A ADC #1 (no CLC) STA
		assertNull(transform("0x9000", "0x9008"));
		put("0x9100", "48 ba bd 01 01 0a 09 01 8d 01 80"); // ... ASL A ORA #1 STA -- exact
		assertEquals(new ReloadTransform(1, 1), transform("0x9100", "0x9108"));
	}

	/** A value site that does not store A itself is refused. */
	@Test
	public void valueSiteNotStoringAIsRefused() throws Exception {
		put("0x9000", "48 ba bd 01 01 8e 01 80"); // PHA TSX LDA $0101,X STX $8001
		assertNull(transform("0x9000", "0x9005"));
	}

	// ------------------------------------------------------------------
	// grm-oj20: the memory-latch clobber still discards
	// ------------------------------------------------------------------

	/**
	 * The grm-oj20 shape with a stack reload grafted on: the helper saves and reloads A, but then
	 * commits a table byte selected by Y ({@code LDA $E000,Y / STA $E000,Y}). The reload is not
	 * what reaches the value site, so the A read-back is still discarded.
	 */
	@Test
	public void memoryLatchCommitOfYStillDiscardsTheReadBack() throws Exception {
		put("0xc000", "ad 10 00"); // LDA $0010 -- mirror read
		put("0xc003", "a4 30"); // LDY $30   -- unrelated RAM
		put("0xc005", "20 00 91"); // JSR helper ($9100)
		put("0xc008", "60");
		// PHA TSX LDA $0101,X LDA $E000,Y STA $E000,Y PLA RTS
		put("0x9100", "48 ba bd 01 01 b9 00 e0 99 00 e0 68 60");

		JsonObject params = new JsonObject();
		params.addProperty("start", 0xE000);
		params.addProperty("end", 0xFFFF);
		params.addProperty("mask", 0x07);
		MemoryLatchBankSwitchStrategy latch = new MemoryLatchBankSwitchStrategy();
		latch.configure(program, params, 0x07);
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		latch.observeMirrors(
			BankMirrors.of(space, Map.of(0x10L, Set.of(BankMirrors.Kind.WRITE_THROUGH))));
		HelperModel helper = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0x07, 0,
			latch, builder.addr("0x9108"), builder.addr("0x9108"), null);

		assertNull(HelperArgumentRecovery.argumentReloadTransform(program, helper, 'A'));
		StateOracle oracle = a -> BankState.unknown();
		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0xc005"), helper, BankState.unknown(), new HashMap<>(), new HashSet<>(),
			RegisterEnv.NONE, oracle);
		assertFalse(effect.argumentResolved());
		assertNull(effect.readBack());
	}
}
