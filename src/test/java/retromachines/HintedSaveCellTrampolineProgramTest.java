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

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

/**
 * Pins the grm-mej.9 additions to {@link SaveRestoreTrampolines#restoresEntryBank}: a HINTED
 * save cell ({@code banking.save_cells}), the early-out branch, and the biased identity byte.
 * <p>
 * The fixture is tmnt3's {@code FUN_919e} (bytes at {@code $919E}, simplified to the walk's own
 * vocabulary; the select write and bank write are folded into one {@code STA $8000} commit):
 * <pre>
 *   9000: PHA / LDA $27 / BNE 9020      ; early out: 9020 is PLA / RTS
 *   9005: LDA $A000 / STA $F0           ; save the live bank's identity byte in the cell
 *   900A: LDA #$3A / STA $8000          ; COMMIT -- a mechanism write
 *   900F: PLA / JSR $9100               ; the inner call (clobbers A)
 *   9013: LDA $F0 / STA $8000           ; RESTORE from the cell        &lt;- switchSite
 *   9018: RTS
 * </pre>
 */
public class HintedSaveCellTrampolineProgramTest extends AbstractBundledLanguageTest {

	private static final Set<Long> HINT = Set.of(0xF0L);
	private static final BoardDescriptorModel.FieldSpec R7 =
		new BoardDescriptorModel.FieldSpec("r7", 10, 6);
	private static final BoardDescriptorModel.FieldSpec R6 =
		new BoardDescriptorModel.FieldSpec("r6", 4, 6);

	private ProgramBuilder builder;
	private ProgramDB program;
	private AddressSpace baseSpace;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("RAM", "0x0000", 0x800);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		baseSpace = program.getAddressFactory().getDefaultAddressSpace();
	}

	private Address addr(String address) {
		return builder.addr(address);
	}

	private HelperDiscovery.HelperModel model(Address entry, Address switchSite) {
		return new HelperDiscovery.HelperModel(null, entry, null, null, 0xFFFF, 0, null,
			switchSite, entry, null);
	}

	private BankMirrors identity() {
		return BankMirrors.of(baseSpace, Map.of(0xA000L, Set.of(BankMirrors.Kind.ROM_IDENTIFYING)));
	}

	private boolean restores(BankMirrors mirrors, Set<Long> cells, Address... mechanism) {
		return SaveRestoreTrampolines.restoresEntryBank(program,
			model(addr("0x9000"), addr("0x9015")), mirrors, Set.of(mechanism), cells);
	}

	/** The positive tmnt3 shape, with {@code LDA $F0} at 9013 and the given bytes in between. */
	private void tmnt3Shape(String exitBytes, String branchBytes) throws Exception {
		builder.setBytes("0x9000", "48", true); // PHA
		builder.setBytes("0x9001", "a5 27", true); // LDA $27
		builder.setBytes("0x9003", branchBytes, true); // BNE $9020
		builder.setBytes("0x9005", "ad 00 a0", true); // LDA $A000
		builder.setBytes("0x9008", "85 f0", true); // STA $F0
		builder.setBytes("0x900a", "a9 3a", true); // LDA #$3A
		builder.setBytes("0x900c", "8d 00 80", true); // STA $8000 -- COMMIT
		builder.setBytes("0x900f", "68", true); // PLA
		builder.setBytes("0x9010", "20 00 91", true); // JSR $9100
		builder.setBytes("0x9100", "a9 ff 60", true); // LDA #$FF / RTS -- clobbers A
		builder.setBytes("0x9020", exitBytes, true); // PLA / RTS -- the early out
	}

	private void tmnt3Shape(String exitBytes) throws Exception {
		tmnt3Shape(exitBytes, "d0 1b");
	}

	private void restoreTail(String at) throws Exception {
		builder.setBytes(at, "a5 f0", true); // LDA $F0
		builder.setBytes("0x9015", "8d 00 80", true); // STA $8000 -- RESTORE
		builder.setBytes("0x9018", "60", true); // RTS
	}

	private void fullShape() throws Exception {
		tmnt3Shape("68 60");
		restoreTail("0x9013");
	}

	// ------------------------------------------------------------------
	// Accepted
	// ------------------------------------------------------------------

	@Test
	public void hintedCellAcrossTheInnerCallWithEarlyOutIsAVerifiedNoOp() throws Exception {
		fullShape();
		assertTrue(restores(identity(), HINT, addr("0x900c")));
	}

	// ------------------------------------------------------------------
	// Declined: each breaks exactly one piece
	// ------------------------------------------------------------------

	@Test
	public void noHintDeclines() throws Exception {
		fullShape();
		assertFalse("without the hint the cell is unproven and the branch aborts the walk",
			restores(identity(), Set.of(), addr("0x900c")));
	}

	@Test
	public void aDifferentHintedCellDeclines() throws Exception {
		fullShape();
		assertFalse(restores(identity(), Set.of(0xF2L), addr("0x900c")));
	}

	@Test
	public void cellOverwrittenBetweenSaveAndRestoreDeclines() throws Exception {
		tmnt3Shape("68 60");
		builder.setBytes("0x9013", "a9 00 85 f0", true); // LDA #0 / STA $F0 -- clobbers the cell
		builder.setBytes("0x9017", "a5 f0", true);
		builder.setBytes("0x9019", "8d 00 80", true); // the restore
		builder.setBytes("0x901c", "60", true);
		assertFalse(SaveRestoreTrampolines.restoresEntryBank(program,
			model(addr("0x9000"), addr("0x9019")), identity(), Set.of(addr("0x900c")), HINT));
	}

	@Test
	public void indexedStoreMightBeTheCellAndDeclines() throws Exception {
		tmnt3Shape("68 60");
		builder.setBytes("0x9013", "95 f0", true); // STA $F0,X -- target not static
		builder.setBytes("0x9015", "a5 f0", true);
		builder.setBytes("0x9017", "8d 00 80", true);
		builder.setBytes("0x901a", "60", true);
		assertFalse(SaveRestoreTrampolines.restoresEntryBank(program,
			model(addr("0x9000"), addr("0x9017")), identity(), Set.of(addr("0x900c")), HINT));
	}

	@Test
	public void identityByteLoadedAfterTheMechanismWriteDeclines() throws Exception {
		builder.setBytes("0x9000", "48", true); // PHA
		builder.setBytes("0x9001", "a9 3a", true); // LDA #$3A
		builder.setBytes("0x9003", "8d 00 80", true); // STA $8000 -- COMMIT first
		builder.setBytes("0x9006", "ad 00 a0", true); // LDA $A000 -- reads the NEW bank's byte
		builder.setBytes("0x9009", "85 f0", true); // STA $F0
		builder.setBytes("0x900b", "68", true); // PLA
		builder.setBytes("0x900c", "20 00 91", true); // JSR
		builder.setBytes("0x9100", "60", true);
		builder.setBytes("0x900f", "a5 f0", true); // LDA $F0
		builder.setBytes("0x9011", "8d 00 80", true); // restore
		builder.setBytes("0x9014", "60", true);
		assertFalse(SaveRestoreTrampolines.restoresEntryBank(program,
			model(addr("0x9000"), addr("0x9011")), identity(), Set.of(addr("0x9003")), HINT));
	}

	@Test
	public void takenPathThatSwitchesDeclines() throws Exception {
		tmnt3Shape("8d 00 80 60"); // STA $8000 / RTS on the early out
		restoreTail("0x9013");
		assertFalse(restores(identity(), HINT, addr("0x900c"), addr("0x9020")));
	}

	@Test
	public void takenPathThatCallsDeclines() throws Exception {
		tmnt3Shape("20 00 91 60"); // JSR / RTS
		restoreTail("0x9013");
		assertFalse(restores(identity(), HINT, addr("0x900c")));
	}

	@Test
	public void takenPathWithStackImbalanceDeclines() throws Exception {
		tmnt3Shape("60"); // bare RTS with the PHA'd byte still on the stack
		restoreTail("0x9013");
		assertFalse(restores(identity(), HINT, addr("0x900c")));
	}

	@Test
	public void takenPathThatWritesTheCellDeclines() throws Exception {
		tmnt3Shape("68 85 f0 60"); // PLA / STA $F0 / RTS
		restoreTail("0x9013");
		assertFalse(restores(identity(), HINT, addr("0x900c")));
	}

	@Test
	public void backwardBranchDeclines() throws Exception {
		tmnt3Shape("68 60", "d0 f0"); // BNE backwards
		restoreTail("0x9013");
		assertFalse(restores(identity(), HINT, addr("0x900c")));
	}

	// ------------------------------------------------------------------
	// The biased identity byte
	// ------------------------------------------------------------------

	private BankMirrors biased(boolean withHint) {
		BankMirrors.IdentifyingEncoding enc = new BankMirrors.IdentifyingEncoding(0, 0, 8, 1,
			Set.of(0, 2, 4, 6), Set.of(0, 1, 2, 3, 4, 5, 6, 7));
		BankMirrors m = BankMirrors.of(baseSpace,
			Map.of(0xA000L, Set.of(BankMirrors.Kind.ROM_IDENTIFYING)), Map.of(0xA000L, R7),
			Map.of(0xA000L, enc));
		if (withHint) {
			List<String> refusals = new ArrayList<>();
			m = m.withMembershipHints(
				List.of(new BankMirrors.MembershipHint(0xA000, 0, 0, 8, 1, "test")), refusals);
			assertTrue(refusals.toString(), refusals.isEmpty());
		}
		return m;
	}

	private BankSwitchStrategy strategy(Map<Address, Integer> committed) {
		return (BankSwitchStrategy) Proxy.newProxyInstance(getClass().getClassLoader(),
			new Class<?>[] { BankSwitchStrategy.class }, (proxy, method, args) -> {
				if (method.getName().equals("bankFieldCommittedBySite")) {
					ghidra.program.model.listing.Instruction i =
						(ghidra.program.model.listing.Instruction) args[1];
					return committed.getOrDefault(i.getMinAddress(), -1);
				}
				throw new UnsupportedOperationException(method.getName());
			});
	}

	private Integer scoped(BankMirrors mirrors, BankSwitchStrategy strategy) {
		HelperDiscovery.HelperModel helper = new HelperDiscovery.HelperModel(null, addr("0x9000"),
			null, null, 0xFFFF, 0, strategy, addr("0x9015"), addr("0x9000"), null);
		return SaveRestoreTrampolines.restoredFieldMask(program, helper, mirrors,
			Set.of(addr("0x900c")), HINT);
	}

	@Test
	public void biasedByteWithHintRestoresExactlyItsField() throws Exception {
		fullShape();
		Map<Address, Integer> committed = Map.of(addr("0x900c"), R7.positionedMask(),
			addr("0x9013"), 0, addr("0x9015"), R7.positionedMask());
		// the walk's mechanism sites: commit 900c and the restore at 9015 (switchSite 9015)
		HelperDiscovery.HelperModel helper = new HelperDiscovery.HelperModel(null, addr("0x9000"),
			null, null, 0xFFFF, 0, strategy(committed), addr("0x9015"), addr("0x9000"), null);
		Integer mask = SaveRestoreTrampolines.restoredFieldMask(program, helper, biased(true),
			Set.of(addr("0x900c")), HINT);
		assertEquals(Integer.valueOf(R7.positionedMask()), mask);
	}

	@Test
	public void biasedByteWithoutHintDeclines() throws Exception {
		fullShape();
		HelperDiscovery.HelperModel helper = new HelperDiscovery.HelperModel(null, addr("0x9000"),
			null, null, 0xFFFF, 0,
			strategy(Map.of(addr("0x900c"), R7.positionedMask(), addr("0x9015"),
				R7.positionedMask())),
			addr("0x9015"), addr("0x9000"), null);
		assertNull(SaveRestoreTrampolines.restoredFieldMask(program, helper, biased(false),
			Set.of(addr("0x900c")), HINT));
	}

	@Test
	public void biasedByteCommittingAnotherFieldDeclines() throws Exception {
		fullShape();
		HelperDiscovery.HelperModel helper = new HelperDiscovery.HelperModel(null, addr("0x9000"),
			null, null, 0xFFFF, 0,
			strategy(Map.of(addr("0x900c"), R6.positionedMask(), addr("0x9015"),
				R7.positionedMask())),
			addr("0x9015"), addr("0x9000"), null);
		assertNull("a bank committed into R6 is never put back by an R7 restore",
			SaveRestoreTrampolines.restoredFieldMask(program, helper, biased(true),
				Set.of(addr("0x900c")), HINT));
	}

	@Test
	public void biasedByteWithUndeterminableSiteDeclines() throws Exception {
		fullShape();
		HelperDiscovery.HelperModel helper = new HelperDiscovery.HelperModel(null, addr("0x9000"),
			null, null, 0xFFFF, 0, strategy(Map.of(addr("0x9015"), R7.positionedMask())),
			addr("0x9015"), addr("0x9000"), null);
		assertNull(SaveRestoreTrampolines.restoredFieldMask(program, helper, biased(true),
			Set.of(addr("0x900c")), HINT));
	}

	@Test
	public void biasedByteWithNoStrategyDeclines() throws Exception {
		fullShape();
		assertNull(scoped(biased(true), null));
	}
}
