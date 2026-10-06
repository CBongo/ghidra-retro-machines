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
import static org.junit.Assert.assertNull;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

import retromachines.SaveRestoreTrampolines.FieldPairing;

/**
 * Pins the grm-mej.10 pairing-aware walk, {@link SaveRestoreTrampolines#restoredFieldMask(
 * ghidra.program.model.listing.Program, HelperDiscovery.HelperModel, BankMirrors, Set, Set, List)}
 * -- tmnt3's {@code FUN_9169} (bead grm-mej.17), simplified to one data commit per register:
 * <pre>
 *   9000: LDA $27 / BNE 8FF0            ; early out onto a shared RTS (a BACKWARD branch)
 *   9004: LDA $A000 / STA $F0           ; save the live R7 identity byte
 *   9009: LDX #$3A / STX $8001          ; R7 = $3A
 *   900e: JSR $9100                     ; inner call
 *   9011: LDX $F0 / STX $8001           ; R7 := saved           (low,  +0)
 *   9016: INX / STX $8003 / RTS         ; R6 := saved + 1       (high, +1)
 * </pre>
 */
public class PairedFieldTrampolineProgramTest extends AbstractBundledLanguageTest {

	private static final BoardDescriptorModel.FieldSpec R7 =
		new BoardDescriptorModel.FieldSpec("r7", 10, 6);
	private static final BoardDescriptorModel.FieldSpec R6 =
		new BoardDescriptorModel.FieldSpec("r6", 4, 6);
	private static final Set<Long> CELLS = Set.of(0xF0L);
	private static final List<FieldPairing> PAIR =
		List.of(new FieldPairing(R6.positionedMask(), R7.positionedMask(), 1));

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
		builder.setBytes("0x8ff0", "60", true); // the shared RTS
		builder.setBytes("0x9100", "a9 ff 60", true); // inner: LDA #$FF / RTS
	}

	private Address addr(String a) {
		return builder.addr(a);
	}

	private void lay(String restoreLoad, String highStore) throws Exception {
		builder.setBytes("0x9000", "a5 27 d0 ec", true); // LDA $27 / BNE $8FF0
		builder.setBytes("0x9004", "ad 00 a0 85 f0", true); // LDA $A000 / STA $F0
		builder.setBytes("0x9009", "a2 3a 8e 01 80", true); // LDX #$3A / STX $8001
		builder.setBytes("0x900e", "20 00 91", true); // JSR $9100
		builder.setBytes("0x9011", restoreLoad + " 8e 01 80", true); // LDX $F0 / STX $8001
		builder.setBytes("0x9016", highStore, true); // INX / STX $8003 / RTS
	}

	private void layFull() throws Exception {
		lay("a6 f0", "e8 8e 03 80 60");
	}

	private BankMirrors mirrors() {
		return BankMirrors.of(baseSpace, Map.of(0xA000L, Set.of(BankMirrors.Kind.ROM_IDENTIFYING)),
			Map.of(0xA000L, R7));
	}

	private Set<Address> sites() {
		return Set.of(addr("0x900b"), addr("0x9013"), addr("0x9017"));
	}

	private Integer claim(Set<Long> cells, List<FieldPairing> pairs) {
		Map<Address, Integer> committed = Map.of(addr("0x900b"), R7.positionedMask(),
			addr("0x9013"), R7.positionedMask(), addr("0x9017"), R6.positionedMask());
		BankSwitchStrategy strategy = (BankSwitchStrategy) Proxy.newProxyInstance(
			getClass().getClassLoader(), new Class<?>[] { BankSwitchStrategy.class },
			(proxy, method, args) -> {
				if (method.getName().equals("bankFieldCommittedBySite")) {
					ghidra.program.model.listing.Instruction i =
						(ghidra.program.model.listing.Instruction) args[1];
					return committed.getOrDefault(i.getMinAddress(), -1);
				}
				throw new UnsupportedOperationException(method.getName());
			});
		HelperDiscovery.HelperModel helper = new HelperDiscovery.HelperModel(null, addr("0x9000"),
			null, null, 0xFFFF, 0, strategy, addr("0x9017"), addr("0x9000"), null);
		return SaveRestoreTrampolines.restoredFieldMask(program, helper, mirrors(), sites(), cells,
			pairs);
	}

	@Test
	public void restoreOfR7AndSavedPlusOneIntoPairedR6RestoresBothFields() throws Exception {
		layFull();
		assertEquals(Integer.valueOf(R7.positionedMask() | R6.positionedMask()),
			claim(CELLS, PAIR));
	}

	@Test
	public void withoutThePairingTheHelperIsNotAFieldScopedNoOp() throws Exception {
		layFull();
		assertNull("R6 := saved+1 is only R6's old value under the pairing",
			claim(CELLS, List.of()));
	}

	@Test
	public void aPairingWithAnotherOffsetDeclines() throws Exception {
		layFull();
		assertNull(claim(CELLS, List.of(
			new FieldPairing(R6.positionedMask(), R7.positionedMask(), 2))));
	}

	@Test
	public void withoutTheSaveCellHintDeclines() throws Exception {
		layFull();
		assertNull(claim(Set.of(), PAIR));
	}

	@Test
	public void r7NotRestoredFromTheSavedByteDeclines() throws Exception {
		lay("a2 00", "e8 8e 03 80 60"); // LDX #0 instead of LDX $F0
		assertNull(claim(CELLS, PAIR));
	}

	@Test
	public void highStoreOfSomethingOtherThanSavedPlusOneDeclines() throws Exception {
		lay("a6 f0", "ca 8e 03 80 60"); // DEX: saved - 1
		assertNull(claim(CELLS, PAIR));
	}

	@Test
	public void unbalancedStackAtTheRtsDeclines() throws Exception {
		lay("a6 f0", "e8 8e 03 80 48 60"); // PHA left on the stack at RTS
		assertNull(claim(CELLS, PAIR));
	}
}
