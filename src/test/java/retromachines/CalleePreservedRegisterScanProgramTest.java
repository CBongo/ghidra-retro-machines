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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Bead grm-mej.13: a register a callee provably preserves keeps its value across the call in
 * {@link StoredValueScanner}'s backward walks ({@code resolveStoredValue}, the banktest2 "C5"
 * shape, and the shared all-or-nothing {@code constantValue}). Caller lives in FIX ($C000), the
 * stored-to cell is RAM; callees are placed per test. Anything the summary cannot vouch for must
 * behave exactly as before: the register is lost.
 */
public class CalleePreservedRegisterScanProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	private static final StoredValueScanner.Hooks NO_HOOKS = new StoredValueScanner.Hooks() {
		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			return null;
		}
	};

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		MemoryBlock ram = builder.createMemory(".ram", "0x100", 0x700);
		builder.createMemory("PRG", "0x8000", 0x4000);
		builder.createMemory("FIX", "0xC000", 0x4000);
		program = builder.getProgram();
		int tx = program.startTransaction("writable");
		try {
			zp.setWrite(true);
			ram.setWrite(true);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	private void code(String addr, String hex) throws Exception {
		builder.setBytes(addr, hex, false);
		builder.disassemble(addr, hex.replace(" ", "").length() / 2, false);
	}

	private Instruction at(String addr) {
		Instruction i = program.getListing().getInstructionAt(builder.addr(addr));
		assertNotNull("nothing at " + addr, i);
		return i;
	}

	/** The byte the scanner resolves for the store at {@code storeAddr}, or null if not fully known. */
	private Integer storedA(String storeAddr) {
		BankState v = StoredValueScanner.resolveStoredValueScan(program, at(storeAddr), 'A',
			BankState.unknown(), 0xFF, NO_HOOKS, RegisterEnv.NONE).value();
		return (v.knownMask() & 0xFF) == 0xFF ? v.bits() & 0xFF : null;
	}

	private Integer constant(String instrAddr, char reg) {
		return StoredValueScanner.constantRegisterValue(program, at(instrAddr), reg, NO_HOOKS,
			RegisterEnv.NONE, new StoredValueScanner.Budget(64));
	}

	/** LDA #$35 / JSR $C100 / STA $0200 at $C000; the store is at $C005. */
	private void callerA() throws Exception {
		code("0xc000", "a9 35 20 00 c1 8d 00 02");
	}

	@Test
	public void preservingCalleeKeepsTheImmediate() throws Exception {
		callerA();
		code("0xc100", "60"); // bare RTS
		assertEquals(Integer.valueOf(0x35), storedA("0xc005"));
	}

	@Test
	public void calleeThatClobbersAIsTodaysResult() throws Exception {
		callerA();
		code("0xc100", "a9 00 60"); // LDA #0 / RTS
		assertNull(storedA("0xc005"));
	}

	@Test
	public void calleePreservingOnlyXDoesNotHelpAValue() throws Exception {
		callerA();
		code("0xc100", "8a 48 a9 00 68 aa 60"); // TXA/PHA/LDA #0/PLA/TAX/RTS: X kept, A lost
		assertNull(storedA("0xc005"));
	}

	@Test
	public void xDefinedBeforeACallPreservingXSurvivesInConstantValue() throws Exception {
		code("0xc000", "a2 07 20 00 c1 86 10"); // LDX #7 / JSR $C100 / STX $10
		code("0xc100", "8a 48 a9 00 68 aa 60"); // preserves X, clobbers A
		assertEquals(Integer.valueOf(7), constant("0xc005", 'X'));
	}

	@Test
	public void xClobberingCalleeLosesXInConstantValue() throws Exception {
		code("0xc000", "a2 07 20 00 c1 86 10");
		code("0xc100", "e8 60"); // INX / RTS
		assertNull(constant("0xc005", 'X'));
	}

	@Test
	public void flagsAreNeverPreservedAcrossACall() throws Exception {
		// CLC / JSR (bare RTS) / ADC #1: the carry must still be treated as clobbered
		code("0xc000", "18 20 00 c1 69 01 8d 00 02"); // CLC / JSR / ADC #1 / STA $0200
		code("0xc100", "60");
		StoredValueScanner.Budget b = new StoredValueScanner.Budget(64);
		assertNull(StoredValueScanner.constantLocValue(program, at("0xc004"),
			ConstantSemantics.Loc.C, NO_HOOKS, RegisterEnv.NONE, b));
	}

	@Test
	public void calleeInABankedWindowIsNotSteppedOver() throws Exception {
		builder.createOverlayMemory("PRG_B1", "0x8000", 0x100); // makes PRG a banked window
		code("0xc000", "a9 35 20 00 90 8d 00 02"); // JSR $9000, inside the window
		code("0x9000", "60"); // would preserve everything if looked into
		assertNull(storedA("0xc005"));
	}

	@Test
	public void abandonedSummaryIsTodaysResult() throws Exception {
		callerA();
		code("0xc100", "a2 ff 9a 60"); // TXS abandons the summary
		assertNull(storedA("0xc005"));
	}

	@Test
	public void nestedPreservationComposes() throws Exception {
		callerA();
		code("0xc100", "20 00 c2 60"); // JSR $C200 / RTS
		code("0xc200", "60");
		assertEquals(Integer.valueOf(0x35), storedA("0xc005"));
	}

	@Test
	public void nestedClobberPropagates() throws Exception {
		callerA();
		code("0xc100", "20 00 c2 60");
		code("0xc200", "a9 01 60"); // LDA #1 / RTS
		assertNull(storedA("0xc005"));
	}

	@Test
	public void unresolvedCalleeIsTodaysResult() throws Exception {
		callerA(); // nothing disassembled at $C100
		assertNull(storedA("0xc005"));
	}

	/**
	 * A state-dependent load before a preserving call, for the bank-state hazard: the callee
	 * keeps A but may switch the bank, so the load must be resolved under the state AT the call,
	 * never under the store's. The hook answers a load with exactly the state it is handed, so
	 * the resolved byte says which state the walk used; {@code stateAtCall == null} models a
	 * direct-site strategy with no oracle.
	 */
	private static final class StateEchoHooks implements StoredValueScanner.Hooks {
		final BankState stateAtCall;
		int loadsAsked;

		StateEchoHooks(BankState stateAtCall) {
			this.stateAtCall = stateAtCall;
		}

		@Override
		public boolean isMechanismWrite(Instruction instr) {
			return false;
		}

		@Override
		public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
				BankState inStateAtStore) {
			loadsAsked++;
			return inStateAtStore;
		}

		@Override
		public BankState stateAt(Address addr) {
			return stateAtCall;
		}
	}

	/** LDA $0300 / JSR $C100 (bare RTS) / STA $0200; resolved with the store's state = $77. */
	private BankState loadAcrossPreservingCall(StateEchoHooks hooks) throws Exception {
		code("0xc000", "ad 00 03 20 00 c1 8d 00 02");
		code("0xc100", "60");
		return StoredValueScanner.resolveStoredValueScan(program, at("0xc006"), 'A',
			BankState.fullyKnown(0xFF, 0x77), 0xFF, hooks, RegisterEnv.NONE).value();
	}

	@Test
	public void loadBeforeAPreservingCallUsesTheStateAtTheCall() throws Exception {
		StateEchoHooks hooks = new StateEchoHooks(BankState.fullyKnown(0xFF, 0x22));
		BankState v = loadAcrossPreservingCall(hooks);
		assertEquals("resolved under the state at the call, not the store's", 0xFF,
			v.knownMask() & 0xFF);
		assertEquals(0x22, v.bits() & 0xFF);
	}

	@Test
	public void loadBeforeAPreservingCallWithNoStateStopsWithoutAskingTheHook() throws Exception {
		StateEchoHooks hooks = new StateEchoHooks(null);
		BankState v = loadAcrossPreservingCall(hooks);
		assertEquals("blind walk must not resolve a state-dependent load", 0, v.knownMask());
		assertEquals("blind walk must not consult the hook (the ironsword rule)", 0,
			hooks.loadsAsked);
	}
}
