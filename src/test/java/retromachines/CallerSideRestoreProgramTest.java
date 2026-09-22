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
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.HashSet;
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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import retromachines.BankSwitchStrategy.HelperDeposit;
import retromachines.BankSwitchStrategy.SwitchOutcome;
import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperArgumentRecovery.StateOracle;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Pins bead grm-yflf's CALLER-SIDE restore classification -- the half of the feature that
 * recognizes a caller reading its own bank back out of a live mirror it maintains, rather than
 * (as {@link HelperNoArgumentRestoreProgramTest} covers) a helper reloading it from a save slot
 * inside its own prologue.
 * <p>
 * Two production shapes motivate every case here, both from Mega Man 2:
 * <ul>
 * <li>{@code FUN_c000} at {@code ca12}/{@code cb60}: begins {@code STA $29} on its way to the MMC1
 * chain, so {@code $29} is a write-through shadow of the live bank ({@link BankMirrors.Discovery}
 * route (a)). Its NMI tail does {@code LDA $29 / PHA / JSR ... / PLA / JSR $C000} -- a caller
 * reading the shadow back, carrying it across an intervening call via the stack, then handing it
 * to the very helper that maintains it.</li>
 * <li>{@code d0c3}: the bare form of the same idiom with no intervening call --
 * {@code LDA $29 / JSR $C000}.</li>
 * </ul>
 * Neither call site has a caller-supplied ARGUMENT in the ordinary sense: the byte was never
 * computed by the caller, only read back from a mirror the callee itself established. Reporting it
 * as an unresolved "argument not recovered" WARNING would be a false alarm; reporting it as a
 * resolved VALUE would be an overclaim whenever the mirror could not actually be proven fresh
 * (bead grm-p9y's {@code shadowCoherentAt}). {@link BankSwitchStrategy.ValueStop#RESTORED_BANK}
 * and {@link StoredValueScanner.ReadBack} exist to name this shape honestly in between the two:
 * {@code readBack} names the mirror, where it was read, and (bead grm-mej.3 increment 3) which
 * call the read was carried across, and {@code BoardBankAnalyzer} turns that into a NOTE rather
 * than a WARNING.
 * <p>
 * The cases below run three layers, matching the file this bead's other half is tested at
 * ({@link HelperNoArgumentRestoreProgramTest}) and the layering established by
 * {@link CallCrossingPushPullProgramTest}:
 * <ul>
 * <li><b>Discovery</b> (A, B): {@link BankMirrors.Discovery#scanArgumentCells(Program, Map, Map)}'s
 * new "rule 2-prime" -- an argument load of a cell that the CALLED helper's own body writes
 * through is the two-sided corroboration route (a)'s ordinary rule already accepts, just found
 * across the call boundary instead of within one function.</li>
 * <li><b>Recovery</b> (C-G): {@link HelperArgumentRecovery#recoverCallArgument} end to end with a
 * hand-built {@link BankSwitchStrategy} stub, covering the read-back's shape requirements
 * (identity accumulators, a plain fixed address, a recognized mirror kind) and the fact that the
 * KIND query only exists on the engine's oracle-backed path.</li>
 * <li><b>Engine</b> (H): {@link BankDataflowEngine#runDataflow} end to end on a real
 * {@link MemoryLatchBankSwitchStrategy}, showing both outcomes a caller-side mirror read can reach
 * depending on whether the tracked state at the read is provably coherent (RESOLVED) or not
 * (RESTORED_BANK, with a populated {@code readBack}).</li>
 * </ul>
 * Case I is a regression pin on {@link CallEffect#asSecondTierRelay()}, the sibling of
 * {@link HelperNoArgumentRestoreProgramTest#asSecondTierRelayCarriesRestoreCellThroughUnchanged}
 * for the {@code readBack} field added alongside {@code restoreCell}.
 * <p>
 * Fixture note inherited from {@code CallCrossingPushPullProgramTest}: {@link ProgramBuilder}
 * blocks are created read-only, so a RAM block backing any mirror cell must be made writable
 * explicitly.
 */
public class CallerSideRestoreProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private AddressSpace baseSpace;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		MemoryBlock zp = builder.createMemory(".zp", "0x0", 0x100);
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		baseSpace = program.getAddressFactory().getDefaultAddressSpace();
		makeWritable(zp);
	}

	private void makeWritable(MemoryBlock block) {
		int tx = program.startTransaction("set block write permission");
		try {
			block.setWrite(true);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	private Address addr(String address) {
		return builder.addr(address);
	}

	private Address addr(int a) {
		return addr(String.format("0x%x", a));
	}

	private void put(String address, String hex) throws Exception {
		builder.setBytes(address, hex, true);
	}

	private void putAt(int a, String hex) throws Exception {
		put(String.format("0x%x", a), hex);
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	// ==================================================================
	// A, B -- Discovery rule 2-prime: BankMirrors.Discovery.scanArgumentCells(Program, Map, Map)
	// ==================================================================

	/**
	 * Lays the ca12 shape reduced to its Discovery-relevant bytes: helper H at {@code $9000}
	 * ({@code STA $29} then the mechanism write {@code STA $C000} at {@code $9002}), and a caller
	 * at {@code $9100} that reads {@code $29} back immediately before calling H. Returns H's
	 * {@link Function} so its body can be handed to {@code scanArgumentCells}.
	 * <p>
	 * A SECOND, unrelated switch site ({@code $9012}, fed from an immediate rather than from
	 * {@code $29}) is included deliberately: with only {@code $9002} as a switch site,
	 * {@code build()}'s THIRD corroboration route -- coverage, {@code coversAMechanismField} --
	 * would admit {@code $29} on its own (one store maintaining the only switch there is, exactly
	 * db3's shape), leaving rule 2-prime nothing to prove. With a second switch site {@code $29}
	 * does not maintain, coverage fails, the two-distinct-stores route needs a second store site
	 * that does not exist, and the ONLY route left standing is "one store corroborated by a load" --
	 * which is exactly what these cases are pinning.
	 */
	private Function layRule2PrimeFixture() throws Exception {
		put("0x9000", "85 29"); // STA $29        -- route (a)'s store
		put("0x9002", "8d 00 c0"); // STA $C000       <- switch site 1 (maintains $29)
		put("0x9005", "60"); // RTS
		Function h = builder.createEmptyFunction("H", "0x9000", 6, null);

		put("0x9010", "a9 06"); // LDA #$06        -- unrelated switch site's own value
		put("0x9012", "8d 00 c0"); // STA $C000       <- switch site 2 (does NOT maintain $29)

		put("0x9100", "a5 29"); // LDA $29         -- the caller's argument load
		put("0x9102", "20 00 90"); // JSR $9000       <- the call
		put("0x9105", "60"); // RTS
		return h;
	}

	private List<Address> rule2PrimeSwitchSites() {
		return List.of(addr("0x9002"), addr("0x9012"));
	}

	/**
	 * A. The affirmative case rule 2-prime exists for: {@code $29} has exactly ONE write-through
	 * store (H's own {@code STA $29}), which alone is a coincidence route (a) refuses to admit --
	 * but the caller's {@code LDA $29} immediately before calling H is a load of a cell that H's
	 * OWN body writes through, which is the same two-sided evidence route (a)'s ordinary corroborated
	 * rule accepts within one function, just found across the call boundary. {@code build()}'s
	 * unchanged rule ("1 store + >=1 load") then types {@code $29} {@link BankMirrors.Kind#WRITE_THROUGH}.
	 */
	@Test
	public void argumentLoadOfACellTheCalledHelperWritesThroughCorroboratesTheShadow()
			throws Exception {
		Function h = layRule2PrimeFixture();

		BankMirrors.Discovery discovery = new BankMirrors.Discovery(baseSpace);
		discovery.scanWriteThroughShadows(program, rule2PrimeSwitchSites());
		discovery.scanArgumentCells(program, Map.of(addr("0x9102"), 'A'),
			Map.of(addr("0x9102"), h.getBody()));
		BankMirrors mirrors = discovery.build();

		assertEquals(Set.of(BankMirrors.Kind.WRITE_THROUGH), mirrors.kindsAt(addr("0x29")));
	}

	/**
	 * B (negative, no helper body at all). The two-argument {@code scanArgumentCells} overload --
	 * kept for the pre-grm-yflf derivation tests -- must leave behaviour UNCHANGED: with no body to
	 * consult, the argument load records only route (b)'s ordinary {@code argumentLoads} evidence,
	 * never a {@code writeThroughLoad}, so the single write-through store from route (a) stays
	 * uncorroborated and {@code $29} resolves to NEITHER {@code WRITE_THROUGH} (needs a second
	 * store or a corroborating load) NOR {@code INPUT} (needs a second call site; there is only
	 * one here).
	 */
	@Test
	public void twoArgumentOverloadLeavesBehaviourUnchanged() throws Exception {
		layRule2PrimeFixture();

		BankMirrors.Discovery discovery = new BankMirrors.Discovery(baseSpace);
		discovery.scanWriteThroughShadows(program, rule2PrimeSwitchSites());
		discovery.scanArgumentCells(program, Map.of(addr("0x9102"), 'A')); // 2-arg overload
		BankMirrors mirrors = discovery.build();

		assertTrue("one store, no corroborating load or second call site -- must not resolve",
			mirrors.kindsAt(addr("0x29")).isEmpty());
	}

	/**
	 * B (negative, wrong body). The three-argument form must not corroborate off ANY body handed
	 * to it -- only one that actually CONTAINS one of the cell's existing write-through stores.
	 * Handing it an unrelated function's body (which does not contain {@code $9000}) must behave
	 * exactly like the two-argument overload above.
	 */
	@Test
	public void aHelperBodyThatDoesNotContainTheStoreDoesNotCorroborate() throws Exception {
		layRule2PrimeFixture();
		put("0x9200", "60"); // RTS -- an unrelated one-instruction function
		Function unrelated = builder.createEmptyFunction("unrelated", "0x9200", 1, null);

		BankMirrors.Discovery discovery = new BankMirrors.Discovery(baseSpace);
		discovery.scanWriteThroughShadows(program, rule2PrimeSwitchSites());
		discovery.scanArgumentCells(program, Map.of(addr("0x9102"), 'A'),
			Map.of(addr("0x9102"), unrelated.getBody()));
		BankMirrors mirrors = discovery.build();

		assertTrue(mirrors.kindsAt(addr("0x29")).isEmpty());
	}

	// ==================================================================
	// C-G -- Recovery-level: HelperArgumentRecovery.recoverCallArgument
	// ==================================================================

	/**
	 * A minimal {@link BankSwitchStrategy} that deposits {@code argValue} verbatim, delivers a
	 * fixed {@link BankMirrors} set via {@link #observedMirrors()} (the KIND query
	 * {@code OracleHooks.isLiveBankMirror} reads, engine-path only), and optionally overrides
	 * {@link #callerSideHooks()} -- copied in spirit from
	 * {@code CallCrossingPushPullProgramTest.StubStrategy}.
	 */
	private static final class MirrorAwareStrategy implements BankSwitchStrategy {

		private final BankMirrors mirrors;
		private final StoredValueScanner.Hooks hooksOverride;

		MirrorAwareStrategy(BankMirrors mirrors) {
			this(mirrors, null);
		}

		MirrorAwareStrategy(BankMirrors mirrors, StoredValueScanner.Hooks hooksOverride) {
			this.mirrors = mirrors;
			this.hooksOverride = hooksOverride;
		}

		@Override
		public String strategyName() {
			return "caller-restore-probe";
		}

		@Override
		public void configure(ghidra.program.model.listing.Program program, JsonObject params,
				int stateMask) {
			// no configuration needed
		}

		@Override
		public SwitchOutcome computeSwitchOutcome(ghidra.program.model.listing.Program program,
				Instruction instr, BankState inState) {
			return SwitchOutcome.of(BankState.unknown());
		}

		@Override
		public HelperDeposit depositHelperArgument(ghidra.program.model.listing.Program program,
				Instruction switchSite, BankState argValue, BankState inState, int stateMask,
				RegisterEnv callerRegs) {
			return new HelperDeposit(stateMask, argValue);
		}

		@Override
		public BankMirrors observedMirrors() {
			return mirrors;
		}

		@Override
		public StoredValueScanner.Hooks callerSideHooks() {
			return hooksOverride == null ? BankSwitchStrategy.super.callerSideHooks()
					: hooksOverride;
		}
	}

	/** {@code Hooks} whose {@code resolveMirrorLoad} answers {@code mirrorCell} with a wholly
	 *  unknown state (rather than declining with {@code null}) -- an "I recognize this as a mirror
	 *  but know nothing about it right now" answer, distinct from "I have no opinion". */
	private static StoredValueScanner.Hooks mirrorAnswersUnknown(Address mirrorCell) {
		return new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return false;
			}

			@Override
			public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return null;
			}

			@Override
			public BankState resolveMirrorLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return mirrorCell.equals(resolvedTarget) ? BankState.unknown() : null;
			}
		};
	}

	private BankMirrors singleMirror(String cellAddress, BankMirrors.Kind kind) {
		return BankMirrors.of(baseSpace, Map.of(addr(cellAddress).getOffset(), Set.of(kind)));
	}

	/** A single-instruction helper ({@code STA $E000}) at {@code $9100}, the same shape
	 *  {@code CallCrossingPushPullProgramTest.mirrorHelper} uses. */
	private HelperModel mirrorHelper(BankSwitchStrategy strategy) {
		return new HelperModel(null, addr("0x9100"), null, 'A', 0xFF, 0, strategy,
			addr("0x9100"), addr("0x9100"), null);
	}

	private CallEffect recoverWithOracle(HelperModel helper, String callSite, StateOracle oracle)
			throws Exception {
		return HelperArgumentRecovery.recoverCallArgument(program, instructionAt(callSite), helper,
			BankState.unknown(), new HashMap<>(), new HashSet<>(), RegisterEnv.NONE, oracle);
	}

	/** {@code LDA $29 / PHA / JSR work / PLA / JSR helper} -- the ca12 shape, with the mirror
	 *  cell's own read-back carried across the intervening call via the stack. */
	private void layPushPullReadBackShape() throws Exception {
		put("0x8000", "a5 29"); // LDA $29
		put("0x8002", "48"); // PHA
		put("0x8003", "20 00 90"); // JSR work ($9000)
		put("0x8006", "68"); // PLA
		put("0x8007", "20 00 91"); // JSR helper ($9100)  <- callInstr
		put("0x800a", "60"); // RTS
		put("0x9000", "60"); // RTS (work)
		put("0x9100", "8d 00 e0"); // STA $E000  -- single-instruction helper
	}

	/**
	 * C. The ca12 shape end to end, WITH an oracle: the read-back must be recognized even though
	 * the value stays unresolved (the oracle answers wholly unknown at every address, including the
	 * push). Pins the shape requirements together -- identity accumulators, a plain fixed address,
	 * the call actually crossed -- and every {@link StoredValueScanner.ReadBack} component.
	 */
	@Test
	public void callCrossingReadBackIsRecognizedWithAnOracle() throws Exception {
		layPushPullReadBackShape();
		MirrorAwareStrategy strategy =
			new MirrorAwareStrategy(singleMirror("0x29", BankMirrors.Kind.WRITE_THROUGH));
		HelperModel helper = mirrorHelper(strategy);
		StateOracle oracle = a -> BankState.unknown();

		CallEffect effect = recoverWithOracle(helper, "0x8007", oracle);

		assertTrue("the read-back value itself must stay unresolved", !effect.argumentResolved());
		StoredValueScanner.ReadBack readBack = effect.readBack();
		assertNotNull("the read-back must be recognized even though its value is unknown",
			readBack);
		assertEquals(addr("0x29"), readBack.cell());
		assertEquals(addr("0x8000"), readBack.readAt());
		assertEquals("the call the read-back was carried across", addr("0x8003"),
			readBack.carriedAcross());
		assertEquals("restoredFrom() is the one accessor a consumer needs", addr("0x29"),
			effect.restoredFrom());
		assertNull("this is a caller-side read-back, not a helper-prologue reload",
			effect.restoreCell());
	}

	/**
	 * C (variant). The same shape, but with {@code callerSideHooks} answering
	 * {@link #mirrorAnswersUnknown} rather than declining outright with {@code null} -- an "I know
	 * this is a mirror but have nothing to say" answer. {@code stopped()} discards a
	 * {@code RESTORED_BANK} reason only when the COMBINED value ends up known, so this must reach
	 * the identical outcome as the declining-{@code null} case above.
	 */
	@Test
	public void callCrossingReadBackIsRecognizedWhenTheMirrorHookAnswersUnknownRatherThanNull()
			throws Exception {
		layPushPullReadBackShape();
		MirrorAwareStrategy strategy = new MirrorAwareStrategy(
			singleMirror("0x29", BankMirrors.Kind.WRITE_THROUGH), mirrorAnswersUnknown(addr("0x29")));
		HelperModel helper = mirrorHelper(strategy);
		StateOracle oracle = a -> BankState.unknown();

		CallEffect effect = recoverWithOracle(helper, "0x8007", oracle);

		assertNotNull(effect.readBack());
		assertEquals(addr("0x29"), effect.readBack().cell());
	}

	/**
	 * D. The bare d0c3 shape -- {@code LDA $29 / JSR helper}, no push at all. The read-back must
	 * still be recognized, and {@code carriedAcross()} must be {@code null}: nothing was crossed,
	 * so there is nothing to name.
	 */
	@Test
	public void bareReadBackWithNoInterveningCallHasNoCarriedAcross() throws Exception {
		put("0x8100", "a5 29"); // LDA $29
		put("0x8102", "20 00 91"); // JSR helper ($9100)
		put("0x8105", "60"); // RTS
		put("0x9100", "8d 00 e0"); // STA $E000 (same single-instruction helper)

		MirrorAwareStrategy strategy =
			new MirrorAwareStrategy(singleMirror("0x29", BankMirrors.Kind.WRITE_THROUGH));
		HelperModel helper = mirrorHelper(strategy);
		StateOracle oracle = a -> BankState.unknown();

		CallEffect effect = recoverWithOracle(helper, "0x8102", oracle);

		StoredValueScanner.ReadBack readBack = effect.readBack();
		assertNotNull(readBack);
		assertEquals(addr("0x29"), readBack.cell());
		assertEquals(addr("0x8100"), readBack.readAt());
		assertNull("nothing was crossed to reach this load", readBack.carriedAcross());
	}

	/**
	 * E. A MODIFIED read-back -- {@code LDA $29 / AND #$0F / JSR helper} -- must never be reported
	 * as a read-back at all: the shape requires IDENTITY accumulators (the byte deposited must be
	 * exactly the byte read), and an {@code AND} breaks that regardless of whether the mask algebra
	 * goes on to resolve some of the bits some other way.
	 */
	@Test
	public void aModifiedLoadIsNeverAReadBack() throws Exception {
		put("0x8110", "a5 29"); // LDA $29
		put("0x8112", "29 0f"); // AND #$0F
		put("0x8114", "20 00 91"); // JSR helper ($9100)
		put("0x8117", "60"); // RTS
		put("0x9100", "8d 00 e0"); // STA $E000

		MirrorAwareStrategy strategy =
			new MirrorAwareStrategy(singleMirror("0x29", BankMirrors.Kind.WRITE_THROUGH));
		HelperModel helper = mirrorHelper(strategy);
		StateOracle oracle = a -> BankState.unknown();

		CallEffect effect = recoverWithOracle(helper, "0x8114", oracle);

		assertNull("an AND breaks the identity-accumulator requirement -- never a read-back",
			effect.readBack());
	}

	/**
	 * F. A read of a cell that is NOT in the strategy's mirror set at all -- {@code LDA $30 / JSR
	 * helper} against a mirror set that only knows {@code $29} -- must never be reported as a
	 * read-back, however plain and unmodified the load is.
	 */
	@Test
	public void aLoadOfANonMirrorCellIsNeverAReadBack() throws Exception {
		put("0x8120", "a5 30"); // LDA $30 -- not a mirror
		put("0x8122", "20 00 91"); // JSR helper ($9100)
		put("0x8125", "60"); // RTS
		put("0x9100", "8d 00 e0"); // STA $E000

		MirrorAwareStrategy strategy =
			new MirrorAwareStrategy(singleMirror("0x29", BankMirrors.Kind.WRITE_THROUGH));
		HelperModel helper = mirrorHelper(strategy);
		StateOracle oracle = a -> BankState.unknown();

		CallEffect effect = recoverWithOracle(helper, "0x8122", oracle);

		assertNull(effect.readBack());
	}

	/**
	 * G. No oracle at all -- the plain, pre-grm-mej.3 six-argument {@code recoverCallArgument}
	 * form, over the SAME ca12 shape as case C. The read-back's KIND query
	 * ({@code isLiveBankMirror}) is answered only by {@code OracleHooks}, which is constructed only
	 * when an oracle is supplied -- so even the identical shape that resolves to a read-back under
	 * an oracle must come back with {@code readBack() == null} here. Doubly so because, with no
	 * oracle, {@code resumeStateAfterPairing} also abandons the call-crossing pairing outright (no
	 * {@code stateAt} to resume from), so the walk never even reaches the mirror load.
	 */
	@Test
	public void withNoOracleAtAllTheReadBackNeverFires() throws Exception {
		layPushPullReadBackShape();
		MirrorAwareStrategy strategy =
			new MirrorAwareStrategy(singleMirror("0x29", BankMirrors.Kind.WRITE_THROUGH));
		HelperModel helper = mirrorHelper(strategy);

		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8007"), helper, BankState.unknown(), new HashMap<>(), new HashSet<>());

		assertNull(effect.readBack());
	}

	// ==================================================================
	// H -- Engine-level: BankDataflowEngine.runDataflow
	// ==================================================================

	private BoardDescriptorModel.BoardModel board4Bit() {
		JsonObject map = JsonParser.parseString("""
				{
				  "banking": {
				    "initial_state": 0,
				    "mechanisms": [ { "strategy": "memory-latch" } ],
				    "state": [ { "name": "bank", "bits": 4 } ]
				  }
				}
				""").getAsJsonObject();
		BoardDescriptorModel.BoardModel board = BoardDescriptorModel.BoardModel.parse(map,
			new MessageLog(), "test", "test-descriptor.json");
		assertNotNull(board);
		return board;
	}

	private void makeFunction(int start, int endInclusive, String name) throws Exception {
		Address startAddr = addr(start);
		Address endAddr = addr(endInclusive);
		int tx = program.startTransaction("create function");
		try {
			program.getFunctionManager().createFunction(name, startAddr,
				new AddressSet(startAddr, endAddr), SourceType.ANALYSIS);
		}
		finally {
			program.endTransaction(tx, true);
		}
		builder.createEntryPoint(String.format("0x%x", start), name);
	}

	private void markAsyncEntry(Address... entries) {
		int tx = program.startTransaction("set async entry points");
		try {
			program.getOptions(Program.PROGRAM_INFO).setString(
				DescriptorSupport.ASYNC_ENTRY_POINTS_PROPERTY,
				DescriptorSupport.formatAsyncEntryPoints(List.of(entries)));
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	/**
	 * Lays the engine-level ca12 shape: {@code RESET} reads its own write-through mirror
	 * ({@code $29}), carries it across an unrelated call ({@code far}) on the stack, then feeds it
	 * to the SAME helper ({@code H16}) that maintains the mirror -- byte for byte the shape
	 * {@link BankMirrors.Discovery#scanArgumentCells(Program, Map, Map)} (cases A/B above) exists
	 * to corroborate, now run through the real fixpoint.
	 */
	private void layEngineReadBackShape() throws Exception {
		putAt(0xC000, "a5 29"); // LDA $29    -- mirror read
		putAt(0xC002, "48"); // PHA
		putAt(0xC003, "20 40 c0"); // JSR far    ($C040)
		putAt(0xC006, "68"); // PLA
		putAt(0xC007, "20 30 c0"); // JSR H16    ($C030)  <- must classify against the push
		putAt(0xC00a, "60"); // RTS
		putAt(0xC030, "8d 00 90"); // STA $9000  (H16, the mechanism write)
		putAt(0xC033, "60"); // RTS
		putAt(0xC040, "60"); // RTS (far)

		makeFunction(0xC000, 0xC00a, "RESET");
		makeFunction(0xC030, 0xC033, "H16");
	}

	private BankDataflowEngine.DataflowResult runEngine() throws Exception {
		BoardDescriptorModel.BoardModel board = board4Bit();
		MemoryLatchBankSwitchStrategy latch = new MemoryLatchBankSwitchStrategy();
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x9000);
		params.addProperty("end", 0x9100);
		params.addProperty("mask", board.mask());
		latch.configure(program, params, board.mask());
		latch.observeMirrors(
			BankMirrors.of(baseSpace, Map.of(0x29L, Set.of(BankMirrors.Kind.WRITE_THROUGH))));

		BankStrategyRegistry.ConfiguredMechanism mechanism =
			new BankStrategyRegistry.ConfiguredMechanism(latch, board.mask(), 0);

		Function h16 = program.getFunctionManager().getFunctionAt(addr(0xC030));
		assertNotNull(h16);
		HelperModel helper = new HelperModel(h16, addr(0xC030), null, 'A', board.mask(), 0, latch,
			addr(0xC030), addr(0xC030), null);

		return BankDataflowEngine.runDataflow(program, TaskMonitor.DUMMY, program.getListing(),
			List.of(mechanism), board, Map.of(h16, helper), Set.of());
	}

	/**
	 * H (resolved). {@code RESET} is an ORDINARY (non-async) entry, seeded with
	 * {@code initial_state} FULLY KNOWN -- and the mirror read at {@code $C000} sits at the
	 * function's own entry, with nothing between it and the seed, so
	 * {@code shadowCoherentAt}'s own rule ("the containing function's entry ... is COHERENT")
	 * lets {@code MemoryLatchBankSwitchStrategy} answer it from tracked state. The call at
	 * {@code $C007} must therefore RESOLVE (bank 0, the seed), and a resolved read-back is just a
	 * resolved value -- {@code readBack()} must be {@code null} exactly as
	 * {@code StoredValueScanner.stopped()}'s javadoc says a known combined value discards it.
	 */
	@Test(timeout = 30000)
	public void engineResolvesTheReadBackWhenTheMirrorIsProvablyCoherentAtEntry() throws Exception {
		layEngineReadBackShape();

		BankDataflowEngine.DataflowResult result = runEngine();

		BankDataflowEngine.CallSwitch callSwitch = result.callSwitches().get(addr(0xC007));
		assertNotNull("the JSR H16 must be recognized as a resolved call switch", callSwitch);
		assertTrue("the mirror is coherent at the function's own entry -- must resolve",
			callSwitch.argumentResolved());
		assertNull("a resolved read is not classified RESTORED_BANK", callSwitch.readBack());
		assertEquals(0, callSwitch.effect().bits());
	}

	/**
	 * H (restored). The SAME shape, but {@code RESET} is now an ASYNC entry point (bead grm-913):
	 * it may be reached from arbitrary mainline context, so the engine seeds it wholly UNKNOWN
	 * rather than with {@code initial_state}. {@code shadowCoherentAt} still says the mirror read
	 * is coherent (nothing has touched {@code $29} or the latch since function entry) -- but
	 * "coherent" only means "not stale", not "known". With no known state to answer from, the call
	 * at {@code $C007} must come back UNRESOLVED and carrying a {@link StoredValueScanner.ReadBack}
	 * naming {@code $29}, the read at {@code $C000}, and the call at {@code $C003} it was carried
	 * across on the stack -- the honest {@code RESTORED_BANK} NOTE this bead exists to produce
	 * instead of either a confident wrong answer or an unexplained WARNING.
	 */
	@Test(timeout = 30000)
	public void engineClassifiesTheReadBackAsRestoredWhenTheSeedIsUnknown() throws Exception {
		layEngineReadBackShape();
		markAsyncEntry(addr(0xC000));

		BankDataflowEngine.DataflowResult result = runEngine();

		BankDataflowEngine.CallSwitch callSwitch = result.callSwitches().get(addr(0xC007));
		assertNotNull("the JSR H16 must be recognized as a call switch even though it does not "
				+ "resolve", callSwitch);
		assertTrue("an unknown seed cannot resolve the mirror read",
			!callSwitch.argumentResolved());
		StoredValueScanner.ReadBack readBack = callSwitch.readBack();
		assertNotNull("the honest RESTORED_BANK classification depends on this being populated",
			readBack);
		assertEquals(addr("0x29"), readBack.cell());
		assertEquals(addr(0xC000), readBack.readAt());
		assertEquals("carried across the intervening JSR far on the stack", addr(0xC003),
			readBack.carriedAcross());
	}

	// ==================================================================
	// I -- Regression pin: CallEffect#asSecondTierRelay must not disturb readBack
	// ==================================================================

	/**
	 * Sibling of {@code HelperNoArgumentRestoreProgramTest#asSecondTierRelayCarriesRestoreCellThroughUnchanged}
	 * for the {@code readBack} field added alongside {@code restoreCell}: flipping
	 * {@code secondTierRelay} must not disturb it in either direction.
	 */
	@Test
	public void asSecondTierRelayCarriesReadBackThroughUnchanged() {
		Address cell = addr("0x29");
		Address readAt = addr("0x8000");
		Address carriedAcross = addr("0x8003");
		StoredValueScanner.ReadBack readBack = new StoredValueScanner.ReadBack(cell, readAt,
			carriedAcross);
		CallEffect base =
			new CallEffect(BankState.unknown(), 0xFF, false, false, false, null, readBack);

		CallEffect flipped = base.asSecondTierRelay();

		assertEquals(readBack, base.readBack());
		assertEquals(readBack, flipped.readBack());
		assertTrue(flipped.secondTierRelay());
	}
}
