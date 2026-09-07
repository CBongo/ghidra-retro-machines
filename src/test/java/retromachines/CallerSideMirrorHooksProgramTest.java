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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

import retromachines.BankSwitchStrategy.HelperDeposit;
import retromachines.BankSwitchStrategy.SwitchOutcome;
import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperArgumentRecovery.CallSiteRegKey;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Pins {@code HelperArgumentRecovery}'s mirror-aware {@code NO_HOOKS} conversion (bead
 * grm-mej.3 item 4): the three caller-side {@link StoredValueScanner} scans -- the primary
 * register scan in {@code recoverCallArgument}, the caller's-cell route
 * ({@link StoredValueScanner#callerCellValue}), and the A/X/Y env scan in {@code surviving} --
 * now thread a REAL tracked in-state and a strategy-supplied
 * {@link BankSwitchStrategy#callerSideHooks} instead of the historical {@code NO_HOOKS}
 * (unknown in-state, no hooks at all).
 * <p>
 * <b>The mandatory landmine test in this file</b> ({@link #mirrorLoadBeforeAnInterveningMechanismWriteStaysUnknown})
 * is the one this bead's own instructions call out as non-negotiable: {@code NO_HOOKS}
 * answering {@code isMechanismWrite() == false} unconditionally was harmless only because the
 * in-state at these sites was hardcoded {@link BankState#unknown()} and nothing consulted it.
 * The moment a caller-side scan is handed a REAL in-state, an {@code isMechanismWrite} that
 * still answers {@code false} lets a mirror load that executes BEFORE a mechanism write resolve
 * against the state AFTER it -- a confidently wrong bank. The test below is built on a MIRROR
 * LOAD specifically (not an immediate), because an immediate's value does not depend on the
 * in-state at all and so cannot distinguish "withdrawn correctly" from "in-state never mattered"
 * -- see {@code StoredValueScanner.findMatchingPush}'s javadoc for this exact test-design trap
 * from a previous increment.
 */
public class CallerSideMirrorHooksProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private MemoryBlock zp;
	private MemoryBlock prg;
	private AddressSpace baseSpace;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		zp = builder.createMemory(".zp", "0x0", 0x100);
		prg = builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
		baseSpace = program.getAddressFactory().getDefaultAddressSpace();
		makeWritable(zp);
		romifyPrg();
	}

	// ------------------------------------------------------------------
	// Scaffolding
	// ------------------------------------------------------------------

	private void makeWritable(MemoryBlock block) {
		setWritable(block, true);
	}

	private void romifyPrg() {
		setWritable(prg, false);
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
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	private MemoryLatchBankSwitchStrategy discreteLatch() {
		JsonObject params = new JsonObject();
		params.addProperty("start", 0x8000);
		params.addProperty("end", 0xFFFF);
		params.addProperty("mask", 0x0F);
		params.addProperty("shift", 0);
		MemoryLatchBankSwitchStrategy strategy = new MemoryLatchBankSwitchStrategy();
		strategy.configure(program, params, 0xFF);
		return strategy;
	}

	private BankMirrors mirrorsOf(long offset, BankMirrors.Kind... kinds) {
		return BankMirrors.of(baseSpace, Map.of(offset, Set.of(kinds)));
	}

	/**
	 * A minimal {@link BankSwitchStrategy} that (a) deposits {@code argValue} verbatim, exactly
	 * like the interface default, and (b) captures whatever {@link RegisterEnv} it is handed --
	 * the same technique {@code HelperEnvNarrowingProgramTest}'s {@code EnvCapturingStrategy}
	 * uses -- so a test can inspect the A/X/Y {@code surviving} resolved, independent of what the
	 * deposit itself returns.
	 * <p>
	 * {@link #callerSideHooksOverride} is null by default (behaving exactly like
	 * {@link BankSwitchStrategy}'s own default {@code callerSideHooks}); tests that need mirror
	 * resolution set it explicitly, which is what lets the SAME stub serve both the "no
	 * override" and "mirror-aware override" tests below without duplicating the deposit/capture
	 * plumbing.
	 */
	private static final class StubStrategy implements BankSwitchStrategy {

		RegisterEnv captured;
		StoredValueScanner.Hooks callerSideHooksOverride;

		@Override
		public String strategyName() {
			return "caller-side-mirror-probe";
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
			this.captured = callerRegs;
			return new HelperDeposit(stateMask, argValue);
		}

		@Override
		public StoredValueScanner.Hooks callerSideHooks() {
			return callerSideHooksOverride == null ? BankSwitchStrategy.super.callerSideHooks()
					: callerSideHooksOverride;
		}
	}

	/**
	 * A {@link StoredValueScanner.Hooks} that answers a mirror load of {@code mirrorAddress}
	 * with {@code inStateAtStore} verbatim, and treats a store to {@code mechanismAddress} as
	 * the mechanism write -- a hand-built stand-in for what
	 * {@link MemoryLatchBankSwitchStrategy}'s own {@code callerSideHooks()} does for real, kept
	 * separate from that class so these tests pin {@code HelperArgumentRecovery}'s PLUMBING
	 * (the threading, the cache key) rather than one strategy's mirror geometry --
	 * {@link #memoryLatchCallerSideHooksWireMirrorAndMechanismWriteTogether} below pins the real
	 * wiring on the shipped strategy.
	 */
	private static StoredValueScanner.Hooks mirrorHooks(Address mirrorAddress,
			Address mechanismAddress) {
		return new StoredValueScanner.Hooks() {
			@Override
			public boolean isMechanismWrite(Instruction instr) {
				return instr.getMinAddress().equals(mechanismAddress);
			}

			@Override
			public BankState resolveLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return null; // scope discipline: caller-side hooks never answer resolveLoad
			}

			@Override
			public BankState resolveMirrorLoad(Instruction loadInstr, Address resolvedTarget,
					BankState inStateAtStore) {
				return mirrorAddress.equals(resolvedTarget) ? inStateAtStore : null;
			}
		};
	}

	// ------------------------------------------------------------------
	// 1. Positive: a mirror load at the call site resolves from real in-state
	// ------------------------------------------------------------------

	/**
	 * {@code LDA $9000 / JSR $9100} where {@code $9000} is a stated mirror: before this bead the
	 * caller-side register scan ({@code recoverCallArgument}'s primary {@code local}, the
	 * historical {@code NO_HOOKS} site at what was line 202) always came back
	 * {@link BankState#unknown()} here, because {@code NO_HOOKS} never resolves a mirror
	 * regardless of what is tracked. With a strategy that overrides
	 * {@link BankSwitchStrategy#callerSideHooks} to resolve {@code $9000}, and the call's real
	 * tracked in-state (bank 5) threaded through as {@code localIn}, the same scan now resolves
	 * the caller's argument to bank 5.
	 */
	@Test
	public void mirrorLoadAtCallSiteResolvesFromRealInState() throws Exception {
		builder.setBytes("0x8000", "ad 00 90", true); // LDA $9000  -- mirror read
		builder.setBytes("0x8003", "20 00 91", true); // JSR $9100  <- callInstr
		builder.setBytes("0x9100", "8d 00 e0", true); // STA $E000  -- single-instruction helper

		StubStrategy strategy = new StubStrategy();
		strategy.callerSideHooksOverride =
			mirrorHooks(builder.addr("0x9000"), builder.addr("0xDEAD")); // no mechanism write here
		HelperModel helper = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFF, 0,
			strategy, builder.addr("0x9100"), builder.addr("0x9100"), null);

		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8003"), helper, BankState.fullyKnown(0xFF, 5), new HashMap<>(),
			new HashSet<>());

		assertEquals("the mirror load must resolve the tracked bank", 0xFF,
			effect.state().knownMask());
		assertEquals(5, effect.state().bits());
	}

	// ------------------------------------------------------------------
	// 2. The mandatory landmine: withdrawal across an intervening mechanism write
	// ------------------------------------------------------------------

	/**
	 * Identical shape to the positive test above, except a mechanism write ({@code STA $E000})
	 * now sits BETWEEN the mirror load and the call, and the tracked in-state supplied
	 * ({@code bank 9}) is the bank AFTER that write -- exactly the confidently-wrong-bank shape
	 * this bead's instructions call out: "a {@code LDA $8000} read BEFORE an intervening
	 * mechanism write would be answered with the state AFTER that write" if
	 * {@code isMechanismWrite} were wired to always answer {@code false}.
	 * <p>
	 * Built on a MIRROR LOAD, not an immediate: an immediate {@code LDA #5} would also come back
	 * "5" regardless of withdrawal, since its value never depended on in-state at all, and would
	 * therefore pass whether or not the withdrawal wiring is correct. Only a value that is
	 * SUPPOSED to track in-state can distinguish the two.
	 */
	@Test
	public void mirrorLoadBeforeAnInterveningMechanismWriteStaysUnknown() throws Exception {
		builder.setBytes("0x8000", "ad 00 90", true); // LDA $9000  -- mirror read (OLD bank)
		builder.setBytes("0x8003", "8d 00 e0", true); // STA $E000  -- mechanism write, intervenes
		builder.setBytes("0x8006", "20 00 91", true); // JSR $9100  <- callInstr
		builder.setBytes("0x9100", "8d 00 e0", true); // STA $E000  -- single-instruction helper

		StubStrategy strategy = new StubStrategy();
		strategy.callerSideHooksOverride =
			mirrorHooks(builder.addr("0x9000"), builder.addr("0x8003"));
		HelperModel helper = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFF, 0,
			strategy, builder.addr("0x9100"), builder.addr("0x9100"), null);

		// The tracked in-state at the call is bank 9 -- the bank AFTER the $8003 mechanism
		// write, i.e. exactly what a broken isMechanismWrite would (wrongly) hand back for a
		// load that executed BEFORE that write.
		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8006"), helper, BankState.fullyKnown(0xFF, 9), new HashMap<>(),
			new HashSet<>());

		assertEquals("a mirror load before an intervening mechanism write must NOT resolve", 0,
			effect.state().knownMask());
	}

	// ------------------------------------------------------------------
	// 3. No-regression: a strategy that does not override callerSideHooks is unaffected
	// ------------------------------------------------------------------

	/**
	 * Same fixture as the positive test, but the strategy never overrides
	 * {@link BankSwitchStrategy#callerSideHooks}, so it gets the interface's default -- which
	 * must behave exactly like the retired {@code NO_HOOKS}: no mirror resolution at all,
	 * regardless of the real in-state now being threaded through. This is the "every strategy
	 * that does not override keeps today's behaviour exactly" guarantee.
	 */
	@Test
	public void strategyWithoutOverrideStaysBlindToMirrorsExactlyLikeNoHooks() throws Exception {
		builder.setBytes("0x8000", "ad 00 90", true); // LDA $9000  -- mirror read
		builder.setBytes("0x8003", "20 00 91", true); // JSR $9100  <- callInstr
		builder.setBytes("0x9100", "8d 00 e0", true); // STA $E000  -- single-instruction helper

		StubStrategy strategy = new StubStrategy(); // callerSideHooksOverride left null -> default

		HelperModel helper = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFF, 0,
			strategy, builder.addr("0x9100"), builder.addr("0x9100"), null);

		CallEffect effect = HelperArgumentRecovery.recoverCallArgument(program,
			instructionAt("0x8003"), helper, BankState.fullyKnown(0xFF, 5), new HashMap<>(),
			new HashSet<>());

		assertEquals("the default callerSideHooks must decline every mirror, like NO_HOOKS", 0,
			effect.state().knownMask());
	}

	// ------------------------------------------------------------------
	// 4. The memo: two calls at the same address under different in-states must not collide
	// ------------------------------------------------------------------

	/**
	 * Pins tripwire 2's fix directly: {@code envCache} (a.k.a. {@code callSiteRegCache}) is now
	 * keyed on {@link CallSiteRegKey} -- (call address, {@code localIn}) -- rather than address
	 * alone, because {@code surviving}'s A/X/Y scan is mirror-aware and therefore genuinely
	 * state-dependent. Two calls at the identical {@code callInstr} address, sharing one
	 * {@code envCache}, but under different tracked in-states, must resolve A to the two
	 * DIFFERENT banks their own in-state names -- if the memo still collapsed on address alone,
	 * the second call would silently see the first call's cached env.
	 */
	@Test
	public void sameCallAddressUnderDifferentInStatesDoesNotShareOneCacheEntry() throws Exception {
		builder.setBytes("0x8000", "ad 00 90", true); // LDA $9000  -- mirror read
		builder.setBytes("0x8003", "20 00 91", true); // JSR $9100  <- callInstr (dequeued twice)
		builder.setBytes("0x9100", "8d 00 e0", true); // STA $E000  -- single-instruction helper

		StubStrategy strategy = new StubStrategy();
		strategy.callerSideHooksOverride =
			mirrorHooks(builder.addr("0x9000"), builder.addr("0xDEAD"));
		HelperModel helper = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFF, 0,
			strategy, builder.addr("0x9100"), builder.addr("0x9100"), null);

		Map<CallSiteRegKey, RegisterEnv> sharedEnvCache = new HashMap<>();
		Set<Function> restoringTrampolines = new HashSet<>();
		Instruction callInstr = instructionAt("0x8003");

		HelperArgumentRecovery.recoverCallArgument(program, callInstr, helper,
			BankState.fullyKnown(0xFF, 5), sharedEnvCache, restoringTrampolines);
		BankState firstEnvA = strategy.captured.a();

		HelperArgumentRecovery.recoverCallArgument(program, callInstr, helper,
			BankState.fullyKnown(0xFF, 9), sharedEnvCache, restoringTrampolines);
		BankState secondEnvA = strategy.captured.a();

		assertEquals("first in-state's bank must resolve in the env", 5, firstEnvA.bits());
		assertEquals("second in-state's bank must resolve in the env", 9, secondEnvA.bits());
		assertNotEquals("the two in-states must not collapse onto one cache entry", firstEnvA,
			secondEnvA);
		assertEquals("two distinct in-states at the same address must produce two cache entries",
			2, sharedEnvCache.size());
	}

	// ------------------------------------------------------------------
	// 5. The real strategy: MemoryLatchBankSwitchStrategy's own callerSideHooks wiring
	// ------------------------------------------------------------------

	/**
	 * Pins the actual production override rather than a hand-built stand-in: item 3's mandatory
	 * rule is that a strategy answering {@code resolveMirrorLoad} from real state at a caller
	 * site MUST make {@code isMechanismWrite} here delegate to its OWN mechanism-write detector
	 * ({@code writesInRange}), and MUST NOT answer {@code resolveLoad} (scope discipline: a
	 * bank-invariant ROM byte at a caller-side site is a separate widening, left out of this
	 * increment).
	 */
	@Test
	public void memoryLatchCallerSideHooksWireMirrorAndMechanismWriteTogether() throws Exception {
		MemoryLatchBankSwitchStrategy latch = discreteLatch();
		latch.observeMirrors(mirrorsOf(0x42, BankMirrors.Kind.ROM_IDENTIFYING));

		builder.setBytes("0x8000", "a5 42", true); // LDA $42     -- mirror read
		builder.setBytes("0x8002", "8d 00 c0", true); // STA $C000   -- write into the latch's own range

		StoredValueScanner.Hooks callerHooks = latch.callerSideHooks();

		assertTrue("a store into the latch's own range is this strategy's mechanism write",
			callerHooks.isMechanismWrite(instructionAt("0x8002")));
		assertNull("resolveLoad must stay out of scope for caller-side hooks -- see "
				+ "BankSwitchStrategy.callerSideHooks()'s scope-discipline note",
			callerHooks.resolveLoad(instructionAt("0x8000"), builder.addr("0x42"),
				BankState.fullyKnown(0x0F, 5)));

		BankState mirrored = callerHooks.resolveMirrorLoad(instructionAt("0x8000"),
			builder.addr("0x42"), BankState.fullyKnown(0x0F, 5));
		assertNotNull("a ROM_IDENTIFYING mirror on a shift=0 board must resolve", mirrored);
		assertEquals(5, mirrored.bits() & 0x0F);
	}
}
