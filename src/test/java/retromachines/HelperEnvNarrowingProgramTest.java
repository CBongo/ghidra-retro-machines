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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

import retromachines.BankSwitchStrategy.HelperDeposit;
import retromachines.BankSwitchStrategy.SwitchOutcome;
import retromachines.HelperDiscovery.HelperModel;
import retromachines.HelperDiscovery.Relay;

/**
 * Pins {@code HelperArgumentRecovery.unwalkedPrologueSegments} (bead grm-4bgh increment 3): the
 * narrowing of {@link HelperArgumentRecovery}'s grm-k90 prologue-survival filter to exactly the
 * segments {@code recoverCallArgument}'s own mini-inline scan does not itself walk.
 * <p>
 * These tests go through the public {@code recoverCallArgument} entry point rather than probing
 * the private {@code callSiteRegisters}/{@code surviving} helpers directly, using a
 * {@link BankSwitchStrategy} stub that simply captures the {@link RegisterEnv} it is handed --
 * the same technique {@code MemoryLatchStrategyProgramTest} uses to observe an env's contents,
 * generalized to a strategy that does nothing else. Capturing the FULL env (A/X/Y) rather than
 * routing through a real mechanism's {@code depositHelperArgument} is deliberate: it isolates
 * exactly what changed -- what the env carries -- from a mini-inline scan's own independent
 * ability to resolve the same clobber, which for an ordinary helper would otherwise mask the
 * narrowing entirely (see the first test's javadoc).
 */
public class HelperEnvNarrowingProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	/** Captures the {@link RegisterEnv} handed to {@code depositHelperArgument}, nothing else. */
	private static final class EnvCapturingStrategy implements BankSwitchStrategy {
		RegisterEnv captured;

		@Override
		public String strategyName() {
			return "env-capturing-probe";
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
			return new HelperDeposit(0, BankState.unknown());
		}
	}

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	private RegisterEnv recover(HelperModel helper, String callSite, EnvCapturingStrategy probe)
			throws Exception {
		Instruction callInstr = instructionAt(callSite);
		Map<Address, RegisterEnv> envCache = new HashMap<>();
		Set<Function> restoringTrampolines = new HashSet<>();
		HelperArgumentRecovery.recoverCallArgument(program, callInstr, helper, BankState.unknown(),
			envCache, restoringTrampolines);
		return probe.captured;
	}

	/**
	 * <b>Ordinary helper, one prologue segment, entirely WALKED by the mini-inline scan.</b> The
	 * helper's prologue clobbers Y with an unrelated immediate before the mechanism write (which
	 * reads A, not Y) -- exactly the shape that, before grm-4bgh increment 3, forced the whole
	 * env's Y to {@link BankState#unknown()} even though this segment is fully covered by the
	 * scan {@code recoverCallArgument} itself would run.
	 * <p>
	 * Per the class javadoc: this is observed only because the env is captured directly. A real
	 * mechanism whose switch site actually read Y would meet the same {@code LDY #$99} in its own
	 * backward scan before ever reaching the env, and would report unknown regardless of what the
	 * env carries -- which is exactly the "cannot change an answer that was already right"
	 * argument documented on {@code callSiteRegisters}.
	 */
	@Test
	public void ordinaryHelperClobberInWalkedSegmentNowYieldsALiveEnvValue() throws Exception {
		builder.setBytes("0x9000", "a9 07", true); // LDA #$07  -- caller's A
		builder.setBytes("0x9002", "a0 05", true); // LDY #$05  -- caller's Y
		builder.setBytes("0x9004", "20 00 91", true); // JSR $9100 <- callInstr
		builder.setBytes("0x9100", "a0 99", true); // LDY #$99  -- prologue clobbers Y
		builder.setBytes("0x9102", "8d 00 e0", true); // STA $E000 <- entry..switchSite, reads A

		EnvCapturingStrategy probe = new EnvCapturingStrategy();
		HelperModel helper = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFF, 0,
			probe, builder.addr("0x9102"), builder.addr("0x9102"), null);

		RegisterEnv env = recover(helper, "0x9004", probe);

		assertNotNull("strategy must have been reached for the env to be captured", env);
		assertEquals("Y's prologue clobber lies entirely inside the mini-inline scan's own span, "
			+ "so the narrowed filter no longer forces it to unknown", 0xFF,
			env.y().knownMask());
		assertEquals(0x05, env.y().bits());
	}

	/**
	 * <b>Call-edge wrapper, prefix segment NOT walked by the mini-inline scan.</b> The wrapper's
	 * own prefix ({@code entry..relay.callSite()}) clobbers Y before handing off to the real
	 * helper; the scan stops at {@code relay.calleeEntry()} and never sees that clobber. This is
	 * exactly the soundness hole grm-k90 was filed on, and the narrowed filter must still catch
	 * it: the prefix segment is NOT contained in {@code [entryAddr, switchSite]}, so it stays in
	 * the filtered list and Y is correctly reported unknown.
	 */
	@Test
	public void callEdgeWrapperClobberInUnwalkedPrefixStillYieldsUnknown() throws Exception {
		builder.setBytes("0x9000", "a9 07", true); // LDA #$07  -- caller's A
		builder.setBytes("0x9002", "a0 05", true); // LDY #$05  -- caller's Y
		builder.setBytes("0x9004", "20 00 a0", true); // JSR $A000 <- callInstr
		builder.setBytes("0xa000", "a0 99", true); // LDY #$99  <- wrapper prefix clobbers Y
		builder.setBytes("0xa002", "20 00 a1", true); // JSR $A100 <- relay.callSite()
		builder.setBytes("0xa100", "8d 00 e0", true); // STA $E000 <- relay.calleeEntry() == switchSite

		EnvCapturingStrategy probe = new EnvCapturingStrategy();
		Relay relay = new Relay(builder.addr("0xa002"), builder.addr("0xa100"));
		HelperModel helper = new HelperModel(null, builder.addr("0xa000"), null, 'A', 0xFF, 0,
			probe, builder.addr("0xa100"), builder.addr("0xa100"), relay);

		RegisterEnv env = recover(helper, "0x9004", probe);

		assertNotNull("strategy must have been reached for the env to be captured", env);
		assertEquals(
			"Y's clobber sits in the wrapper's prefix, which the mini-inline scan never walks "
				+ "-- the filter must still catch it", 0x00, env.y().knownMask());
	}
}
