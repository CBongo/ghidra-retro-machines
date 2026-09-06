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
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;

import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Pins {@code HelperDiscovery.HelperModel.sites} and {@code HelperArgumentRecovery.foldDeposits}
 * (bead grm-4bgh.5): a {@link BankSwitchStrategy} whose {@code depositsPerSite()} answers
 * {@code true} now folds ONE deposit PER RECOGNIZED SITE, in ascending address order, rather than
 * the single max-address {@code switchSite} deposit every helper produced before.
 * <p>
 * <b>The motivating shape</b> is River City Ransom's {@code FUN_fed1}, an MMC3 select-data
 * helper: {@code STA $8000} select R6, {@code STA $8001} data R6 = A*2, {@code STA $8000} select
 * R7, {@code STA $8001} data R7 = A*2+1 -- four recognized sites, two real deposits into two
 * distinct fields, from one caller argument. Before this bead, {@code HelperModel.switchSite}'s
 * max-address proxy picked only the LAST site (the R7 data write), so the R6 deposit was never
 * consulted at all -- see {@link BankSwitchStrategy#depositsPerSite}'s javadoc, which quotes this
 * exact sentence.
 * <p>
 * <b>Why the fixtures below have R6 resolve and R7 come back honestly unresolved (rather than
 * both resolving to concrete values).</b> {@code StoredValueScanner}'s mid-scan mechanism-write
 * abort ({@code Hooks#isMechanismWrite}) fires unconditionally on ANY recognized site encountered
 * while walking backward -- in EVERY one of its backward walks (register, stack-relative reload,
 * PLA/PHA matching, and store-to-load forwarding alike). That means a data write's value can only
 * ever be recovered by {@link BankSwitchStrategy#depositHelperArgument}'s {@code callerRegs}
 * mini-inline (grm-hum increment 2) when its OWN defining instructions lie entirely between the
 * PREVIOUS recognized site and itself -- reaching any further back, past an earlier site, always
 * aborts to unknown, regardless of mechanism. So a data write's value can be genuinely
 * caller-argument-derived (crossing nothing) only when nothing about it needs the original
 * argument from before an earlier site; the R7 write here is deliberately built so its own stored
 * byte is whatever register state survives across the R7 select write immediately before it,
 * which the abort makes permanently unrecoverable. This is not a weaker test of the fold: it
 * shows the fold's OWNERSHIP claim (both target fields are attributed to this call) holds even
 * when only one of the two values actually resolves -- an even stronger reading of "the R6
 * deposit... is never consulted" than a fixture where both happen to resolve.
 */
public class MultiDepositHelperProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	/**
	 * A select/data pair over {@code $9000-$9FFF} (MMC3-shaped, address-parity dispatch) with
	 * THREE tracked fields packed into one 12-bit field-local space: {@code select[0,4)},
	 * {@code r6[4,8)}, {@code r7[8,12)} -- disjoint, so R6 and R7 can both be owned by one
	 * {@link BankState} unambiguously. Mirrors {@code SelectDataHelperFallbackProgramTest}'s
	 * configuration approach, extended to two data targets instead of one.
	 */
	private SelectDataBankSwitchStrategy strategy() {
		JsonObject fieldLayout = new JsonObject();
		JsonObject selectLayout = new JsonObject();
		selectLayout.addProperty("lsb", 0);
		selectLayout.addProperty("width", 4);
		fieldLayout.add("select", selectLayout);
		JsonObject r6Layout = new JsonObject();
		r6Layout.addProperty("lsb", 4);
		r6Layout.addProperty("width", 4);
		fieldLayout.add("r6", r6Layout);
		JsonObject r7Layout = new JsonObject();
		r7Layout.addProperty("lsb", 8);
		r7Layout.addProperty("width", 4);
		fieldLayout.add("r7", r7Layout);

		JsonObject targets = new JsonObject();
		targets.addProperty("6", "r6");
		targets.addProperty("7", "r7");

		JsonObject params = new JsonObject();
		params.addProperty("start", 0x9000);
		params.addProperty("end", 0x9FFF);
		params.addProperty("select_field", "select");
		params.add("targets", targets);
		params.add("_field_layout", fieldLayout);

		SelectDataBankSwitchStrategy strategy = new SelectDataBankSwitchStrategy();
		strategy.configure(program, params, 0xFFF);
		return strategy;
	}

	private static final int SELECT_MASK = 0x00F;
	private static final int R6_MASK = 0x0F0;
	private static final int R7_MASK = 0xF00;

	private Instruction instructionAt(String address) {
		Instruction instr = program.getListing().getInstructionAt(builder.addr(address));
		assertNotNull("nothing disassembled at " + address, instr);
		return instr;
	}

	/**
	 * Builds the {@code FUN_fed1} shape, straight-line, with sites at {@code $9102} (select R6),
	 * {@code $9107} (data R6), {@code $910C} (select R7), {@code $9112} (data R7):
	 * <pre>
	 *   9100  LDA #$06
	 *   9102  STA $9000     ; S1 -- select R6 (constant 6, resolves trivially: nothing precedes it)
	 *   9105  LDA #$0A
	 *   9107  STA $9001     ; S2 -- data R6 = $0A (resolves: its own LDA is adjacent, no site to cross)
	 *   910A  LDA #$07
	 *   910C  STA $9000     ; S3 -- select R7 (constant 7, same reasoning as S1)
	 *   910F  TXA           ; a WALL for VALUE resolution only -- see below
	 *   9110  STA $9001     ; S4 -- data R7: unresolvable (see below)
	 *   9113  RTS
	 * </pre>
	 * The caller leaves A undefined (a bare {@code NOP}) so the call-site register scan that
	 * seeds {@code HelperArgumentRecovery}'s shared {@code argValue} starts unknown too.
	 * <p>
	 * <b>Why the {@code TXA} at $910F is load-bearing, not filler.</b> Without it, S4's OWN value
	 * would trivially resolve to a WRONG, UNINTENDED value: {@code
	 * HelperArgumentRecovery.valueSuppliedInsideHelper} (which seeds the shared {@code argValue}
	 * before the per-site fold ever runs) scans backward from {@code switchSite} using {@code
	 * NO_HOOKS} -- deliberately hook-agnostic, since that scan runs "outside any mechanism's
	 * interpretation". {@code NO_HOOKS.isMechanismWrite} is unconditionally {@code false}, so a
	 * plain {@code STA $9000} (S3) is completely TRANSPARENT to it and the scan walks straight
	 * through to the {@code LDA #$07} behind it -- resolving a KNOWN, but semantically wrong,
	 * shared value (S3's own SELECT constant, not any real "argument"). Once {@code argValue} is
	 * known, {@code SelectDataBankSwitchStrategy}'s {@code callerRegs} override never
	 * re-evaluates (it only falls back to evaluation when {@code argValue.knownMask() == 0}), so
	 * that one shared value would be deposited verbatim into EVERY site, including both selects
	 * and both data writes -- collapsing this whole fixture to one uniform number and defeating
	 * the point of the test. {@code TXA} is a register-value MODIFIER {@code
	 * StoredValueScanner.resolveStoredValue}'s generic walk cannot resolve (it is not
	 * specially handled the way {@code LDA}/{@code AND}/{@code ORA}/{@code PLA} are), so it
	 * declines immediately regardless of which {@code Hooks} are in play -- it blocks NO_HOOKS
	 * and the real, mechanism-aware hooks identically. It is, however, completely invisible to
	 * {@code SelectDataBankSwitchStrategy.selectSuppliedInsideHelper}'s search for "the nearest
	 * earlier write": that search only asks whether an instruction WRITES memory, so it steps
	 * over the {@code TXA} exactly as it steps over any other non-write instruction and still
	 * finds S3 as R7's governing select. The two behave differently on purpose -- ownership
	 * (which field a call touches) and value (what byte it deposits) are different questions,
	 * and this fixture is built so only the second one goes honestly unresolved for R7.
	 */
	private HelperModel buildFed1Fixture() throws Exception {
		builder.setBytes("0x8000", "ea", true); // NOP -- caller's A is left genuinely unresolved
		builder.setBytes("0x8001", "20 00 91", true); // JSR $9100

		builder.setBytes("0x9100", "a9 06", true); // LDA #$06
		builder.setBytes("0x9102", "8d 00 90", true); // STA $9000   S1: select R6
		builder.setBytes("0x9105", "a9 0a", true); // LDA #$0A
		builder.setBytes("0x9107", "8d 01 90", true); // STA $9001   S2: data R6 = $0A
		builder.setBytes("0x910a", "a9 07", true); // LDA #$07
		builder.setBytes("0x910c", "8d 00 90", true); // STA $9000   S3: select R7
		builder.setBytes("0x910f", "8a", true); // TXA          -- the value-resolution wall
		builder.setBytes("0x9110", "8d 01 90", true); // STA $9001   S4: data R7 (unresolvable)
		builder.setBytes("0x9113", "60", true); // RTS

		return new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFFF, 0, strategy(),
			builder.addr("0x9110"), builder.addr("0x9102"), null,
			List.of(builder.addr("0x9102"), builder.addr("0x9107"), builder.addr("0x910c"),
				builder.addr("0x9110")));
	}

	private CallEffect recover(HelperModel helper) throws Exception {
		Instruction callInstr = instructionAt("0x8001");
		return HelperArgumentRecovery.recoverCallArgument(program, callInstr, helper,
			BankState.unknown(), new HashMap<>(), new HashSet<>());
	}

	// ------------------------------------------------------------------
	// 1. The headline case: both target fields are owned by one call
	// ------------------------------------------------------------------

	/**
	 * <b>Fails without the fold.</b> {@code HelperModel.switchSite} is the max-address site --
	 * here {@code $9110}, the R7 data write -- and {@code foldDeposits} without the
	 * {@code depositsPerSite()} branch calls {@code depositHelperArgument} exactly ONCE, at that
	 * single site. This test's own case 3 ({@link #straightLineGuardDeclinesFoldsToSingleSite})
	 * IS that single-site computation (the guard that disables folding falls back to precisely
	 * this call) and independently pins its answer as {@code ownedMask == R7_MASK} with R7
	 * unresolved -- i.e. R6 is not owned AT ALL. That is the confident regression described by
	 * {@link BankSwitchStrategy#depositsPerSite}'s javadoc: "the R6 deposit -- the one that
	 * actually resolves -- is never consulted." With the fold, R6's field is not merely resolved,
	 * it is the only one of the two that resolves in this fixture, so keeping it depends entirely
	 * on the fold consulting site {@code $9107} at all.
	 */
	@Test
	public void fed1ShapeFoldsBothTargetFieldsFromDisjointSites() throws Exception {
		HelperModel helper = buildFed1Fixture();
		CallEffect result = recover(helper);

		assertEquals(
			"select, r6 AND r7 are all owned -- the fold consulted every recognized site, not"
				+ " just the max-address one",
			SELECT_MASK | R6_MASK | R7_MASK, result.ownedMask());
		assertEquals(
			"select and r6 fully resolve; r7 does not -- see this class's javadoc for why the"
				+ " abort makes that the honest answer here",
			SELECT_MASK | R6_MASK, result.state().knownMask());
		assertEquals("select ends at 7 (the later write, see case 2) and r6 = $0A at its field"
			+ " offset (bits [4,8))", 0x0A7, result.state().bits());
	}

	// ------------------------------------------------------------------
	// 2. Later site wins on a field both select writes share
	// ------------------------------------------------------------------

	/**
	 * The two select writes ({@code $9102} then {@code $910C}) deposit the SAME field with
	 * different values (6, then 7). Sites fold in ascending address order and a later site
	 * overwrites an earlier one on the bits it owns ({@code BankDataflowEngine.overwrite}) -- so
	 * the fold must end at 7, not 6. A fold that instead unioned in FIRST-write-wins order, or
	 * that only ever consulted one of the two select sites, would report 6 here.
	 */
	@Test
	public void laterSelectWriteOverwritesTheEarlierOneOnTheSharedField() throws Exception {
		HelperModel helper = buildFed1Fixture();
		CallEffect result = recover(helper);

		assertEquals("select is fully known", SELECT_MASK,
			result.state().knownMask() & SELECT_MASK);
		assertEquals("the SECOND select write (7) wins over the first (6)", 0x7,
			result.state().bits() & SELECT_MASK);
	}

	// ------------------------------------------------------------------
	// 3. The straight-line guard declines when a jump could route around a later site
	// ------------------------------------------------------------------

	/**
	 * Same shape as {@link #buildFed1Fixture}, with an unconditional-shaped span broken by a
	 * conditional branch ({@code BEQ +0}) inserted between the R6 data write and the R7 select
	 * write. {@code sitesRunUnconditionally} refuses to fold across ANY jump in the walked span
	 * -- a conditional branch could route around a later site, so attributing every site's
	 * deposit to one call would risk shipping a value from a path that did not run. The fold must
	 * decline and fall back to the single {@code switchSite} deposit it always produced: only R7
	 * (the max-address site) is owned, and its value is unresolved for the same reason as in
	 * case 1 (crossing R3's select write is forbidden).
	 */
	@Test
	public void straightLineGuardDeclinesFoldsToSingleSite() throws Exception {
		builder.setBytes("0x8000", "ea", true); // NOP -- A left unresolved
		builder.setBytes("0x8001", "20 00 91", true); // JSR $9100

		builder.setBytes("0x9100", "a9 06", true); // LDA #$06
		builder.setBytes("0x9102", "8d 00 90", true); // STA $9000   S1: select R6
		builder.setBytes("0x9105", "a9 0a", true); // LDA #$0A
		builder.setBytes("0x9107", "8d 01 90", true); // STA $9001   S2: data R6
		builder.setBytes("0x910a", "f0 00", true); // BEQ +0       -- breaks the straight-line span
		builder.setBytes("0x910c", "a9 07", true); // LDA #$07
		builder.setBytes("0x910e", "8d 00 90", true); // STA $9000   S3: select R7
		builder.setBytes("0x9111", "8a", true); // TXA          -- same value-resolution wall as case 1
		builder.setBytes("0x9112", "8d 01 90", true); // STA $9001   S4: data R7
		builder.setBytes("0x9115", "60", true); // RTS

		HelperModel helper = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFFF, 0,
			strategy(), builder.addr("0x9112"), builder.addr("0x9102"), null,
			List.of(builder.addr("0x9102"), builder.addr("0x9107"), builder.addr("0x910e"),
				builder.addr("0x9112")));

		CallEffect result = recover(helper);

		assertEquals("only r7 (the max-address switchSite) is owned -- r6 is never consulted"
			+ " once the guard declines", R7_MASK, result.ownedMask());
		assertEquals("r7's value is unresolved (honest poison, not a wrong guess)", 0,
			result.state().knownMask() & R7_MASK);
	}

	// ------------------------------------------------------------------
	// 4. A single-site helper is unaffected by depositsPerSite
	// ------------------------------------------------------------------

	/**
	 * {@code foldDeposits} requires at least two sites before it even asks
	 * {@code sitesRunUnconditionally}; a one-site helper -- every register-write and
	 * memory-latch helper, and a select-data helper whose body happens to contain only one
	 * recognized write -- takes the exact same single-deposit path it always did, byte for byte.
	 * Mirrors {@code SelectDataHelperFallbackProgramTest}'s fixture (entry coincides with the
	 * switch site, so there is no prologue to survive) but drives the FULL
	 * {@code recoverCallArgument} entry point end to end, including the call-site register scan,
	 * to prove the whole path -- not just the strategy method -- is untouched.
	 */
	@Test
	public void singleSiteHelperIsUnchangedByDepositsPerSite() throws Exception {
		builder.setBytes("0x8000", "a9 2a", true); // LDA #$2A -- caller's argument
		builder.setBytes("0x8002", "20 00 92", true); // JSR $9200
		builder.setBytes("0x9200", "8d 01 90", true); // STA $9001 -- entry == firstSite == switchSite

		// select known as 6 (the tracked target r6) in the state flowing into the call.
		BankState callSiteIn = new BankState(SELECT_MASK, 0x6);

		HelperModel helper = new HelperModel(null, builder.addr("0x9200"), null, 'A', 0xFFF, 0,
			strategy(), builder.addr("0x9200"), builder.addr("0x9200"), null, null);

		Instruction callInstr = instructionAt("0x8002");
		CallEffect result = HelperArgumentRecovery.recoverCallArgument(program, callInstr, helper,
			callSiteIn, new HashMap<>(), new HashSet<>());

		assertEquals("only r6 is owned -- select-data's single-target no-poison contract, exactly"
			+ " as with zero sites folded", R6_MASK, result.ownedMask());
		assertEquals("r6 fully resolves from the caller's $2A", R6_MASK,
			result.state().knownMask() & R6_MASK);
		assertEquals("$2A's low nibble (0xA) lands in r6, field-local at bit 4", 0xA0,
			result.state().bits() & R6_MASK);
	}

	// ------------------------------------------------------------------
	// 5. depositsPerSite() is false for serial-shift, true for select-data
	// ------------------------------------------------------------------

	/**
	 * The direct, cheap assertion guarding the distinction the whole design rests on:
	 * serial-shift's several writes are instalments of ONE value (only the last commits, which is
	 * exactly what the max-address {@code switchSite} proxy already picks), so it must keep the
	 * default {@code false} -- folding a deposit per site there would attribute four partial
	 * chains that never independently happened. select-data overrides to {@code true}. Neither
	 * strategy needs {@code configure} called first: the method consults no configured field.
	 */
	@Test
	public void depositsPerSiteDistinguishesSerialShiftFromSelectData() {
		assertFalse("serial-shift's five writes are instalments of one value, not independent"
			+ " deposits", new SerialShiftBankSwitchStrategy().depositsPerSite());
		assertTrue("select-data's sites are independent deposits into distinct fields",
			new SelectDataBankSwitchStrategy().depositsPerSite());
	}
}
