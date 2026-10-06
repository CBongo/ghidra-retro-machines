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

import retromachines.BankStrategyRegistry.ConfiguredMechanism;
import retromachines.DescriptorSupport.BankStack;
import retromachines.HelperArgumentRecovery.CallEffect;

/**
 * Pins {@link BankStackBrackets} (bead grm-mej.10): a RAM bank stack's push/pop helpers are
 * recognized by shape, a pop is paired with the one push that dominates it, and the claim is
 * field-scoped. The fixture is tmnt3's stack, simplified to the walk's vocabulary (the select
 * write is dropped; one data commit per register):
 * <pre>
 *   push 9000: PHA / LDA $A000 / LDY $F2 / INC $F2 / STA $00F3,Y / PLA / STA $8001 / RTS
 *   pop  9200: DEC $F2 / LDY $F2 / LDA $00F3,Y / STA $8001 / RTS
 *   pop2 9300: DEC $F2 / LDY $F2 / LDA $00F3,Y / STA $8001 / CLC / ADC #1 / STA $8003 / RTS
 *   stub 9010: LDA #$20 / BNE $9000
 * </pre>
 */
public class BankStackBracketsProgramTest extends AbstractBundledLanguageTest {

	private static final BoardDescriptorModel.FieldSpec R7 =
		new BoardDescriptorModel.FieldSpec("r7", 10, 6);
	private static final BoardDescriptorModel.FieldSpec R6 =
		new BoardDescriptorModel.FieldSpec("r6", 4, 6);
	private static final List<BankStack> STACK = List.of(new BankStack(0xF2, 0xF3));
	private static final SaveRestoreTrampolines.FieldPairing PAIR =
		new SaveRestoreTrampolines.FieldPairing(R6.positionedMask(), R7.positionedMask(), 1);

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
		helpers();
	}

	private Address addr(String a) {
		return builder.addr(a);
	}

	private void put(String at, String bytes) throws Exception {
		builder.setBytes(at, bytes, true);
	}

	/** Push, pop, pop2 (R7 then R6 := slot+1), the stub, and an empty inner routine. */
	private void helpers() throws Exception {
		put("0x9000", "48 ad 00 a0 a4 f2 e6 f2 99 f3 00 68 8d 01 80 60");
		put("0x9100", "60");
		put("0x9200", "c6 f2 a4 f2 b9 f3 00 8d 01 80 60");
		put("0x9300", "c6 f2 a4 f2 b9 f3 00 8d 01 80 18 69 01 8d 03 80 60");
		put("0x9010", "a9 20 d0 ec"); // LDA #$20 / BNE $9000 (the entry stub)
	}

	private BankMirrors mirrors() {
		return BankMirrors.of(baseSpace, Map.of(0xA000L, Set.of(BankMirrors.Kind.ROM_IDENTIFYING)),
			Map.of(0xA000L, R7));
	}

	private ConfiguredMechanism mechanism() {
		Map<Address, Integer> committed = Map.of(addr("0x900c"), R7.positionedMask(),
			addr("0x9207"), R7.positionedMask(), addr("0x9307"), R7.positionedMask(),
			addr("0x930d"), R6.positionedMask(), addr("0x9509"), R7.positionedMask());
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
		return new ConfiguredMechanism(strategy, 0xFFFF, 0);
	}

	private Set<Address> sites() {
		return Set.of(addr("0x900c"), addr("0x9207"), addr("0x9307"), addr("0x930d"),
			addr("0x9509"));
	}

	private BankStackBrackets.Claims find(List<BankStack> stacks,
			List<SaveRestoreTrampolines.FieldPairing> pairs) {
		return BankStackBrackets.find(program, mirrors(), List.of(mechanism()), sites(), stacks,
			pairs);
	}

	private BankStackBrackets.Claims find() {
		return find(STACK, List.of());
	}

	/** The simple bracket: push at 8000, inner call, pop at 8006. */
	private void bracket(String popTarget) throws Exception {
		put("0x8000", "20 00 90 20 00 91 20 " + popTarget + " 60");
	}

	// ------------------------------------------------------------------
	// Accepted
	// ------------------------------------------------------------------

	@Test
	public void pushInnerCallPopIsAVerifiedBracketRestoringR7() throws Exception {
		bracket("00 92");
		BankStackBrackets.Claims claims = find();
		BankStackBrackets.Pop pop = claims.pops().get(addr("0x8006"));
		assertNotNull(pop);
		assertEquals(addr("0x8000"), pop.pushSite());
		assertEquals(R7.positionedMask(), pop.restoredMask());
		assertEquals(Integer.valueOf(R7.positionedMask()),
			claims.privatePushes().get(addr("0x8000")));
	}

	@Test
	public void entryStubThatBranchesIntoThePushIsAPush() throws Exception {
		put("0x8000", "20 10 90 20 00 91 20 00 92 60");
		BankStackBrackets.Pop pop = find().pops().get(addr("0x8006"));
		assertNotNull("LDA #imm / BNE push is an entry stub of the push", pop);
		assertEquals(addr("0x8000"), pop.pushSite());
	}

	@Test
	public void loopBetweenPushAndPopStillPairs() throws Exception {
		// 8000 push / 8003 JSR inner / 8006 LDX... BNE 8003 (loop) / 8008 pop
		put("0x8000", "20 00 90 20 00 91 d0 fb 20 00 92 60");
		BankStackBrackets.Pop pop = find().pops().get(addr("0x8008"));
		assertNotNull(pop);
		assertEquals(addr("0x8000"), pop.pushSite());
	}

	@Test
	public void pairingMakesTheAPlusOneCommitRestoreTheHighFieldToo() throws Exception {
		bracket("00 93");
		BankStackBrackets.Pop pop = find(STACK, List.of(PAIR)).pops().get(addr("0x8006"));
		assertNotNull(pop);
		assertEquals(R7.positionedMask() | R6.positionedMask(), pop.restoredMask());
	}

	// ------------------------------------------------------------------
	// Declined
	// ------------------------------------------------------------------

	@Test
	public void noBankStackHintMakesNoClaim() throws Exception {
		bracket("00 92");
		assertTrue(find(List.of(), List.of()).isEmpty());
	}

	@Test
	public void aDifferentStackPointerMakesNoClaim() throws Exception {
		bracket("00 92");
		assertTrue(find(List.of(new BankStack(0xF4, 0xF3)), List.of()).isEmpty());
	}

	@Test
	public void withoutThePairingTheAPlusOneCommitRestoresOnlyR7() throws Exception {
		bracket("00 93");
		BankStackBrackets.Pop pop = find().pops().get(addr("0x8006"));
		assertNotNull(pop);
		assertEquals("R6 := slot+1 is not provably R6's old value without the pairing",
			R7.positionedMask(), pop.restoredMask());
	}

	@Test
	public void aPairingWithTheWrongOffsetDoesNotRestoreTheHighField() throws Exception {
		bracket("00 93");
		BankStackBrackets.Pop pop = find(STACK, List.of(new SaveRestoreTrampolines.FieldPairing(
			R6.positionedMask(), R7.positionedMask(), 2))).pops().get(addr("0x8006"));
		assertEquals(R7.positionedMask(), pop.restoredMask());
	}

	@Test
	public void popWithoutAMatchingPushMakesNoClaim() throws Exception {
		put("0x8000", "20 00 91 20 00 92 60");
		assertNull(find().pops().get(addr("0x8003")));
	}

	@Test
	public void secondPushBeforeThePopPairsOnlyWithTheNearerPush() throws Exception {
		put("0x8000", "20 00 90 20 00 90 20 00 92 60");
		BankStackBrackets.Claims claims = find();
		assertEquals("the pop reloads the SECOND push's slot", addr("0x8003"),
			claims.pops().get(addr("0x8006")).pushSite());
		assertFalse("the first push is never a bracket: another push is open before any pop",
			claims.privatePushes().containsKey(addr("0x8000")));
	}

	@Test
	public void aPathThatSkipsThePushMakesNoClaim() throws Exception {
		// LDA $10 / BEQ skip / JSR push / skip: JSR inner / JSR pop
		put("0x8000", "a5 10 f0 03 20 00 90 20 00 91 20 00 92 60");
		assertTrue("the BEQ path reaches the pop with no push open", find().isEmpty());
	}

	@Test
	public void codeThatCanJumpIntoTheBracketMakesNoClaim() throws Exception {
		bracket("00 92");
		put("0x8100", "4c 03 80"); // JMP $8003 -- from outside, into the open region
		assertTrue(find().isEmpty());
	}

	@Test
	public void directWriteToTheStackPointerBetweenMakesNoClaim() throws Exception {
		put("0x8000", "20 00 90 e6 f2 20 00 92 60");
		assertTrue(find().isEmpty());
	}

	@Test
	public void directWriteToASlotBetweenMakesNoClaim() throws Exception {
		put("0x8000", "20 00 90 99 f3 00 20 00 92 60"); // STA $00F3,Y
		assertTrue(find().isEmpty());
	}

	@Test
	public void popThatDoesNotCommitTheSlotIsNotAPop() throws Exception {
		// DEC $F2 / LDY $F2 / LDA $00F3,Y / LDA #5 / STA $8001 / RTS: reloads the slot but commits 5
		put("0x9500", "c6 f2 a4 f2 b9 f3 00 a9 05 8d 01 80 60");
		put("0x8000", "20 00 90 20 00 91 20 00 95 60");
		assertTrue(find().isEmpty());
	}

	@Test
	public void pushStoringSomethingOtherThanTheIdentityByteIsNotAPush() throws Exception {
		// PHA / LDA $0200 (not a live-bank mirror) / LDY $F2 / INC $F2 / STA $00F3,Y / PLA / RTS
		put("0x9600", "48 ad 00 02 a4 f2 e6 f2 99 f3 00 68 60");
		put("0x8000", "20 00 96 20 00 91 20 00 92 60");
		assertTrue(find().isEmpty());
	}

	// ------------------------------------------------------------------
	// The engine fold
	// ------------------------------------------------------------------

	private static final int SELECT = 0b111;
	private static final int BOTH = R7.positionedMask() | R6.positionedMask();
	private static final BankMirrors.IdentifyingEncoding EVEN_ONLY =
		new BankMirrors.IdentifyingEncoding(0, 0, 8, 1, Set.of(0, 2, 4, 6, 8, 10),
			Set.of(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11));

	private BankStackBrackets.Claims claimsFor(int mask) {
		return new BankStackBrackets.Claims(
			Map.of(addr0(0x8006), new BankStackBrackets.Pop(addr0(0x8000),
				new BankStackBrackets.Restore(mask, R7.positionedMask(), EVEN_ONLY, List.of(PAIR)))),
			Map.of(addr0(0x8000), BOTH), Map.of());
	}

	private Address addr0(long offset) {
		return baseSpace.getAddress(offset);
	}

	private CallEffect popEffect() {
		// the pop's own select write is known (mask SELECT, value 6); R7/R6 are owned but unknown
		return new CallEffect(new BankState(SELECT, 6), SELECT | BOTH, false, false, null);
	}

	private BankState atPush(int r6, int r7) {
		return new BankState(BOTH, (r6 << R6.lsb()) | (r7 << R7.lsb()));
	}

	private int field(CallEffect e, BoardDescriptorModel.FieldSpec f) {
		return (e.state().bits() >> f.lsb()) & ((1 << f.width()) - 1);
	}

	@Test
	public void evenPushTimeR7RestoresR7AndComputesR6AsPlusOne() throws Exception {
		BankState at = atPush(0, 8);
		CallEffect folded = BankDataflowEngine.applyBracketClaim(popEffect(), addr0(0x8006),
			claimsFor(BOTH), p -> p.equals(addr0(0x8000)) ? at : null);
		assertEquals(BOTH | SELECT, folded.state().knownMask());
		assertEquals(8, field(folded, R7));
		assertEquals("R6 is R7 + 1, not the push-time R6", 9, field(folded, R6));
		assertEquals(6, folded.state().bits() & SELECT);
		assertTrue(folded.argumentResolved());
	}

	@Test
	public void oddPushTimeR7DepositsUnknownNotTheStalePair() throws Exception {
		// the initial_state seed: r6=0, r7=1, both known -- but bank 1 carries no identity byte
		BankState at = atPush(0, 1);
		CallEffect folded = BankDataflowEngine.applyBracketClaim(popEffect(), addr0(0x8006),
			claimsFor(BOTH), p -> at);
		assertEquals("r7 odd: unknown", 0, folded.state().knownMask() & R7.positionedMask());
		assertEquals("r6 must not be copied as 0", 0, folded.state().knownMask() & R6.positionedMask());
		assertEquals(SELECT, folded.state().knownMask() & SELECT);
		assertTrue("the bracket is still verified, so no failed-recovery warning",
			folded.argumentResolved());
	}

	@Test
	public void unknownPushTimeR7DepositsUnknown() throws Exception {
		CallEffect folded = BankDataflowEngine.applyBracketClaim(popEffect(), addr0(0x8006),
			claimsFor(BOTH), p -> BankState.unknown());
		assertEquals(0, folded.state().knownMask() & BOTH);
		assertTrue(folded.argumentResolved());
	}

	@Test
	public void unpairedRestoreAppliesTheIdentityRuleAlone() throws Exception {
		CallEffect r7Only = new CallEffect(new BankState(SELECT, 7),
			SELECT | R7.positionedMask(), false, false, null);
		CallEffect even = BankDataflowEngine.applyBracketClaim(r7Only, addr0(0x8006),
			claimsFor(R7.positionedMask()), p -> atPush(0, 4));
		assertEquals(4, field(even, R7));
		CallEffect odd = BankDataflowEngine.applyBracketClaim(r7Only, addr0(0x8006),
			claimsFor(R7.positionedMask()), p -> atPush(0, 3));
		assertEquals(0, odd.state().knownMask() & R7.positionedMask());
	}

	@Test
	public void restoredHighFieldWrapsToItsWidth() throws Exception {
		// r7 = 10 is even and verified; r6 = 11 fits 6 bits -- and a width-limited sum wraps
		CallEffect folded = BankDataflowEngine.applyBracketClaim(popEffect(), addr0(0x8006),
			claimsFor(BOTH), p -> atPush(0, 10));
		assertEquals(11, field(folded, R6));
	}

	@Test
	public void helperRestoreComputesFromTheStateAtTheCall() throws Exception {
		BankStackBrackets.Restore restore =
			new BankStackBrackets.Restore(BOTH, R7.positionedMask(), EVEN_ONLY, List.of(PAIR));
		CallEffect owned = new CallEffect(new BankState(SELECT, 6), SELECT, true, false, null);
		CallEffect folded = BankStackBrackets.fold(owned, restore, atPush(0, 6));
		assertEquals(6, field(folded, R7));
		assertEquals(7, field(folded, R6));
		CallEffect oddCall = BankStackBrackets.fold(owned, restore, atPush(0, 1));
		assertEquals(0, oddCall.state().knownMask() & BOTH);
		assertEquals(BOTH | SELECT, oddCall.ownedMask() & (BOTH | SELECT));
	}

	@Test
	public void callSiteWithNoClaimIsUntouched() throws Exception {
		CallEffect effect = popEffect();
		assertEquals(effect, BankDataflowEngine.applyBracketClaim(effect, addr0(0x8010),
			claimsFor(R7.positionedMask()), p -> null));
		assertEquals(effect, BankDataflowEngine.applyBracketClaim(effect, addr0(0x8006),
			BankStackBrackets.Claims.NONE, p -> null));
	}

	@Test
	public void claimedPushWithUnrecoverableArgumentIsNotAFailedRecovery() throws Exception {
		CallEffect push = new CallEffect(new BankState(SELECT, 7), SELECT | BOTH, false, false, null);
		CallEffect folded = BankDataflowEngine.applyBracketClaim(push, addr0(0x8000),
			claimsFor(BOTH), p -> null);
		assertTrue(folded.argumentResolved());
		assertEquals("the in-bracket state is still honestly unknown", 0,
			folded.state().knownMask() & BOTH);
		// an unknown bit OUTSIDE the push helper's data fields is a real failure and still warns
		CallEffect other = new CallEffect(new BankState(0, 0), SELECT | BOTH, false, false, null);
		assertFalse(BankDataflowEngine.applyBracketClaim(other, addr0(0x8000), claimsFor(BOTH),
			p -> null).argumentResolved());
	}
}
