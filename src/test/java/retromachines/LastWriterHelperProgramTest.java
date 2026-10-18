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
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

import retromachines.HelperArgumentRecovery.CallEffect;
import retromachines.HelperDiscovery.HelperModel;

/**
 * Pins {@code HelperArgumentRecovery.lastWriterFold} and its per-site caller-cell channel (bead
 * grm-mej.27): a per-site helper whose sites do NOT run straight-line is summarized by the sites
 * that are last writer on every path to a return, not by the max-address {@code switchSite}.
 * <p>
 * <b>The shape</b> is a commit-from-shadow helper with a deferred-work tail, generalized from
 * megaman3's {@code FUN_ff6b}: select R6, R6 = shadow {@code $f4}, select R7, R7 = shadow
 * {@code $f5}, then a flag test that either returns or switches OTHER banks in at higher
 * addresses, makes a call, and jumps back to the helper's own entry -- so the shadows are
 * committed again before the only return:
 * <pre>
 *   9100  LDA #$06 / STA $9000     S1  select R6
 *   9105  LDA $f4  / STA $9001     S2  R6 <- shadow
 *   910a  LDA #$07 / STA $9000     S3  select R7
 *   910f  LDA $f5  / STA $9001     S4  R7 <- shadow
 *   9114  LDA $f7  / BNE $9119
 *   9118  RTS
 *   9119  LDA #$06 / STA $9000     S5
 *   911e  LDA #$0b / STA $9001     S6  R6 = $b (never live at the return)
 *   9123  LDA #$07 / STA $9000     S7
 *   9128  LDA #$0c / STA $9001     S8  R7 = $c -- the max-address switchSite
 *   912d  JSR $9200                    work this walk does not follow
 *   9130  JMP $9100                    back-edge to the entry
 * </pre>
 * Before grm-mej.27 the call took S8 alone: R7 = $c, select and R6 left as the caller's.
 */
public class LastWriterHelperProgramTest extends AbstractProgramTest {

	private static final int SELECT_MASK = 0x00F;
	private static final int R6_MASK = 0x0F0;
	private static final int R7_MASK = 0xF00;

	@Before
	public void setUp() throws Exception {
		builder = newBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		// Writable RAM, for the same reason HelperInboundCellProgramTest needs it: a read-only
		// block would make a shadow load read as a constant ROM byte.
		MemoryBlock ram = builder.createMemory("RAM", "0x0000", 0x800);
		program = builder.getProgram();
		makeWritable(ram);
	}

	/** Same select/data layout as {@code MultiDepositHelperProgramTest}: select, r6, r7 in 4 bits each. */
	private SelectDataBankSwitchStrategy strategy() {
		JsonObject fieldLayout = new JsonObject();
		String[] names = { "select", "r6", "r7" };
		for (int i = 0; i < names.length; i++) {
			JsonObject layout = new JsonObject();
			layout.addProperty("lsb", 4 * i);
			layout.addProperty("width", 4);
			fieldLayout.add(names[i], layout);
		}
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

	/** The helper in the class javadoc; {@code tailStore} is spliced into the deferred path. */
	private HelperModel buildHelper(String tailStore) throws Exception {
		builder.setBytes("0x9100", "a9 06 8d 00 90", true); // S1
		builder.setBytes("0x9105", "a5 f4 8d 01 90", true); // S2
		builder.setBytes("0x910a", "a9 07 8d 00 90", true); // S3
		builder.setBytes("0x910f", "a5 f5 8d 01 90", true); // S4
		builder.setBytes("0x9114", "a5 f7 d0 01", true); // LDA $f7 / BNE $9119
		builder.setBytes("0x9118", "60", true); // RTS
		builder.setBytes("0x9119", "a9 06 8d 00 90", true); // S5
		builder.setBytes("0x911e", "a9 0b 8d 01 90", true); // S6
		builder.setBytes("0x9123", "a9 07 8d 00 90", true); // S7
		builder.setBytes("0x9128", "a9 0c 8d 01 90", true); // S8
		builder.setBytes("0x912d", tailStore, true); // 3 bytes: JSR $9200, or a shadow store
		builder.setBytes("0x9130", "4c 00 91", true); // JMP $9100
		builder.setBytes("0x9200", "60", true); // RTS
		return new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFFF, 0, strategy(),
			builder.addr("0x912a"), builder.addr("0x9102"), null,
			List.of(builder.addr("0x9102"), builder.addr("0x9107"), builder.addr("0x910c"),
				builder.addr("0x9111"), builder.addr("0x911b"), builder.addr("0x9120"),
				builder.addr("0x9125"), builder.addr("0x912a")));
	}

	private CallEffect recover(HelperModel helper, String callAddr) throws Exception {
		return HelperArgumentRecovery.recoverCallArgument(program, instructionAt(callAddr), helper,
			BankState.unknown(), new HashMap<>(), new HashMap<>());
	}

	/**
	 * The last-writer half. The caller stores no shadow, so neither bank value can resolve -- but
	 * the call now OWNS select, R6 and R7 (the helper writes all three on every path), select is
	 * the last select write on every return path (S3 = 7), and nothing from the deferred path
	 * (S6's $b, S8's $c) is claimed. The warning stands: no bank value was recovered.
	 */
	@Test
	public void backEdgeToEntryMakesTheEarlierSitesTheLastWriters() throws Exception {
		builder.setBytes("0x8000", "ea", true); // NOP -- no shadow stored
		builder.setBytes("0x8001", "20 00 91", true); // JSR $9100
		CallEffect result = recover(buildHelper("20 00 92"), "0x8001");

		assertEquals("every field the helper writes is owned", SELECT_MASK | R6_MASK | R7_MASK,
			result.ownedMask());
		assertEquals("only select is known: the shadows were not stored by this caller",
			SELECT_MASK, result.state().knownMask());
		assertEquals("select is S3's 7, the last select write before every return", 0x7,
			result.state().bits() & SELECT_MASK);
		assertFalse("no bank value recovered, so the call still warns", result.argumentResolved());
	}

	/**
	 * The per-site cell half: {@code LDX #$03 / STX $f4 / INX / STX $f5} before the call, and
	 * each winning data write's own straight-line load names its own cell. R6 = 3 and R7 = 4 --
	 * two cell-sourced deposits from one call, neither of which is the face-value argument.
	 */
	@Test
	public void callerStoredShadowsResolvePerSite() throws Exception {
		builder.setBytes("0x8000", "a2 03 86 f4 e8 86 f5", true); // LDX #3 / STX $f4 / INX / STX $f5
		builder.setBytes("0x8007", "20 00 91", true); // JSR $9100
		CallEffect result = recover(buildHelper("20 00 92"), "0x8007");

		assertEquals(SELECT_MASK | R6_MASK | R7_MASK, result.ownedMask());
		assertEquals("select, r6 and r7 all known", SELECT_MASK | R6_MASK | R7_MASK,
			result.state().knownMask());
		assertEquals("select 7, r6 = $f4 = 3, r7 = $f5 = 4", 0x437, result.state().bits());
		assertTrue(result.argumentResolved());
	}

	/**
	 * The premise's boundary: a PLACEABLE store to a shadow on the back-edge path ({@code STA $f4}
	 * where the call was) means the second commit may read the helper's own byte, so R6's cell
	 * channel declines. R7's shadow is untouched there and still resolves.
	 */
	@Test
	public void aVisibleShadowStoreOnTheBackEdgeDeclinesThatCell() throws Exception {
		builder.setBytes("0x8000", "a2 03 86 f4 e8 86 f5", true);
		builder.setBytes("0x8007", "20 00 91", true);
		CallEffect result = recover(buildHelper("8d f4 00"), "0x8007"); // STA $00f4

		assertEquals(SELECT_MASK | R6_MASK | R7_MASK, result.ownedMask());
		assertEquals("r6 unknown, select and r7 known", SELECT_MASK | R7_MASK,
			result.state().knownMask());
		assertEquals(0x407, result.state().bits() & (SELECT_MASK | R7_MASK));
	}

	/**
	 * A jump OUT of the helper's body (bead grm-mej.28, generalized from smb3's NMI body leaving
	 * through {@code JMP $cecf}) is an exit through code the walk cannot see, not a reason to
	 * decline the whole analysis:
	 * <pre>
	 *   9100  LDA #$06 / STA $9000     S1  select R6
	 *   9105  LDA #$02 / STA $9001     S2  R6 = 2
	 *   910a  LDA #$07 / STA $9000     S3  select R7
	 *   910f  LDA #$04 / STA $9001     S4  R7 = 4
	 *   9114  LDA $f7  / BEQ $911b
	 *   9118  JMP $9300                    into ANOTHER function: the exit state is not this body's
	 *   911b  LDA #$05 / STA $9001     S5  R7 = 5 -- the max-address switchSite
	 *   9120  RTS
	 * </pre>
	 * Before grm-mej.28 the walk declined at the jump and the call took S5 alone, claiming
	 * R7 = 5 although the other arm returns from code that may write anything. Now every field
	 * the helper writes is owned, and none is known: each one's writer set on the leaving arm
	 * includes CALL.
	 */
	@Test
	public void aJumpOutOfTheBodyIsAnUnknownExitNotADecline() throws Exception {
		builder.setBytes("0x9100", "a9 06 8d 00 90", true); // S1
		builder.setBytes("0x9105", "a9 02 8d 01 90", true); // S2
		builder.setBytes("0x910a", "a9 07 8d 00 90", true); // S3
		builder.setBytes("0x910f", "a9 04 8d 01 90", true); // S4
		builder.setBytes("0x9114", "a5 f7 f0 03", true); // LDA $f7 / BEQ $911b
		builder.setBytes("0x9118", "4c 00 93", true); // JMP $9300
		builder.setBytes("0x911b", "a9 05 8d 01 90", true); // S5
		builder.setBytes("0x9120", "60", true); // RTS
		builder.setBytes("0x9300", "60", true); // RTS, a separate function
		builder.setBytes("0x8000", "20 00 91", true); // JSR $9100
		makeFunction(0x9100, 0x9120, "helper");
		makeFunction(0x9300, 0x9300, "elsewhere");
		HelperModel helper = new HelperModel(null, builder.addr("0x9100"), null, 'A', 0xFFF, 0,
			strategy(), builder.addr("0x911d"), builder.addr("0x9102"), null,
			List.of(builder.addr("0x9102"), builder.addr("0x9107"), builder.addr("0x910c"),
				builder.addr("0x9111"), builder.addr("0x911d")));
		CallEffect result = recover(helper, "0x8000");

		assertEquals("every field the helper writes is owned", SELECT_MASK | R6_MASK | R7_MASK,
			result.ownedMask());
		assertEquals("nothing is known: the leaving arm may rewrite every field", 0,
			result.state().knownMask());
		assertFalse("no bank value recovered, so the call warns", result.argumentResolved());
	}

	private void makeFunction(int start, int endInclusive, String name) throws Exception {
		Address s = builder.addr(String.format("0x%x", start));
		Address e = builder.addr(String.format("0x%x", endInclusive));
		inTx(program, "create function", () -> {
			program.getFunctionManager().createFunction(name, s,
				new AddressSet(s, e),
				SourceType.ANALYSIS);
		});
	}
}
