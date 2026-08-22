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
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Pins the loader-to-analyzer channel for asynchronously reached entry points (bead grm-913):
 * {@link DescriptorSupport#ASYNC_ENTRY_POINTS_PROPERTY} and its
 * {@link DescriptorSupport#formatAsyncEntryPoints}/{@link DescriptorSupport#parseAsyncEntryPoints}
 * pair.
 * <p>
 * Why this channel is worth its own test rather than being covered incidentally: it is the only
 * thing standing between {@link BoardBankAnalyzer}'s dataflow and an unsound seed. The analyzer
 * seeds every function entry with {@code banking.initial_state} fully known, which is true of a
 * reset entry and false of an interrupt handler -- an interrupt fires from arbitrary mainline
 * context, so the bank live on entry is whatever the interrupted code had. If a token stops
 * round-tripping, the seeding silently reverts to the unsound state for that entry and nothing
 * else fails, which is the failure direction that reads as "no change".
 * <p>
 * The analyzer-level consequence -- an interrupt handler's bank claims weakening to warnings --
 * is pinned by the headless NES fixtures, which have a real vector table; these tests
 * deliberately stop at the property, which is a pure function of (program, string).
 */
public class AsyncEntryPointsProgramTest extends AbstractBundledLanguageTest {

	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("Test", "6502:LE:16:default");
		builder.createMemory("PRG", "0x8000", 0x8000);
		program = builder.getProgram();
	}

	/** Writes {@code spec} straight into the property, bypassing the format side. */
	private void setProperty(String spec) {
		int tx = program.startTransaction("set async entry points");
		try {
			program.getOptions(Program.PROGRAM_INFO)
					.setString(DescriptorSupport.ASYNC_ENTRY_POINTS_PROPERTY, spec);
		}
		finally {
			program.endTransaction(tx, true);
		}
	}

	// ------------------------------------------------------------------
	// Round trip
	// ------------------------------------------------------------------

	/** The whole point: what the loader writes is what the analyzer reads back. */
	@Test
	public void formattedAddressesParseBackToThemselves() {
		List<Address> written = List.of(builder.addr("0x9000"), builder.addr("0xff8f"));
		setProperty(DescriptorSupport.formatAsyncEntryPoints(written));

		assertEquals(Set.copyOf(written), DescriptorSupport.parseAsyncEntryPoints(program));
	}

	/**
	 * Space-qualified tokens, not bare hex. The seeds the analyzer compares against are
	 * {@link Address} objects from the function manager, so an offset that lost its space
	 * would compare equal to the wrong thing on a program with overlays.
	 */
	@Test
	public void formatEmitsSpaceQualifiedTokens() {
		String spec = DescriptorSupport.formatAsyncEntryPoints(List.of(builder.addr("0x9000")));

		assertEquals(builder.addr("0x9000").toString(), spec);
		assertTrue("token must round-trip through the address factory",
			program.getAddressFactory().getAddress(spec) != null);
	}

	// ------------------------------------------------------------------
	// Absence and malformed input
	// ------------------------------------------------------------------

	/**
	 * A program imported before this property existed -- and every non-NES program -- must
	 * analyze exactly as it did, i.e. with no entry weakened.
	 */
	@Test
	public void absentPropertyYieldsNoAsyncEntries() {
		assertEquals(Set.of(), DescriptorSupport.parseAsyncEntryPoints(program));
	}

	/** Same for a property present but empty, which the loader never writes but a user can. */
	@Test
	public void blankPropertyYieldsNoAsyncEntries() {
		setProperty("   ");

		assertEquals(Set.of(), DescriptorSupport.parseAsyncEntryPoints(program));
	}

	/**
	 * An unresolvable token is skipped, not raised. This property is an optimization of
	 * soundness rather than a correctness precondition: a program whose blocks moved since
	 * import must still analyze, and losing one weakened seed is exactly the pre-grm-913
	 * behavior. Raising here would cost a user their whole analysis over a stale string.
	 */
	@Test
	public void unresolvableTokenIsSkippedAndTheRestSurvive() {
		setProperty("not-an-address " + builder.addr("0x9000"));

		assertEquals(Set.of(builder.addr("0x9000")),
			DescriptorSupport.parseAsyncEntryPoints(program));
	}

	/** Empty input formats to the empty string, which the read side already treats as absent. */
	@Test
	public void emptyListFormatsToEmptyString() {
		assertEquals("", DescriptorSupport.formatAsyncEntryPoints(List.of()));
	}
}
