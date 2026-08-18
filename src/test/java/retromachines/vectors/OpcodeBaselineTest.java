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
package retromachines.vectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

/**
 * Pure-logic coverage (Tier 1, no Ghidra emulation) of the {@link OpcodeBaseline} per-opcode
 * bless idiom (bead grm-c9d.2): parse/format round trip, and the sanity checks that keep a
 * baseline-gated harness from silently measuring nothing. See {@link OpcodeBaseline#compare}
 * for the rules this exercises.
 */
public class OpcodeBaselineTest {

	@Test
	public void formatAndParseRoundTrip() {
		OpcodeBaseline pass = new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of());
		OpcodeBaseline fail =
			new OpcodeBaseline("E4", "MOV A,dp", OpcodeBaseline.Status.FAIL, 0, 32, List.of("A", "PSW"));

		assertEquals("E8  MOV A,#imm  PASS  32/32", pass.format());
		assertEquals("E4  MOV A,dp  FAIL  0/32  A,PSW", fail.format());

		List<OpcodeBaseline> parsed = OpcodeBaseline.parse(List.of(pass.format(), fail.format()));
		assertEquals(List.of(pass, fail), parsed);
	}

	@Test
	public void parseSkipsBlankAndCommentLines() {
		List<OpcodeBaseline> parsed = OpcodeBaseline.parse(List.of(
			"# generated; review the diff, do not hand-edit casually",
			"",
			"E8  MOV A,#imm  PASS  32/32",
			"   ",
			"# regenerate: -Dgrm.spc700.regenerateBaseline=true"));
		assertEquals(1, parsed.size());
		assertEquals("E8", parsed.get(0).opcodeHex());
	}

	@Test
	public void mnemonicWithInternalSpaceRoundTrips() {
		// "MOV A,#imm" has a single internal space; the two-or-more-space field separator must
		// not be fooled by it.
		OpcodeBaseline row = new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of());
		OpcodeBaseline reparsed = OpcodeBaseline.parseLine(row.format());
		assertEquals(row, reparsed);
	}

	@Test
	public void compareIsCleanWhenActualMatchesBaseline() {
		List<OpcodeBaseline> baseline = List.of(
			new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of()),
			new OpcodeBaseline("E4", "MOV A,dp", OpcodeBaseline.Status.FAIL, 0, 32, List.of("A", "PSW")));
		List<OpcodeBaseline> actual = List.of(
			new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of()),
			new OpcodeBaseline("E4", "MOV A,dp", OpcodeBaseline.Status.FAIL, 0, 32, List.of("A", "PSW")));
		assertTrue(OpcodeBaseline.compare(baseline, actual).isEmpty());
	}

	@Test
	public void compareAllowsFailToPassProgress() {
		// grm-c9d.3 fixing ONE opcode out of many is exactly this transition; it must never be a
		// problem. A second, still-failing opcode is included deliberately: a baseline reduced
		// to a single row that goes all-PASS is the "did the baseline just go stale" case (see
		// compareFlagsZeroFailuresWhenBaselineExpectsMany below), not plain incremental progress.
		List<OpcodeBaseline> baseline = List.of(
			new OpcodeBaseline("E4", "MOV A,dp", OpcodeBaseline.Status.FAIL, 0, 32, List.of("A", "PSW")),
			new OpcodeBaseline("E5", "MOV A,dp+X", OpcodeBaseline.Status.FAIL, 0, 32, List.of("A")));
		List<OpcodeBaseline> actual = List.of(
			new OpcodeBaseline("E4", "MOV A,dp", OpcodeBaseline.Status.PASS, 32, 32, List.of()),
			new OpcodeBaseline("E5", "MOV A,dp+X", OpcodeBaseline.Status.FAIL, 0, 32, List.of("A")));
		assertTrue(OpcodeBaseline.compare(baseline, actual).isEmpty());
	}

	@Test
	public void compareFlagsPassToFailRegression() {
		List<OpcodeBaseline> baseline =
			List.of(new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of()));
		List<OpcodeBaseline> actual =
			List.of(new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.FAIL, 10, 32, List.of("PSW")));
		List<String> problems = OpcodeBaseline.compare(baseline, actual);
		assertEquals(1, problems.size());
		assertTrue(problems.get(0).contains("E8"));
		assertTrue(problems.get(0).contains("PASS -> FAIL"));
	}

	@Test
	public void compareFlagsFewerOpcodesThanBaseline() {
		List<OpcodeBaseline> baseline = List.of(
			new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of()),
			new OpcodeBaseline("E4", "MOV A,dp", OpcodeBaseline.Status.FAIL, 0, 32, List.of("A")));
		List<OpcodeBaseline> actual =
			List.of(new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of()));
		List<String> problems = OpcodeBaseline.compare(baseline, actual);
		assertTrue(problems.stream().anyMatch(p -> p.contains("fewer opcodes")));
		assertTrue(problems.stream().anyMatch(p -> p.contains("E4") && p.contains("missing")));
	}

	@Test
	public void compareFlagsZeroFailuresWhenBaselineExpectsMany() {
		// This fires for two indistinguishable-from-the-data-alone reasons, and both deserve a
		// loud gate rather than a silent pass: (a) the harness is broken -- wrong language,
		// empty vector set, a comparison that never fires -- so it "passes" against a spec
		// everyone agrees is broken; or (b) every opcode genuinely got fixed but nobody
		// regenerated the committed baseline to match, per the grm-c9d.3 workflow ("each fix
		// flips entries FAIL -> PASS and the baseline diff IS the progress report"). Either way,
		// the fix is the same: regenerate the baseline (see next test for the resulting clean
		// compare) -- never to ignore this check.
		List<OpcodeBaseline> baseline = List.of(
			new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of()),
			new OpcodeBaseline("E4", "MOV A,dp", OpcodeBaseline.Status.FAIL, 0, 32, List.of("A")));
		List<OpcodeBaseline> actual = List.of(
			new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of()),
			new OpcodeBaseline("E4", "MOV A,dp", OpcodeBaseline.Status.PASS, 32, 32, List.of()));
		List<String> problems = OpcodeBaseline.compare(baseline, actual);
		assertTrue(problems.stream().anyMatch(p -> p.contains("zero failures")));
	}

	@Test
	public void compareIsCleanOnceBaselineIsRegeneratedToMatch() {
		// The follow-up to the previous test: once the baseline is regenerated (E4 updated to
		// PASS to match reality), the same actual run compares clean.
		List<OpcodeBaseline> regeneratedBaseline = List.of(
			new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of()),
			new OpcodeBaseline("E4", "MOV A,dp", OpcodeBaseline.Status.PASS, 32, 32, List.of()));
		List<OpcodeBaseline> actual = List.of(
			new OpcodeBaseline("E8", "MOV A,#imm", OpcodeBaseline.Status.PASS, 32, 32, List.of()),
			new OpcodeBaseline("E4", "MOV A,dp", OpcodeBaseline.Status.PASS, 32, 32, List.of()));
		assertTrue(OpcodeBaseline.compare(regeneratedBaseline, actual).isEmpty());
	}
}
