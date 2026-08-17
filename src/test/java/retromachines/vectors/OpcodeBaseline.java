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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A committed, per-opcode pass/fail baseline (bead grm-c9d.2) -- this project's "bless" idiom
 * applied to a semantics defect list instead of a golden dump.
 *
 * <p>The point: a vector harness proving p-code semantics against a spec KNOWN to be broken
 * (SPC700 today, per grm-c9d.1/grm-c9d.3) cannot be wired as ordinary JUnit assertions, or the
 * project gate goes red the moment it lands and stays red until every opcode is fixed. Instead
 * each opcode's PASS/FAIL and mismatched-field summary is checked against a committed baseline
 * file. The baseline recording a FAIL is not a test failure -- it is the documented, reviewable
 * state of a known defect; only a <em>regression</em> (an opcode moving PASS -> FAIL) or the
 * harness silently measuring less than before is a hard failure. See {@link #compare} for the
 * exact rules.
 *
 * <h2>File format</h2>
 * One row per opcode, fields separated by two-or-more spaces (mnemonics may contain single
 * spaces, e.g. {@code "MOV A,#imm"}, so the separator must be wider than any field's internal
 * spacing):
 * <pre>
 * E8  MOV A,#imm    PASS  32/32
 * E4  MOV A,dp      FAIL   0/32  A,PSW
 * </pre>
 * Blank lines and lines starting with {@code #} (a header/comment block explaining provenance
 * and how to regenerate -- see the per-suite test that owns the real file) are ignored.
 */
public record OpcodeBaseline(String opcodeHex, String mnemonic, boolean pass, int passedCount,
		int totalCount, List<String> mismatchedFields) {

	private static final Pattern SPLIT = Pattern.compile("\\s{2,}");

	/** Renders this row in the committed file's format (see class doc). */
	public String format() {
		String base = opcodeHex + "  " + mnemonic + "  " + (pass ? "PASS" : "FAIL") + "  " +
			passedCount + "/" + totalCount;
		if (mismatchedFields.isEmpty()) {
			return base;
		}
		return base + "  " + String.join(",", mismatchedFields);
	}

	/** Renders a whole row set, one line per row, no header. */
	public static List<String> formatAll(List<OpcodeBaseline> rows) {
		return rows.stream().map(OpcodeBaseline::format).collect(Collectors.toList());
	}

	/**
	 * Parses a baseline file's lines (as read, in order; blank/{@code #}-comment lines are
	 * skipped).
	 */
	public static List<OpcodeBaseline> parse(List<String> lines) {
		List<OpcodeBaseline> rows = new ArrayList<>();
		for (String line : lines) {
			String trimmed = line.strip();
			if (trimmed.isEmpty() || trimmed.startsWith("#")) {
				continue;
			}
			rows.add(parseLine(trimmed));
		}
		return rows;
	}

	/** Parses one non-comment, non-blank row. */
	public static OpcodeBaseline parseLine(String line) {
		String[] fields = SPLIT.split(line.strip());
		if (fields.length < 4) {
			throw new IllegalArgumentException("malformed baseline row (need at least " +
				"opcode/mnemonic/PASS-FAIL/ratio): '" + line + "'");
		}
		String opcodeHex = fields[0];
		String mnemonic = fields[1];
		boolean pass = switch (fields[2]) {
			case "PASS" -> true;
			case "FAIL" -> false;
			default -> throw new IllegalArgumentException(
				"baseline row '" + line + "': expected PASS or FAIL, got '" + fields[2] + "'");
		};
		String[] ratio = fields[3].split("/", 2);
		if (ratio.length != 2) {
			throw new IllegalArgumentException(
				"baseline row '" + line + "': malformed ratio '" + fields[3] + "'");
		}
		int passedCount = Integer.parseInt(ratio[0]);
		int totalCount = Integer.parseInt(ratio[1]);
		List<String> mismatched = fields.length >= 5
				? List.of(fields[4].split(","))
				: List.of();
		return new OpcodeBaseline(opcodeHex, mnemonic, pass, passedCount, totalCount, mismatched);
	}

	/**
	 * Compares a committed baseline against an actual run's per-opcode results, returning every
	 * problem found (empty = the run is consistent with the baseline). Rules, in the order they
	 * are checked:
	 * <ol>
	 * <li><b>Coverage regression:</b> {@code actual} covers fewer opcodes than {@code baseline}
	 * lists, or a baseline opcode is entirely absent from {@code actual} -- the harness stopped
	 * measuring something it used to.</li>
	 * <li><b>Zero-failures sanity:</b> {@code baseline} records at least one FAIL but
	 * {@code actual} records none -- against a spec baseline itself says is broken, an
	 * all-green run means the harness measured nothing (wrong language, empty vector set,
	 * comparison that never fires), not that the spec got fixed one opcode at a time without a
	 * baseline update.</li>
	 * <li><b>Regression:</b> an opcode the baseline marks PASS comes back FAIL in
	 * {@code actual}. (The reverse -- FAIL in the baseline, PASS in {@code actual} -- is
	 * progress, not a problem; it is exactly what updating the baseline during grm-c9d.3 records.)</li>
	 * </ol>
	 */
	public static List<String> compare(List<OpcodeBaseline> baseline, List<OpcodeBaseline> actual) {
		List<String> problems = new ArrayList<>();
		Map<String, OpcodeBaseline> baselineByOp = byOpcode(baseline);
		Map<String, OpcodeBaseline> actualByOp = byOpcode(actual);

		if (actual.size() < baseline.size()) {
			problems.add("this run covered fewer opcodes (" + actual.size() + ") than the " +
				"baseline (" + baseline.size() + ") -- the harness is measuring less than before");
		}
		for (String op : baselineByOp.keySet()) {
			if (!actualByOp.containsKey(op)) {
				problems.add("opcode " + op + " is in the baseline but missing from this run");
			}
		}

		boolean baselineHasFailures = baseline.stream().anyMatch(r -> !r.pass());
		boolean actualHasFailures = actual.stream().anyMatch(r -> !r.pass());
		if (baselineHasFailures && !actualHasFailures) {
			problems.add("baseline expects failing opcodes but this run produced zero failures " +
				"-- a harness that passes against a spec known to be broken is measuring " +
				"nothing (check the language id, the vector set, and the comparison itself)");
		}

		for (Map.Entry<String, OpcodeBaseline> entry : baselineByOp.entrySet()) {
			OpcodeBaseline before = entry.getValue();
			OpcodeBaseline after = actualByOp.get(entry.getKey());
			if (after == null) {
				continue; // already reported above
			}
			if (before.pass() && !after.pass()) {
				problems.add(entry.getKey() + " regressed PASS -> FAIL (" + after.passedCount() +
					"/" + after.totalCount() + "; mismatched: " +
					String.join(",", after.mismatchedFields()) + ")");
			}
		}
		return problems;
	}

	private static Map<String, OpcodeBaseline> byOpcode(List<OpcodeBaseline> rows) {
		Map<String, OpcodeBaseline> byOp = new LinkedHashMap<>();
		for (OpcodeBaseline row : rows) {
			byOp.put(row.opcodeHex(), row);
		}
		return byOp;
	}
}
