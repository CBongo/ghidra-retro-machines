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
import java.util.regex.Matcher;
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
 * EF  SLEEP         N/A    0/32  legitimately halts the processor pending an interrupt
 * 9E  DIV YA,X      PASS  999/999  (1 decode-boundary)
 * </pre>
 * Blank lines and lines starting with {@code #} (a header/comment block explaining provenance
 * and how to regenerate -- see the per-suite test that owns the real file) are ignored.
 *
 * <p>The optional trailing {@code (N decode-boundary)} token (see {@link #decodeBoundaryCount})
 * records cases excluded from the ratio because they hit the harness's decode-boundary artifact
 * (see {@code VectorRunner#isDecodeBoundaryCase}) -- a THIRD category, distinct from both
 * PASS/FAIL and from {@link Status#NOT_APPLICABLE}, and per-<em>case</em> rather than
 * per-<em>opcode</em>. It always renders (when nonzero) even on a row that also has mismatched
 * fields, so the excluded count stays visible rather than folded silently into the denominator.
 *
 * <h2>{@code N/A}, not {@code PASS} or {@code FAIL} (grm-c9d.3 increment 9)</h2>
 * A small, explicit set of opcodes (currently {@code SLEEP}/{@code STOP} -- see
 * {@code Spc700VectorHarnessSupport}'s allowlist) legitimately halt the processor; there is no
 * correct post-single-step state to compare a vector against, so every case for them would
 * otherwise report a spurious {@code execution failed} mismatch forever, indistinguishable from a
 * real semantic bug and permanently floored below {@code N/1000}. {@link Status#NOT_APPLICABLE}
 * makes that distinction visible in the baseline file itself rather than silently swallowing the
 * exception -- swallowing it would be exactly the kind of silent-no-op failure mode this project
 * treats as worse than an honest red elsewhere (see {@code CLAUDE.md}). The allowlist producing
 * {@code N/A} rows must stay narrow and named per opcode with a stated reason, never a blanket
 * "exceptions don't count".
 */
public record OpcodeBaseline(String opcodeHex, String mnemonic, Status status, int passedCount,
		int totalCount, List<String> mismatchedFields, int decodeBoundaryCount) {

	/**
	 * Convenience constructor for callers with no decode-boundary cases to report (the common
	 * case, and every pre-existing call site before grm-c9d.3 increment 12): equivalent to the
	 * canonical constructor with {@code decodeBoundaryCount = 0}.
	 */
	public OpcodeBaseline(String opcodeHex, String mnemonic, Status status, int passedCount,
			int totalCount, List<String> mismatchedFields) {
		this(opcodeHex, mnemonic, status, passedCount, totalCount, mismatchedFields, 0);
	}

	/** A row's outcome: fully matched, at least one mismatch, or not applicable (see class doc). */
	public enum Status {
		PASS("PASS"), FAIL("FAIL"), NOT_APPLICABLE("N/A");

		private final String label;

		Status(String label) {
			this.label = label;
		}

		static Status fromLabel(String label, String line) {
			for (Status s : values()) {
				if (s.label.equals(label)) {
					return s;
				}
			}
			throw new IllegalArgumentException(
				"baseline row '" + line + "': expected PASS, FAIL, or N/A, got '" + label + "'");
		}
	}

	/** True iff this row fully matched the vectors ({@link Status#PASS}). */
	public boolean pass() {
		return status == Status.PASS;
	}

	private static final Pattern SPLIT = Pattern.compile("\\s{2,}");
	private static final Pattern BOUNDARY_TOKEN = Pattern.compile("^\\((\\d+) decode-boundary\\)$");

	/** Renders this row in the committed file's format (see class doc). */
	public String format() {
		StringBuilder sb = new StringBuilder();
		sb.append(opcodeHex).append("  ").append(mnemonic).append("  ").append(status.label)
				.append("  ").append(passedCount).append("/").append(totalCount);
		if (decodeBoundaryCount > 0) {
			sb.append("  (").append(decodeBoundaryCount).append(" decode-boundary)");
		}
		if (!mismatchedFields.isEmpty()) {
			sb.append("  ").append(String.join(",", mismatchedFields));
		}
		return sb.toString();
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
		Status status = Status.fromLabel(fields[2], line);
		String[] ratio = fields[3].split("/", 2);
		if (ratio.length != 2) {
			throw new IllegalArgumentException(
				"baseline row '" + line + "': malformed ratio '" + fields[3] + "'");
		}
		int passedCount = Integer.parseInt(ratio[0]);
		int totalCount = Integer.parseInt(ratio[1]);

		int decodeBoundaryCount = 0;
		int nextField = 4;
		if (fields.length > nextField) {
			Matcher m = BOUNDARY_TOKEN.matcher(fields[nextField]);
			if (m.matches()) {
				decodeBoundaryCount = Integer.parseInt(m.group(1));
				nextField++;
			}
		}
		List<String> mismatched = fields.length > nextField
				? List.of(fields[nextField].split(","))
				: List.of();
		return new OpcodeBaseline(opcodeHex, mnemonic, status, passedCount, totalCount, mismatched,
			decodeBoundaryCount);
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

		boolean baselineHasFailures = baseline.stream().anyMatch(r -> r.status() == Status.FAIL);
		boolean actualHasFailures = actual.stream().anyMatch(r -> r.status() == Status.FAIL);
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
