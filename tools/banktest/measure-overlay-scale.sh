#!/usr/bin/env bash
# Manual, CI-excluded scale measurement: runs OverlayScaleMeasure.java (a
# read-only, counts-only companion to VerifyBankTest.java) over one or more
# real-world NES ROMs, to gauge how BoardBankAnalyzer's overlay bookkeeping
# scales past the small synthetic nesbanktest*.nes fixtures (which top out at
# a handful of banks; a real cartridge can carry ~191 overlays and thousands
# of references). Not part of build-and-test.sh -- invoke by hand:
#
#   bash tools/banktest/measure-overlay-scale.sh <rom1> [<rom2> ...]
#
# For each ROM this: sanitizes a parenthesis/space-free copy (analyzeHeadless.bat
# chokes on parentheses -- see run-banktest.sh's note), creates a throwaway
# project, runs analyzeHeadless with default analysis (BoardBankAnalyzer
# included) plus -postScript OverlayScaleMeasure.java, times the run, and
# extracts the MEASURE lines plus BoardBankAnalyzer's own
# "overlay references added/confirmed" summary line from the log. Prints a
# summary table at the end; a failing ROM gets an error row and the batch
# continues.
#
# Environment overrides:
#   GHIDRA_HEADLESS         path to analyzeHeadless(.bat)
#   BANKTEST_SETTINGS_BASE  if set, relocate Ghidra's user settings dir (and
#                            therefore where it looks for installed
#                            Extensions) to this directory, exactly as
#                            run-banktest.sh/build-and-test.sh do, so the
#                            per-worktree isolated Extensions install (from
#                            `build-and-test.sh check nes-banking`) is picked
#                            up instead of the shared %APPDATA% one. Defaults
#                            to <repo>/build/ghidra-home, matching
#                            build-and-test.sh's derivation, so this script
#                            works standalone after that install has run.
set -u

if [ $# -eq 0 ]; then
	echo "usage: $0 <rom1> [<rom2> ...]" >&2
	exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Default headless path derives from gradle.properties' ghidraTargetVersion (single
# source of truth for the targeted Ghidra version, bead grm-9r7); GHIDRA_HEADLESS
# still overrides.
GRM_TARGET_VERSION="$(sed -n 's/^ghidraTargetVersion=//p' "$REPO_ROOT/gradle.properties")"
GHIDRA_HEADLESS="${GHIDRA_HEADLESS:-D:/ghidra_${GRM_TARGET_VERSION}_PUBLIC/support/analyzeHeadless.bat}"

# Native (Windows) path form for arguments handed to analyzeHeadless.bat.
native() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi
}

# Isolation mechanism -- same as run-banktest.sh: relocate the user settings dir
# (and therefore where analyzeHeadless looks for installed Extensions) to the
# per-worktree build/ghidra-home tree that build-and-test.sh populates, instead
# of the shared %APPDATA%/ghidra install. Default matches build-and-test.sh's
# SETTINGS_BASE derivation exactly (REPO_ROOT/build/ghidra-home); honor an
# already-exported BANKTEST_SETTINGS_BASE if the caller set one.
if [ -z "${BANKTEST_SETTINGS_BASE:-}" ]; then
	if [ -d "$REPO_ROOT/build/ghidra-home" ]; then
		BANKTEST_SETTINGS_BASE="$REPO_ROOT/build/ghidra-home"
	else
		echo "NOTE: $REPO_ROOT/build/ghidra-home not found (run" \
			"'bash tools/banktest/build-and-test.sh check nes-banking' first to install the" \
			"isolated extension); falling back to the shared %APPDATA%/ghidra install." >&2
		BANKTEST_SETTINGS_BASE=
	fi
fi
if [ -n "${BANKTEST_SETTINGS_BASE:-}" ]; then
	base_native="$(native "$BANKTEST_SETTINGS_BASE")"
	export GHIDRA_HEADLESS_JAVA_OPTIONS="${GHIDRA_HEADLESS_JAVA_OPTIONS:-} -Dapplication.settingsdir=$base_native -Dapplication.cachedir=$base_native/cache"
fi

WORK="${MEASURE_WORK_DIR:-$(mktemp -d)}"
mkdir -p "$WORK"
echo "== work dir: $WORK =="

sanitize() {
	# Strip anything that isn't [A-Za-z0-9._-]; analyzeHeadless.bat chokes on
	# parentheses (and spaces are asking for trouble in unquoted contexts).
	printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'
}

declare -a ROW_NAME ROW_BLOCKS_TOTAL ROW_BLOCKS_OVERLAY ROW_SPACES_OVERLAY
declare -a ROW_REFS ROW_REFS_ADDED ROW_WARNINGS ROW_WALL ROW_LOG ROW_STATUS

for rom in "$@"; do
	if [ ! -f "$rom" ]; then
		echo "ERROR: $rom: not found" >&2
		ROW_NAME+=("$(basename "$rom")")
		ROW_BLOCKS_TOTAL+=("-"); ROW_BLOCKS_OVERLAY+=("-"); ROW_SPACES_OVERLAY+=("-")
		ROW_REFS+=("-"); ROW_REFS_ADDED+=("-"); ROW_WARNINGS+=("-")
		ROW_WALL+=("-"); ROW_LOG+=("-"); ROW_STATUS+=("MISSING")
		continue
	fi

	base="$(basename "$rom")"
	safe_name="$(sanitize "${base%.*}")"
	safe_ext="$(sanitize "${base##*.}")"
	rom_copy="$WORK/${safe_name}.${safe_ext}"
	cp -f "$rom" "$rom_copy"

	proj="$WORK/proj_${safe_name}"
	mkdir -p "$proj"
	log="$WORK/${safe_name}.log"

	echo "== $safe_name: importing $base via analyzeHeadless (NesRomLoader) =="

	start_ns="$(date +%s%N)"
	"$GHIDRA_HEADLESS" "$(native "$proj")" headless \
		-import "$(native "$rom_copy")" \
		-loader NesRomLoader \
		-scriptPath "$(native "$SCRIPT_DIR")" \
		-postScript OverlayScaleMeasure.java \
		-deleteProject \
		>"$log" 2>&1
	status=$?
	end_ns="$(date +%s%N)"
	wall_s="$(awk -v a="$start_ns" -v b="$end_ns" 'BEGIN { printf "%.2f", (b - a) / 1000000000 }')"

	ROW_NAME+=("$safe_name")
	ROW_LOG+=("$log")
	ROW_WALL+=("$wall_s")

	if [ $status -ne 0 ]; then
		echo "ERROR: analyzeHeadless exited $status for $safe_name (log: $log)" >&2
		ROW_BLOCKS_TOTAL+=("-"); ROW_BLOCKS_OVERLAY+=("-"); ROW_SPACES_OVERLAY+=("-")
		ROW_REFS+=("-"); ROW_REFS_ADDED+=("-"); ROW_WARNINGS+=("-")
		ROW_STATUS+=("FAIL(exit=$status)")
		continue
	fi

	# Headless wraps script println output as
	#   "INFO  OverlayScaleMeasure.java> <msg> (GhidraScript)  "
	# -- strip the prefix/suffix the same way run-banktest.sh does for
	# VerifyBankTest, then read the MEASURE lines out.
	stripped="$WORK/${safe_name}.out"
	sed 's/\r$//; s/^.*OverlayScaleMeasure\.java> //; s/ (GhidraScript)[[:space:]]*$//' \
		"$log" >"$stripped"

	if ! grep -q '^=== MEASURE END ===$' "$stripped"; then
		echo "ERROR: no MEASURE block for $safe_name -- did OverlayScaleMeasure run? (log: $log)" >&2
		ROW_BLOCKS_TOTAL+=("-"); ROW_BLOCKS_OVERLAY+=("-"); ROW_SPACES_OVERLAY+=("-")
		ROW_REFS+=("-"); ROW_REFS_ADDED+=("-"); ROW_WARNINGS+=("-")
		ROW_STATUS+=("FAIL(no-measure-block)")
		continue
	fi

	blocks_total="$(sed -n 's/^MEASURE blocks\.total //p' "$stripped" | head -n1)"
	blocks_overlay="$(sed -n 's/^MEASURE blocks\.overlay //p' "$stripped" | head -n1)"
	spaces_overlay="$(sed -n 's/^MEASURE spaces\.overlay //p' "$stripped" | head -n1)"
	refs_into_overlay="$(sed -n 's/^MEASURE refs\.intoOverlay //p' "$stripped" | head -n1)"
	bookmarks_warning="$(sed -n 's/^MEASURE bookmarks\.warning //p' "$stripped" | head -n1)"

	# BoardBankAnalyzer's own tally, e.g.:
	#   "... 1234 instructions tracked, 567 overlay references added/confirmed, ..."
	refs_added="$(grep -o '[0-9][0-9]* overlay references added/confirmed' "$stripped" | \
		tail -n1 | awk '{print $1}')"

	ROW_BLOCKS_TOTAL+=("${blocks_total:--}")
	ROW_BLOCKS_OVERLAY+=("${blocks_overlay:--}")
	ROW_SPACES_OVERLAY+=("${spaces_overlay:--}")
	ROW_REFS+=("${refs_into_overlay:--}")
	ROW_REFS_ADDED+=("${refs_added:--}")
	ROW_WARNINGS+=("${bookmarks_warning:--}")
	ROW_STATUS+=("OK")
done

echo
printf '%-24s %8s %8s %8s %10s %12s %8s %8s %s\n' \
	"ROM" "blk.tot" "blk.ovl" "spc.ovl" "refs.ovl" "refsAdded" "warn" "wall_s" "status"
for i in "${!ROW_NAME[@]}"; do
	printf '%-24s %8s %8s %8s %10s %12s %8s %8s %s\n' \
		"${ROW_NAME[$i]}" "${ROW_BLOCKS_TOTAL[$i]}" "${ROW_BLOCKS_OVERLAY[$i]}" \
		"${ROW_SPACES_OVERLAY[$i]}" "${ROW_REFS[$i]}" "${ROW_REFS_ADDED[$i]}" \
		"${ROW_WARNINGS[$i]}" "${ROW_WALL[$i]}" "${ROW_STATUS[$i]}"
done

echo
echo "per-ROM logs:"
for i in "${!ROW_NAME[@]}"; do
	echo "  ${ROW_NAME[$i]}: ${ROW_LOG[$i]}"
done

echo
echo "work dir kept for inspection: $WORK"
