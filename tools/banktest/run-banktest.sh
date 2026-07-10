#!/usr/bin/env bash
# C64 banking-analyzer regression suite driver (bead grm-wzl).
#
# Usage: run-banktest.sh [check|bless]
#
#   check (default)  Generate the test PRGs, import each with analyzeHeadless
#                    using the C64PrgLoader, run VerifyBankTest.java, and fail
#                    if any criterion fails or the normalized behavior dump
#                    differs from the golden copies in expected/.
#   bless            Same run, but (re)capture the dumps into expected/.
#
# Environment overrides:
#   GHIDRA_HEADLESS  path to analyzeHeadless(.bat)
#   PYTHON           python interpreter to use for mkbanktest.py
#
# Note: analyzeHeadless.bat chokes on parentheses in filenames -- keep every
# generated path free of them.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPECTED_DIR="$SCRIPT_DIR/expected"
GHIDRA_HEADLESS="${GHIDRA_HEADLESS:-D:/ghidra_12.1.2_PUBLIC/support/analyzeHeadless.bat}"
MODE="${1:-check}"

case "$MODE" in
	check|bless) ;;
	*) echo "usage: $0 [check|bless]" >&2; exit 2 ;;
esac

PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
	if command -v python3 >/dev/null 2>&1; then PYTHON=python3; else PYTHON=python; fi
fi

# Native (Windows) path form for arguments handed to analyzeHeadless.bat.
native() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi
}

WORK="$(mktemp -d)"
fail=0

"$PYTHON" "$SCRIPT_DIR/mkbanktest.py" "$WORK/prg" || { echo "FAIL: mkbanktest.py" >&2; exit 1; }

for name in banktest banktest2 banktest3 banktest4; do
	proj="$WORK/proj_$name"
	mkdir -p "$proj"
	log="$WORK/$name.log"
	echo "== $name: importing $name.prg via analyzeHeadless =="
	"$GHIDRA_HEADLESS" "$(native "$proj")" headless \
		-import "$(native "$WORK/prg/$name.prg")" \
		-loader C64PrgLoader \
		-scriptPath "$(native "$SCRIPT_DIR")" \
		-postScript VerifyBankTest.java \
		>"$log" 2>&1
	status=$?

	# Headless wraps script println output as
	#   "INFO  VerifyBankTest.java> <msg> (GhidraScript)  "
	# -- strip the prefix, the " (GhidraScript)" suffix, trailing whitespace and
	# CRs, then cut the normalized dump out by its markers.
	stripped="$WORK/$name.out"
	sed 's/\r$//; s/^.*VerifyBankTest\.java> //; s/ (GhidraScript)[[:space:]]*$//' \
		"$log" >"$stripped"
	awk '/^=== BANKDUMP BEGIN ===$/{f=1;next} /^=== BANKDUMP END ===$/{f=0} f' \
		"$stripped" >"$WORK/$name.dump"
	grep '^CRITERION ' "$stripped" || true

	if [ $status -ne 0 ]; then
		echo "FAIL: analyzeHeadless exited $status for $name (log: $log)"
		fail=1
		continue
	fi
	if ! grep -q '^=== BANKDUMP END ===$' "$stripped"; then
		echo "FAIL: no BANKDUMP section for $name -- did VerifyBankTest run? (log: $log)"
		fail=1
		continue
	fi
	if ! grep -q '^SUITE PASS$' "$stripped"; then
		echo "FAIL: criteria failed for $name (log: $log)"
		fail=1
	fi

	if [ "$MODE" = bless ]; then
		mkdir -p "$EXPECTED_DIR"
		cp "$WORK/$name.dump" "$EXPECTED_DIR/$name.dump"
		echo "blessed $EXPECTED_DIR/$name.dump"
	else
		if [ ! -f "$EXPECTED_DIR/$name.dump" ]; then
			echo "FAIL: missing golden $EXPECTED_DIR/$name.dump (run bless first)"
			fail=1
		elif diff -u <(tr -d '\r' <"$EXPECTED_DIR/$name.dump") "$WORK/$name.dump"; then
			echo "dump matches golden: $name"
		else
			echo "FAIL: dump differs from golden for $name"
			fail=1
		fi
	fi
done

if [ $fail -ne 0 ]; then
	echo "SUITE FAILED (work dir kept for inspection: $WORK)"
	exit 1
fi
rm -rf "$WORK"
echo "SUITE OK ($MODE)"
