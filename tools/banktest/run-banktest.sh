#!/usr/bin/env bash
# C64 + NES banking-analyzer regression suite driver (bead grm-wzl, extended to NES
# by grm-5tl.17).
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
#   GHIDRA_HEADLESS         path to analyzeHeadless(.bat)
#   PYTHON                  python interpreter to use for mkbanktest.py
#   BANKTEST_SETTINGS_BASE  if set, relocate Ghidra's user settings dir (and
#                            therefore where it looks for installed
#                            Extensions) to this directory via
#                            -Dapplication.settingsdir, so the run reads a
#                            per-worktree isolated Extensions install instead
#                            of the shared %APPDATA%/ghidra one. Also sets
#                            -Dapplication.cachedir under the same tree. Set
#                            by build-and-test.sh; left unset here preserves
#                            today's behavior (shared %APPDATA% install), so
#                            the manual GUI-adjacent flow still works.
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

# Isolation mechanism (Ghidra 12.1.2 source):
#   ApplicationUtilities.getDefaultUserSettingsDir honors -Dapplication.settingsdir
#   to relocate the user settings dir (and GhidraApplicationLayout.
#   findExtensionInstallationDirectories reads [settings dir]/Extensions first),
#   and PROPERTY_CACHE_DIR / -Dapplication.cachedir relocates the user cache
#   dir similarly. analyzeHeadless.bat appends GHIDRA_HEADLESS_JAVA_OPTIONS to
#   its VM args, so we can inject both properties per-invocation without
#   touching any install file. native() must be defined above this point.
if [ -n "${BANKTEST_SETTINGS_BASE:-}" ]; then
	base_native="$(native "$BANKTEST_SETTINGS_BASE")"
	export GHIDRA_HEADLESS_JAVA_OPTIONS="${GHIDRA_HEADLESS_JAVA_OPTIONS:-} -Dapplication.settingsdir=$base_native -Dapplication.cachedir=$base_native/cache"
fi

WORK="$(mktemp -d)"
fail=0

"$PYTHON" "$SCRIPT_DIR/mkbanktest.py" "$WORK/prg" || { echo "FAIL: mkbanktest.py" >&2; exit 1; }
"$PYTHON" "$SCRIPT_DIR/mknesbanktest.py" "$WORK/nes" || { echo "FAIL: mknesbanktest.py" >&2; exit 1; }
"$PYTHON" "$SCRIPT_DIR/mkbasictest.py" "$WORK/prg" || { echo "FAIL: mkbasictest.py" >&2; exit 1; }
"$PYTHON" "$SCRIPT_DIR/mkemutest.py" "$WORK/prg" || { echo "FAIL: mkemutest.py" >&2; exit 1; }
"$PYTHON" "$SCRIPT_DIR/mkdecrypttest.py" "$WORK/prg" || { echo "FAIL: mkdecrypttest.py" >&2; exit 1; }

# Imports $2 (a .prg or .nes fixture) via $3 (the loader name), runs VerifyBankTest.java,
# extracts the normalized dump, and check|bless's it against expected/$1.dump.
run_one() {
	local name="$1" fixture="$2" loader="$3"
	local proj="$WORK/proj_$name"
	mkdir -p "$proj"
	local log="$WORK/$name.log"
	echo "== $name: importing $(basename "$fixture") via analyzeHeadless ($loader) =="
	"$GHIDRA_HEADLESS" "$(native "$proj")" headless \
		-import "$(native "$fixture")" \
		-loader "$loader" \
		-scriptPath "$(native "$SCRIPT_DIR")" \
		-postScript VerifyBankTest.java \
		>"$log" 2>&1
	local status=$?

	# Headless wraps script println output as
	#   "INFO  VerifyBankTest.java> <msg> (GhidraScript)  "
	# -- strip the prefix, the " (GhidraScript)" suffix, trailing whitespace and
	# CRs, then cut the normalized dump out by its markers.
	local stripped="$WORK/$name.out"
	sed 's/\r$//; s/^.*VerifyBankTest\.java> //; s/ (GhidraScript)[[:space:]]*$//' \
		"$log" >"$stripped"
	awk '/^=== BANKDUMP BEGIN ===$/{f=1;next} /^=== BANKDUMP END ===$/{f=0} f' \
		"$stripped" >"$WORK/$name.dump"
	grep '^CRITERION ' "$stripped" || true

	if [ $status -ne 0 ]; then
		echo "FAIL: analyzeHeadless exited $status for $name (log: $log)"
		fail=1
		return
	fi
	if ! grep -q '^=== BANKDUMP END ===$' "$stripped"; then
		echo "FAIL: no BANKDUMP section for $name -- did VerifyBankTest run? (log: $log)"
		fail=1
		return
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
}

for name in banktest banktest2 banktest3 banktest4; do
	run_one "$name" "$WORK/prg/$name.prg" C64PrgLoader
done

run_one c64basictest "$WORK/prg/c64basictest.prg" C64PrgLoader

run_one emurecoverytest "$WORK/prg/emurecoverytest.prg" C64PrgLoader

run_one decryptloop "$WORK/prg/decryptloop.prg" C64PrgLoader

run_one nesbanktest "$WORK/nes/nesbanktest.nes" NesRomLoader
run_one nesbanktest2 "$WORK/nes/nesbanktest2.nes" NesRomLoader
run_one nesmodetest "$WORK/nes/nesmodetest.nes" NesRomLoader
run_one nesmmc3test "$WORK/nes/nesmmc3test.nes" NesRomLoader
run_one nesmmc3test2 "$WORK/nes/nesmmc3test2.nes" NesRomLoader
run_one nesserialtest "$WORK/nes/nesserialtest.nes" NesRomLoader
run_one nesmmc1test "$WORK/nes/nesmmc1test.nes" NesRomLoader

if [ $fail -ne 0 ]; then
	echo "SUITE FAILED (work dir kept for inspection: $WORK)"
	exit 1
fi
rm -rf "$WORK"
echo "SUITE OK ($MODE)"
