#!/usr/bin/env bash
# C64 + C128 + NES banking-analyzer regression suite driver (bead grm-wzl, extended
# to NES by grm-5tl.17).
#
# Usage: run-banktest.sh [check|bless] [chunk ...]
#
#   check (default)  Generate the test PRGs, import each with analyzeHeadless
#                    using the C64PrgLoader, run VerifyBankTest.java, and fail
#                    if any criterion fails or the normalized behavior dump
#                    differs from the golden copies in expected/.
#   bless            Same run, but (re)capture the dumps into expected/.
#
# Chunks (default: all):
#   c64-banking   banktest through banktest4
#   c64-loader    arbitrary-address PRGs, ROM loading, and symbol toggle
#   c64-recovery  emulation and decrypt/recovery fixtures
#   basic-petscii c64basictest
#   basic-dialects PET BASIC 4/C128 BASIC 7 token dialects, plus C64 BASIC 2 regression
#   pet-loader    PET 4032 descriptor, PRG placement, IO types, and fixed ROM slots
#   c128-loader   C128 native BASIC PRG placement, fixed ROM slots, and MMU IO
#   nes-banking   all NES banking/MMC fixtures
#   petscii-strings PetsciiStringAnalyzer C64 PRG fixture
#   all           every chunk above
#
#   --list-chunks  print the available chunk names and exit
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

usage() {
	echo "usage: $0 [check|bless] [chunk ...]" >&2
	echo "       $0 --list-chunks" >&2
}

list_chunks() {
	printf '%s\n' \
		c64-banking \
		c64-loader \
		c64-recovery \
		basic-petscii \
		basic-dialects \
		pet-loader \
		c128-loader \
		nes-banking \
		petscii-strings \
		all
}

if [ "${1:-}" = "--list-chunks" ]; then
	if [ $# -ne 1 ]; then
		usage
		exit 2
	fi
	list_chunks
	exit 0
fi

MODE=check
if [ $# -gt 0 ] && { [ "$1" = check ] || [ "$1" = bless ]; }; then
	MODE="$1"
	shift
fi
CHUNKS=("$@")
if [ ${#CHUNKS[@]} -eq 0 ]; then
	CHUNKS=(all)
fi

# Validate every requested chunk before creating a work directory or generating
# fixtures, so a typo cannot leave partial output behind.
for chunk in "${CHUNKS[@]}"; do
	case "$chunk" in
		c64-banking|c64-loader|c64-recovery|basic-petscii|basic-dialects|pet-loader|c128-loader|nes-banking|petscii-strings|all) ;;
		*)
			echo "unknown chunk: $chunk" >&2
			usage
			exit 2
			;;
	esac
done

selected() {
	local wanted="$1" chunk
	for chunk in "${CHUNKS[@]}"; do
		[ "$chunk" = all ] || [ "$chunk" = "$wanted" ] && return 0
	done
	return 1
}

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

generate() {
	local generator="$1" destination="$2"
	"$PYTHON" "$SCRIPT_DIR/$generator" "$destination" || {
		echo "FAIL: $generator" >&2
		exit 1
	}
}

if selected c64-banking; then generate mkbanktest.py "$WORK/prg"; fi
if selected c64-loader; then
	generate mkromtest.py "$WORK/prg"
	generate mkprgloadtest.py "$WORK/prg"
fi
if selected c64-recovery; then
	generate mkemutest.py "$WORK/prg"
	generate mkdecrypttest.py "$WORK/prg"
	generate mkrollingtest.py "$WORK/prg"
	generate mksuspecttest.py "$WORK/prg"
fi
if selected basic-petscii && ! selected basic-dialects; then
	generate mkbasictest.py "$WORK/prg"
fi
if selected basic-dialects; then
	generate mkbasictest.py "$WORK/prg"
	generate mkdialectbasictest.py "$WORK/prg"
fi
if selected pet-loader; then generate mkpettest.py "$WORK/prg"; fi
if selected c128-loader; then generate mkc128test.py "$WORK/prg"; fi
if selected nes-banking; then generate mknesbanktest.py "$WORK/nes"; fi
if selected petscii-strings; then generate mkpetsciistringtest.py "$WORK/prg"; fi

# Imports $2 (a .prg or .nes fixture) via $3 (the loader name), runs VerifyBankTest.java,
# extracts the normalized dump, and check|bless's it against expected/$1.dump.
run_one() {
	local name="$1" fixture="$2" loader="$3" extra="${4:-}"
	local proj="$WORK/proj_$name"
	mkdir -p "$proj"
	local log="$WORK/$name.log"
	echo "== $name: importing $(basename "$fixture") via analyzeHeadless ($loader) =="
	# $extra is intentionally unquoted so multi-token loader args (e.g.
	# "-loader-kernalRom <path>") word-split into separate arguments.
	"$GHIDRA_HEADLESS" "$(native "$proj")" headless \
		-import "$(native "$fixture")" \
		-loader "$loader" \
		$extra \
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

if selected c64-banking; then
	for name in banktest banktest2 banktest3 banktest4; do
		run_one "$name" "$WORK/prg/$name.prg" C64PrgLoader
	done
fi

if selected basic-petscii && ! selected basic-dialects; then
	run_one c64basictest "$WORK/prg/c64basictest.prg" C64PrgLoader
fi

if selected basic-dialects; then
	# Keep the broad BASIC 2 fixture in this cross-dialect chunk, then prove the
	# same token ranges select BASIC 2, 4, and 7 semantics per machine.
	run_one c64basictest "$WORK/prg/c64basictest.prg" C64PrgLoader
	run_one c64basic2tokentest "$WORK/prg/c64basic2tokentest.prg" C64PrgLoader
	run_one c64basicoverflowtest "$WORK/prg/c64basicoverflowtest.prg" C64PrgLoader
	run_one petbasic4test "$WORK/prg/petbasic4test.prg" PetPrgLoader
	run_one c128basic7test "$WORK/prg/c128basic7test.prg" C128PrgLoader
fi

if selected pet-loader; then
	run_one pet4032test "$WORK/prg/pet4032test.prg" PetPrgLoader \
		"-loader-basicRom $(native "$WORK/prg/pet-basic.bin") -loader-editorRom $(native "$WORK/prg/pet-editor.bin") -loader-kernalRom $(native "$WORK/prg/pet-kernal.bin")"
fi

if selected c128-loader; then
	run_one c128nativebasic7test "$WORK/prg/c128nativebasic7test.prg" C128PrgLoader \
		"-loader-basicLoRom $(native "$WORK/prg/c128-basic-lo.bin") -loader-basicHiRom $(native "$WORK/prg/c128-basic-hi.bin") -loader-editorRom $(native "$WORK/prg/c128-editor.bin") -loader-kernalRom $(native "$WORK/prg/c128-kernal.bin")"
fi

if selected c64-recovery; then
	run_one emurecoverytest "$WORK/prg/emurecoverytest.prg" C64PrgLoader
	run_one decryptloop "$WORK/prg/decryptloop.prg" C64PrgLoader
	run_one rollingdecrypt "$WORK/prg/rollingdecrypt.prg" C64PrgLoader
	run_one suspectdecrypt "$WORK/prg/suspectdecrypt.prg" C64PrgLoader
fi

if selected c64-loader; then
	# Arbitrary-address PRG placement (grm-dvx): base RAM, RAM beneath the three
	# banked windows, 16-bit wrapping through P6510, and base-space emulation at $C000.
	run_one prgplacementtest "$WORK/prg/prgplacementtest.prg" C64PrgLoader
	run_one prgwraptest "$WORK/prg/prgwraptest.prg" C64PrgLoader
	run_one c000emutest "$WORK/prg/c000emutest.prg" C64PrgLoader

	# ROM loading (bead grm-mbm): import with synthetic ROM paths via the loaders'
	# command-line options (-loader-<arg>), asserting the ROM blocks come back
	# initialized. Exercises the same command-line option path a headless user would use.
	run_one romload "$WORK/prg/romload.prg" C64PrgLoader \
		"-loader-kernalRom $(native "$WORK/prg/kernal.bin") -loader-basicRom $(native "$WORK/prg/basic.bin") -loader-chargenRom $(native "$WORK/prg/chargen.bin")"

	# Symbol-set toggle (bead grm-zlj): import with the basic-zeropage checkbox on (a
	# default-off set) and assert it -- and only it -- was applied. Reuses any valid C64 PRG.
	cp -f "$WORK/prg/romload.prg" "$WORK/prg/symtoggle.prg"
	run_one symtoggle "$WORK/prg/symtoggle.prg" C64PrgLoader \
		"-loader-symbols-basic-zeropage true"
fi

if selected nes-banking; then
	run_one nesbanktest "$WORK/nes/nesbanktest.nes" NesRomLoader
	run_one nesbanktest2 "$WORK/nes/nesbanktest2.nes" NesRomLoader
	run_one nesmodetest "$WORK/nes/nesmodetest.nes" NesRomLoader
	run_one nesmmc3test "$WORK/nes/nesmmc3test.nes" NesRomLoader
	run_one nesmmc3test2 "$WORK/nes/nesmmc3test2.nes" NesRomLoader
	run_one nesserialtest "$WORK/nes/nesserialtest.nes" NesRomLoader
	run_one nesmmc1test "$WORK/nes/nesmmc1test.nes" NesRomLoader
fi

if selected petscii-strings; then
	run_one petsciistringtest "$WORK/prg/petsciistringtest.prg" C64PrgLoader
fi

if [ $fail -ne 0 ]; then
	echo "SUITE FAILED (work dir kept for inspection: $WORK)"
	exit 1
fi
rm -rf "$WORK"
echo "SUITE OK ($MODE)"
