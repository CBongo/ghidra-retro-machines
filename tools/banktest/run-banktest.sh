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
# Default headless path derives from gradle.properties' ghidraTargetVersion (single source of
# truth for the targeted Ghidra version, bead grm-9r7); GHIDRA_HEADLESS still overrides.
GRM_TARGET_VERSION="$(sed -n 's/^ghidraTargetVersion=//p' "$SCRIPT_DIR/../../gradle.properties")"
GHIDRA_HEADLESS="${GHIDRA_HEADLESS:-D:/ghidra_${GRM_TARGET_VERSION}_PUBLIC/support/analyzeHeadless.bat}"

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

# --- candidate-dump cache (bead grm-lne) --------------------------------
# The review-then-bless loop runs `check` (imports every fixture and diffs its
# dump against the golden) and then `bless` (which otherwise re-imports every
# fixture just to recapture the identical dump). analyzeHeadless import is the
# expensive step, so `check` stashes each freshly produced dump in a
# content-addressed cache and `bless` reuses it -- but ONLY when the cache key
# still matches the current inputs, so a stale candidate is never blessed.
#
# The key folds in everything that can change a dump: the fixture bytes, the
# loader name, the loader options (each existing-file argument replaced by its
# own hash so a volatile per-run mktemp path does not perturb the key), the
# VerifyBankTest dump script, and the installed extension's identity. If that
# identity cannot be established (run standalone against the shared %APPDATA%
# install with no isolated Extensions tree) or sha256sum/unzip are unavailable,
# caching is disabled and bless re-imports as before -- correctness over speed.
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CACHE_DIR="$REPO_ROOT/build/banktest-cache"

ext_identity() {
	# Content fingerprint of the installed extension jar(s), or non-zero if it
	# cannot be determined (=> caching disabled). NOT a file mtime/stamp: gradle
	# rewrites the dist zip on every build (new timestamps, identical bytecode),
	# so an mtime-based id never matches across a check->bless pair. unzip -v's
	# CRC-32 column depends only on entry content, so hashing the sorted
	# (CRC, name) pairs across the installed Extensions jars yields an id that is
	# stable across a no-op rebuild yet changes the moment any compiled class or
	# bundled data file changes.
	local base="${BANKTEST_SETTINGS_BASE:-}" jars out
	[ -n "$base" ] || return 1
	command -v unzip >/dev/null 2>&1 || return 1
	jars="$(find "$base" -type f -name '*.jar' -path '*/Extensions/*' 2>/dev/null | LC_ALL=C sort)"
	[ -n "$jars" ] || return 1
	out="$(printf '%s\n' "$jars" | while IFS= read -r j; do
		unzip -v "$j" 2>/dev/null | awk '$7 ~ /^[0-9a-fA-F]{8}$/ {print $7, $NF}'
	done | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
	[ -n "$out" ] || return 1
	printf '%s' "$out"
}
# Compute the extension identity once; empty => caching disabled for this run.
EXT_ID="$(ext_identity)" || EXT_ID=""

normalize_opts() {
	# Echo the loader-opts string with each existing-file argument replaced by
	# its sha256, so ROM-content changes invalidate the key but the volatile
	# mktemp path prefix does not. $1 is intentionally word-split like $extra.
	local out="" tok
	for tok in $1; do
		if [ -f "$tok" ]; then
			out="$out $(sha256sum "$tok" | cut -d' ' -f1)"
		else
			out="$out $tok"
		fi
	done
	printf '%s' "$out"
}

cache_key() {
	# args: fixture loader extra hargs  ->  sha256 key on stdout, or empty if disabled
	local fixture="$1" loader="$2" extra="$3" hargs="${4:-}"
	command -v sha256sum >/dev/null 2>&1 || { printf ''; return 0; }
	[ -n "$EXT_ID" ] || { printf ''; return 0; }
	{
		printf 'fixture:'; sha256sum "$fixture" | cut -d' ' -f1
		printf 'loader:%s\n' "$loader"
		printf 'opts:%s\n' "$(normalize_opts "$extra")"
		printf 'dumpscript:'; sha256sum "$SCRIPT_DIR/VerifyBankTest.java" | cut -d' ' -f1
		printf 'ext:%s\n' "$EXT_ID"
		# Only fixtures that pass extra headless args run one of the repo's ghidra_scripts/
		# scripts (via the installed extension), so fold those inputs in ONLY for them -- an
		# unconditional term would invalidate every other fixture's cached candidate on any
		# script edit. They need a term of their own because EXT_ID fingerprints the installed
		# *.jar entries only, and a ghidra_scripts/*.java file ships beside the jar, not in it.
		if [ -n "$hargs" ]; then
			printf 'hargs:%s\n' "$hargs"
			printf 'repo_scripts:'
			cat "$REPO_ROOT"/ghidra_scripts/*.java 2>/dev/null | sha256sum | cut -d' ' -f1
		fi
	} | sha256sum | cut -d' ' -f1
}

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
	# copybankedrom needs kernal.bin, which mkromtest.py generates. Only the c64-loader branch
	# above asks for it, so this chunk would fail when selected on its own; generate is
	# idempotent, so selecting both chunks simply runs it twice.
	generate mkromtest.py "$WORK/prg"
	generate mkemutest.py "$WORK/prg"
	generate mkdecrypttest.py "$WORK/prg"
	generate mkrollingtest.py "$WORK/prg"
	generate mksuspecttest.py "$WORK/prg"
	generate mkcopytest.py "$WORK/prg"
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
if selected nes-banking; then
	generate mknesbanktest.py "$WORK/nes"
	generate mknescopytest.py "$WORK/nes"
fi
if selected petscii-strings; then generate mkpetsciistringtest.py "$WORK/prg"; fi

# Imports $2 (a .prg or .nes fixture) via $3 (the loader name), runs VerifyBankTest.java,
# extracts the normalized dump, and check|bless's it against expected/$1.dump.
#
#   run_one <name> <fixture> <Loader> ["extra loader opts"] ["extra headless args"]
#
# $4 carries loader options (-loader-xxx ...); $5 carries analyzeHeadless arguments that are
# NOT loader options -- today only "-preScript <script> <args...>", which is how the manual
# run-from-elsewhere front-end (grm-1.7.1.1) gets exercised. They are separate parameters
# because normalize_opts hashes $4's file arguments for the candidate cache, which is
# meaningless (and would mangle key:value script args) for $5.
run_one() {
	local name="$1" fixture="$2" loader="$3" extra="${4:-}" hargs="${5:-}"
	local key cached
	key="$(cache_key "$fixture" "$loader" "$extra" "$hargs")"
	cached="$CACHE_DIR/$key.dump"

	# bless fast path: a prior check already produced the exact candidate for
	# these inputs -- reuse it (reprint its criteria, show the golden diff) and
	# skip the expensive re-import. Mirrors the non-cache bless below: copy the
	# candidate regardless, but flag the suite if its cached criteria failed.
	if [ "$MODE" = bless ] && [ -n "$key" ] && [ -f "$cached" ]; then
		echo "== $name: reusing cached candidate from prior check (no re-import) =="
		[ -f "$CACHE_DIR/$key.crit" ] && cat "$CACHE_DIR/$key.crit"
		mkdir -p "$EXPECTED_DIR"
		if [ -f "$EXPECTED_DIR/$name.dump" ]; then
			diff -u <(tr -d '\r' <"$EXPECTED_DIR/$name.dump") "$cached" \
				&& echo "no change vs golden: $name"
		else
			echo "no existing golden for $name -- creating it"
		fi
		cp "$cached" "$EXPECTED_DIR/$name.dump"
		echo "blessed (from cache) $EXPECTED_DIR/$name.dump"
		if [ -f "$CACHE_DIR/$key.crit" ] && ! grep -q '^SUITE PASS$' "$CACHE_DIR/$key.crit"; then
			echo "FAIL: cached criteria did not pass for $name"
			fail=1
		fi
		return
	fi

	local proj="$WORK/proj_$name"
	mkdir -p "$proj"
	local log="$WORK/$name.log"
	echo "== $name: importing $(basename "$fixture") via analyzeHeadless ($loader) =="
	# $extra and $hargs are intentionally unquoted so multi-token arguments (e.g.
	# "-loader-kernalRom <path>", "-preScript X.java k:v") word-split into separate arguments.
	#
	# -scriptPath names ONLY this harness dir, deliberately. The repo's own ghidra_scripts/ is
	# not added: HeadlessOptions.setScriptDirectories appends the install's default script
	# directories (GhidraScriptUtil's Application.findModuleSubDirectories("ghidra_scripts")),
	# and build-and-test.sh has already installed the extension -- ghidra_scripts and all --
	# into the isolated Ghidra home, so a shipped script is found there as the SHIPPED artifact.
	# That is also the only workable form: -scriptPath's ';'-separated list
	# (HeadlessOptions.java:266-269) cannot survive analyzeHeadless.bat, which re-tokenizes its
	# arguments and splits a quoted "path1;path2" back into two ("Bad argument: <path2>").
	"$GHIDRA_HEADLESS" "$(native "$proj")" headless \
		-import "$(native "$fixture")" \
		-loader "$loader" \
		$extra \
		$hargs \
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

	# Stash this valid candidate (and its criteria verdict) so a follow-up bless
	# can reuse it without re-importing. Keyed by inputs, so a later
	# rebuild/edit misses and forces a fresh import.
	if [ -n "$key" ]; then
		mkdir -p "$CACHE_DIR"
		cp "$WORK/$name.dump" "$cached"
		grep -E '^(CRITERION |SUITE (PASS|FAIL))' "$stripped" >"$CACHE_DIR/$key.crit" || true
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
	run_one copyloop "$WORK/prg/copyloop.prg" C64PrgLoader
	run_one copydata "$WORK/prg/copydata.prg" C64PrgLoader
	run_one copyoverlay "$WORK/prg/copyoverlay.prg" C64PrgLoader

	# grm-bqs: a copy loop landing UNDER the KERNAL window. The base-space block at $E000 is
	# the window's home occupant (KERNAL), but the write reaches RAM_E000, so the copy must be
	# carved inside that overlay and KERNAL must survive whole. Run BOTH ways -- no ROM and
	# ROM supplied -- because the placement has to be identical either way: which occupant a
	# write reaches is a hardware fact, not a fallback for an uninitialized ROM block. That is
	# also what hid the bug, since a supplied dump made KERNAL initialized and refused the
	# carve for the wrong reason. Same copyhinttest/copyhintnorom pattern used below.
	run_one copybanked "$WORK/prg/copybanked.prg" C64PrgLoader
	cp -f "$WORK/prg/copybanked.prg" "$WORK/prg/copybankedrom.prg"
	run_one copybankedrom "$WORK/prg/copybankedrom.prg" C64PrgLoader \
		"-loader-kernalRom $(native "$WORK/prg/kernal.bin")"

	# grm-9a0: the mirror case -- a copy loop whose SOURCE is a banked, NON-HOME occupant (the
	# character ROM, banked in over $D000 by the fixture's own LDA #$33 / STA $01), with an
	# ordinary base-space RAM destination so only the read is banked. Run BOTH ways for the
	# opposite reason to copybanked above: here the two runs MUST DIFFER, and that difference is
	# the whole demonstration. With no chargen dump the source occupant is uninitialized, so
	# TransferMaterializer's gate 0 refuses and materializes nothing; with the dump supplied the
	# copy lands carrying the character ROM's own bytes. Before the fix the recognizer named the
	# base-space $D000 -- the IO home occupant -- in BOTH runs, so supplying the dump changed
	# nothing and the character ROM's bytes were never reached. chargen.bin comes from
	# mkromtest.py, already generated for this chunk above.
	run_one copybankedsrc "$WORK/prg/copybankedsrc.prg" C64PrgLoader
	cp -f "$WORK/prg/copybankedsrc.prg" "$WORK/prg/copybankedsrcrom.prg"
	run_one copybankedsrcrom "$WORK/prg/copybankedsrcrom.prg" C64PrgLoader \
		"-loader-chargenRom $(native "$WORK/prg/chargen.bin")"

	# The MANUAL run-from-elsewhere front-end (grm-1.7.1.1): the shipped
	# ghidra_scripts/RunFromElsewhereTransfer.java driven as a -preScript, which is the only
	# regression path the manual front-ends have (the GUI plugin is untestable here -- see
	# docs/testing.md). Deliberately reuses copyloop.prg rather than generating a fixture: its
	# $200E payload is a known 8 bytes and its $C000-$CFFF RAM block is uninitialized, so a
	# hand-specified $200E -> $C800 transfer exercises the same carve-in-place path with
	# arguments that came from a person instead of a recognizer. Copied to a distinct name
	# because VerifyBankTest dispatches on the program name (a file still called copyloop.prg
	# would take checkCopyLoop's branch), the same trick symtoggle uses.
	#
	# Running BEFORE auto-analysis also proves the two front-ends do not collide: the manual
	# COPY_c800 carve happens first, then CopyLoopAnalyzer carves COPY_c000 out of what is left
	# of RAM_C000.
	cp -f "$WORK/prg/copyloop.prg" "$WORK/prg/rfemanual.prg"
	run_one rfemanual "$WORK/prg/rfemanual.prg" C64PrgLoader "" \
		"-preScript RunFromElsewhereTransfer.java src:200e dst:c800 len:8 disassemble:false"
	# The script's own verdict line, which lives outside the dump markers so VerifyBankTest
	# cannot assert on it. Skipped when bless reused a cached candidate: that path runs no
	# import, so there is no fresh log to read.
	if [ -f "$WORK/rfemanual.log" ] &&
		! grep -q 'RFE placement IN_PLACE block COPY_c800' "$WORK/rfemanual.log"; then
		echo "FAIL: RunFromElsewhereTransfer did not report an in-place COPY_c800 placement"
		fail=1
	fi
fi

if selected c64-loader; then
	# Arbitrary-address PRG placement (grm-dvx): base RAM, RAM beneath the three
	# banked windows, 16-bit wrapping through P6510, and base-space emulation at $C000.
	run_one prgplacementtest "$WORK/prg/prgplacementtest.prg" C64PrgLoader
	run_one prgwraptest "$WORK/prg/prgwraptest.prg" C64PrgLoader
	run_one c000emutest "$WORK/prg/c000emutest.prg" C64PrgLoader

	# grm-z15.2: 0x101-byte payload at $FF00 wraps 1 byte to $0000, straddling the
	# P6510 R6510 struct's memory-block boundary (DDR initialized, PORT not).
	run_one prgstraddletest "$WORK/prg/prgstraddletest.prg" C64PrgLoader

	# grm-z15.1: entry point in a non-executable block, and a zero-payload PRG.
	run_one prgentrytest "$WORK/prg/prgentrytest.prg" C64PrgLoader
	# A zero-payload PRG places no bytes anywhere, so with no ROM images supplied the
	# whole memory map would stay uninitialized and analyzeHeadless refuses to import
	# ("No memory blocks were defined") before VerifyBankTest ever runs. Supply the
	# same synthetic ROMs romload.prg uses so there is initialized memory to import,
	# while still exercising the zero-payload PRG placement path under test.
	run_one prgemptytest "$WORK/prg/prgemptytest.prg" C64PrgLoader \
		"-loader-kernalRom $(native "$WORK/prg/kernal.bin") -loader-basicRom $(native "$WORK/prg/basic.bin") -loader-chargenRom $(native "$WORK/prg/chargen.bin")"

	# ROM loading (bead grm-mbm): import with synthetic ROM paths via the loaders'
	# command-line options (-loader-<arg>), asserting the ROM blocks come back
	# initialized. Exercises the same command-line option path a headless user would use.
	run_one romload "$WORK/prg/romload.prg" C64PrgLoader \
		"-loader-kernalRom $(native "$WORK/prg/kernal.bin") -loader-basicRom $(native "$WORK/prg/basic.bin") -loader-chargenRom $(native "$WORK/prg/chargen.bin")"

	# Descriptor copied_from boot-copy hint (bead grm-1.7.1.2): machines/c64.yaml declares
	# CHRGET as 0x18 bytes of KERNAL $E3A2 copied to $0073. With the synthetic KERNAL supplied
	# the hint must materialize in the base space holding $A2..$B9; with NO ROM option the
	# directive must be ignored outright (no block, no overlay fallback) -- the ROM-gated rule
	# of docs/smc-inplace-vs-overlay.md section 6. Reuses romload.prg as an ordinary C64 PRG.
	cp -f "$WORK/prg/romload.prg" "$WORK/prg/copyhinttest.prg"
	run_one copyhinttest "$WORK/prg/copyhinttest.prg" C64PrgLoader \
		"-loader-kernalRom $(native "$WORK/prg/kernal.bin")"
	cp -f "$WORK/prg/romload.prg" "$WORK/prg/copyhintnorom.prg"
	run_one copyhintnorom "$WORK/prg/copyhintnorom.prg" C64PrgLoader

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
	run_one nesmmc1overridetest "$WORK/nes/nesmmc1overridetest.nes" NesRomLoader \
		"-loader-placement W8000:5"
	run_one nesbandaitest "$WORK/nes/nesbandaitest.nes" NesRomLoader

	# grm-1.7.6: CopyLoopAnalyzer is gated on the descriptor + a 6502/6510 language, not on
	# the C64 loader, so it fires on NES ROMs too. This is the only fixture where the copy
	# loop runs from a bank overlay and stores into base-space PRG RAM -- i.e. the only
	# coverage of that widened gate, and the only fixture where a recognized copy's
	# destination has to cross out of an overlay space to be carved in place.
	run_one nescopytest "$WORK/nes/nescopytest.nes" NesRomLoader
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
