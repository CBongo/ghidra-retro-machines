#!/usr/bin/env bash
# C64 + C128 + NES banking-analyzer regression suite driver (bead grm-wzl, extended
# to NES by grm-5tl.17).
#
# Usage: run-banktest.sh [check|bless] [--force-criteria] [--no-build] [chunk ...]
#
#   check (default)  Generate the test PRGs, import each with analyzeHeadless
#                    using the C64PrgLoader, run VerifyBankTest.java, and fail
#                    if any criterion fails or the normalized behavior dump
#                    differs from the golden copies in expected/.
#   bless            Same run, but (re)capture the dumps into expected/ --
#                    EXCEPT for a fixture whose criteria failed, which is
#                    refused and left byte-identical (bead grm-aqi).
#   --force-criteria bless a fixture even though its criteria failed. Only
#                    meaningful with bless; reports every row it forced.
#   --no-build       skip the pre-flight build/install (see GRM_SKIP_BUILD below).
#
# Chunks (default: all):
#   c64-banking   banktest through banktest4
#   c64-loader    arbitrary-address PRGs, ROM loading, and symbol toggle
#   c64-recovery  emulation and decrypt/recovery fixtures
#   basic-petscii c64basictest
#   basic-dialects PET BASIC 4/C128 BASIC 7 token dialects, plus C64 BASIC 2 regression
#   pet-loader    PET 4032 descriptor, PRG placement, IO types, and fixed ROM slots
#   snes-loader   SNES cartridge loader: header detection, static LoROM/HiROM layout,
#                 byte-mapped mirrors, IO typing, and the reset entry point
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
#                            by build-and-test.sh. Left unset, this script now
#                            DEFAULTS to the same isolated tree (grm-4t2d) --
#                            see the fallback call below for why that changed.
#   GRM_SHARED_GHIDRA_INSTALL=1
#                           opt out of that default and read the shared
#                            %APPDATA%/ghidra install instead -- the manual
#                            GUI-adjacent flow. Rarely what you want: results
#                            from it cannot be attributed to this working
#                            tree's source, because only tools/install-gui.ps1
#                            ever writes that install. Note BANKTEST_SETTINGS_BASE=
#                            (explicitly empty) does NOT do this; the fallback
#                            treats empty as unset, so this flag is the way.
#   GRM_SKIP_BUILD=1        same opt-out as --no-build, for scripted callers that would
#                            rather set an env var than thread a flag through. Either form
#                            is a no-op when GRM_EXTENSION_BUILT_THIS_RUN=1 is already set
#                            (build-and-test.sh just built for this run) -- see below.
#
# BUILD-BY-DEFAULT (bead grm-4t2d option (e)). This script used to analyze with whatever
# extension was already sitting in build/ghidra-home -- the fast inner loop, and therefore
# the script most likely to silently test a build older than the working tree (grm-mej.2,
# grm-mlp2/grm-7rct; see AGENTS.md and the which-script-builds-the-extension bd memory). It
# now runs `gradle stageExtensionForTests` (build.gradle) before analyzing, unless
# --no-build/GRM_SKIP_BUILD opts out, or GRM_EXTENSION_BUILT_THIS_RUN=1 says build-and-test.sh
# already did it for this run. The task has real Gradle inputs/outputs, so the common case
# (nothing relevant changed) costs a few seconds, not a full rebuild.
#
# Note: analyzeHeadless.bat chokes on parentheses in filenames -- keep every
# generated path free of them.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Establishes REPO_ROOT and GRM_TARGET_VERSION, and defines native() etc.
. "$SCRIPT_DIR/lib/common.sh"
EXPECTED_DIR="$SCRIPT_DIR/expected"
# Default headless path derives from gradle.properties' ghidraTargetVersion (single source of
# truth for the targeted Ghidra version, bead grm-9r7); GHIDRA_HEADLESS still overrides.
grm_default_headless

usage() {
	echo "usage: $0 [check|bless] [--force-criteria] [--no-build] [chunk ...]" >&2
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
		snes-loader \
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

# --force-criteria/--no-build are parsed as leading flags rather than chunk names so the
# chunk validator below keeps rejecting typos outright.
FORCE_CRITERIA=0
NO_BUILD=0
while [ $# -gt 0 ]; do
	case "$1" in
		--force-criteria) FORCE_CRITERIA=1; shift ;;
		--no-build) NO_BUILD=1; shift ;;
		--) shift; break ;;
		*) break ;;
	esac
done
# A check run writes no goldens, so the flag could only mislead there -- refuse
# it rather than accept a no-op that reads as "and bless the failures too".
if [ "$FORCE_CRITERIA" -eq 1 ] && [ "$MODE" != bless ]; then
	echo "--force-criteria is only meaningful with bless" >&2
	usage
	exit 2
fi
CHUNKS=("$@")
if [ ${#CHUNKS[@]} -eq 0 ]; then
	CHUNKS=(all)
fi

# Validate every requested chunk before creating a work directory or generating
# fixtures, so a typo cannot leave partial output behind.
for chunk in "${CHUNKS[@]}"; do
	case "$chunk" in
		c64-banking|c64-loader|c64-recovery|basic-petscii|basic-dialects|pet-loader|snes-loader|c128-loader|nes-banking|petscii-strings|all) ;;
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

# Relocate the user settings dir (and therefore the Extensions dir) to the per-worktree
# isolated install; see lib/common.sh for the mechanism.
#
# THIS SCRIPT USED TO BE THE ODD ONE OUT, and it was not a decision so much as a leftover
# (bead grm-4t2d, 2026-08-25). History: grm-r3h (71c043c) introduced the isolated install with
# this script as the MECHANISM and build-and-test.sh as the POLICY that sets the base, so
# "unset" here meant "the GUI flow" and was reasonable when build-and-test.sh was the only
# caller. Then realrom-test.sh (grm-zai) and measure-overlay-scale.sh (grm-6a7.3) arrived as
# STANDALONE runners, needed the isolated install, and grm-9mw (29ce77f) factored
# grm_settings_base_fallback out for them -- without revisiting this script, which kept its
# original behaviour by default rather than by intent.
#
# THE COST OF LEAVING IT: a direct `run-banktest.sh check <chunk>` read
# %APPDATA%/ghidra/<ver>/Extensions, the GUI install, which ONLY tools/install-gui.ps1 ever
# writes -- a manual step agents are told never to run. So nothing in the normal loop refreshed
# it and it drifted without bound, while every run still succeeded normally. Measured
# 2026-08-25: that install was three days stale and predated aea1021, which is what made
# grm-mlp2's "clean tree baseline" execute genuinely older analysis code, cost a three-point
# bisect, and produce a P1 filed against main in error (grm-7rct, retracted). Unlike a stale
# isolated install, nothing an agent may do could ever correct it.
#
# All four runners now default to the same isolated tree. The GUI-install flow is still
# reachable, but you have to ask for it.
if [ "${GRM_SHARED_GHIDRA_INSTALL:-}" = 1 ]; then
	echo "NOTE: GRM_SHARED_GHIDRA_INSTALL=1 -- reading the shared %APPDATA%/ghidra install" \
		"instead of the isolated build/ghidra-home tree. Only tools/install-gui.ps1 writes" \
		"that install, so this run cannot be attributed to the current source state." >&2
fi

# Build-by-default preflight (bead grm-4t2d option (e); see the header comment). Skipped
# outright when build-and-test.sh already built+staged for this run (GRM_EXTENSION_BUILT_THIS_RUN),
# so the two scripts never do the work twice, and skipped on request via --no-build/GRM_SKIP_BUILD.
# Only meaningful against the isolated install -- GRM_SHARED_GHIDRA_INSTALL=1 reads the
# %APPDATA% install that only tools/install-gui.ps1 ever writes, which this script must not build.
#
# THIS MUST RUN BEFORE grm_settings_base_fallback, AND THAT ORDER IS LOAD-BEARING (bug found
# 2026-08-29 while building ab-test.sh). The fallback decides whether to use the isolated install
# by testing whether build/ghidra-home EXISTS, and staging is what creates it. With the fallback
# first, a FRESH WORKTREE -- which by definition has no build/ dir yet -- took the shared %APPDATA%
# branch, and staging then installed into a build/ghidra-home the run was no longer pointed at:
# the extension under test got built correctly and then not used. That is the grm-4t2d hazard
# wearing a new hat. Under --no-build the directory may legitimately still be absent, and the
# fallback's NOTE is then correct rather than misleading.
EXT_NOTE_SUFFIX=""
if [ "${GRM_EXTENSION_BUILT_THIS_RUN:-}" = 1 ]; then
	: # build-and-test.sh already built+staged for this run; do not double-build
elif [ "${GRM_SHARED_GHIDRA_INSTALL:-}" = 1 ]; then
	EXT_NOTE_SUFFIX="shared-install"
elif [ "$NO_BUILD" -eq 1 ] || [ "${GRM_SKIP_BUILD:-}" = 1 ]; then
	EXT_NOTE_SUFFIX="no-build"
else
	grm_ensure_extension_staged
fi

if [ "${GRM_SHARED_GHIDRA_INSTALL:-}" != 1 ]; then
	grm_settings_base_fallback "${CHUNKS[0]}"
fi
grm_apply_settings_base

WORK="$(grm_work_dir banktest)"
fail=0
# Rows bless_candidate refused (criteria failed) or forced through anyway, so the
# end-of-run summary can name them instead of leaving them in the scrollback.
REFUSED=()
FORCED=()

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
CACHE_DIR="$REPO_ROOT/build/banktest-cache"

# ext_identity() lives in lib/common.sh (shared with realrom-test.sh).
# Compute the extension identity once; empty => caching disabled for this run.
EXT_ID="$(ext_identity)" || EXT_ID=""

# ANNOUNCE IT (bead grm-4t2d). This value was originally computed here only to key the cache,
# which is why the whole reason for the FIRST version of this note existed: the identity was
# there and stayed silent. Now that this script builds by default (see the header comment and
# EXT_NOTE_SUFFIX above), the note's job is to say WHICH of the three states applied, so a
# surprising result can be attributed correctly rather than blamed on a stale build that this
# run just fixed -- or credited to a rebuild that --no-build/GRM_SKIP_BUILD deliberately skipped.
case "${GRM_EXTENSION_BUILT_THIS_RUN:-}/$EXT_NOTE_SUFFIX" in
	1/*)
		grm_installed_extension_note "$EXT_ID" \
			"(built and installed by build-and-test.sh for this run, so it matches this tree.)"
		;;
	*/shared-install)
		grm_installed_extension_note "$EXT_ID" \
			"(GRM_SHARED_GHIDRA_INSTALL=1 -- this run does NOT build; it reads the shared" \
			" %APPDATA%/ghidra install, which only tools/install-gui.ps1 ever writes, so it" \
			" cannot be attributed to the current source state.)"
		;;
	*/no-build)
		grm_installed_extension_note "$EXT_ID" \
			"(--no-build/GRM_SKIP_BUILD skipped the pre-flight build -- this script analyzed" \
			" with whatever was already installed. A surprising result may be a stale" \
			" extension rather than your change; re-run without that flag/var to rebuild" \
			" first, and treat any baseline or bisect taken through this run as unproven.)"
		;;
	*)
		grm_installed_extension_note "$EXT_ID" \
			"(built and staged by THIS run via 'gradle stageExtensionForTests' before" \
			" analyzing, so it matches this working tree.)"
		;;
esac

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
	# args: fixture loader extra hargs pargs  ->  sha256 key on stdout, or empty if disabled
	local fixture="$1" loader="$2" extra="$3" hargs="${4:-}" pargs="${5:-}"
	command -v sha256sum >/dev/null 2>&1 || { printf ''; return 0; }
	[ -n "$EXT_ID" ] || { printf ''; return 0; }
	{
		printf 'fixture:'; sha256sum "$fixture" | cut -d' ' -f1
		printf 'loader:%s\n' "$loader"
		printf 'opts:%s\n' "$(normalize_opts "$extra")"
		printf 'dumpscript:'; sha256sum "$SCRIPT_DIR/VerifyBankTest.java" | cut -d' ' -f1
		printf 'ext:%s\n' "$EXT_ID"
		# Only fixtures that pass extra headless args run one of the repo's ghidra_scripts/
		# scripts (via the installed extension), or a tools/banktest/-local postScript of their
		# own (pargs), so fold those inputs in ONLY for them -- an unconditional term would
		# invalidate every other fixture's cached candidate on any script edit. The term
		# survives grm-9mw's move to the shared loose-inclusive ext_identity, which DOES now
		# cover the installed ghidra_scripts/*.java, because it hashes a different thing: the
		# SOURCE tree copy. Editing a script without rebuilding leaves EXT_ID untouched, so only
		# this term forces the conservative re-import.
		if [ -n "$hargs" ] || [ -n "$pargs" ]; then
			printf 'hargs:%s\n' "$hargs"
			printf 'pargs:%s\n' "$pargs"
			printf 'repo_scripts:'
			cat "$REPO_ROOT"/ghidra_scripts/*.java 2>/dev/null | sha256sum | cut -d' ' -f1
			# pargs names scripts that live in THIS directory, not ghidra_scripts/, and so are
			# covered by neither the repo_scripts term above nor dumpscript (which hashes only
			# VerifyBankTest.java) -- without a term of their own, an edit to one would be
			# invisible to the cache and a stale candidate would be served. Derived from the
			# pargs tokens rather than naming a script literally, so a future post-verify script
			# is covered the day it is added instead of the day someone remembers to edit this.
			# Silent on a token that names no file here (a script argument, or one not yet
			# created): a missing file must degrade to "no contribution", never break the key.
			for tok in $pargs; do
				case "$tok" in
				*.java)
					[ -f "$SCRIPT_DIR/$tok" ] || continue
					printf 'pargscript:%s:' "$tok"
					sha256sum "$SCRIPT_DIR/$tok" | cut -d' ' -f1
					;;
				esac
			done
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
if selected snes-loader; then generate mksnestest.py "$WORK/snes"; fi
if selected c128-loader; then generate mkc128test.py "$WORK/prg"; fi
if selected nes-banking; then
	generate mknesbanktest.py "$WORK/nes"
	generate mknescopytest.py "$WORK/nes"
fi
if selected petscii-strings; then generate mkpetsciistringtest.py "$WORK/prg"; fi

# The ENTIRE tail of a bless, shared by the cached fast path and the fresh-import
# path below (bead grm-aqi). Both used to carry their own copy of this, and the two
# drifted -- only the cached one showed the golden diff, and they flagged failed
# criteria on opposite sides of the copy. Anything a bless decides belongs here, so
# "cached and uncached behave the same" holds by construction rather than by review.
#
#   bless_candidate <name> <candidate-dump> <criteria-ok 0|1>
#
# The criteria verdict arrives as a plain flag because its SOURCE differs -- the
# cached path reads a stored .crit, the fresh path the live headless output -- while
# the decision made from it must not.
bless_candidate() {
	local name="$1" candidate="$2" crit_ok="$3"
	local golden="$EXPECTED_DIR/$name.dump"
	mkdir -p "$EXPECTED_DIR"

	# Print the diff BEFORE the gate: on a refusal this is what you would have
	# blessed, which is the thing worth seeing.
	if [ -f "$golden" ]; then
		diff -u <(tr -d '\r' <"$golden") "$candidate" \
			&& echo "no change vs golden: $name"
	else
		echo "no existing golden for $name -- creating it"
	fi

	# Fail closed. A criteria failure says the fixture's own asserted invariants are
	# violated -- a different claim from "the dump moved", which is what bless exists
	# to accept. It also leaves no trace in the artifact: the golden holds only the
	# BANKDUMP section, never the SUITE verdict, so a blessed-over-a-failure oracle is
	# indistinguishable from a good one afterwards and `git diff` cannot show it.
	if [ "$crit_ok" -ne 1 ] && [ "$FORCE_CRITERIA" -ne 1 ]; then
		echo "REFUSED: criteria failed for $name -- golden left unchanged"
		echo "         re-run with --force-criteria to bless it anyway"
		fail=1
		REFUSED+=("$name")
		return
	fi

	# Publish atomically (grm-aqi acceptance criteria; grm_atomic_publish shared with
	# grm-z34, lib/common.sh): write a sibling temp and rename, so an interrupted or
	# out-of-space run leaves the old oracle intact rather than a truncated one.
	if ! grm_atomic_publish "$candidate" "$golden"; then
		echo "FAIL: could not write $golden"
		fail=1
		return
	fi

	if [ "$crit_ok" -ne 1 ]; then
		echo "FORCED bless over failed criteria: $golden"
		FORCED+=("$name")
	else
		echo "blessed $golden"
	fi
}

# Imports $2 (a .prg or .nes fixture) via $3 (the loader name), runs VerifyBankTest.java,
# extracts the normalized dump, and check|bless's it against expected/$1.dump.
#
#   run_one <name> <fixture> <Loader> ["extra loader opts"] ["extra headless args"] ["post-verify args"]
#
# $4 carries loader options (-loader-xxx ...); $5 carries analyzeHeadless arguments that are
# NOT loader options -- today only "-preScript <script> <args...>", which is how the manual
# run-from-elsewhere front-end (grm-1.7.1.1) gets exercised. They are separate parameters
# because normalize_opts hashes $4's file arguments for the candidate cache, which is
# meaningless (and would mangle key:value script args) for $5.
#
# $6 carries analyzeHeadless arguments placed AFTER "-postScript VerifyBankTest.java" --
# today only "-postScript AssertBankOrderIndependence.java" (bead grm-q39f). This slot has to
# come after the dump, never before it: a postScript running here perturbs the program (it
# retracts and re-derives bank comments to test order-independence), and VerifyBankTest's dump
# is the golden-compared artifact -- it must observe the program exactly as every OTHER
# fixture's postScript chain leaves it, not as this one leaves it mid-perturbation.
run_one() {
	local name="$1" fixture="$2" loader="$3" extra="${4:-}" hargs="${5:-}" pargs="${6:-}"
	local key cached
	key="$(cache_key "$fixture" "$loader" "$extra" "$hargs" "$pargs")"
	cached="$CACHE_DIR/$key.dump"

	# bless fast path: a prior check already produced the exact candidate for
	# these inputs -- reuse it (reprint its criteria, show the golden diff) and
	# skip the expensive re-import. The bless itself is bless_candidate's, exactly
	# as on the fresh path, so the two cannot decide differently.
	if [ "$MODE" = bless ] && [ -n "$key" ] && [ -f "$cached" ]; then
		echo "== $name: reusing cached candidate from prior check (no re-import) =="
		[ -f "$CACHE_DIR/$key.crit" ] && cat "$CACHE_DIR/$key.crit"
		# A .crit that is missing (or empty, which is what the `|| true` on its
		# writer leaves when the run produced no verdict at all) counts as a
		# failure, not as a pass: the cache lives under build/ and is disposable,
		# so the cost of that is one re-check, and the alternative is blessing on
		# the strength of an absent record.
		local crit_ok=0
		grep -q '^SUITE PASS$' "$CACHE_DIR/$key.crit" 2>/dev/null && crit_ok=1
		bless_candidate "$name" "$cached" "$crit_ok"
		return
	fi

	local proj="$WORK/proj_$name"
	mkdir -p "$proj"
	local log="$WORK/$name.log"
	echo "== $name: importing $(basename "$fixture") via analyzeHeadless ($loader) =="
	# $extra, $hargs and $pargs are intentionally unquoted so multi-token arguments (e.g.
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
		$pargs \
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
	# Same shape the cached path replays from .crit (and the same regex that writes
	# it below), so a fresh bless and a cached one print the same thing -- including
	# the SUITE verdict line, which a fresh run used to swallow.
	grep -E '^(CRITERION |SUITE (PASS|FAIL))' "$stripped" || true

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
	local crit_ok=1
	if ! grep -q '^SUITE PASS$' "$stripped"; then
		crit_ok=0
		# In bless mode the verdict is bless_candidate's to act on (refuse, or force
		# and report). Flagging the suite here as well would make --force-criteria
		# unable to exit 0, i.e. an override that does not actually override.
		if [ "$MODE" != bless ]; then
			echo "FAIL: criteria failed for $name (log: $log)"
			fail=1
		fi
	fi

	# Stash this valid candidate (and its criteria verdict) so a follow-up bless
	# can reuse it without re-importing. Keyed by inputs, so a later
	# rebuild/edit misses and forces a fresh import.
	#
	# This cache lives under build/ and is disposable (a miss just costs one re-import), so
	# a write failure here (grm-z34) does not fail the run -- but it also must not leave a
	# torn/partial entry for a LATER run to read back as valid, nor silently claim success.
	# grm_atomic_publish[_stdin] publish via a sibling temp + rename, so a half-written
	# .dump/.crit never lands; on failure the entry is simply left absent (equivalent to a
	# cache miss) and reported, matching the existing "caching disabled" degrade path used
	# when EXT_ID/sha256sum/unzip are unavailable.
	if [ -n "$key" ]; then
		if ! mkdir -p "$CACHE_DIR"; then
			echo "NOTE: could not create $CACHE_DIR -- candidate cache disabled for $name" >&2
		elif ! grm_atomic_publish "$WORK/$name.dump" "$cached"; then
			echo "NOTE: could not write candidate cache for $name -- skipping" >&2
			rm -f "$cached"
		elif ! grep -E '^(CRITERION |SUITE (PASS|FAIL))' "$stripped" | grm_atomic_publish_stdin "$CACHE_DIR/$key.crit"; then
			echo "NOTE: could not write criteria cache for $name -- invalidating candidate cache entry" >&2
			rm -f "$cached" "$CACHE_DIR/$key.crit"
		fi
	fi

	if [ "$MODE" = bless ]; then
		bless_candidate "$name" "$WORK/$name.dump" "$crit_ok"
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

# Imports a fixture expected to be REJECTED by the loader (bead grm-gea): asserts the
# log both names the expected rejection reason and reports "Import failed", and that
# the per-fixture project holds no saved Program (no partial layout left behind by the
# aborted import). Unlike run_one there is no golden dump to diff -- a rejected import
# produces none -- so this has no bless mode; check and bless both just verify the same
# invariants.
#
# NOT exit-status-based: analyzeHeadless logs a per-file "ERROR REPORT" and an
# "Import failed for file:" line for a Loader.load() exception, but still exits 0 for
# the overall (multi-file-capable) run -- confirmed empirically against this exact
# fixture. The log content is therefore the only reliable signal.
#
# "No partial layout" is asserted by absence of a saved-domain-file (*.db) under the
# project directory: every project.rep/ directory carries its own bookkeeping
# (idata/~index.dat, project.prp, ...) whether or not anything was imported, but only a
# *committed* Program adds a numbered idata/<NN>/ folder holding a ~NNNNNNNN.db --
# confirmed empirically by diffing a successful project directory against this one.
run_reject() {
	local name="$1" fixture="$2" loader="$3" expect_msg="$4"
	local proj="$WORK/proj_$name"
	mkdir -p "$proj"
	local log="$WORK/$name.log"
	echo "== $name: importing $(basename "$fixture") via analyzeHeadless ($loader), expecting rejection =="
	"$GHIDRA_HEADLESS" "$(native "$proj")" headless \
		-import "$(native "$fixture")" \
		-loader "$loader" \
		>"$log" 2>&1

	if ! grep -qF "$expect_msg" "$log"; then
		echo "FAIL: $name log does not mention the expected rejection reason ($expect_msg) (log: $log)"
		fail=1
		return
	fi
	if ! grep -q '^ERROR REPORT: Import failed for file:' "$log"; then
		echo "FAIL: $name log does not report an import failure (log: $log)"
		fail=1
		return
	fi
	if find "$proj" -iname '*.db' 2>/dev/null | grep -q .; then
		echo "FAIL: $name left a partial Program layout (*.db found under $proj)"
		fail=1
		return
	fi
	echo "PASS: $name rejected as expected ($expect_msg), no partial layout"
}

# ANALYZER-OFF CENSUS (bead grm-8uaz). Imports the SAME image TWICE, once with "NES Bank
# State" left at its default (on) and once with it forced off via SetAnalyzerEnabled.java as a
# -preScript, both times running BaseSpaceCensus.java as a -postScript, and asserts the property
# that motivates this fixture: enabling our analyzer must never REDUCE how much base-space code
# Ghidra's OWN pipeline disassembles. grm-nems is why this exists and is not hypothetical: tmnt
# measured 3426 base-space instructions / 117 functions with the analyzer off and only 2006 / 67
# with it on, on a cold cache -- turning the analyzer ON made stock disassembly produce LESS
# code. Nothing anywhere asserted that until now.
#
#   run_census <name> <fixture> <Loader>
#
# Deliberately outside run_one's cache/candidate machinery and NOT gated on $MODE: there is no
# golden here to bless. run_one's cache and bless_candidate both exist to answer "did the
# recorded BEHAVIOR change since last time", which presupposes a recorded behavior worth
# preserving byte-for-byte -- exactly what this fixture does NOT have, on purpose. Its property
# is a pure INEQUALITY (on >= off) that must hold on every run, not a value to pin and diff
# against; a golden file would just be two numbers someone could "bless" past without ever
# looking at whether the inequality still holds, which is precisely the false-green failure mode
# grm-nems fell into (nothing was asserting this at all). So both "check" and "bless" invocations
# run the same two imports and the same assertion.
run_census() {
	local name="$1" fixture="$2" loader="$3"

	local proj_on="$WORK/proj_${name}_census_on"
	local proj_off="$WORK/proj_${name}_census_off"
	mkdir -p "$proj_on" "$proj_off"
	local log_on="$WORK/${name}_census_on.log"
	local log_off="$WORK/${name}_census_off.log"

	echo "== $name: census import #1/2 (analyzer ON, default) via analyzeHeadless ($loader) =="
	"$GHIDRA_HEADLESS" "$(native "$proj_on")" headless \
		-import "$(native "$fixture")" \
		-loader "$loader" \
		-scriptPath "$(native "$SCRIPT_DIR")" \
		-postScript BaseSpaceCensus.java \
		>"$log_on" 2>&1

	echo "== $name: census import #2/2 (analyzer OFF, via SetAnalyzerEnabled.java) via analyzeHeadless ($loader) =="
	"$GHIDRA_HEADLESS" "$(native "$proj_off")" headless \
		-import "$(native "$fixture")" \
		-loader "$loader" \
		-preScript SetAnalyzerEnabled.java analyzer:NES_Bank_State enabled:false \
		-scriptPath "$(native "$SCRIPT_DIR")" \
		-postScript BaseSpaceCensus.java \
		>"$log_off" 2>&1

	# Headless wraps script println output as "INFO  <Script.java>> <msg> (GhidraScript)" --
	# strip that the same way run_one does, so the CENSUS lines below can be grepped plainly.
	local stripped_on="$WORK/${name}_census_on.out"
	local stripped_off="$WORK/${name}_census_off.out"
	sed 's/\r$//; s/^.*\(BaseSpaceCensus\|SetAnalyzerEnabled\)\.java> //; s/ (GhidraScript)[[:space:]]*$//' \
		"$log_on" >"$stripped_on"
	sed 's/\r$//; s/^.*\(BaseSpaceCensus\|SetAnalyzerEnabled\)\.java> //; s/ (GhidraScript)[[:space:]]*$//' \
		"$log_off" >"$stripped_off"

	local analyzer_on analyzer_off instrs_on instrs_off functions_on functions_off
	analyzer_on="$(grep -m1 '^CENSUS analyzer ' "$stripped_on" | sed 's/^CENSUS analyzer //')"
	analyzer_off="$(grep -m1 '^CENSUS analyzer ' "$stripped_off" | sed 's/^CENSUS analyzer //')"
	instrs_on="$(grep -m1 '^CENSUS instrs.baseSpace ' "$stripped_on" | awk '{print $3}')"
	instrs_off="$(grep -m1 '^CENSUS instrs.baseSpace ' "$stripped_off" | awk '{print $3}')"
	functions_on="$(grep -m1 '^CENSUS functions.baseSpace ' "$stripped_on" | awk '{print $3}')"
	functions_off="$(grep -m1 '^CENSUS functions.baseSpace ' "$stripped_off" | awk '{print $3}')"

	# ANTI-VACUITY GUARD, and the reason it is essential rather than a nicety: if the two runs'
	# CENSUS analyzer lines do not actually differ (on-run "true", off-run "false"), then
	# SetAnalyzerEnabled.java did not resolve/flip the analyzer that run's census reported on,
	# and the comparison below is analyzer-on vs analyzer-on -- it PROVES NOTHING about the
	# property this fixture exists to check. A typo'd analyzer name would otherwise yield a
	# fixture that reports green forever while asserting nothing, exactly the failure mode this
	# whole bead is a response to.
	local verdict="OK"
	if [ -z "$instrs_on" ] || [ -z "$instrs_off" ] || [ -z "$functions_on" ] || [ -z "$functions_off" ]; then
		echo "FAIL: $name census produced no CENSUS lines on one or both legs (bead grm-8uaz) --" >&2
		echo "      on-run log: $log_on" >&2
		echo "      off-run log: $log_off" >&2
		fail=1
		verdict="VACUOUS"
	elif [ "$analyzer_on" != "NES Bank State=true" ] || [ "$analyzer_off" != "NES Bank State=false" ]; then
		echo "FAIL: $name census is VACUOUS (bead grm-8uaz) -- the on-run and off-run CENSUS" >&2
		echo "      analyzer lines do not show the expected true/false split, so this never" >&2
		echo "      compared analyzer-on against analyzer-off and proves nothing:" >&2
		echo "      on-run:  CENSUS analyzer $analyzer_on" >&2
		echo "      off-run: CENSUS analyzer $analyzer_off" >&2
		fail=1
		verdict="VACUOUS"
	elif [ "$instrs_on" -lt "$instrs_off" ] || [ "$functions_on" -lt "$functions_off" ]; then
		echo "FAIL: $name violates the analyzer-off census property (bead grm-8uaz) --" >&2
		echo "      enabling \"NES Bank State\" REDUCED how much base-space code Ghidra's own" >&2
		echo "      pipeline disassembled, which means the analyzer is perturbing Ghidra's" >&2
		echo "      disassembly pipeline rather than only annotating what it already found." >&2
		echo "      See bead grm-nems for the real-ROM incident this guards against." >&2
		fail=1
		verdict="VIOLATION"
	fi

	echo "CENSUS $name: instrs on=$instrs_on off=$instrs_off delta=$((instrs_on - instrs_off)); " \
		"functions on=$functions_on off=$functions_off delta=$((functions_on - functions_off)); " \
		"verdict=$verdict"
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

if selected snes-loader; then
	# The pair is deliberate: identical cartridges, one behind a 512-byte copier header, so a
	# regression in copier detection (which shifts every offset in the image) cannot hide.
	run_one snestest "$WORK/snes/snestest.smc" SnesRomLoader
	run_one snestestcopier "$WORK/snes/snestestcopier.smc" SnesRomLoader
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

	# grm-gea: exhaustive size/wrap-boundary coverage, following up grm-dvx. The
	# implementation already enforces every one of these; these fixtures close the
	# acceptance-test coverage gap identified in grm-dvx's final review.
	run_one prgnowraptest "$WORK/prg/prgnowraptest.prg" C64PrgLoader
	run_one prgwrap1test "$WORK/prg/prgwrap1test.prg" C64PrgLoader
	run_one prgfulltest "$WORK/prg/prgfulltest.prg" C64PrgLoader
	run_reject prgoverflowtest "$WORK/prg/prgoverflowtest.prg" C64PrgLoader \
		"16-bit CBM image may contain at most 65536 bytes"

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
	run_one nesuxhelpertest "$WORK/nes/nesuxhelpertest.nes" NesRomLoader

	# The 6502 SKIP-IDIOM front-end (bead grm-pfp): the shipped
	# ghidra_scripts/FixSkipInstructions.java driven as a -postScript, which is the only
	# regression path that script has -- and it MUST be a postScript, because the conflict it
	# repairs (a BIT whose operand bytes are themselves an instruction, so the offcut entry can
	# be neither disassembled nor made a function) does not exist until after disassembly.
	# See make_prg_skip()'s docstring for the fixture's three sites and what each one proves;
	# the shape is Wizards & Warriors (U) $BC05/$BC08.
	#
	# $5 is run_one's slot for non-loader headless arguments and is placed BEFORE
	# -postScript VerifyBankTest.java, so the repair happens first and VerifyBankTest observes
	# the repaired program. function:true is the default, stated explicitly because S6 asserts
	# on it: a recovered entry that is not a function belongs to no body and is never analyzed.
	#
	# $6 is run_one's slot for POST-verify headless arguments -- AssertBankOrderIndependence.java
	# (bead grm-q39f), which retracts this round's bank comments and re-derives them in one pass
	# to check that the result does not depend on having gone through the repair-then-reanalyze
	# sequence above. It runs after VerifyBankTest's dump on purpose (see run_one's docstring),
	# so it perturbs the program only after the golden-compared artifact has already been taken.
	run_one nesskiptest "$WORK/nes/nesskiptest.nes" NesRomLoader "" \
		"-postScript FixSkipInstructions.java function:true" \
		"-postScript AssertBankOrderIndependence.java"
	# The script's own verdict line, which lives outside the dump markers so VerifyBankTest
	# cannot assert on it -- and it is the only place the WEAK candidate is visible at all,
	# since not applying it leaves nothing in the program to observe. The counts pin the whole
	# classification: three carriers found, one per confidence tier, and only the two confident
	# ones acted on. Skipped when bless reused a cached candidate: that path runs no import, so
	# there is no fresh log to read.
	if [ -f "$WORK/nesskiptest.log" ] &&
		! grep -q 'SKIPFIX summary candidates=3 referenced=1 strong=1 weak=1 applied=2 failed=0' \
			"$WORK/nesskiptest.log"; then
		echo "FAIL: FixSkipInstructions did not report 3 candidates (1/1/1) with 2 applied"
		fail=1
	fi
	# grm-q39f: bank-comment order-independence. A program analyzed once over its final
	# structure must produce the same bank-comment set as one analyzed, perturbed by
	# FixSkipInstructions above, and re-analyzed -- which is what every fixture here actually
	# measures. AssertBankOrderIndependence.java's own verdict line is what proves it; a MATCH
	# means the two paths agreed, and anything else (including VACUOUS, which means the
	# comparison never actually exercised retraction) is a genuine finding, not noise. Same
	# cached-candidate caveat as the SKIPFIX check above: skipped when bless reused a cached
	# candidate, since that path runs no fresh import.
	if [ -f "$WORK/nesskiptest.log" ] &&
		! grep -q 'ORDERINDEP .* verdict=MATCH' "$WORK/nesskiptest.log"; then
		echo "FAIL: bank-comment order-independence check failed (bead grm-q39f) -- a program" >&2
		echo "      analyzed once over its final structure produced a DIFFERENT bank-comment" >&2
		echo "      set than one analyzed, perturbed, and re-analyzed. See the ORDERINDEP" >&2
		echo "      line(s) below for the verdict and any differing addresses:" >&2
		grep 'ORDERINDEP' "$WORK/nesskiptest.log" >&2 || true
		fail=1
	fi

	# grm-mej.2 increment 2 (Tier 3): bank-MIRROR derive/observe/consume/annotate/retarget
	# end-to-end, plus the SS2d requiresOnEntry guard -- see make_prg_mirrortest()'s docstring.
	run_one nesmirrortest "$WORK/nes/nesmirrortest.nes" NesRomLoader

	# grm-913: interrupt-entry bank state. An NMI/IRQ handler must NOT be seeded with
	# banking.initial_state fully known -- see make_prg_nmi()'s docstring for the megaman /
	# wizwarr shape it reproduces, and for the RESET-path control that keeps the fix from
	# reading as "weaken everything".
	run_one nesnmitest "$WORK/nes/nesnmitest.nes" NesRomLoader

	# grm-7e5o: an 8 KiB NROM PRG -- SMALLER than either 16 KiB window, so the image
	# mirrors four times across $8000-$FFFF. Synthetic stand-in for Galaxian (J) and
	# Controller Test Program (J), which cannot be shipped. See make_prg_nromsub().
	run_one nesnromsubtest "$WORK/nes/nesnromsubtest.nes" NesRomLoader

	run_one nesmodetest "$WORK/nes/nesmodetest.nes" NesRomLoader
	run_one nesmmc3test "$WORK/nes/nesmmc3test.nes" NesRomLoader
	run_one nesmmc3test2 "$WORK/nes/nesmmc3test2.nes" NesRomLoader
	run_one nesserialtest "$WORK/nes/nesserialtest.nes" NesRomLoader
	run_one nesmmc1test "$WORK/nes/nesmmc1test.nes" NesRomLoader
	run_one nesmmc1overridetest "$WORK/nes/nesmmc1overridetest.nes" NesRomLoader \
		"-loader-placement W8000:5"

	# grm-2dr increment 1: pass-through-wrapper recognition (a fallthrough-only function
	# whose last instruction lands exactly on a real bank-switch helper's entry). Separate
	# fixture from nesmmc1test so that one stays byte-identical -- see make_prg_wrapper()'s
	# docstring for the real-ROM shapes (Castlevania 2, TMNT) it models.
	run_one neswrappertest "$WORK/nes/neswrappertest.nes" NesRomLoader

	# grm-2dr increment 2: call-edge-wrapper recognition (a function that reaches its
	# helper by an interior JSR rather than by falling through). Separate again from
	# neswrappertest, so THAT golden staying byte-identical remains the proof increment 2
	# left increment 1 alone -- see make_prg_relay()'s docstring for blmaster's FUN_e61b.
	run_one nesrelaytest "$WORK/nes/nesrelaytest.nes" NesRomLoader

	run_one nesbandaitest "$WORK/nes/nesbandaitest.nes" NesRomLoader

	# grm-tas: MMC2 board (machines/nes-mmc2.yaml, iNES mapper 9) -- PRG bank select at
	# $A000-$AFFF plus the CHR0-register decoy proving the mechanism does not also claim
	# $B000-$BFFF. See make_prg_mmc2()'s docstring.
	run_one nesmmc2test "$WORK/nes/nesmmc2test.nes" NesRomLoader

	# grm-fxm: MMC5 board (machines/nes-mmc5.yaml, iNES mapper 5) -- the first shipped board
	# with NO register-less PRG window in ANY mode, and the only one whose registers live
	# outside the $8000-$FFFF PRG space entirely ($5100/$5114-$5117), so no PRG window needs
	# on_write: mechanism and there is no bus-conflict hazard. The fixture exercises both
	# axes: an ordinary within-mode bank switch, then a PRG MODE change (3 -> 0) whose
	# window set is a different shape, not just a different bank. See make_prg_mmc5().
	run_one nesmmc5test "$WORK/nes/nesmmc5test.nes" NesRomLoader

	# grm-p25h: MMC5 BANK-NUMBER WRAPPING (banking.bank_wrap: image). A bank register is
	# wider than any one cartridge decodes, so the hardware truncates and games rely on it
	# (rtk2 writes 96/97/126 to a 32-bank cart, meaning 0/1/30). Separate fixture from
	# nesmmc5test so that golden stays byte-identical and a moved line here cannot be
	# confused with the mode-change axis. See make_prg_mmc5wrap().
	run_one nesmmc5wraptest "$WORK/nes/nesmmc5wraptest.nes" NesRomLoader

	# grm-1.7.6: CopyLoopAnalyzer is gated on the descriptor + a 6502/6510 language, not on
	# the C64 loader, so it fires on NES ROMs too. This is the only fixture where the copy
	# loop runs from a bank overlay and stores into base-space PRG RAM -- i.e. the only
	# coverage of that widened gate, and the only fixture where a recognized copy's
	# destination has to cross out of an overlay space to be carved in place.
	run_one nescopytest "$WORK/nes/nescopytest.nes" NesRomLoader

	run_census nesbanktest "$WORK/nes/nesbanktest.nes" NesRomLoader
	# A second board, deliberately: on UxROM (nesbanktest) the loader places almost all PRG into
	# overlay windows, so base space holds only a handful of instructions and the inequality has
	# very little to bite on. MMC3 keeps a FIXED bank, which lands in base space -- the same shape
	# tmnt has, and tmnt is the row grm-nems measured the violation on.
	run_census nesmmc3test "$WORK/nes/nesmmc3test.nes" NesRomLoader
fi

if selected petscii-strings; then
	run_one petsciistringtest "$WORK/prg/petsciistringtest.prg" C64PrgLoader
fi

# Name the rows bless_candidate acted unusually on. A bless over a whole chunk
# scrolls, and both of these are exactly the lines you must not miss.
if [ ${#REFUSED[@]} -gt 0 ]; then
	echo "REFUSED to bless (criteria failed, goldens unchanged): ${REFUSED[*]}"
fi
if [ ${#FORCED[@]} -gt 0 ]; then
	echo "FORCED bless over failed criteria (--force-criteria): ${FORCED[*]}"
fi

if [ $fail -ne 0 ]; then
	echo "SUITE FAILED (work dir kept for inspection: $WORK)"
	exit 1
fi
rm -rf "$WORK"
echo "SUITE OK ($MODE)"
