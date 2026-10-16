#!/usr/bin/env bash
# OPTIONAL, hash-pinned real-ROM regression tier for the NES board descriptors and (bead
# grm-9nxj.15) the SNES cartridge loader.
# Deliberately NOT a run-banktest.sh chunk and NOT invoked by build-and-test.sh's
# default gate (whose `all` selects every chunk) -- real ROMs are copyrighted and
# user-supplied, so this lives alongside measure-overlay-scale.sh and is invoked by
# hand:
#
#   bash tools/banktest/realrom-test.sh check    [SET ...] [--only|--except <ids>] [--no-build] <romdir> ...
#   bash tools/banktest/realrom-test.sh bless    [SET ...] [--only|--except <ids>] [--no-build] <romdir> ...
#   bash tools/banktest/realrom-test.sh nominate <romdir> ...
#   bash tools/banktest/realrom-test.sh coverage [SET ...] [--only|--except <ids>] [--no-build]
#   bash tools/banktest/realrom-test.sh --list-sets
#
# SETS ARE NAMED POSITIONALLY, NOT SELECTED BY A FLAG PER PLATFORM (bead grm-ughg). This
# mirrors build-and-test.sh's chunk vocabulary, which is the in-repo precedent for exactly
# this problem, and it is the whole point of the refactor: adding a platform must add a ROW
# to realrom/sets.tsv, not a flag here, a `case` arm below and a paragraph in CLAUDE.md
# warning people which third of the tier the new flag covers.
#
#   core          the always-run floor -- five stable rows, ~40s (see sets.tsv)
#   nes-curated   the curated NES board-representative set
#   nes-gme       the NES game-music-extraction titles of interest
#   snes-cart     the SNES alt-board cartridge loader sample
#   nes | snes    PLATFORM GROUPS: every set declared for that platform
#   all           every set on every platform
#
# A bare `check` runs `core` (owner's ruling, 2026-09-06). It used to mean the curated NES
# set -- a third of the tier -- which is the specific misreading CLAUDE.md spent three
# paragraphs warning about. Naming something SMALLER and clearly labelled is the fix; every
# run still announces the sets it resolved and the rows they expanded to.
#
# THE PRE-grm-ughg FLAGS WERE REMOVED (grm-x4y1.5): `--gme`, `--all` and `--snes` are now
# ordinary unknown options (exit 2) whose error names the replacement:
#   --gme -> nes-gme   --all -> nes   --snes -> snes   (no flag -> core, no longer nes-curated)
# The bare word `all` spans every platform, because a word that does not mean what it says is
# what grm-ughg was filed about. Sets compose and are deduplicated by id, so naming several is
# safe.
#
# MULTI-PLATFORM RUNS ARE NOW POSSIBLE, and every per-platform parameter is resolved PER ROW
# from realrom/platforms.tsv rather than once per invocation: the ROM-dir environment
# variable, the file extensions the index scans, the extension of the temp copy the import
# sees (which reaches the golden as `REALROM program <id><ext>`), the Ghidra loader, the dump
# postScript, whether analysis runs at all, whether `nominate` is meaningful, whether the run
# refreshes the staleness stamp, and which build-and-test.sh chunk to name in an isolation
# hint. Adding a platform is a row in that table.
#
# A PLATFORM WHOSE ROM DIRS ARE UNAVAILABLE SKIPS LOUDLY RATHER THAN KILLING THE RUN, so
# `all` is usable by someone holding one platform's images. But if NO platform has any dirs
# the run still refuses outright with a nonzero exit -- this tier never reports a clean gate
# for something that did not execute (CLAUDE.md), and that guarantee is unchanged.
#
# The SNES rows still import with -noanalysis: they are LOADER rows -- block layout,
# byte-mapped mirrors, IO typing, entry point -- and nothing SnesRealRomDump.java emits
# depends on auto-analysis, so skipping it is both much faster on a 4-6 MB cartridge and
# immune to the analyzer jitter that makes two NES rows unstable. That is now the declared
# `import_args` field rather than an `if` in the middle of this script.
#
# `nominate` emits paste-ready manifest rows for a ROM dir -- hashing each dump, decoding its
# iNES mapper and resolving the claiming board -- and flags any mapper no shipped descriptor
# claims as a board gap. It needs no Ghidra install. It is NES-ONLY: it decodes iNES headers
# and resolves machines/nes-*.yaml, neither of which means anything for a SNES cartridge, so
# it refuses SNES sets rather than emitting garbage rows. Use the grm-9nxj.13 corpus survey
# (build-and-test.sh check snes-rom-corpus -> build/snes-rom-corpus/roms.tsv) to select and
# hash SNES candidates instead; that is what the current thirteen rows were drawn from.
#
# --only/--except take comma-separated manifest ids and select which rows the run
# considers at all. --except exists for the recurring case this tier actually hits: ONE title
# is held back at a known-good golden while every other title needs re-blessing, and blessing
# it would erase the record a bead depends on. megaman has twice been that title (grm-g73,
# grm-hum). Before these flags the only way to scope a bless was to stage the wanted ROMs into
# a separate directory, which is easy to get quietly wrong. An id that is not in the manifest
# is a hard ERROR, never a silent no-op: a typo in `--except megman` must not bless megaman.
# Filtered rows are omitted from the run and counted separately -- deliberately NOT reported as
# SKIP, which means "ROM absent".
#
# KNOWN-FAILING ROW -- read this before believing a megaman FAIL. TWO SEPARATE THINGS ail this
# row, and conflating them is how a real regression gets waved through:
#
#   1. JITTER (grm-g73). megaman is bistable: two identical imports of the same ROM against the
#      same build produce one of two dumps, differing ONLY in
#        REALROM count refs.intoOverlay     1704  <-> 1703
#        REALROM count instrs.inOverlay     7429  <-> 7431
#      moving in OPPOSITE directions. Measured over ten fresh imports (grm-g73, 2026-08-10):
#      8/2 in favour of the golden, so the row flaps PASS/FAIL at about a 20% rate on an
#      unchanged build. In all ten runs bankComments and warnings were CONSTANT and no sample.*
#      line moved -- count-line-only with no sample movement is this bead's own jitter criterion.
#
#   2. AN UNBLESSED REAL CHANGE (grm-ii6), not a stale golden and not jitter:
#        REALROM count bankComments          156  ->  157   (the new one is d571 bank -> 4)
#      grm-mej.2 increment 2 (ac77ee6) introduced it -- measured by rebuilding at ac77ee6^ and
#      at ac77ee6 and running this row against each. It is stable: 157 at three independently
#      built later states, including BOTH of megaman's jitter states, so it is orthogonal to
#      finding 1. Whether `d571 bank -> 4` is CORRECT is an open question on grm-ii6; do not
#      bless it until someone has read the ROM there.
#
# SO: DO NOT JUDGE THIS ROW BY A LINE WHITELIST. The old wording here ("if those two lines are
# the only diff it is grm-g73; any other line moving is real") would have called finding 2 a
# fresh regression, and a later attempt to widen the whitelist to include bankComments would
# have hidden a real behaviour change instead. A whitelist cannot tell those apart. Only an A/B
# across a genuine rebuild can:
#
#   git stash -u
#   bash tools/banktest/realrom-test.sh check --only megaman
#   ... then restore and re-run, and diff the two dumps.
#
# THE REBUILD USED TO BE A MANUAL STEP HERE, AND IT WAS THE WHOLE TEST (bead grm-4t2d option
# (e), 2026-08-26): this script now builds by DEFAULT (`gradle stageExtensionForTests`) before
# analyzing, so the git-stash dance above rebuilds itself on both sides -- there is no longer a
# manual "rebuild between sides" step to forget. Skipping it (the old failure mode) analyzed
# both sides with the same installed extension, returned byte-identical dumps, and read as "my
# change moved nothing" -- that is how ac77ee6 shipped a zero-movement claim that was wrong on
# two rows. Every run still prints the installed extension identity as a SAFETY NET, not the
# primary mechanism anymore: if it does not CHANGE between the two sides of an A/B, something
# is wrong with the rebuild (or you passed --no-build/GRM_SKIP_BUILD) -- throw the comparison
# away and find out why before trusting it. (`rm -rf build/realrom-cache` first if you are
# about to bless -- see grm-g73.)
#
# This harness deliberately does NOT retry or tolerate the delta -- a golden whose diff you can
# trust is the entire point of this tier, and hiding a known-noisy row would cost that for every
# other row too. See docs/testing.md's real-ROM section.
# Cause is grm-eyn: Ghidra over-reads several of this ROM's jump tables, and the resulting
# spurious computed-jump targets race the real instruction flow for the same bytes (6502
# alignment is 1, so both decodings are self-consistent). No configuration workaround exists.
# Diagnose with DeterminismProbe.java via REALROM_EXTRA_POSTSCRIPT, below.
#
# Each pinned title is identified by its whole-file SHA-256 in
# tools/banktest/realrom/manifest.tsv, so the harness validates against the exact
# known-good dump and cleanly SKIPs (never FAILs) when a ROM is absent or is a
# different/bad dump. For each manifest row whose hash is present in the supplied
# dir(s), it imports the ROM via analyzeHeadless + NesRomLoader with full analysis,
# runs RealRomDump.java, and diffs the normalized REALROM block against
# realrom/expected/<id>.dump (check) or regenerates it (bless). ROM binaries are never
# committed; the goldens (our derived, copyright-safe analysis metadata) are.
#
# BUILD-BY-DEFAULT (bead grm-4t2d option (e)). This script used to require a prior
#   bash tools/banktest/build-and-test.sh check nes-banking
# to populate build/ghidra-home, and analyzed with whatever was already there if you forgot
# -- the real-ROM tier being one of the two scripts people reach for most (see the header note
# above and AGENTS.md's "Only build-and-test.sh builds the extension" history). It now runs
# `gradle stageExtensionForTests` (build.gradle) itself before analyzing, so no prior
# build-and-test.sh run is required. Environment overrides mirror measure-overlay-scale.sh:
#   GHIDRA_HEADLESS         path to analyzeHeadless(.bat)
#   BANKTEST_SETTINGS_BASE  relocate Ghidra user-settings/Extensions dir (defaults to
#                            <repo>/build/ghidra-home)
#   GRM_ROM_DIR             default rom dir(s) if none given on the command line (NES sets)
#   GRM_SNES_ROM_DIR        the same, for the SNES sets. Separate on purpose: GRM_ROM_DIR stays
#                            NES-only, and both are read with identical semantics --
#                            space-separated dirs, each indexed at DEPTH 1 ONLY. A value
#                            containing ';' is split on ';' only, so a dir whose name has a
#                            space is written 'H:/a;H:/All NES Roms/USA' (grm-3rel).
#   GRM_BANKTEST_WORK       base dir for per-run work dirs (defaults to
#                            <repo>/build/banktest-work). A PASSING run deletes its work
#                            dir; a FAILING one keeps logs/dumps/diffs but not the ROM copies
#                            or proj_* dirs. Old kept dirs are pruned at the start of each
#                            run (GRM_WORK_KEEP_DAYS, default 7; GRM_WORK_KEEP_FAILURES,
#                            default 3 newest per tag) and stale cache entries too
#                            (GRM_CACHE_KEEP_DAYS, default 14) -- bead grm-uqhd. A dir
#                            named via REALROM_WORK_DIR is never deleted.
#   REALROM_WORK_DIR        use this exact dir instead of a fresh one
#   GRM_KEEP_PROJECT_DIR    base dir for --keep-project (defaults to
#                            <repo>/build/kept-projects/realrom)
#   GRM_SKIP_BUILD=1        same opt-out as --no-build (below), for scripted callers
#   GRM_REALROM_BATCH_SIZE  rows per analyzeHeadless JVM (bead grm-x4y1.3); --batch-size wins; 1 =
#                            one JVM per row. See the "batched imports" block above flush_batch.
#   GRM_REALROM_SOLO_RERUNS solo diagnostic reruns for a batched row that FAILs (bead grm-u7cy;
#                            default 3, minimum 1). See finish_row.
set -u

# realrom/ holds the two driver tables (bead grm-ughg) as well as the manifests and goldens.
# Resolved here, ABOVE the common.sh sourcing that establishes SCRIPT_DIR for everything else,
# because --list-sets must work with no Ghidra install, no ROM dirs and no git repo -- it is
# the thing you run when you do not know what to type yet.
REALROM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/realrom"
SETS_TSV="$REALROM_DIR/sets.tsv"
PLATFORMS_TSV="$REALROM_DIR/platforms.tsv"

# Rows per analyzeHeadless JVM (bead grm-x4y1.3). Measured 2026-10-14, check all (45 rows), all
# 45/45 PASS at every size, so every size's dumps are byte-identical to the per-row ones:
# size 1 537s, 5 409s, 10 387s, 20 376s, 45 368s. Past ~10 the curve is flat (the 45-row run
# only forms 3 batches anyway: grouping by platform/loader-opts flushes first), while a batch
# crash re-runs every row in it solo, so 20 trades the last ~2% of wall time for a smaller
# fallback. Precedence: --batch-size, then GRM_REALROM_BATCH_SIZE, then this.
GRM_REALROM_BATCH_SIZE_DEFAULT=20

# Solo diagnostic reruns of a batched row that FAILs (bead grm-u7cy). One was not enough: grm-pwuh
# (deadly_towers) passed its single solo rerun and was triaged for a day as a cross-program leak,
# while solo it was FAIL/FAIL/PASS -- one sample cannot tell "batch-dependent" from "flaky". Three
# samples, stopping early once a pass and a fail have both been seen. A row that passes solo
# rarely (deadly_towers with DeterminismProbe: 1 in 11) can still fail all three; the
# solo-vs-solo dump comparison in finish_row is what flags that case as nondeterministic.
GRM_REALROM_SOLO_RERUNS="${GRM_REALROM_SOLO_RERUNS:-3}"
if ! [[ "$GRM_REALROM_SOLO_RERUNS" =~ ^[1-9][0-9]*$ ]]; then
	echo "REALROM: GRM_REALROM_SOLO_RERUNS must be a positive integer, got '$GRM_REALROM_SOLO_RERUNS'" >&2
	exit 2
fi

USAGE="usage: $0 check|bless|nominate [SET ...] [--only <ids>|--except <ids>] [--no-build] [--keep-project] [--require-all] [--batch-size N] <romdir> ...
       $0 coverage [SET ...] [--only <ids>|--except <ids>] [--no-build]
       $0 --list-sets
       $0 ids [SET ...]

ids (bead grm-x4y1.5) is read-only and instant: it prints the manifest id of every row the named
SETs admit, one per line on stdout, and nothing else (no build, no ROM dirs, no staleness note).
ab-test.sh uses it to check --only ids against a set without re-parsing sets.tsv itself.

coverage (bead grm-eawl) is read-only: it imports nothing, needs no ROM dirs, and reports per
row whether build/realrom-cache holds an entry for the CURRENT extension build -- i.e. whether
the row has RAN at this build. It says nothing about whether the row passed. Like check it
stages the build first (so the build identity matches what a check would use) unless
--no-build/GRM_SKIP_BUILD is given. It never fails a run.

--require-all (check/bless, bead grm-x4y1.2) exits nonzero if ANY selected row was SKIPPED for want
of a ROM. Without it a run with skips exits 0 and prints: REALROM check: OK (PARTIAL: N skipped)

Every analyzeHeadless run has a timeout (200s + 90s per program; GRM_HEADLESS_TIMEOUT=S sets a flat
limit, 0 disables; GRM_HEADLESS_TIMEOUT_BASE / _PER_PROGRAM tune it). A timeout FAILs that row.

--batch-size N (check/bless, bead grm-x4y1.3; env GRM_REALROM_BATCH_SIZE, the flag wins; default
$GRM_REALROM_BATCH_SIZE_DEFAULT) imports up to N rows per analyzeHeadless JVM instead of one JVM per row, to pay JVM
startup once per batch. Imports stay serial inside the JVM. Only rows whose import is identical
apart from the file (same platform, same loader-opts column) share a batch. 1 = one JVM per row
(the pre-grm-x4y1.3 behaviour). A batch that crashes or times out is re-run row by row. A row whose
batched dump DIFFERS from its golden stays FAIL and is re-run solo as a diagnostic, up to
GRM_REALROM_SOLO_RERUNS (default 3) times, printing \"BATCH-DEPENDENT\" (every solo rerun passes: a
batch-sensitivity bug), \"FLAKY\" (solo reruns disagree: nondeterministic even alone) or \"genuine
diff\" (every one fails); bless refuses to bless a batched dump that a solo import does not reproduce. --keep-project forces size 1.

--keep-project (check/bless only; requires --only, bead grm-haj3) keeps each imported row's
analyzed Ghidra project instead of passing -deleteProject, at a FIXED path that the next
--keep-project run of the same row overwrites:
  build/kept-projects/realrom/<id>/headless.gpr     (base: GRM_KEEP_PROJECT_DIR)
That is the exact program the row's dump was taken from -- same loader, options, extension
build and decompiler -- so a follow-up tool (e.g. pyghidra-mcp --project-path) can be pointed
at it. It forces a real import: bless's cached-candidate shortcut is skipped. It changes
nothing about the dump, the golden comparison, or the candidate cache.

SETs are named positionally and compose (rows are deduplicated by id). With no SET,
'core' is used -- the always-run floor, NOT the whole tier. Run --list-sets for the
table, which is realrom/sets.tsv plus the platform groups derived from it."

# Reads one field of one row from a header-first TSV. Used for BOTH sets.tsv and
# platforms.tsv so the two cannot drift on quoting or on how a missing row is reported, and
# so a new column is readable by name rather than by position -- the manifests' own
# mapper/board columns are the cautionary tale here: positional reads are why nobody noticed
# for months that the driver parses them and never uses them.
# Prints nothing and returns 1 when the key is absent; callers decide whether that is fatal
# (an unknown set name) or normal (an optional column).
tsv_field() {
	local file="$1" key="$2" column="$3"
	awk -F'\t' -v key="$key" -v col="$column" '
		NR == 1 { for (i = 1; i <= NF; i++) if ($i == col) c = i; next }
		!/^#/ && NF && $1 == key { if (c) { print $c; found = 1 } exit }
		END { exit(found ? 0 : 1) }
	' "$file"
}

# Every value in one column, in file order, blank/comment/header rows skipped.
tsv_column() {
	local file="$1" column="$2"
	awk -F'\t' -v col="$column" '
		NR == 1 { for (i = 1; i <= NF; i++) if ($i == col) c = i; next }
		!/^#/ && NF && c { print $c }
	' "$file"
}

for f in "$SETS_TSV" "$PLATFORMS_TSV"; do
	[ -f "$f" ] || {
		echo "ERROR: missing $f -- this script is table-driven (bead grm-ughg)." >&2
		exit 2
	}
done

# --list-sets mirrors build-and-test.sh's --list-chunks, deliberately including the DERIVED
# platform groups: they are real names a caller may type, and a list that omitted them would
# send people back to reading this script, which is exactly what the vocabulary replaces.
if [ "${1:-}" = "--list-sets" ]; then
	[ "$#" -eq 1 ] || {
		echo "ERROR: --list-sets cannot be combined with other arguments" >&2
		exit 2
	}
	printf '%-14s %-6s %-6s %s\n' SET PLATFORM ROWS DESCRIPTION
	while IFS=$'\t' read -r set_name set_plat set_manifests set_rows set_desc; do
		case "$set_name" in ""|set|"#"*) continue ;; esac
		if [ "$set_rows" = '*' ]; then
			row_count=all
		else
			row_count="$(printf '%s' "$set_rows" | tr ',' '\n' | grep -c .)"
		fi
		printf '%-14s %-6s %-6s %s\n' "$set_name" "$set_plat" "$row_count" "$set_desc"
	done < <(tr -d '\r' < "$SETS_TSV")
	echo
	echo "platform groups -- every set declared for that platform:"
	while IFS= read -r p; do
		[ -n "$p" ] || continue
		printf '%-14s %-6s %-6s %s\n' "$p" "$p" "" \
			"all $p sets; ROM dirs from $(tsv_field "$PLATFORMS_TSV" "$p" rom_dir_env)"
	done < <(tsv_column "$PLATFORMS_TSV" platform)
	printf '%-14s %-6s %-6s %s\n' all "" "" "every set on every platform"
	echo
	echo "mode 'coverage [SET ...]': read-only; which of a set's rows have RAN at the current build"
	echo "(derived from build/realrom-cache; imports nothing, needs no ROM dirs; 'ran' != passed)."
	exit 0
fi

MODE="${1:-}"
case "$MODE" in
	check|bless|nominate|coverage|ids) shift ;;
	*)
		echo "$USAGE" >&2
		exit 2
		;;
esac

# REALROM_EXTRA_PRESCRIPT changes what ANALYSIS DOES, not merely what is reported afterwards --
# its reason for existing is SetAnalyzerEnabled.java, which turns an analyzer off (bead grm-8uaz's
# census, checking the property grm-nems violated). A dump produced that way describes a
# deliberately crippled analysis, so writing it into a golden would pin the wrong output and every
# later run would "pass" against it. There is no legitimate bless in that state, so refuse rather
# than rely on the operator remembering. realrom_cache_key carries the same value, so the two
# states cannot share a cached candidate either.
if [ "$MODE" = bless ] && [ -n "${REALROM_EXTRA_PRESCRIPT:-}" ]; then
	echo "REALROM: refusing to bless with REALROM_EXTRA_PRESCRIPT set." >&2
	echo "  A -preScript can disable an analyzer, so the dump would describe a crippled" >&2
	echo "  analysis and the golden would pin it. Re-run without it, or use check." >&2
	exit 2
fi

# Row selection (see the header note). Empty ONLY_IDS means "every row"; EXCEPT_IDS is
# applied on top. Both are kept as comma-delimited strings with sentinel commas so a
# membership test is a plain substring match -- no associative arrays, matching the
# portability level of the rest of this script.
ONLY_IDS=""
EXCEPT_IDS=""
# Which SETS this run considers, in the order named. Empty here means "the caller named
# none", which resolves to `core` below -- kept distinct from an explicit `core` so the
# notes can tell the two apart.
REQUESTED_SETS=()
NO_BUILD=0
KEEP_PROJECT=0
REQUIRE_ALL=0
BATCH_SIZE_ARG=""
while [ $# -gt 0 ]; do
	case "$1" in
		# The pre-grm-ughg flags were removed in grm-x4y1.5. Say what to type instead of a bare
		# "unknown option", so a stale invocation from habit or scrollback is told its fix.
		--gme|--all|--snes)
			case "$1" in --gme) repl=nes-gme ;; --all) repl=nes ;; --snes) repl=snes ;; esac
			echo "ERROR: unknown option '$1' (removed in grm-x4y1.5) -- name the set positionally:" \
				"'$repl' instead of '$1'." >&2
			echo "$USAGE" >&2
			exit 2
			;;
		--no-build)
			NO_BUILD=1
			shift
			;;
		--keep-project)
			KEEP_PROJECT=1
			shift
			;;
		--require-all)
			REQUIRE_ALL=1
			shift
			;;
		--batch-size=*) BATCH_SIZE_ARG="${1#--batch-size=}"; shift ;;
		--batch-size)
			[ $# -ge 2 ] || { echo "ERROR: --batch-size needs a value" >&2; exit 2; }
			BATCH_SIZE_ARG="$2"; shift 2 ;;
		--only|--except)
			[ $# -ge 2 ] || { echo "ERROR: $1 needs a comma-separated id list" >&2; exit 2; }
			# Normalize to ",a,b,c," so ",$id," can never match a partial id.
			list=",$(printf '%s' "$2" | tr -d '[:space:]'),"
			if [ "$1" = "--only" ]; then ONLY_IDS="$list"; else EXCEPT_IDS="$list"; fi
			shift 2
			;;
		--)
			shift
			break
			;;
		-*)
			echo "ERROR: unknown option '$1'" >&2
			echo "$USAGE" >&2
			exit 2
			;;
		*)
			# A positional word is a SET NAME if the tables know it, an existing DIRECTORY if it is
			# one, and otherwise a hard ERROR. The third case is the point: without it a typo'd set
			# name ('nes-gem') silently becomes a romdir, the run indexes nothing from it, and every
			# row SKIPs -- a clean-looking run that checked nothing, which is precisely the failure
			# mode this script refuses everywhere else (see the --only/--except unknown-id error).
			if tsv_field "$SETS_TSV" "$1" set >/dev/null 2>&1 ||
				tsv_field "$PLATFORMS_TSV" "$1" platform >/dev/null 2>&1 ||
				[ "$1" = all ]; then
				REQUESTED_SETS+=("$1")
				shift
			elif [ -d "$1" ]; then
				break
			else
				echo "ERROR: '$1' is neither a known set nor an existing directory." >&2
				echo "hint: $0 --list-sets" >&2
				exit 2
			fi
			;;
	esac
done
# --keep-project keeps one analyzed project per row (tens of MB each), so it is scoped to an
# explicit --only list rather than silently keeping a whole set's worth; and only check/bless
# import anything to keep.
if [ "$KEEP_PROJECT" = 1 ]; then
	if [ "$MODE" != check ] && [ "$MODE" != bless ]; then
		echo "ERROR: --keep-project applies to check/bless only (got '$MODE')." >&2
		exit 2
	fi
	if [ -z "$ONLY_IDS" ]; then
		echo "ERROR: --keep-project needs --only <ids>: it keeps one project per row, so name" \
			"the rows you want kept." >&2
		exit 2
	fi
fi
# Batch size (bead grm-x4y1.3): validated for every mode so a typo fails fast, applied below.
BATCH_SRC="default"
BATCH_N="$GRM_REALROM_BATCH_SIZE_DEFAULT"
if [ -n "$BATCH_SIZE_ARG" ]; then
	BATCH_N="$BATCH_SIZE_ARG"; BATCH_SRC="--batch-size"
elif [ -n "${GRM_REALROM_BATCH_SIZE:-}" ]; then
	BATCH_N="$GRM_REALROM_BATCH_SIZE"; BATCH_SRC="env GRM_REALROM_BATCH_SIZE"
fi
case "$BATCH_N" in
	''|*[!0-9]*|0|0[0-9]*)
		echo "ERROR: invalid batch size '$BATCH_N' ($BATCH_SRC): must be a positive integer (1 = one JVM per row)" >&2
		exit 2
		;;
esac
if [ "$KEEP_PROJECT" = 1 ]; then
	BATCH_ON=0
	BATCH_BANNER="off -- --keep-project forces size 1 (each row keeps its own project)"
elif [ "$BATCH_N" -le 1 ]; then
	BATCH_ON=0
	BATCH_BANNER="off (size 1 = one analyzeHeadless per row; $BATCH_SRC)"
else
	BATCH_ON=1
	BATCH_BANNER="up to $BATCH_N rows per analyzeHeadless JVM ($BATCH_SRC); imports serial inside it"
fi

# Sourced BEFORE the GRM_ROM_DIR/ROM_DIRS check (bead grm-6kv), unlike every other block
# below that only needs it once ROM dirs are known: the staleness note below must still
# print on the "no ROM dirs supplied" exit path, and doing that needs REPO_ROOT/git.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Establishes REPO_ROOT and GRM_TARGET_VERSION, and defines native() etc.
. "$SCRIPT_DIR/lib/common.sh"

# Staleness signal (bead grm-6kv, rescoped per the 2026-08-15 user ruling: this tier stays
# manual/opt-in -- build-and-test.sh's default gate still does not invoke it -- but "nobody
# ran it" must be VISIBLE rather than silent, which is exactly what let grm-mu7 destroy three
# pinned ROMs unnoticed for a day). grm_realrom_staleness_note()/GRM_REALROM_STAMP live in
# lib/common.sh, shared with build-and-test.sh so the two cannot drift on the message or the
# stamp format. Printed on every invocation (check, bless, nominate, and even the "no ROM
# dirs" usage-exit below), so no code path through this script goes quiet about how long
# it's been.
[ "$MODE" = ids ] || grm_realrom_staleness_note

# ------------------------------------------------------------------
# SET AND PLATFORM RESOLUTION (bead grm-ughg). Everything that used to be a `case` on
# MANIFEST_SET is now read from realrom/sets.tsv and realrom/platforms.tsv.
#
# WHY THIS SHAPE. The pre-grm-ughg script carried TWO axes in ONE variable: MANIFEST_SET had
# four values (core/gme/all/snes) while the platform block distinguished only two cases (snes
# vs everything else). That is why adding --snes was cheap AND made the shape worse -- it
# could ride the existing variable without anyone separating the axes first. Here the axes are
# separate by construction: a SET names rows and declares its platform; a PLATFORM declares
# how to import a row. Adding a platform is a row in platforms.tsv plus a row in sets.tsv.
#
# Resolution of a requested name, in order:
#   all           -> every set in sets.tsv
#   <platform>    -> every set whose platform column is that platform
#   <set>         -> that set
# Sets compose and rows are deduplicated by id, so naming several (or a set and the group
# containing it) is safe and idempotent.
# ------------------------------------------------------------------
[ ${#REQUESTED_SETS[@]} -gt 0 ] || REQUESTED_SETS=(core)

# manifest path -> platform, and platform -> its ROM dirs. Both are filled during resolution
# below and read by the row walk, which is what makes a multi-platform run possible at all:
# the loader, dump script and copy extension are decided PER ROW from its manifest's platform
# rather than once per invocation.
declare -A MANIFEST_PLATFORM_OF
declare -A PLATFORM_DIRS_OF

ALL_SETS=()
while IFS= read -r s; do
	[ -n "$s" ] || continue
	ALL_SETS+=("$s")
done < <(tsv_column "$SETS_TSV" set)

RESOLVED_SETS=()
resolved_has() {
	local want="$1" have
	for have in ${RESOLVED_SETS[@]+"${RESOLVED_SETS[@]}"}; do
		[ "$have" = "$want" ] && return 0
	done
	return 1
}
add_set() {
	resolved_has "$1" || RESOLVED_SETS+=("$1")
}
for want in "${REQUESTED_SETS[@]}"; do
	case "$want" in
		all)
			for s in "${ALL_SETS[@]}"; do add_set "$s"; done
			;;
		*)
			if tsv_field "$PLATFORMS_TSV" "$want" platform >/dev/null 2>&1; then
				# A platform group: every set declared for it. Empty is an ERROR rather than a
				# quiet no-op -- "run every snes set" finding none means the tables disagree.
				found=0
				for s in "${ALL_SETS[@]}"; do
					[ "$(tsv_field "$SETS_TSV" "$s" platform)" = "$want" ] || continue
					add_set "$s"; found=1
				done
				[ "$found" = 1 ] || {
					echo "ERROR: platform group '$want' matches no set in $(basename "$SETS_TSV")" >&2
					exit 2
				}
			elif tsv_field "$SETS_TSV" "$want" set >/dev/null 2>&1; then
				add_set "$want"
			else
				echo "ERROR: unknown set '$want'" >&2
				echo "hint: $0 --list-sets" >&2
				exit 2
			fi
			;;
	esac
done

# Expand the resolved sets into (a) the manifests to read, (b) the ids those sets allow, and
# (c) the platforms involved. A set's `rows` column is either '*' (every id in its manifests)
# or an explicit comma-separated id list -- which is how `core` is a cross-manifest SUBSET
# without being a sixth manifest file, i.e. without re-creating the problem this bead is
# about. The allowed-id list composes with --only/--except rather than replacing it.
MANIFESTS=()
PLATFORMS_USED=()
SET_IDS=","
for s in "${RESOLVED_SETS[@]}"; do
	s_plat="$(tsv_field "$SETS_TSV" "$s" platform)"
	s_rows="$(tsv_field "$SETS_TSV" "$s" rows)"
	resolved_has_plat=0
	for p in ${PLATFORMS_USED[@]+"${PLATFORMS_USED[@]}"}; do
		[ "$p" = "$s_plat" ] && resolved_has_plat=1
	done
	[ "$resolved_has_plat" = 1 ] || PLATFORMS_USED+=("$s_plat")
	tsv_field "$PLATFORMS_TSV" "$s_plat" platform >/dev/null 2>&1 || {
		echo "ERROR: set '$s' declares platform '$s_plat', which is not in $(basename "$PLATFORMS_TSV")" >&2
		exit 2
	}

	old_ifs="$IFS"; IFS=','
	for mf in $(tsv_field "$SETS_TSV" "$s" manifests); do
		IFS="$old_ifs"
		mpath="$REALROM_DIR/$mf"
		if [ ! -f "$mpath" ]; then
			echo "ERROR: set '$s' needs $mpath, which does not exist." >&2
			if [ "$(tsv_field "$PLATFORMS_TSV" "$s_plat" nominate)" = yes ]; then
				echo "       Populate it with: $0 nominate <romdir> [<romdir> ...]" >&2
			else
				echo "       nominate does not apply to platform '$s_plat'; select rows from the" >&2
				echo "       grm-9nxj.13 corpus survey (build/snes-rom-corpus/roms.tsv) instead." >&2
			fi
			exit 2
		fi
		already=0
		for existing in ${MANIFESTS[@]+"${MANIFESTS[@]}"}; do
			[ "$existing" = "$mpath" ] && already=1
		done
		[ "$already" = 1 ] || MANIFESTS+=("$mpath")
		# MANIFEST_PLATFORM_OF maps a manifest path to its platform, which is what lets the row
		# walk resolve loader/dump/extension PER ROW in a multi-platform run.
		MANIFEST_PLATFORM_OF["$mpath"]="$s_plat"
		if [ "$s_rows" = '*' ]; then
			while IFS= read -r rid; do
				[ -n "$rid" ] || continue
				case "$SET_IDS" in *",$rid,"*) ;; *) SET_IDS="$SET_IDS$rid," ;; esac
			done < <(awk -F'\t' '!/^#/ && NF && $1 != "id" { sub(/\r$/, "", $1); print $1 }' "$mpath")
		fi
		IFS=','
	done
	IFS="$old_ifs"

	if [ "$s_rows" != '*' ]; then
		old_ifs="$IFS"; IFS=','
		for rid in $s_rows; do
			IFS="$old_ifs"
			[ -n "$rid" ] || continue
			case "$SET_IDS" in *",$rid,"*) ;; *) SET_IDS="$SET_IDS$rid," ;; esac
			IFS=','
		done
		IFS="$old_ifs"
	fi
done

if [ "$MODE" = ids ]; then
	# Read-only row listing for ab-test.sh (grm-x4y1.5): SET_IDS is ",a,b,c," -- one id per line.
	ids_out="${SET_IDS#,}"; ids_out="${ids_out%,}"
	[ -z "$ids_out" ] || printf '%s\n' "$ids_out" | tr ',' '\n'
	exit 0
fi

echo "== sets: ${RESOLVED_SETS[*]} (platform(s): ${PLATFORMS_USED[*]};" \
	"${#MANIFESTS[@]} manifest file(s)) =="

# ------------------------------------------------------------------
# PER-PLATFORM ROM DIRS.
#
# Positional romdirs apply to EVERY platform in the run: they carry no platform of their own,
# and indexing a directory with a platform's extensions simply finds whatever is there. Each
# platform otherwise reads its own declared environment variable.
#
# A platform with no dirs SKIPS its rows loudly rather than killing the run, so a
# multi-platform set is usable by someone holding one platform's images. But if NO platform
# has any dirs the run still refuses outright with a nonzero exit: this tier must never report
# a clean gate for something that did not execute (CLAUDE.md), and that guarantee predates and
# survives this refactor.
# ------------------------------------------------------------------
#
# PLATFORM_DIRS_OF holds each platform's dirs NEWLINE-separated (bead grm-3rel), never
# space-joined: a space-joined list was word-split again by every reader, so a dir whose own
# name contains a space was cut in pieces even when passed as a single argument. Read it back
# with platform_dirs, never with an unquoted expansion.
#
# The env variables keep their whitespace-separated form for compatibility, but a value that
# contains ';' (PATH-style on Windows; ':' cannot work here, every drive letter has one) is split
# on ';' ONLY, which is how a dir with a space in its name is spelled in GRM_ROM_DIR.
dir_list_from_env() {
	local v="$1" part
	if [[ "$v" == *";"* ]]; then
		local IFS=';'
		for part in $v; do
			# Trim surrounding whitespace so 'a; b' means 'a' and 'b'.
			part="${part#"${part%%[![:space:]]*}"}"
			part="${part%"${part##*[![:space:]]}"}"
			[ -n "$part" ] && printf '%s\n' "$part"
		done
	else
		for part in $v; do printf '%s\n' "$part"; done
	fi
	return 0
}
# platform_dirs <platform> <array-name>: fill the named array with that platform's dirs.
platform_dirs() {
	local -n pd_out="$2"
	pd_out=()
	[ -n "${PLATFORM_DIRS_OF[$1]:-}" ] || return 0
	mapfile -t pd_out <<<"${PLATFORM_DIRS_OF[$1]}"
}
POSITIONAL_DIRS=("$@")
ANY_DIRS=0
for p in "${PLATFORMS_USED[@]}"; do
	p_env="$(tsv_field "$PLATFORMS_TSV" "$p" rom_dir_env)"
	if [ ${#POSITIONAL_DIRS[@]} -gt 0 ]; then
		PLATFORM_DIRS_OF["$p"]="$(printf '%s\n' "${POSITIONAL_DIRS[@]}")"
	else
		PLATFORM_DIRS_OF["$p"]="$(dir_list_from_env "${!p_env:-}")"
	fi
	if [ -n "${PLATFORM_DIRS_OF[$p]}" ]; then
		ANY_DIRS=1
	elif [ "$MODE" = coverage ]; then
		: # coverage never reads ROM dirs
	else
		echo "REALROM: platform '$p' has no ROM dirs -- $p_env is unset and no romdir was" \
			"passed. Its rows will SKIP; nothing about them is being checked." >&2
	fi
done
if [ "$ANY_DIRS" -eq 0 ] && [ "$MODE" != coverage ]; then
	envs=""
	for p in "${PLATFORMS_USED[@]}"; do
		envs="$envs $(tsv_field "$PLATFORMS_TSV" "$p" rom_dir_env)"
	done
	echo "REALROM: SKIPPED -- no ROM dirs supplied and none of$envs is set. This tier was" \
		"NOT run; nothing about real-ROM regressions was checked. Set one (each may hold" \
		"several dirs, space-separated, or ';'-separated if a name has a space) or pass" 		"romdir arguments." >&2
	echo "$USAGE" >&2
	exit 2
fi

EXPECTED_DIR="$REALROM_DIR/expected"

# Installs one platform's parameters into the ROM_* variables the rest of this script already
# reads. Called per row (and per ROM-dir index pass), which is how the pre-existing cache-key,
# import and golden-check code below works unchanged in a multi-platform run: it still reads
# ROM_LOADER/ROM_DUMP_SCRIPT/ROM_COPY_EXT/ROM_IMPORT_ARGS/ROM_EXTS, they are simply set from
# the table now instead of from a `case` on the manifest set.
# Memoized per platform (grm-x4y1.4): the first call for a platform pays the seven tsv_field awk
# spawns, every later call is pure assignment. It used to re-resolve on every manifest row
# (35 x 7 spawns, ~7s on Windows), including rows --only filtered out.
declare -A _PLAT_MEMO=()
use_platform() {
	local p="$1" ia ex
	PLATFORM="$p"
	if [ -z "${_PLAT_MEMO[$p]+x}" ]; then
		# '-' rather than an empty cell, so the column is never ambiguous in a TSV where a
		# trailing empty field and a missing one look identical.
		ia="$(tsv_field "$PLATFORMS_TSV" "$p" import_args)"
		if [ "$ia" = "-" ]; then ia=""; fi
		ex="$(tsv_field "$PLATFORMS_TSV" "$p" image_exts)"
		_PLAT_MEMO[$p]=1
		_PLAT_ENV[$p]="$(tsv_field "$PLATFORMS_TSV" "$p" rom_dir_env)"
		_PLAT_LOADER[$p]="$(tsv_field "$PLATFORMS_TSV" "$p" loader)"
		_PLAT_DUMP[$p]="$(tsv_field "$PLATFORMS_TSV" "$p" dump_script)"
		_PLAT_COPY[$p]="$(tsv_field "$PLATFORMS_TSV" "$p" copy_ext)"
		_PLAT_IA[$p]="$ia"
		_PLAT_EXTS[$p]="$ex"
	fi
	ROM_ENV="${_PLAT_ENV[$p]}"
	ROM_LOADER="${_PLAT_LOADER[$p]}"
	ROM_DUMP_SCRIPT="${_PLAT_DUMP[$p]}"
	ROM_COPY_EXT="${_PLAT_COPY[$p]}"
	ROM_IMPORT_ARGS=()
	if [ -n "${_PLAT_IA[$p]}" ]; then
		read -r -a ROM_IMPORT_ARGS <<< "${_PLAT_IA[$p]}"
	fi
	IFS=',' read -r -a ROM_EXTS <<< "${_PLAT_EXTS[$p]}"
}
declare -A _PLAT_ENV=() _PLAT_LOADER=() _PLAT_DUMP=() _PLAT_COPY=() _PLAT_IA=() _PLAT_EXTS=()

# Emits every row of the SELECTED manifests, each prefixed with its platform, so a consumer
# can resolve per-row parameters without knowing which file a row came from.
manifest_rows() {
	local m
	for m in "${MANIFESTS[@]}"; do
		awk -F'\t' -v plat="${MANIFEST_PLATFORM_OF[$m]}" \
			'{ sub(/\r$/, ""); print plat "\t" $0 }' "$m"
	done
}

# Every manifest named by ANY set, selected or not -- for the questions that are about the
# repo rather than about this invocation (id uniqueness, "is this ROM already pinned?").
all_declared_manifests() {
	local s mf seen=""
	for s in "${ALL_SETS[@]}"; do
		local old_ifs="$IFS"; IFS=','
		for mf in $(tsv_field "$SETS_TSV" "$s" manifests); do
			IFS="$old_ifs"
			case "$seen" in *" $mf "*) IFS=','; continue ;; esac
			seen="$seen $mf "
			[ -f "$REALROM_DIR/$mf" ] && printf '%s\n' "$REALROM_DIR/$mf"
			IFS=','
		done
		IFS="$old_ifs"
	done
}

# Ragged rows are a RENDERING defect, never a correctness one -- `read` treats a missing
# trailing field and an empty one identically -- so this warns and continues. It exists
# because the fix (a trailing tab on rows with no loader_opts) is invisible whitespace that
# editors and paste buffers strip, so without a reminder the GitHub table quietly degrades.
for m in "${MANIFESTS[@]}"; do
	ragged="$(tr -d '\r' < "$m" | awk -F'\t' '!/^#/ && NF && NF != 8 { printf "%s ", $1 }')"
	[ -z "$ragged" ] || {
		echo "NOTE: $(basename "$m") has rows that are not 8 fields wide: $ragged" >&2
		echo "      GitHub's table view wants a uniform column count; pad with a trailing tab." >&2
	}
done
mkdir -p "$EXPECTED_DIR"

# One id must mean one row. Ids name goldens (expected/<id>.dump), name the ROM copy the
# import sees (so they reach the golden as `REALROM program <id>.nes`), and are what
# --only/--except match -- so a duplicate across the two manifests would import twice and
# have the second row silently overwrite the first's golden. Same reasoning as the
# unknown-id error below: the expensive failure here is the one that looks like success.
# Checks EVERY manifest, not just the selected ones: uniqueness is a property of the repo,
# not of how this invocation was flagged, and a `--gme` run that skipped the check would
# happily bless a row whose id collides with a curated one.
#
# manifest-snes.tsv is in here for exactly that reason (bead grm-9nxj.15): an id is a filename
# under expected/, and expected/ is ONE directory shared by every platform, so a SNES row
# named `megaman` would overwrite the NES golden of that name. Uniqueness is a property of the
# repo, not of the platform.
mapfile -t all_manifests < <(all_declared_manifests)
dupe_ids="$(cat "${all_manifests[@]}" | tr -d '\r' \
	| awk -F'\t' '!/^#/ && NF && $1 != "id" { print $1 }' \
	| LC_ALL=C sort | uniq -d)"
if [ -n "$dupe_ids" ]; then
	echo "ERROR: id(s) appear in more than one manifest:" >&2
	printf '  %s\n' $dupe_ids >&2
	echo "       Each id must be unique across ${all_manifests[*]}" >&2
	exit 2
fi

# Validate --only/--except ids against the manifest BEFORE importing anything. An
# unknown id is an error rather than a no-op: the whole point of --except is to protect a
# deliberately-stale golden, and a silently-ignored typo would bless the very title the
# caller was trying to spare. (Same reasoning as the manifest's own hash pinning: the
# expensive failure here is the one that looks like success.)
if [ -n "$ONLY_IDS$EXCEPT_IDS" ]; then
	manifest_ids=",$(awk -F'\t' '!/^#/ && NF && $1 != "id" { sub(/\r$/, "", $1); printf "%s,", $1 }' "${MANIFESTS[@]}")"
	for spec in "$ONLY_IDS" "$EXCEPT_IDS"; do
		[ -n "$spec" ] || continue
		# Strip the sentinel commas, then walk the ids.
		inner="${spec#,}"; inner="${inner%,}"
		IFS=',' read -r -a want <<< "$inner"
		for w in "${want[@]}"; do
			[ -n "$w" ] || continue
			case "$manifest_ids" in
				*",$w,"*) ;;
				*)
					echo "ERROR: '$w' is not an id in ${MANIFESTS[*]}" >&2
					echo "hint: this run covers set(s) '${RESOLVED_SETS[*]}' only." \
						"Name another set, a platform group, or 'all' -- see $0 --list-sets" >&2
					known="${manifest_ids#,}"
					echo "known ids: ${known%,}" >&2
					exit 2
					;;
			esac
		done
	done
fi

# ------------------------------------------------------------------
# nominate: emit paste-ready manifest rows for the ROMs in the supplied dir(s).
#
# Adding a title by hand means hashing the dump, decoding the iNES mapper byte and
# looking up which board claims it -- three chances to transcribe something wrong into a
# file whose whole job is being exactly right. This does all three from the ROM itself.
# It runs before any Ghidra setup because it needs none: no extension install, no
# headless, no project.
# ------------------------------------------------------------------
if [ "$MODE" = nominate ]; then
	# NES-ONLY, and it says so rather than emitting garbage (bead grm-9nxj.15). Everything
	# below decodes an iNES header and resolves machines/nes-*.yaml `ines_mappers:`; run
	# against SNES cartridges it would report every one of them as "NOT an iNES image" -- a
	# clean-looking run whose entire output is wrong about what it examined.
	# Whether nominate means anything is now a DECLARED platform capability
	# (platforms.tsv `nominate`) rather than a hardcoded refusal of one platform's name.
	for p in "${PLATFORMS_USED[@]}"; do
		[ "$(tsv_field "$PLATFORMS_TSV" "$p" nominate)" = yes ] && continue
		echo "ERROR: nominate does not apply to platform '$p' -- it decodes iNES headers and" >&2
		echo "       resolves machines/nes-*.yaml, neither of which applies there." >&2
		echo "       For SNES rows use the grm-9nxj.13 corpus survey, which emits name, size," >&2
		echo "       sha256 and the parsed header fields per image:" >&2
		echo "         bash tools/banktest/build-and-test.sh check snes-rom-corpus" >&2
		echo "         # -> build/snes-rom-corpus/roms.tsv" >&2
		exit 2
	done
	if ! command -v od >/dev/null 2>&1; then
		echo "ERROR: od not found on PATH (needed to decode iNES headers)." >&2
		exit 2
	fi
	if ! command -v sha256sum >/dev/null 2>&1; then
		echo "ERROR: sha256sum not found on PATH (needed to pin ROMs by hash)." >&2
		exit 2
	fi

	ines_mapper() {
		# $1 rom -> iNES mapper number on stdout; non-zero if not an iNES image.
		# Mirrors NesRomLoader.InesHeader.parse (src/main/java/retromachines/NesRomLoader.java),
		# including both header-rot cases it handles: NES 2.0's 12-bit mapper, and the
		# "DiskDude!"-style archaic headers that scribble ASCII into bytes 7-15, where
		# flags7's high nibble is not a mapper nibble and only the low nibble may be trusted.
		local h
		# shellcheck disable=SC2207
		h=($(od -An -tu1 -N16 -v "$1" 2>/dev/null)) || return 1
		[ "${#h[@]}" -eq 16 ] || return 1
		# "NES\x1a"
		[ "${h[0]}" -eq 78 ] && [ "${h[1]}" -eq 69 ] &&
			[ "${h[2]}" -eq 83 ] && [ "${h[3]}" -eq 26 ] || return 1
		local low=$(( h[6] >> 4 ))
		if [ $(( h[7] & 0x0C )) -eq 8 ]; then
			printf '%d' $(( ((h[8] & 0x0F) << 8) | (h[7] & 0xF0) | low ))
		elif [ "${h[12]}" -ne 0 ] || [ "${h[13]}" -ne 0 ] ||
			[ "${h[14]}" -ne 0 ] || [ "${h[15]}" -ne 0 ]; then
			printf '%d' "$low"
		else
			printf '%d' $(( (h[7] & 0xF0) | low ))
		fi
	}

	board_for_mapper() {
		# $1 mapper -> board id (the descriptor's `id:`) on stdout, or empty.
		# Reads the shipped descriptors' `ines_mappers:` directly rather than duplicating
		# the table, so a newly-shipped board is nominatable the day it lands.
		local want="$1" f list
		for f in "$REPO_ROOT"/machines/nes-*.yaml; do
			list="$(awk -F'ines_mappers:' '/ines_mappers:/{print $2; exit}' "$f" |
				tr -cd '0-9,' )"
			case ",$list," in
				*",$want,"*) awk '/^[[:space:]]*id:/{print $2; exit}' "$f"; return 0 ;;
			esac
		done
		return 1
	}

	# Hashes already spoken for, so a title pinned anywhere is reported rather than
	# re-nominated under a second id (which the duplicate guard above would reject anyway).
	# Deliberately scans EVERY manifest, not just the selected ones: "is this already
	# pinned?" is a question about the repo, not about how this invocation was flagged, and
	# answering it from a narrower set would nominate a duplicate of a row that exists.
	mapfile -t nominate_known < <(all_declared_manifests)
	known_shas=" $(cat "${nominate_known[@]}" | tr -d '\r' |
		awk -F'\t' '!/^#/ && NF && $1 != "id" { printf "%s:%s ", tolower($3), $1 }')"

	echo "# Nominated rows -- review, then paste into realrom/manifest-gme.tsv."
	echo "# id is the containing directory name where the ROM sits in a per-title subdir"
	echo "# (your game-music-extraction shorthand), else the file's base name."
	n_new=0; n_known=0; n_unsupported=0; n_notines=0
	shopt -s nullglob nocaseglob
	platform_dirs "${PLATFORMS_USED[0]}" nominate_dirs
	for dir in "${nominate_dirs[@]}"; do
		# Normalize away trailing slashes so the "is it in a per-title subdir?" test below
		# is an exact path comparison rather than a basename guess.
		while [ "${dir%/}" != "$dir" ]; do dir="${dir%/}"; done
		for f in "$dir"/*.nes "$dir"/*/*.nes; do
			[ -f "$f" ] || continue
			base="$(basename "$f" .nes)"
			# A per-title subdir names the row; a ROM sitting loose in a scanned dir does not.
			if [ "$(dirname "$f")" = "$dir" ]; then
				id_raw="$base"
			else
				id_raw="$(basename "$(dirname "$f")")"
			fi
			id="$(printf '%s' "$id_raw" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9' '_' | sed 's/__*/_/g; s/^_//; s/_$//')"
			sha="$(sha256sum "$f" | cut -d' ' -f1)"

			case "$known_shas" in
				*" $sha:"*)
					was="${known_shas##*" $sha:"}"; was="${was%% *}"
					echo "# already pinned as '$was': $base"
					n_known=$((n_known + 1))
					continue
					;;
			esac

			if ! mapper="$(ines_mapper "$f")"; then
				echo "# NOT an iNES image (no NES\\x1a magic), skipped: $f"
				n_notines=$((n_notines + 1))
				continue
			fi
			if board="$(board_for_mapper "$mapper")"; then
				# Trailing tab is deliberate: GitHub's tabular viewer wants every row to have
				# the same field count as the header, so rows with no loader_opts carry an
				# explicit empty final field rather than ending short. `read` treats the two
				# identically, so an editor that strips it costs rendering, never correctness.
				printf '%s\t%s\t%s\t%s\t%s\t%s.dump\t\n' "$id" "$base" "$sha" "$mapper" "$board" "$id"
				n_new=$((n_new + 1))
			else
				# Not a failure -- this is the planning signal the expanded set exists to give.
				printf '# NO SHIPPED BOARD claims mapper %s -- %s (id would be %s)\n' \
					"$mapper" "$base" "$id"
				n_unsupported=$((n_unsupported + 1))
			fi
		done
	done
	shopt -u nullglob nocaseglob
	echo "#"
	echo "# nominated=$n_new  already-pinned=$n_known  unsupported-mapper=$n_unsupported  not-ines=$n_notines"
	[ "$n_unsupported" -eq 0 ] ||
		echo "# An unsupported mapper is a board gap, not a bad dump: it is a candidate for a new descriptor."
	exit 0
fi

# A golden must be ABOUT the row that points at it: it records `REALROM program <id>.nes`
# and `REALROM sha256 <the row's hash>`, both derived from the row. Checking that at rest
# costs two greps per file and needs no ROMs, so even a `check` that SKIPs everything still
# verifies it -- which is precisely the situation the stale-candidate bug (grm-c9u) survived.
# An ABSENT golden is not an error here: adding a row before blessing it is the documented
# workflow, and the row walk already reports that as a FAIL with a clearer message.
if [ "$MODE" = check ]; then
	mismatched=""
	while IFS=$'\t' read -r g_plat g_id g_title g_sha _ _ g_golden _ _; do
		case "${g_id:-}" in ""|id|\#*) continue ;; esac
		g_path="$EXPECTED_DIR/${g_golden:-$g_id.dump}"
		[ -f "$g_path" ] || continue
		g_ext="$(tsv_field "$PLATFORMS_TSV" "$g_plat" copy_ext)"
		g_prog="$(awk '/^REALROM program /{print $3; exit}' "$g_path")"
		g_gsha="$(awk '/^REALROM sha256 /{print tolower($3); exit}' "$g_path")"
		g_want="$(printf '%s' "$g_sha" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
		if [ "$g_prog" != "$g_id$g_ext" ] || [ "$g_gsha" != "$g_want" ]; then
			mismatched="$mismatched  $g_id: $(basename "$g_path") says program=$g_prog sha=${g_gsha:0:12}...
"
		fi
	done < <(manifest_rows)
	if [ -n "$mismatched" ]; then
		echo "ERROR: golden(s) do not describe the manifest row pointing at them:" >&2
		printf '%s' "$mismatched" >&2
		echo "       Usually an id was renamed without re-blessing, or a stale candidate was" >&2
		echo "       blessed. Re-bless the affected rows: $0 bless --only <ids> <romdir>" >&2
		exit 2
	fi
fi

# Default headless path derives from gradle.properties' ghidraTargetVersion (single
# source of truth); GHIDRA_HEADLESS still overrides.
grm_default_headless

# Build-by-default preflight (bead grm-4t2d option (e); see the header comment). Skipped
# outright when build-and-test.sh already built+staged for this run
# (GRM_EXTENSION_BUILT_THIS_RUN), so the two scripts never do the work twice, and skipped on
# request via --no-build/GRM_SKIP_BUILD.
#
# THIS MUST RUN BEFORE grm_settings_base_fallback, AND THAT ORDER IS LOAD-BEARING (bug found
# 2026-08-29 while building ab-test.sh). The fallback decides whether to use the isolated
# install by testing whether build/ghidra-home EXISTS. Staging is what creates it. With the
# fallback first, a FRESH WORKTREE -- which by definition has no build/ dir yet -- took the
# shared %APPDATA% branch, and then staging installed into build/ghidra-home that the run
# was no longer pointed at: the extension under test was built correctly and then not used.
# That is the grm-4t2d hazard wearing a new hat, and it defeats isolation for exactly the
# "just run realrom-test.sh directly" flow grm-4t2d added. Staging first means the directory
# exists by the time the fallback looks. Under --no-build the directory may legitimately
# still be absent, and the fallback's NOTE is then correct rather than misleading.
EXT_NOTE_SUFFIX=""
if [ "${GRM_EXTENSION_BUILT_THIS_RUN:-}" = 1 ]; then
	: # build-and-test.sh already built+staged for this run; do not double-build
elif [ "$NO_BUILD" -eq 1 ] || [ "${GRM_SKIP_BUILD:-}" = 1 ]; then
	EXT_NOTE_SUFFIX="no-build"
else
	grm_ensure_extension_staged
fi

# Same isolation as measure-overlay-scale.sh: point Ghidra's settings/Extensions dir at
# the per-worktree build/ghidra-home tree.
# The chunk name is only used in the "run build-and-test.sh first" hint, so name one that
# actually covers this run's platform.
grm_settings_base_fallback "$(tsv_field "$PLATFORMS_TSV" "${PLATFORMS_USED[0]}" fallback_chunk)"
grm_apply_settings_base

if ! command -v sha256sum >/dev/null 2>&1; then
	echo "ERROR: sha256sum not found on PATH (needed to hash-pin ROMs)." >&2
	exit 2
fi

# --- candidate-dump cache (bead grm-lne) --------------------------------
# Mirror build-and-test.sh's cache: `check` stashes each freshly imported dump
# so a follow-up `bless` reuses it instead of paying the real-ROM import again
# (median ~7s per row, worst ~52s; a full 33-row --all run is ~6 min -- measured
# 2026-08-31, bead grm-yfma, which corrected a ~1min+ estimate that was roughly
# the worst row stated as typical). Keyed by the pinned ROM sha, the loader options, the RealRomDump
# script, the installed extension identity, and the identity of the Ghidra
# install that runs the analysis (bead grm-kt44), so a rebuild, a manifest edit,
# or a swapped decompile.exe forces a fresh import. Disabled (bless re-imports) when the extension identity
# is unknown (e.g. falling back to the shared %APPDATA% install).
CACHE_DIR="$REPO_ROOT/build/realrom-cache"

# ext_identity() lives in lib/common.sh (shared with run-banktest.sh).
# Compute the extension identity once; empty => caching disabled for this run.
EXT_ID="$(ext_identity)" || EXT_ID=""

# ANNOUNCE IT. This used to be the PRIMARY defense against the single most common failure in
# this tier: an A/B against a stashed baseline silently comparing a build against itself
# because this script did not build and nobody rebuilt between sides (grm-mej.2, 2026-08-10 --
# it cost an incorrect zero-movement claim that had already been committed). As of grm-4t2d
# option (e) this script builds by default, so that failure mode should no longer be reachable
# without deliberately passing --no-build/GRM_SKIP_BUILD -- but the identity is still printed
# as a SAFETY NET: if both sides of an A/B print the SAME line, something is wrong (a stale
# cache, an unintended --no-build, a build that silently no-opped) and the comparison is
# worthless no matter what the dumps say.
case "${GRM_EXTENSION_BUILT_THIS_RUN:-}/$EXT_NOTE_SUFFIX" in
	1/*)
		grm_installed_extension_note "$EXT_ID" \
			"(built and installed by build-and-test.sh for this run, so it matches this tree.)"
		;;
	*/no-build)
		grm_installed_extension_note "$EXT_ID" \
			"(--no-build/GRM_SKIP_BUILD skipped the pre-flight build -- this run analyzed" \
			" with whatever was already installed. For an A/B, that means YOU must rebuild" \
			" between sides, and this line MUST change between them or you are comparing a" \
			" build against itself.)"
		;;
	*)
		grm_installed_extension_note "$EXT_ID" \
			"(built and staged by THIS run via 'gradle stageExtensionForTests' before" \
			" analyzing. For an A/B this now happens automatically on both sides -- this" \
			" line should still change between them; if it does not, treat the comparison" \
			" as unproven and find out why before trusting it.)"
		;;
esac
grm_decompiler_note
grm_packed_db_cache_note
# Resolved Ghidra install root (bead grm-k0h): GHIDRA_HEADLESS -- not GRM_GHIDRA_INSTALL --
# is what actually launches Ghidra, so a native-side A/B (decompile.exe, sleigh.exe) needs
# GRM_GHIDRA_INSTALL set AND this to name the install it resolved to, or a stray default
# install silently gets measured instead. This is inert-by-name-alone, not just informational:
# GRM_GHIDRA_INSTALL now feeds GHIDRA_HEADLESS's default (grm_default_headless above), but the
# env var still wins if the caller set it explicitly, so the two can point at different
# installs -- print both rather than assume they agree.
echo "== ghidra install: $GRM_GHIDRA_INSTALL (headless: $GHIDRA_HEADLESS) =="

# toolchain_identity() lives in lib/common.sh (shared with run-banktest.sh). Computed once;
# empty => caching disabled for this run, exactly as an unknown EXT_ID disables it -- an
# unidentifiable toolchain must degrade to "re-import", never to "reuse and hope" (bead
# grm-kt44). Printed for the same safety-net reason the extension identity is: on a native A/B
# (decompile.exe, sleigh.exe) THIS is the line that must differ between the two sides, while the
# extension identity is expected NOT to.
TOOLCHAIN_ID="$(toolchain_identity)" || TOOLCHAIN_ID=""
if [ -n "$TOOLCHAIN_ID" ]; then
	echo "== ghidra toolchain: $TOOLCHAIN_ID =="
else
	echo "== ghidra toolchain: UNKNOWN (could not fingerprint the install behind $GHIDRA_HEADLESS) =="
	echo "   Candidate-dump caching is DISABLED for this run; every row re-imports."
fi

# sha256 of the REALROM_EXTRA_PRESCRIPT script FILE (bead grm-x4y1.2), resolved the way
# analyzeHeadless resolves it for -preScript: the first word is the script (the rest are its
# arguments, already keyed by name), found as given or under -scriptPath ($SCRIPT_DIR). Empty
# when no prescript is set; "unresolved" when it names no file (the run itself would fail).
prescript_content_hash() {
	local ps="${REALROM_EXTRA_PRESCRIPT:-}" f
	[ -n "$ps" ] || return 0
	ps="${ps%% *}"
	for f in "$ps" "$SCRIPT_DIR/$ps"; do
		[ -f "$f" ] && { sha256sum "$f" | cut -d' ' -f1; return 0; }
	done
	printf 'unresolved'
}

# sha256 of the current $PLATFORM's raw platforms.tsv line (bead grm-x4y1.2), memoized per platform.
declare -A _PLAT_ROWHASH=()
platform_row_hash() {
	if [ -z "${_PLAT_ROWHASH[$PLATFORM]+x}" ]; then
		_PLAT_ROWHASH[$PLATFORM]="$(awk -F'\t' -v p="$PLATFORM" '{ sub(/\r$/, "") } $1 == p { print }' \
			"$PLATFORMS_TSV" | sha256sum | cut -d' ' -f1)"
	fi
	printf '%s' "${_PLAT_ROWHASH[$PLATFORM]}"
}

realrom_cache_key() {
	# args: id rom_sha opts  ->  sha256 key on stdout, or empty if disabled
	# (reads $PLATFORM/$ROM_DUMP_SCRIPT, so call use_platform first)
	#
	# The id is part of the key because it is part of the OUTPUT: import_and_dump names the
	# ROM copy after it, so it reaches the dump as `REALROM program <id>.nes`. Leaving it out
	# meant renaming a row (wizwarr -> ironsword) left the key untouched, so a bless reused
	# the pre-rename candidate and wrote the old name straight back into the golden. Anything
	# that can change the dump has to be in here.
	local id="$1" rom_sha="$2" opts="$3"
	[ -n "$EXT_ID" ] || { printf ''; return 0; }
	[ -n "$TOOLCHAIN_ID" ] || { printf ''; return 0; }
	{
		printf 'id:%s\n' "$id"
		printf 'rom:%s\n' "$rom_sha"
		printf 'opts:%s\n' "$opts"
		# WHICHEVER dump script this row actually uses. Hardcoding RealRomDump.java here
		# would let a SNES golden be served from a cache entry that predates a change to
		# SnesRealRomDump.java -- into a `bless`, in the worst case (bead grm-9nxj.15).
		printf 'dumpscript:%s:' "$ROM_DUMP_SCRIPT"
		sha256sum "$SCRIPT_DIR/$ROM_DUMP_SCRIPT" | cut -d' ' -f1
		# Both dump scripts compile against this shared helper (grm-x4y1.6); an edit to it
		# alone changes every dump, so it must move the key too.
		printf 'dumpsupport:'
		sha256sum "$SCRIPT_DIR/RealRomDumpSupport.java" | cut -d' ' -f1
		printf 'ext:%s\n' "$EXT_ID"
		# The TOOLCHAIN that produces the dump, not just the extension that steers it (bead
		# grm-kt44). Every other term here describes this repo; without this one a run against a
		# patched decompile.exe -- or against a different install via GHIDRA_HEADLESS -- keys
		# identically to a run against the stock one, and the cache serves the wrong arm's dump,
		# into a `bless` in the worst case. See toolchain_identity() in lib/common.sh.
		printf 'toolchain:%s\n' "$TOOLCHAIN_ID"
		# A -preScript runs BEFORE auto-analysis and can change what analysis DOES at all --
		# SetAnalyzerEnabled.java (bead grm-8uaz) turns an analyzer off outright. That is the
		# largest change to the dump there is, so by this function's own rule above ("anything
		# that can change the dump has to be in here") it must be keyed. Without this term an
		# analyzer-OFF dump and a normal dump share a key and the cache would serve one for the
		# other -- into a `bless`, in the worst case. The bless path is refused outright when
		# this is set (see the guard after mode parsing); this term is the second lock.
		# Name AND content (bead grm-x4y1.2): editing the script in place keeps its name, so the
		# name alone left a changed prescript sharing a key with the old one.
		printf 'prescript:%s:%s\n' "${REALROM_EXTRA_PRESCRIPT:-}" "$(prescript_content_hash)"
		# The platform's whole platforms.tsv row (bead grm-x4y1.2): loader, import_args and
		# copy_ext all shape the import (a different loader or -noanalysis changes the dump)
		# and the dumpscript/ext terms above only cover two of those columns.
		printf 'platform-row:%s\n' "$(platform_row_hash)"
		# The optional analysis thread pin (lib/common.sh; off by default since grm-uioc). Pinned
		# and unpinned dumps have differed before (grm-nems, grm-kon2), so a GRM_THREAD_PIN=1
		# diagnostic run must never serve its dump to a normal `bless`.
		printf 'threadpin:%s\n' "${GRM_THREAD_PIN:-0}"
	} | sha256sum | cut -d' ' -f1
}

# ------------------------------------------------------------------
# coverage (bead grm-eawl): which rows have RAN at THIS build? Derived from the candidate cache,
# not from a new ledger -- build/realrom-cache/<key>.dump is written for every row whose sha
# recheck passed (pass OR fail on the golden), keyed on id + ROM sha + opts + dump script +
# EXT_ID + toolchain + prescript + thread pin. So the column says "ran", never anything
# implying the row passed: the data cannot support that claim.
#
# ROM sha256: the key uses the MANIFEST'S PINNED hash, and an entry only exists if the dump's
# own sha matched that pin (the second-layer recheck in the row walk), so using the pin is
# exactly equivalent to hashing the ROM -- no ROM dirs are read or hashed. A row whose ROM is
# not on this machine simply has no entry, which reads as "no entry", the same signal as SKIP.
# EXT_ID/TOOLCHAIN_ID come from the same preflight a `check` runs above (stage unless
# --no-build), so the key is the one a check would compute right now.
# Read-only: writes nothing (no work dir, no state file) and always exits 0.
# ------------------------------------------------------------------
if [ "$MODE" = coverage ]; then
	if [ -z "$EXT_ID" ] || [ -z "$TOOLCHAIN_ID" ]; then
		echo "COVERAGE: cannot compute cache keys -- extension identity (${EXT_ID:-unknown}) or" \
			"toolchain identity (${TOOLCHAIN_ID:-unknown}) is unavailable, so a check would" \
			"not cache either. No row can be reported."
		exit 0
	fi
	[ -z "${REALROM_EXTRA_PRESCRIPT:-}" ] ||
		echo "COVERAGE: REALROM_EXTRA_PRESCRIPT is set -- reporting entries for THAT configuration only."
	printf '\n%-14s %-6s %s\n' ID CACHE NOTE
	n_cov=0; n_cov_total=0
	while IFS=$'\t' read -r row_plat id title sha mapper board golden opts member ||
		[ -n "${id:-}" ]; do
		case "${id:-}" in ""|id|\#*) continue ;; esac
		case "$SET_IDS" in *",$id,"*) ;; *) continue ;; esac
		if { [ -n "$ONLY_IDS" ] && [ "${ONLY_IDS#*,$id,}" = "$ONLY_IDS" ]; } ||
			{ [ -n "$EXCEPT_IDS" ] && [ "${EXCEPT_IDS#*,$id,}" != "$EXCEPT_IDS" ]; }; then
			continue
		fi
		use_platform "$row_plat"
		sha="$(printf '%s' "$sha" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
		key="$(realrom_cache_key "$id" "$sha" "${opts:-}")"
		n_cov_total=$((n_cov_total + 1))
		if [ -n "$key" ] && [ -f "$CACHE_DIR/$key.dump" ]; then
			n_cov=$((n_cov + 1))
			printf '%-14s %-6s %s\n' "$id" ran "at this build"
		else
			printf '%-14s %-6s %s\n' "$id" -- \
				"no entry for this build (never run here, ROM not found when run, or built since)"
		fi
	done < <(manifest_rows)
	echo
	echo "$n_cov of $n_cov_total rows have run at the current extension build (EXT_ID ${EXT_ID:0:12}...)."
	echo "'ran' means the row was imported and its dump cached -- NOT that it matched its golden."
	echo "(failing rows such as megaman/wizwarr also read 'ran'; this is not a pass/fail report.)"
	exit 0
fi

# Retention (bead grm-uqhd): drop old kept-on-failure work dirs and stale cache entries BEFORE
# this run makes its own. Knobs: GRM_WORK_KEEP_DAYS/GRM_WORK_KEEP_FAILURES/GRM_CACHE_KEEP_DAYS.
# Never touches build/realrom-cache/.last-verified (dotfile, not a *.dump/*.crit entry).
grm_prune_work_dirs
grm_prune_cache "$CACHE_DIR"
# Did WE create $WORK (so we may delete it), or did the caller name it? A caller-named dir
# (REALROM_WORK_DIR, e.g. ab-test.sh reading the dumps back afterwards) is never removed.
WORK_IS_OURS=1
[ -n "${REALROM_WORK_DIR:-}" ] && WORK_IS_OURS=0
WORK="${REALROM_WORK_DIR:-$(grm_work_dir realrom)}"
mkdir -p "$WORK"
echo "== work dir: $WORK =="
KEEP_DIR="${GRM_KEEP_PROJECT_DIR:-$REPO_ROOT/build/kept-projects/realrom}"
# Same dot-segment hazard as grm_work_dir (bead grm-hhd): Ghidra rejects a project path with a
# dot-leading segment, e.g. an agent worktree under .claude/worktrees/. Same fallback.
if [ -z "${GRM_KEEP_PROJECT_DIR:-}" ] && _grm_path_has_dot_segment "$REPO_ROOT"; then
	KEEP_DIR="${TMPDIR:-${TEMP:-/tmp}}/grm-kept-projects-$(printf '%s' "$REPO_ROOT" | tr -c 'A-Za-z0-9' '_')/realrom"
fi
# Headless timeout (beads grm-w9ev.5, grm-x4y1.2; shared helper in lib/common.sh). Real-ROM rows
# are slower than synthetic fixtures: median ~7s, worst ~52s (dragonpower ~36s). One row = one
# program, so 200s + 90s/program = 290s, 5.6x the slowest row ever seen -- load can't trip it, a
# real hang is still cut off in minutes. The per-program term is what grm-x4y1.3's batching scales.
grm_headless_timeout_init 200 90
echo "== headless timeout: $TIMEOUT_BANNER =="
echo "== batching: $BATCH_BANNER =="
if [ "$KEEP_PROJECT" = 1 ]; then
	echo "== keeping analyzed projects under: $KEEP_DIR =="
fi

sanitize() {
	# analyzeHeadless.bat chokes on parentheses/spaces -- strip to a safe copy name.
	printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'
}

# ------------------------------------------------------------------
# Build a sha256 -> path index of the supplied ROM dir(s). Depth-1 only (the focus set
# and Dragon Ball ROMs sit directly in their dirs); the giant GoodNES/"All NES Roms"
# subdirs are intentionally not descended.
# ------------------------------------------------------------------
declare -A ROM_BY_SHA
ALL_INDEXED_DIRS=()

# Persistent sha256 index (grm-x4y1.4). Hashing every image in every ROM dir on every run cost
# ~9s for the NES dirs and ~34s more for the SNES dir (959MB), to find the one or five files a
# run actually uses. The cache maps path -> (size, mtime, sha256); a file is re-hashed only when
# its stat changed or it is new, and entries for files that vanished from a scanned dir are
# dropped. It lives under build/ (gitignored), outside build/realrom-cache so that cache's LRU
# prune can never touch it. NOT part of any dump cache key: it only decides WHICH file is
# imported; the pinned-hash check is unchanged and still authoritative, because the row's
# "Second-layer hash check" below compares the sha256 Ghidra itself computed over the bytes it
# imported with the manifest pin. A stale index entry (same size and mtime, different bytes)
# therefore FAILs that row loudly -- it cannot pass a wrong ROM. Concurrent runs in one
# worktree are safe: the index is replaced atomically (grm_atomic_publish_stdin, per-pid temp),
# so the worst case is a run re-hashing what another run already hashed.
ROM_SHA_INDEX="$REPO_ROOT/build/realrom-sha-index.tsv"
declare -A IDX_OLD=() IDX_SEEN=() IDX_DIR_SCANNED=()
idx_dirty=0
if [ -f "$ROM_SHA_INDEX" ]; then
	while IFS=$'	' read -r ix_sz ix_mt ix_h ix_path; do
		[ -n "$ix_path" ] || continue
		IDX_OLD[$ix_path]="$ix_sz $ix_mt $ix_h"
	done < "$ROM_SHA_INDEX"
fi
idx_hashed=0
echo "== indexing ROM dirs by sha256 =="
shopt -s nullglob nocaseglob
for idx_plat in "${PLATFORMS_USED[@]}"; do
	use_platform "$idx_plat"
	platform_dirs "$idx_plat" idx_dirs
	[ ${#idx_dirs[@]} -gt 0 ] || continue
	for dir in "${idx_dirs[@]}"; do
		if [ ! -d "$dir" ]; then
			echo "  WARN: not a directory, skipping: $dir" >&2
			# Still listed in the SKIP note: it prints the dirs TRIED, not only the ones that
			# indexed, so a mangled or mistyped dir is visible right where it matters (grm-3rel).
			ALL_INDEXED_DIRS+=("$dir   <-- NOT A DIRECTORY, not indexed")
			continue
		fi
		count=0
		IDX_DIR_SCANNED[$dir]=1
		# ROM_EXTS is per platform (nes; or sfc/smc/fig/swc for SNES -- a SNES collection uses
		# all four interchangeably, and the copier-headered rows are precisely the .smc ones,
		# so scanning only one extension would SKIP half of a clean/copier pair and quietly
		# turn the pair principle off).
		for ext in "${ROM_EXTS[@]}"; do
			idx_files=("$dir"/*."$ext")
			[ ${#idx_files[@]} -gt 0 ] || continue
			# One stat for the whole glob, not one per file; %n last so a name containing the
			# separator still parses.
			while IFS='|' read -r ix_sz ix_mt f; do
				[ -f "$f" ] || continue
				ix_old="${IDX_OLD[$f]:-}"
				if [ -n "$ix_old" ] && [ "${ix_old%% *}" = "$ix_sz" ] &&
					{ ix_rest="${ix_old#* }"; [ "${ix_rest%% *}" = "$ix_mt" ]; }; then
					h="${ix_rest#* }"
				else
					h="$(sha256sum "$f" | cut -d' ' -f1 | tr 'A-Z' 'a-z')"
					idx_dirty=1
					idx_hashed=$((idx_hashed + 1))
				fi
				IDX_SEEN[$f]="$ix_sz $ix_mt $h"
				# First occurrence wins; a manifest pins one exact dump anyway.
				if [ -z "${ROM_BY_SHA[$h]:-}" ]; then
					ROM_BY_SHA[$h]="$f"
				fi
				count=$((count + 1))
			done < <(stat -c '%s|%.9Y|%n' -- "${idx_files[@]}")
		done
		echo "  [$idx_plat] $dir: indexed $count file(s) matching ${ROM_EXTS[*]}"
		ALL_INDEXED_DIRS+=("$dir")
	done
done
# Persist: every entry seen this run, plus untouched entries for dirs this run did not scan
# (a NES-only run must not forget the SNES hashes). Entries for scanned dirs that were not seen
# are exactly the vanished files, and are dropped.
if [ "$idx_dirty" = 0 ]; then
	for ix_path in "${!IDX_OLD[@]}"; do
		if [ -n "${IDX_DIR_SCANNED[${ix_path%/*}]:-}" ] && [ -z "${IDX_SEEN[$ix_path]:-}" ]; then
			idx_dirty=1; break
		fi
	done
fi
if [ "$idx_dirty" = 1 ]; then
	echo "  sha256 index: re-hashed $idx_hashed file(s); updating $ROM_SHA_INDEX"
	{
		for ix_path in "${!IDX_SEEN[@]}"; do
			printf '%s	%s
' "${IDX_SEEN[$ix_path]// /$'	'}" "$ix_path"
		done
		for ix_path in "${!IDX_OLD[@]}"; do
			[ -z "${IDX_SEEN[$ix_path]:-}" ] || continue
			[ -z "${IDX_DIR_SCANNED[${ix_path%/*}]:-}" ] || continue
			printf '%s	%s
' "${IDX_OLD[$ix_path]// /$'	'}" "$ix_path"
		done
	} | LC_ALL=C sort -t$'	' -k4 | { mkdir -p "${ROM_SHA_INDEX%/*}" && grm_atomic_publish_stdin "$ROM_SHA_INDEX"; } ||
		echo "  NOTE: could not write the sha256 index -- the next run will re-hash" >&2
else
	echo "  sha256 index: all files unchanged, nothing re-hashed"
fi
shopt -u nullglob nocaseglob

# ------------------------------------------------------------------
# Walk the manifest.
# ------------------------------------------------------------------
declare -a ROW_ID ROW_STATUS ROW_DETAIL
n_pass=0; n_fail=0; n_skip=0; n_bless=0; n_filtered=0

# Builds RR_ARGS: every analyzeHeadless argument that follows the -import arg(s) and precedes
# -deleteProject, for the current platform ($ROM_*) and a row's loader opts. ONE definition shared
# by the solo import and the batched import (bead grm-x4y1.3), so the two cannot drift: a batch
# is "the solo invocation with several -import args", and nothing else may differ.
rr_headless_args() {
	local opts="$1"
	RR_ARGS=(-loader "$ROM_LOADER" ${ROM_IMPORT_ARGS[@]+"${ROM_IMPORT_ARGS[@]}"})
	# $opts is intentionally unquoted (multi-token loader options), as it always was.
	# shellcheck disable=SC2206
	RR_ARGS+=($opts)
	RR_ARGS+=(-scriptPath "$(native "$SCRIPT_DIR")")
	# shellcheck disable=SC2206
	[ -z "${REALROM_EXTRA_PRESCRIPT:-}" ] || RR_ARGS+=(-preScript $REALROM_EXTRA_PRESCRIPT)
	RR_ARGS+=(-postScript "$ROM_DUMP_SCRIPT")
	# REALROM_EXTRA_POSTSCRIPT runs one more script (e.g. BankReachProbe.java) on the same
	# import, so a diagnostic does not cost a second analysis (~7s median per row, worst ~52s --
	# grm-yfma). Goldens are unaffected:
	# the awk carve in extract_dump only extracts the REALROM block, and every other script fences its
	# own output. Give it its OWN invocation rather than piggybacking a routine run, though --
	# realrom_cache_key() above does not key REALROM_EXTRA_POSTSCRIPT (only the prescript), so a
	# `bless` (or a re-`check`) can legitimately reuse a cached dump and never run the extra
	# script at all.
	[ -z "${REALROM_EXTRA_POSTSCRIPT:-}" ] || RR_ARGS+=(-postScript "$REALROM_EXTRA_POSTSCRIPT")
}

# Carves the normalized REALROM block out of a headless log (solo log, or one program's section
# of a batch log, bead grm-x4y1.3) into $2. Returns 1, quietly, if the END marker is absent --
# callers say what that means for them.
extract_dump() {
	local log="$1" out="$2"
	# Strip headless's "INFO RealRomDump.java> <msg> (GhidraScript)" wrapping, then carve
	# the REALROM block.
	# The postScript's own name appears in headless's line prefix, so the strip has to
	# name the script this row actually ran (bead grm-9nxj.15).
	local dump_re="${ROM_DUMP_SCRIPT//./\\.}"
	sed "s/\r\$//; s/^.*$dump_re> //; s/ (GhidraScript)[[:space:]]*\$//" "$log" \
		| awk '/^=== REALROM BEGIN ===$/{c=1} c{print} /^=== REALROM END ===$/{c=0}' >"$out"
	grep -q '^=== REALROM END ===$' "$out"
}

import_and_dump() {
	# $1 id  $2 rom_path  $3 loader_opts  -> writes normalized dump to $4
	# $5 (optional) tag: gives the log and project a distinct name so a diagnostic solo rerun of a
	# row (bead grm-x4y1.3) never clobbers that row's batch-section log. The ROM COPY keeps its
	# plain name on purpose: the program name reaches the dump as `REALROM program <id><ext>`.
	local id="$1" rom="$2" opts="$3" out="$4" tag="${5:-}"
	local safe rom_copy proj log
	safe="$(sanitize "$id")"
	rom_copy="$WORK/${safe}$ROM_COPY_EXT"
	cp -f "$rom" "$rom_copy"
	proj="$WORK/proj_${safe}${tag}"
	local -a delete_arg=(-deleteProject)
	if [ "$KEEP_PROJECT" = 1 ]; then
		# Fixed per-row path, wiped first so a kept project is always exactly this run's import.
		proj="$KEEP_DIR/$safe"
		rm -rf "$proj"
		delete_arg=()
	fi
	mkdir -p "$proj"
	log="$WORK/${safe}${tag}.log"

	rr_headless_args "$opts"
	# Under the shared per-run timeout (bead grm-x4y1.2): a hung import FAILs this row instead of
	# stalling the gate. The needle is this row's own project dir, so only its processes die.
	run_headless_timed 1 "row $id" "$log" "$(native "$proj")" \
		"$GHIDRA_HEADLESS" "$(native "$proj")" headless \
		-import "$(native "$rom_copy")" \
		"${RR_ARGS[@]}" \
		${delete_arg[@]+"${delete_arg[@]}"}
	local status=$?
	if [ $status -eq 124 ]; then
		echo "    TIMED OUT: analyzeHeadless for $id exceeded the headless timeout ($TIMEOUT_BANNER;" \
			"raise GRM_HEADLESS_TIMEOUT, or 0 disables) -- row FAILs (log: $log)" >&2
		return 1
	elif [ $status -ne 0 ]; then
		echo "    analyzeHeadless exited $status (log: $log)" >&2
		return 1
	fi

	if ! extract_dump "$log" "$out"; then
		echo "    no REALROM block produced (log: $log)" >&2
		return 1
	fi
	return 0
}

# The per-row tail, shared by the solo path and the batched path (bead grm-x4y1.3, as
# run-banktest.sh's finish_fixture is for grm-w9ev.5): given a row's normalized dump in $out,
# the second-layer hash check, candidate-cache write, bless/golden diff, ROW_* bookkeeping and the
# PASS/FAIL line. Reads the current platform's ROM_* (call use_platform first).
#
#   finish_row <id> <rom> <sha> <golden> <opts> <out> <key> <batched 0|1>
#
# BATCHED ROWS ARE HELD TO ONE EXTRA RULE (owner ruling 2026-10-14, bd memory
# realrom-shared-jvm-ok): shared JVMs are fine, so a batched dump that differs from its golden
# is NEVER silently replaced by a solo result -- that would paper over exactly the analysis
# determinism bug batching is supposed to surface. The row stays FAIL; up to GRM_REALROM_SOLO_RERUNS
# solo reruns are made as a DIAGNOSTIC (bead grm-u7cy) and the row is labelled "BATCH-DEPENDENT"
# (every solo rerun passes), "FLAKY" (they disagree; stops at the first disagreement) or "genuine
# diff" (every one fails, with a NONDETERMINISTIC note if their dumps differ from each other or
# from the batched one). A single rerun could not tell batch-dependent from flaky (grm-pwuh).
# bless is the same rule seen from the other side: a batched dump is blessed only if a solo
# import of the row reproduces it byte for byte (otherwise we would pin a golden that a plain
# `check --batch-size 1` could not reproduce). To keep bless cheap that solo import is made only
# when the batched dump would CHANGE the golden (or none exists); an unchanged dump is just
# re-written as-is.
finish_row() {
	local id="$1" rom="$2" sha="$3" golden="$4" opts="$5" out="$6" key="$7" batched="$8"
	local golden_path="$EXPECTED_DIR/$golden" cached="$CACHE_DIR/$key.dump"
	local solo_out="$WORK/${id}.solo.out"

	# Second-layer hash check: the SHA-256 Ghidra computed on the imported bytes must
	# equal the manifest pin (belt-and-suspenders over the index match).
	local dumped_sha
	dumped_sha="$(sed -n 's/^REALROM sha256 //p' "$out" | head -n1 | tr 'A-Z' 'a-z')"
	if [ "$dumped_sha" != "$sha" ]; then
		ROW_ID+=("$id"); ROW_STATUS+=("FAIL")
		ROW_DETAIL+=("sha mismatch: dumped=$dumped_sha manifest=$sha")
		n_fail=$((n_fail + 1))
		echo "    FAIL: program sha256 $dumped_sha != manifest $sha"
		echo "    (if the ROM file changed without its size/mtime moving, delete $ROM_SHA_INDEX)" >&2
		return 0
	fi

	# bless of a batched row that would change the golden: require the solo import to agree first
	# (see the header). Done BEFORE the cache write so a refused dump is never cached as a
	# blessable candidate.
	if [ "$batched" = 1 ] && [ "$MODE" = bless ] &&
		{ [ ! -f "$golden_path" ] || ! cmp -s "$golden_path" "$out"; }; then
		echo "    batched dump changes the golden; confirming with a solo import before blessing"
		if import_and_dump "$id" "$rom" "$opts" "$solo_out" ".solo" && cmp -s "$out" "$solo_out"; then
			echo "    solo import agrees with the batched dump"
		else
			ROW_ID+=("$id"); ROW_STATUS+=("FAIL")
			ROW_DETAIL+=("REFUSED to bless: solo import differs from batched dump (BATCH-DEPENDENT or nondeterministic)")
			n_fail=$((n_fail + 1))
			echo "    FAIL: REFUSED to bless -- the solo import of $id did not reproduce the batched" \
				"dump (BATCH-DEPENDENT output or a nondeterministic row: file a determinism bead)." \
				"Re-run with --batch-size 1 to bless it from a solo import."
			return 0
		fi
	fi

	# Known-good candidate (sha recheck passed): stash it so a follow-up bless
	# reuses it without re-importing. Disposable (build/-cache) same as run-banktest.sh's
	# candidate cache, so a write failure (grm-z34) disables caching for this row rather
	# than failing it -- but the publish is still atomic, so a torn write is never read
	# back as a valid entry.
	if [ -n "$key" ]; then
		if ! mkdir -p "$CACHE_DIR"; then
			echo "    NOTE: could not create $CACHE_DIR -- candidate cache disabled for $id" >&2
		elif ! grm_atomic_publish "$out" "$cached"; then
			echo "    NOTE: could not write candidate cache for $id -- skipping" >&2
			rm -f "$cached"
		fi
	fi

	if [ "$MODE" = bless ]; then
		if ! grm_atomic_publish "$out" "$golden_path"; then
			ROW_ID+=("$id"); ROW_STATUS+=("FAIL"); ROW_DETAIL+=("could not write $golden")
			n_fail=$((n_fail + 1))
			echo "    FAIL: could not write $golden_path"
			return 0
		fi
		ROW_ID+=("$id"); ROW_STATUS+=("BLESS"); ROW_DETAIL+=("$golden")
		n_bless=$((n_bless + 1))
		echo "    blessed -> $golden_path"
		return 0
	fi

	# check mode
	if [ ! -f "$golden_path" ]; then
		ROW_ID+=("$id"); ROW_STATUS+=("FAIL"); ROW_DETAIL+=("missing golden $golden (bless first)")
		n_fail=$((n_fail + 1))
		echo "    FAIL: golden not found: $golden_path"
		return 0
	fi
	if diff -u "$golden_path" "$out" >"$WORK/${id}.diff" 2>&1; then
		ROW_ID+=("$id"); ROW_STATUS+=("PASS"); ROW_DETAIL+=("")
		n_pass=$((n_pass + 1))
		echo "    PASS"
		return 0
	fi
	local detail="dump differs from golden"
	n_fail=$((n_fail + 1))
	echo "    FAIL: dump differs from golden (see $WORK/${id}.diff)"
	sed -n '1,40p' "$WORK/${id}.diff"
	if [ "$batched" = 1 ]; then
		# Diagnostic only -- the verdict above stands whatever this prints.
		local n_runs="$GRM_REALROM_SOLO_RERUNS" r s_out s_pass=0 s_fail=0 s_err=0 s_varies=0
		local first_ok=""
		echo "    running $id solo up to $n_runs time(s) as a diagnostic (the row stays FAIL either way)"
		for ((r = 1; r <= n_runs; r++)); do
			s_out="$WORK/${id}.solo$r.out"
			if ! import_and_dump "$id" "$rom" "$opts" "$s_out" ".solo$r"; then
				s_err=$((s_err + 1))
				echo "    solo rerun $r/$n_runs: import/dump error"
				continue
			fi
			# Any two dumps of the same row that differ prove nondeterminism, whatever the golden
			# says: compare every solo dump with the batched one and with the first solo dump.
			cmp -s "$out" "$s_out" || s_varies=1
			if [ -z "$first_ok" ]; then first_ok="$s_out"; else cmp -s "$first_ok" "$s_out" || s_varies=1; fi
			if diff -u "$golden_path" "$s_out" >"$WORK/${id}.solo$r.diff" 2>&1; then
				s_pass=$((s_pass + 1)); echo "    solo rerun $r/$n_runs: PASS"
			else
				s_fail=$((s_fail + 1)); echo "    solo rerun $r/$n_runs: FAIL"
			fi
			# A pass and a fail together already settle FLAKY; more samples cannot change that.
			[ "$s_pass" -gt 0 ] && [ "$s_fail" -gt 0 ] && break
		done
		local s_tally="solo passes $s_pass/$((s_pass + s_fail))"
		[ "$s_err" -eq 0 ] || s_tally="$s_tally, $s_err import error(s)"
		if [ $((s_pass + s_fail)) -eq 0 ]; then
			echo "    solo reruns: all import/dump errors -> inconclusive"
			detail="$detail (solo reruns inconclusive)"
		elif [ "$s_fail" -eq 0 ]; then
			echo "    solo reruns: $s_tally -> BATCH-DEPENDENT output (batch-sensitivity bug: file a bead)"
			detail="$detail; BATCH-DEPENDENT ($s_tally)"
			# The batched dump is not a trustworthy candidate for a later bless.
			[ -z "$key" ] || rm -f "$cached"
		elif [ "$s_pass" -gt 0 ]; then
			echo "    solo reruns: $s_tally -> FLAKY: nondeterministic even solo, NOT a batch leak" \
				"(determinism bug: file a bead; compare the $WORK/${id}.solo*.out dumps)"
			detail="$detail; FLAKY ($s_tally)"
			[ -z "$key" ] || rm -f "$cached"
		else
			echo "    solo reruns: $s_tally -> genuine diff"
			detail="$detail (genuine diff: $s_tally)"
			if [ "$s_varies" = 1 ]; then
				echo "    NOTE: the dumps differ from each other (row is NONDETERMINISTIC; compare $out" \
					"and the $WORK/${id}.solo*.out dumps)"
				detail="$detail, NONDETERMINISTIC"
				[ -z "$key" ] || rm -f "$cached"
			fi
		fi
	fi
	ROW_ID+=("$id"); ROW_STATUS+=("FAIL"); ROW_DETAIL+=("$detail")
	return 0
}

# One row, one analyzeHeadless JVM: the pre-grm-x4y1.3 flow, and still the whole flow at
# --batch-size 1, with --keep-project, and for batch-crash fallback.
run_row_solo() {
	local id="$1" title="$2" rom="$3" sha="$4" golden="$5" opts="$6" key="$7"
	local out="$WORK/${id}.dump"
	echo "-- $id ($title): importing $(basename "$rom")"
	if ! import_and_dump "$id" "$rom" "$opts" "$out"; then
		ROW_ID+=("$id"); ROW_STATUS+=("FAIL"); ROW_DETAIL+=("import/dump error")
		n_fail=$((n_fail + 1))
		return 0
	fi
	if [ "$KEEP_PROJECT" = 1 ]; then
		echo "    kept project: $KEEP_DIR/$(sanitize "$id")/headless.gpr"
	fi
	finish_row "$id" "$rom" "$sha" "$golden" "$opts" "$out" "$key" 0
}

# --- batched imports (bead grm-x4y1.3; modelled on run-banktest.sh's grm-w9ev.5 flush_batch) ---
# Rows are queued, then imported by ONE analyzeHeadless with several -import args (Ghidra
# headless processes them serially; the postScript runs once per program), so JVM startup is paid
# per batch rather than per row. A row may share a batch only if its import invocation is
# identical apart from the file: same platform (=> loader, import args, dump script, copy
# extension), same loader-opts column; the prescript and extra postscript are run-wide. Program
# names are the per-row ROM copies "<id><ext>" in $WORK, so they are unique within a project
# (ids are unique across all manifests); a duplicate would flush anyway.
#
# Failure isolation, as in run-banktest.sh: a batch that exits non-zero / times out, or a row
# whose log section or REALROM block is missing, is re-run solo so a crash is attributed to its
# row. A row whose batched dump merely DIFFERS from its golden is NOT re-run in its place -- see
# finish_row.
BQ_ID=(); BQ_TITLE=(); BQ_ROM=(); BQ_SHA=(); BQ_GOLDEN=(); BQ_KEY=()
BQ_PLAT=""; BQ_OPTS=""; BQ_NAMES=""
BATCH_SEQ=0

flush_batch() {
	local reason="${1:-unspecified}"
	local n=${#BQ_ID[@]}
	[ "$n" -gt 0 ] || return 0
	local ids=("${BQ_ID[@]}") titles=("${BQ_TITLE[@]}") roms=("${BQ_ROM[@]}") shas=("${BQ_SHA[@]}")
	local goldens=("${BQ_GOLDEN[@]}") keys=("${BQ_KEY[@]}")
	local plat="$BQ_PLAT" opts="$BQ_OPTS" saved_plat="$PLATFORM"
	BQ_ID=(); BQ_TITLE=(); BQ_ROM=(); BQ_SHA=(); BQ_GOLDEN=(); BQ_KEY=()
	BATCH_SEQ=$((BATCH_SEQ + 1))
	local seq=$BATCH_SEQ i
	echo "BATCH n=$n flush=$reason"
	# The row walk has already moved on to later rows' platforms; the batch needs its own.
	use_platform "$plat"
	if [ "$n" -eq 1 ]; then
		run_row_solo "${ids[0]}" "${titles[0]}" "${roms[0]}" "${shas[0]}" "${goldens[0]}" "$opts" "${keys[0]}"
		use_platform "$saved_plat"
		return 0
	fi

	local proj="$WORK/proj_batch$seq" blog="$WORK/batch$seq.log"
	mkdir -p "$proj"
	echo "== batch $seq: importing ${ids[*]} via analyzeHeadless ($ROM_LOADER) =="
	local imports=() bases=() pairs="" safe
	for i in "${!ids[@]}"; do
		safe="$(sanitize "${ids[$i]}")"
		cp -f "${roms[$i]}" "$WORK/${safe}$ROM_COPY_EXT"
		imports+=(-import "$(native "$WORK/${safe}$ROM_COPY_EXT")")
		bases+=("${safe}$ROM_COPY_EXT")
		# Forward slashes: awk -v would eat the backslashes of a Windows-style $WORK.
		pairs="$pairs ${safe}$ROM_COPY_EXT=${WORK//\\//}/${safe}.log"
		rm -f "$WORK/${safe}.log"
	done
	rr_headless_args "$opts"
	run_headless_timed "$n" "batch $seq" "$blog" "$(native "$proj")" \
		"$GHIDRA_HEADLESS" "$(native "$proj")" headless \
		"${imports[@]}" \
		"${RR_ARGS[@]}" \
		-deleteProject
	local status=$?
	grm_split_batch_log "$blog" "$pairs"

	for i in "${!ids[@]}"; do
		local id="${ids[$i]}" why="" out
		safe="$(sanitize "$id")"
		local sec="$WORK/${safe}.log"
		out="$WORK/${id}.dump"
		if [ "$status" -ne 0 ]; then
			why="batch analyzeHeadless exited $status"
			[ "$status" -eq 124 ] && why="batch analyzeHeadless timed out"
		elif [ ! -s "$sec" ]; then
			why="no section in the batch log"
		elif ! extract_dump "$sec" "$out"; then
			why="no REALROM block in its section of the batch log"
		fi
		if [ -n "$why" ]; then
			echo "NOTE: batch $seq FALLBACK -- re-running $id individually ($why; batch log: $blog)"
			run_row_solo "$id" "${titles[$i]}" "${roms[$i]}" "${shas[$i]}" "${goldens[$i]}" "$opts" "${keys[$i]}"
		else
			echo "-- $id (${titles[$i]}): importing $(basename "${roms[$i]}") [batch $seq, log: $sec]"
			finish_row "$id" "${roms[$i]}" "${shas[$i]}" "${goldens[$i]}" "$opts" "$out" "${keys[$i]}" 1
		fi
	done
	use_platform "$saved_plat"
}

while IFS=$'\t' read -r row_plat id title sha mapper board golden opts member ||
	[ -n "${id:-}" ]; do
	# Skip blank lines, the bare header row, and comments. The manifest deliberately carries
	# no `#` preamble (GitHub's tabular viewer has no comment syntax and would render it as
	# rows) -- see realrom/README.md -- but a one-off comment stays legal.
	case "${id:-}" in ""|id|\#*) continue ;; esac

	# SET membership. A set whose `rows` column is an explicit id list (today: core) admits
	# only those ids; a set with '*' admitted every id in its manifests during resolution. This
	# is applied BEFORE --only/--except so the two compose: --only narrows within the set.
	case "$SET_IDS" in
		*",$id,"*) ;;
		*) continue ;;
	esac

	# Row selection (--only/--except). Applied before any import work, so a filtered row
	# costs nothing. Filtered rows are counted but produce no ROW_* entry: they are not results.
	if { [ -n "$ONLY_IDS" ] && [ "${ONLY_IDS#*,$id,}" = "$ONLY_IDS" ]; } ||
		{ [ -n "$EXCEPT_IDS" ] && [ "${EXCEPT_IDS#*,$id,}" != "$EXCEPT_IDS" ]; }; then
		n_filtered=$((n_filtered + 1))
		echo "-- $id ($title): filtered out"
		continue
	fi

	# The row's PLATFORM decides its loader, dump script, copy extension and import args.
	# Installed per row rather than per run, which is what lets one invocation span platforms;
	# placed after the filters, and memoized, so filtered rows cost nothing (grm-x4y1.4).
	use_platform "$row_plat"
	sha="$(printf '%s' "$sha" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
	golden="${golden:-$id.dump}"
	opts="${opts:-}"
	golden_path="$EXPECTED_DIR/$golden"

	rom="${ROM_BY_SHA[$sha]:-}"
	if [ -z "$rom" ]; then
		ROW_ID+=("$id"); ROW_STATUS+=("SKIP"); ROW_DETAIL+=("no ROM with sha256=$sha")
		n_skip=$((n_skip + 1))
		echo "-- $id ($title): SKIP (ROM not supplied)"
		continue
	fi

	key="$(realrom_cache_key "$id" "$sha" "$opts")"
	cached="$CACHE_DIR/$key.dump"

	# bless fast path: reuse the candidate a prior check imported for this exact
	# ROM + opts + build, showing the golden diff before accepting it. The
	# cached dump was only stored after its sha recheck passed, so it is
	# known-good.
	if [ "$MODE" = bless ] && [ "$KEEP_PROJECT" = 0 ] && [ -n "$key" ] && [ -f "$cached" ]; then
		# Assert the candidate is about THIS row before believing the key. A cache key is a
		# claim that nothing outside it can change the dump, and that claim has been wrong
		# twice: the id was missing (a rename reused the pre-rename candidate and wrote the
		# old name back into the golden) and the loose data/machines/*.map descriptors were
		# outside ext_identity. Both are fixed above; this check is what makes the NEXT
		# omission fail loudly instead of silently blessing a stale dump, which is the whole
		# failure mode this tier exists to prevent.
		cached_prog="$(awk '/^REALROM program /{print $3; exit}' "$cached")"
		cached_sha="$(awk '/^REALROM sha256 /{print tolower($3); exit}' "$cached")"
		if [ "$cached_prog" != "$id$ROM_COPY_EXT" ] || [ "$cached_sha" != "$sha" ]; then
			echo "    stale cache entry ignored (program='$cached_prog' want='$id$ROM_COPY_EXT'," \
				"sha='$cached_sha' want='$sha') -- re-importing" >&2
			rm -f "$cached"
		else
			echo "-- $id ($title): reusing cached candidate from prior check (no re-import)"
			grm_touch_cache_entry "${cached%.dump}"	# LRU (grm-uqhd)
			if [ -f "$golden_path" ]; then
				diff -u "$golden_path" "$cached" && echo "    no change vs golden"
			fi
			# Atomic + fail-closed (grm-z34): a failed publish must not claim BLESS. No
			# criteria-refusal concept here (realrom-test.sh has none, per grm-z34's scoping
			# comment) -- only the write itself can fail.
			if ! grm_atomic_publish "$cached" "$golden_path"; then
				ROW_ID+=("$id"); ROW_STATUS+=("FAIL"); ROW_DETAIL+=("could not write $golden")
				n_fail=$((n_fail + 1))
				echo "    FAIL: could not write $golden_path"
				continue
			fi
			ROW_ID+=("$id"); ROW_STATUS+=("BLESS"); ROW_DETAIL+=("$golden (cached)")
			n_bless=$((n_bless + 1))
			echo "    blessed (from cache) -> $golden_path"
			continue
		fi
	fi

	# Batched path (bead grm-x4y1.3): queue the row; a batch is flushed when the next row cannot
	# share its import invocation, at the size cap, or after the last row.
	if [ "$BATCH_ON" -eq 1 ]; then
		bq_name="$(sanitize "$id")$ROM_COPY_EXT"
		if [ ${#BQ_ID[@]} -gt 0 ]; then
			if [ "$row_plat|$opts" != "$BQ_PLAT|$BQ_OPTS" ]; then
				flush_batch "platform-or-options-change:$id"
			elif [[ " ${BQ_NAMES} " == *" $bq_name "* ]]; then
				flush_batch "duplicate-program-name:$id"
			fi
		fi
		[ ${#BQ_ID[@]} -gt 0 ] || BQ_NAMES=""
		BQ_PLAT="$row_plat"; BQ_OPTS="$opts"; BQ_NAMES="$BQ_NAMES $bq_name"
		BQ_ID+=("$id"); BQ_TITLE+=("$title"); BQ_ROM+=("$rom"); BQ_SHA+=("$sha")
		BQ_GOLDEN+=("$golden"); BQ_KEY+=("$key")
		if [ ${#BQ_ID[@]} -ge "$BATCH_N" ]; then flush_batch "size-cap"; fi
		continue
	fi
	run_row_solo "$id" "$title" "$rom" "$sha" "$golden" "$opts" "$key"
# Process substitution, NOT a pipe: the loop body appends to ROW_ID/ROW_STATUS/ROW_DETAIL
# and bumps the n_* counters, and a pipe would run it in a subshell that discards every
# result at `done` -- while still exiting 0. The `tr` is a second layer behind
# .gitattributes' `*.tsv text eol=lf`, covering a working-tree copy an editor rewrote with
# CRLF after checkout; a stray \r on the row's last field otherwise rides into a path.
done < <(manifest_rows)
flush_batch "end"

echo
printf '%-16s %-6s %s\n' "ID" "STATUS" "DETAIL"
for i in "${!ROW_ID[@]}"; do
	printf '%-16s %-6s %s\n' "${ROW_ID[$i]}" "${ROW_STATUS[$i]}" "${ROW_DETAIL[$i]}"
done
echo
filtered_note=""
[ "$n_filtered" -gt 0 ] && filtered_note=" filtered=$n_filtered"
echo "summary: pass=$n_pass fail=$n_fail skip=$n_skip bless=$n_bless$filtered_note   (work: $WORK)"

# A SKIP is reported per row and is easy to accept as "that ROM does not exist here" when the
# real cause is a romdir that was never passed -- this tier indexes each dir at DEPTH 1 ONLY, so
# a title one directory down is invisible and a collection split across two dirs needs both named.
# That misreading has cost a re-measurement more than once (an agent concluded "6 of 12 rows are
# unmeasurable on this machine" while the missing six sat in a second dir the memory names), so
# say it out loud at the point the count is printed rather than only in this file's header.
if [ "$n_skip" -gt 0 ]; then
	echo "note: $n_skip row(s) SKIPPED for want of a ROM. If that is unexpected, suspect the DIR"
	echo "      LIST before concluding the ROMs are absent: dirs are indexed at depth 1 only, and"
	echo "      several may be given (GRM_ROM_DIR holds them space-separated, or ';'-separated"
	echo "      when a dir's own name has a space). Tried here:"
	for dir in ${ALL_INDEXED_DIRS[@]+"${ALL_INDEXED_DIRS[@]}"}; do
		echo "        $dir"
	done
fi

# SKIPPED means nothing was actually verified (no ROMs matched) -- do not stamp, so the
# "nobody ran this" signal stays honest.
if [ "$n_pass" -eq 0 ] && [ "$n_fail" -eq 0 ] && [ "$n_bless" -eq 0 ]; then
	echo "REALROM $MODE: SKIPPED (no matching ROMs supplied) -- nothing verified"
	[ "$WORK_IS_OURS" = 1 ] && rm -rf "$WORK"	# nothing worth keeping (grm-uqhd)
	[ "$REQUIRE_ALL" = 1 ] && [ "$n_skip" -gt 0 ] && exit 1	# --require-all (grm-x4y1.2)
	exit 0
fi

# Refresh the staleness stamp (bead grm-6kv) whenever rows actually ran -- INCLUDING a FAIL.
# The stamp answers "has anyone run this tier lately", not "did it pass": megaman/smb3 fail
# on an unchanged tree BY DESIGN (see the header note), so gating the stamp on n_fail==0
# would mean it can never update on an ordinary row set and the staleness signal would
# permanently read "never run" even when someone diligently runs it every time. A FAIL is
# already loud on its own (nonzero exit, "REALROM $MODE: FAIL" below) -- recording that a
# run happened at this commit is a separate, additional fact, not a claim that it was clean.
# Best-effort: a failure to write the stamp does not change the pass/fail verdict below, but
# is not swallowed silently either -- atomic via grm_atomic_publish_stdin (lib/common.sh,
# grm-z34), so an interrupted write is never read back as a valid (and misleadingly fresh)
# stamp.
#
# WHETHER A RUN STAMPS AT ALL IS A DECLARED PLATFORM PROPERTY (platforms.tsv
# `stamps_staleness`), not a hardcoded check for one platform's name. The stamp answers ONE
# question -- "has anyone checked real-ROM ANALYSIS regressions at this commit" -- and it is
# what CLAUDE.md points at when it requires this tier before committing a change to
# BoardBankAnalyzer, a BankSwitchStrategy or StoredValueScanner. The SNES rows import with
# -noanalysis and exercise none of that, so letting them refresh the stamp would let a
# thirteen-row loader run silently mark the NES analysis tier as freshly verified -- exactly
# the "quiet green for a tier that did not execute" this stamp exists to prevent. Declaring it
# means the next -noanalysis platform inherits the right behaviour instead of the wrong one.
stamp_ok=0
stamp_skipped=""
for p in "${PLATFORMS_USED[@]}"; do
	if [ "$(tsv_field "$PLATFORMS_TSV" "$p" stamps_staleness)" = yes ]; then
		stamp_ok=1
	else
		stamp_skipped="$stamp_skipped $p"
	fi
done
[ -z "$stamp_skipped" ] ||
	echo "note: platform(s)$stamp_skipped do not refresh the REALROM staleness stamp -- they" \
		"verify loader layout with -noanalysis and say nothing about analysis regressions."

# THE STAMP RECORDS WHICH SETS RAN, not merely that something did (bead grm-ughg). Once `core`
# exists -- a five-row, ~40s floor -- a stamp that said only "someone ran the tier at this
# commit" would let the cheap run silence the warning whose entire job is to demand the
# expensive one. That would be a regression in honesty introduced by the tiering itself, so
# the set list is part of the stamp and grm_realrom_staleness_note() reports it. Line 3 is an
# ADDITION: a pre-existing two-line stamp still reads correctly, as "sets: unknown".
if [ "$stamp_ok" -eq 0 ]; then
	: # nothing in this run is entitled to stamp
elif mkdir -p "$(dirname "$GRM_REALROM_STAMP")" 2>/dev/null; then
	stamp_head="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
	# A run covers the named SETS only in NAME: it may have run two rows of thirty-three.
	# Recording the set list alone would therefore be a MORE specific claim than the
	# pre-grm-ughg stamp made and a wronger one, so a partial run says so and carries the row
	# counts. The stamp may under-claim, never over-claim -- same principle as the CORE note.
	#
	# BOTH causes count, and the SKIP one is the dangerous half. A --only/--except run is
	# partial ON PURPOSE and the caller knows it. A SKIPPED row means the ROM was not found,
	# which is usually a WRONG DIR LIST rather than a missing image -- the misreading CLAUDE.md
	# warns about at length, and the one time you least want this stamp claiming full coverage.
	# Counting only the deliberate cause would have left "1 row ran, 32 ROMs missing" stamping
	# exactly like a clean full-tier run.
	stamp_ran=$((n_pass + n_fail + n_bless))
	stamp_total=$((stamp_ran + n_skip + n_filtered))
	stamp_sets_line="${RESOLVED_SETS[*]}"
	if [ "$n_filtered" -gt 0 ] || [ "$n_skip" -gt 0 ]; then
		stamp_why=""
		[ "$n_filtered" -gt 0 ] && stamp_why="$n_filtered filtered by --only/--except"
		if [ "$n_skip" -gt 0 ]; then
			[ -n "$stamp_why" ] && stamp_why="$stamp_why, "
			stamp_why="$stamp_why$n_skip skipped for want of a ROM"
		fi
		stamp_sets_line="$stamp_sets_line (PARTIAL: $stamp_ran of $stamp_total row(s) ran;"
		stamp_sets_line="$stamp_sets_line $stamp_why)"
	fi
	# Line 4 (bead grm-qp5x.3): which decompiler build produced these results -- the install
	# carries a locally patched decompile.exe, see grm_decompiler_build_name in lib/common.sh.
	stamp_decomp_hash="$(grm_decompiler_hash)"
	stamp_content="$stamp_head
$(date -u +%Y-%m-%dT%H:%M:%SZ)
$stamp_sets_line
$(grm_decompiler_build_name "$stamp_decomp_hash") (${stamp_decomp_hash:-no hash})"
	if ! printf '%s\n' "$stamp_content" | grm_atomic_publish_stdin "$GRM_REALROM_STAMP"; then
		echo "NOTE: could not update $GRM_REALROM_STAMP (staleness signal will be stale itself)" >&2
	fi
else
	echo "NOTE: could not create $(dirname "$GRM_REALROM_STAMP") -- staleness stamp not updated" >&2
fi

if [ "$n_fail" -gt 0 ]; then
	# Keep logs, dumps and diffs for diagnosis, but drop the bulk (bead grm-uqhd): the ROM copies
	# (re-derivable from the ROM dir, and copyrighted images we would rather not scatter) and any
	# leftover proj_* dirs. A caller-named REALROM_WORK_DIR is theirs and is left untouched.
	if [ "$WORK_IS_OURS" = 1 ]; then
		find "$WORK" -maxdepth 1 -type f \( -name '*.nes' -o -name '*.sfc' \) -delete 2>/dev/null
		find "$WORK" -maxdepth 1 -type d -name 'proj_*' -exec rm -rf {} + 2>/dev/null
	fi
	echo "REALROM $MODE: FAIL"
	exit 1
fi
# Success: nothing in $WORK is worth keeping (run-banktest.sh does the same at its end), and
# 200+ never-removed realrom.* dirs of ROM copies were 1.7 GB (bead grm-uqhd).
[ "$WORK_IS_OURS" = 1 ] && rm -rf "$WORK"
# A run with SKIPs still exits 0 (callers rely on it) but must not read like a clean full pass
# (bead grm-x4y1.2); --require-all opts into failing on any skip.
if [ "$n_skip" -gt 0 ]; then
	if [ "$REQUIRE_ALL" = 1 ]; then
		echo "REALROM $MODE: FAIL ($n_skip skipped, --require-all)"
		exit 1
	fi
	echo "REALROM $MODE: OK (PARTIAL: $n_skip skipped)"
	exit 0
fi
echo "REALROM $MODE: OK"
exit 0
