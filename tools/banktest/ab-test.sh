#!/usr/bin/env bash
# Scripted real-ROM A/B (bead grm-5jjs). Turns the hand-run procedure documented across the
# realrom-ab-needs-rebuild / realrom-howto / which-script-builds-the-extension bd memories into
# one command, with the grm-mej.2 "both sides must actually differ" guard ENFORCED instead of
# merely printed.
#
# THE KEY ENABLER: git worktrees. Each side gets its own throwaway worktree, and therefore its
# own REPO_ROOT and its own per-worktree build/ghidra-home -- so "forgot to rebuild between
# sides" is structurally impossible rather than a discipline you must remember. This also means
# the sides could run concurrently (not done here, to keep the script simple and the output
# readable; nothing prevents it later).
#
# WHAT grm-4t2d MADE REDUNDANT: the bead's original sketch called for, per side,
#   `build-and-test.sh check nes-banking` THEN `realrom-test.sh check ...`
# As of grm-4t2d option (e), realrom-test.sh builds and stages the extension itself
# (gradle stageExtensionForTests) before analyzing -- so this script calls realrom-test.sh ONLY.
# Running build-and-test.sh per side first would just pay for the same build twice.
#
# Usage:
#   ab-test.sh [options] REF_A REF_B [REF_C]
#   ab-test.sh --dirty   [options] REF_B
#
#   REF_A, REF_B, REF_C   git refs (commit/branch/tag). Three refs compares adjacent pairs,
#                         named BASE/MID/TIP (attributing two commits separately).
#   --dirty REF           side A is the CURRENT working tree, UNTOUCHED -- no worktree, no
#                         checkout, your uncommitted changes are the side. Side B (REF) gets a
#                         worktree as usual. A dirty tree cannot be checked out twice, so this
#                         is the only way to A/B uncommitted work; the alternative is committing
#                         it to a throwaway branch and passing two refs instead.
#                         Mutually exclusive with supplying REF_A.
#
# Row selection (forwarded verbatim to realrom-test.sh; same semantics there):
#   --gme | --all             select the SET (default, with neither given: core, 5 rows)
#   --only IDS | --except IDS filter WITHIN whichever set --gme/--all (or the core default)
#                             selected -- they narrow it, they do NOT widen it. An --only
#                             naming rows outside core (e.g. dodge, lwings) needs --all or
#                             --gme too, or every named row is filtered out and NOTHING is
#                             compared (see grm-29a9: this used to print a false movement=NO).
#
#   *** A SINGLE-ROW A/B CAN MASK ORDER-DEPENDENT MOVEMENT. *** tmnt (grm-82u3, 2026-08-28)
#   passed on both sides of `--only tmnt` alone and FAILED on the second side of
#   `--only tetris,tmnt` -- same two builds, different verdict, because Ghidra's ClassSearcher
#   indexing is apparently sensitive to which program is analyzed first in an invocation. This
#   script WARNS if --only names exactly one id with no comma. Prefer naming at least one
#   preceding row (`--only <other-id>,<id-you-care-about>`), or use --gme/--all.
#
# Repeat / nondeterminism handling (bistable-golden-sticky-states):
#   --repeat N            run EACH side N times (default 1). Sticky rows are NOT independent
#                         per-run draws -- dodge and ff1 traded places between two consecutive
#                         --all runs on 2026-08-28, and tmnt was byte-identical across two. The
#                         report is therefore a per-side SET of observed dump hashes per id, not
#                         a single diff. A single non-matching run proves nothing.
#
# Dump-shape / toolchain variants:
#   --raise-sample N       raise RealRomDump.java's SAMPLE constant to N on BOTH sides before
#                         running, to see WHICH sample line moved instead of just a count. This
#                         is a headless SCRIPT edit, not part of the extension, so it needs no
#                         rebuild -- but it changes the dump shape, so realrom-test.sh's own
#                         PASS/FAIL against the (unraised) golden is MEANINGLESS under this flag
#                         and this script refuses to report it as a verdict. Dump-vs-dump
#                         diffing (this script's actual comparison) remains valid.
#   --toolchain VERSION    hold source BYTE-IDENTICAL and flip ONLY the LAST side's
#                         gradle.properties' ghidraTargetVersion to VERSION (the grm-9wl6
#                         method). Because the source is unchanged, the two sides' installed
#                         EXTENSION content is expected to be IDENTICAL -- so under this flag the
#                         identity guard checks the resolved Ghidra install path instead of
#                         ext_identity(), and a note explains why ext_identity matching is
#                         expected, not a bug.
#
# Other:
#   --romdir DIR           forwarded to realrom-test.sh (repeatable). Default: GRM_ROM_DIR.
#   --keep-worktrees        do not remove the throwaway worktrees on exit (post-mortem).
#   -h | --help
#
# THE GRM-MEJ.2 GUARD, ENFORCED: after both sides build, this script asserts their installed
# extension identities (ext_identity(), lib/common.sh) DIFFER (or, under --toolchain, that their
# resolved Ghidra install paths differ) and ABORTS LOUDLY if they do not. A silent zero-movement
# claim from comparing a build against itself is exactly what cost grm-mej.2 a committed, pushed,
# wrong result -- this makes that outcome impossible to produce from this script rather than
# merely detectable by eye.
#
# Every side's dumps are compared DUMP-vs-DUMP, never against the golden -- unchanged from the
# hand-run procedure, and the only comparison that is meaningful under --raise-sample.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Establishes REPO_ROOT and GRM_TARGET_VERSION, and defines native()/ext_identity()/etc.
. "$SCRIPT_DIR/lib/common.sh"

usage() {
	sed -n '2,/^set -u/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
	usage
	exit 0
fi

DIRTY=0
ONLY_IDS=""
EXCEPT_IDS=""
ROWFLAG=""
REPEAT=1
RAISE_SAMPLE=""
TOOLCHAIN_VERSION=""
KEEP_WORKTREES=0
ROMDIRS=()
REFS=()

while [ $# -gt 0 ]; do
	case "$1" in
		--dirty) DIRTY=1; shift ;;
		--only) [ $# -ge 2 ] || { echo "ERROR: --only needs an id list" >&2; exit 2; }
			ONLY_IDS="$2"; shift 2 ;;
		--except) [ $# -ge 2 ] || { echo "ERROR: --except needs an id list" >&2; exit 2; }
			EXCEPT_IDS="$2"; shift 2 ;;
		--gme) ROWFLAG="--gme"; shift ;;
		--all) ROWFLAG="--all"; shift ;;
		--repeat) [ $# -ge 2 ] || { echo "ERROR: --repeat needs a count" >&2; exit 2; }
			REPEAT="$2"; shift 2 ;;
		--raise-sample) [ $# -ge 2 ] || { echo "ERROR: --raise-sample needs a count" >&2; exit 2; }
			RAISE_SAMPLE="$2"; shift 2 ;;
		--toolchain) [ $# -ge 2 ] || { echo "ERROR: --toolchain needs a target ghidraTargetVersion" >&2; exit 2; }
			TOOLCHAIN_VERSION="$2"; shift 2 ;;
		--romdir) [ $# -ge 2 ] || { echo "ERROR: --romdir needs a path" >&2; exit 2; }
			ROMDIRS+=("$2"); shift 2 ;;
		--keep-worktrees) KEEP_WORKTREES=1; shift ;;
		-h|--help) usage; exit 0 ;;
		-*) echo "ERROR: unknown option '$1'" >&2; usage >&2; exit 2 ;;
		*) REFS+=("$1"); shift ;;
	esac
done

if [ -n "$ONLY_IDS" ] && [ -n "$EXCEPT_IDS" ]; then
	echo "ERROR: --only and --except are mutually exclusive (matches realrom-test.sh)" >&2
	exit 2
fi
if [ -n "$ONLY_IDS" ]; then
	n_ids=$(( $(printf '%s' "$ONLY_IDS" | tr -cd ',' | wc -c) + 1 ))
	if [ "$n_ids" -eq 1 ]; then
		echo "WARNING: --only names exactly ONE row ('$ONLY_IDS'). A single-row A/B can MASK" >&2
		echo "  order-dependent movement -- tmnt passed alone and failed with a preceding row" >&2
		echo "  in the same invocation (grm-82u3, 2026-08-28). Consider --only <other>,$ONLY_IDS" >&2
		echo "  or --gme/--all instead. Proceeding anyway." >&2
	fi
fi

# --- grm-29a9 point 4: catch a --only that names ids outside the selected set(s), BEFORE ----
# either side runs. This is the actual user error grm-29a9 was filed over: --only/--except
# filter WITHIN whatever --gme/--all (or the core default) selected, they do not widen it, so
# an id that exists in some manifest but not in the selected set is silently "filtered out"
# by realrom-test.sh on every side -- comparing nothing while still printing a verdict.
#
# This duplicates a (much smaller) slice of realrom-test.sh's own set/platform resolution
# (realrom/sets.tsv, realrom/platforms.tsv) rather than reusing it directly, because
# realrom-test.sh has no "just resolve ids, don't run anything" mode to call into. Kept
# deliberately minimal: this script only ever forwards ROWFLAG as "" / --gme / --all.
REALROM_DIR="$SCRIPT_DIR/realrom"
SETS_TSV="$REALROM_DIR/sets.tsv"

ab_tsv_field() {
	local file="$1" key="$2" column="$3"
	awk -F'\t' -v key="$key" -v col="$column" '
		NR == 1 { for (i = 1; i <= NF; i++) if ($i == col) c = i; next }
		!/^#/ && NF && $1 == key { if (c) { print $c; found = 1 } exit }
		END { exit(found ? 0 : 1) }
	' "$file"
}
ab_tsv_column() {
	local file="$1" column="$2"
	awk -F'\t' -v col="$column" '
		NR == 1 { for (i = 1; i <= NF; i++) if ($i == col) c = i; next }
		!/^#/ && NF && c { print $c }
	' "$file"
}

# Prints every id the current ROWFLAG's selected set(s) admit, one per line.
resolve_rowflag_ids() {
	local set_names=() s s_rows mf mpath old_ifs
	case "$ROWFLAG" in
		"") set_names=(core) ;;
		--gme) set_names=(nes-gme) ;;
		--all)
			while IFS= read -r s; do
				[ "$(ab_tsv_field "$SETS_TSV" "$s" platform 2>/dev/null)" = nes ] || continue
				set_names+=("$s")
			done < <(ab_tsv_column "$SETS_TSV" set)
			;;
	esac
	for s in "${set_names[@]}"; do
		s_rows="$(ab_tsv_field "$SETS_TSV" "$s" rows 2>/dev/null || true)"
		if [ "$s_rows" = '*' ]; then
			old_ifs="$IFS"; IFS=','
			for mf in $(ab_tsv_field "$SETS_TSV" "$s" manifests); do
				IFS="$old_ifs"
				mpath="$REALROM_DIR/$mf"
				[ -f "$mpath" ] || continue
				awk -F'\t' '!/^#/ && NF && $1 != "id" { sub(/\r$/, "", $1); print $1 }' "$mpath"
				IFS=','
			done
			IFS="$old_ifs"
		else
			printf '%s\n' "$s_rows" | tr ',' '\n'
		fi
	done
}

if [ -n "$ONLY_IDS" ] && [ -f "$SETS_TSV" ]; then
	mapfile -t _rowflag_ids < <(resolve_rowflag_ids | LC_ALL=C sort -u)
	_unknown=()
	old_ifs="$IFS"; IFS=','
	for _id in $ONLY_IDS; do
		IFS="$old_ifs"
		_found=0
		for _sid in ${_rowflag_ids[@]+"${_rowflag_ids[@]}"}; do
			[ "$_sid" = "$_id" ] && { _found=1; break; }
		done
		[ "$_found" -eq 1 ] || _unknown+=("$_id")
		IFS=','
	done
	IFS="$old_ifs"
	if [ "${#_unknown[@]}" -gt 0 ]; then
		echo "WARNING: --only names id(s) NOT in the selected set (${ROWFLAG:-core, the default}):" >&2
		echo "  ${_unknown[*]}" >&2
		echo "  --only/--except filter WITHIN the selected set(s); they do not widen it. The" >&2
		echo "  default is core (5 rows) -- an --only naming rows outside core needs --gme or" >&2
		echo "  --all too. As given, these id(s) will be filtered out by realrom-test.sh on" >&2
		echo "  EVERY side, comparing nothing for them (grm-29a9). Proceeding anyway." >&2
	fi
fi

# --- resolve the side list -------------------------------------------------
# Each side is: LABEL, REF (empty for the dirty side), TOOLCHAIN (1 if this side gets the
# gradle.properties patch).
declare -a SIDE_LABEL SIDE_REF SIDE_TOOLCHAIN

if [ "$DIRTY" -eq 1 ]; then
	if [ "${#REFS[@]}" -ne 1 ]; then
		echo "ERROR: --dirty takes exactly one REF (the other side); got ${#REFS[@]}" >&2
		usage >&2
		exit 2
	fi
	SIDE_LABEL=(A B)
	SIDE_REF=("" "${REFS[0]}")
	SIDE_TOOLCHAIN=(0 0)
else
	case "${#REFS[@]}" in
		2) SIDE_LABEL=(A B); SIDE_REF=("${REFS[0]}" "${REFS[1]}"); SIDE_TOOLCHAIN=(0 0) ;;
		3) SIDE_LABEL=(BASE MID TIP); SIDE_REF=("${REFS[0]}" "${REFS[1]}" "${REFS[2]}"); SIDE_TOOLCHAIN=(0 0 0) ;;
		*)
			echo "ERROR: need 2 or 3 REFs (or --dirty REF); got ${#REFS[@]}: ${REFS[*]:-<none>}" >&2
			usage >&2
			exit 2
			;;
	esac
fi
N_SIDES="${#SIDE_LABEL[@]}"

if [ -n "$TOOLCHAIN_VERSION" ]; then
	SIDE_TOOLCHAIN[$((N_SIDES - 1))]=1
	echo "== --toolchain: last side (${SIDE_LABEL[$((N_SIDES - 1))]}) gets ghidraTargetVersion=$TOOLCHAIN_VERSION =="
	echo "   Source is expected to be identical across sides under this flag; the identity" \
		"guard below checks the resolved Ghidra install, not the extension content."
fi

case "$REPEAT" in
	''|*[!0-9]*) echo "ERROR: --repeat must be a positive integer, got '$REPEAT'" >&2; exit 2 ;;
esac
if [ "$REPEAT" -lt 1 ]; then
	echo "ERROR: --repeat must be >= 1" >&2
	exit 2
fi

if [ -n "$RAISE_SAMPLE" ]; then
	case "$RAISE_SAMPLE" in
		''|*[!0-9]*) echo "ERROR: --raise-sample must be a positive integer, got '$RAISE_SAMPLE'" >&2; exit 2 ;;
	esac
	echo "== --raise-sample $RAISE_SAMPLE: RealRomDump.java's SAMPLE will be raised on every" \
		"side. realrom-test.sh's own PASS/FAIL against the (unraised) golden is MEANINGLESS" \
		"under this flag and will NOT be reported as a verdict below -- only this script's" \
		"dump-vs-dump diff is trustworthy here. =="
fi

# --- work area --------------------------------------------------------------
# WITHOUT a dot-leading path segment (bead grm-hhd / bd memory worktree-gate-dot-path):
# Ghidra's ProjectLocator rejects one, and grm_work_dir()'s automatic fallback only covers
# REPO_ROOT for the *invoking* worktree -- a throwaway worktree this script creates gets its
# own REPO_ROOT, so it is simplest to just never put one under a dotted path in the first
# place, matching the existing sibling-worktree convention already in use in this checkout
# (e.g. "ghidra-retro-machines-bisect2").
AB_TAG="ab-$$"
AB_BASE="${REPO_ROOT}-${AB_TAG}"
mkdir -p "$AB_BASE" || { echo "ERROR: could not create $AB_BASE" >&2; exit 1; }
echo "== ab-test work area: $AB_BASE =="

CREATED_WORKTREES=()

# Removes only the git WORKTREES (the expensive/large resource); the logs and dump copies
# collected directly under $AB_BASE are left in place either way, so a failed run (guard abort
# or otherwise) is still diagnosable afterward. $AB_BASE itself is never rm -rf'd by this
# script -- it holds no checkout of its own, only logs/*.dump siblings -- so the user can clean
# it up by hand once done reading it.
cleanup() {
	if [ "$KEEP_WORKTREES" -eq 1 ]; then
		echo "== --keep-worktrees: leaving ${#CREATED_WORKTREES[@]} worktree(s) in place =="
		for wt in "${CREATED_WORKTREES[@]:-}"; do
			[ -n "$wt" ] && echo "   $wt"
		done
		return
	fi
	for wt in "${CREATED_WORKTREES[@]:-}"; do
		[ -n "$wt" ] || continue
		echo "== removing worktree $wt =="
		git -C "$REPO_ROOT" worktree remove --force "$wt" 2>&1 || \
			echo "  WARN: could not remove worktree $wt (left in place)" >&2
	done
	echo "== logs and dumps kept at $AB_BASE (rm -rf it yourself once done) =="
}
trap cleanup EXIT

# --- set up each side's checkout ---------------------------------------------------------
declare -a SIDE_ROOT
for i in $(seq 0 $((N_SIDES - 1))); do
	label="${SIDE_LABEL[$i]}"
	ref="${SIDE_REF[$i]}"
	if [ "$DIRTY" -eq 1 ] && [ "$i" -eq 0 ]; then
		SIDE_ROOT[$i]="$REPO_ROOT"
		echo "== side $label: current working tree, UNTOUCHED ($REPO_ROOT) =="
	else
		wt="$AB_BASE/$label"
		echo "== side $label: git worktree add --detach $wt $ref =="
		if ! git -C "$REPO_ROOT" worktree add --detach "$wt" "$ref" >&2; then
			echo "ERROR: could not create worktree for ref '$ref'" >&2
			exit 1
		fi
		CREATED_WORKTREES+=("$wt")
		SIDE_ROOT[$i]="$wt"
	fi

	if [ "${SIDE_TOOLCHAIN[$i]}" -eq 1 ]; then
		gp="${SIDE_ROOT[$i]}/gradle.properties"
		if ! grep -q '^ghidraTargetVersion=' "$gp"; then
			echo "ERROR: $gp has no ghidraTargetVersion= line to patch" >&2
			exit 1
		fi
		sed -i "s/^ghidraTargetVersion=.*/ghidraTargetVersion=$TOOLCHAIN_VERSION/" "$gp"
		echo "   patched $gp -> ghidraTargetVersion=$TOOLCHAIN_VERSION"
	fi

	if [ -n "$RAISE_SAMPLE" ]; then
		rd="${SIDE_ROOT[$i]}/tools/banktest/RealRomDump.java"
		if ! grep -qE 'SAMPLE = [0-9]+' "$rd"; then
			echo "ERROR: $rd has no 'SAMPLE = <n>' to raise" >&2
			exit 1
		fi
		sed -i -E "s/SAMPLE = [0-9]+/SAMPLE = $RAISE_SAMPLE/" "$rd"
		echo "   patched $rd -> SAMPLE = $RAISE_SAMPLE"
	fi

	# Per-side cache: NOT reliably clean even though each worktree is its own tree -- the
	# --dirty side reuses the real repo's build/ dir, which may carry cache from an earlier
	# run. Clearing it unconditionally matches realrom-howto's "before blessing any
	# suspected-nondeterministic row" discipline, cheaply, on every side, every time.
	rm -rf "${SIDE_ROOT[$i]}/build/realrom-cache"

	# Belt and braces, no longer load-bearing. Writing this script exposed an ordering bug in
	# the runners: grm_settings_base_fallback() decides whether to use the isolated
	# build/ghidra-home settings dir by testing whether that directory ALREADY EXISTS, and it
	# ran BEFORE grm_ensure_extension_staged(), which is what creates it. On a brand-new
	# worktree -- this script's whole premise -- the check lost silently and realrom-test.sh
	# analyzed the SHARED %APPDATA% install instead of the isolated one that side had just
	# built. Commit 48b63ce fixed it at the source by staging first, so this mkdir is no
	# longer required; it is kept because it costs nothing and makes this script correct even
	# against an older checkout of the runners.
	mkdir -p "${SIDE_ROOT[$i]}/build/ghidra-home"
done

# --- run realrom-test.sh on each side ----------------------------------------------------
# NOTE on what grm-4t2d made redundant: the bead's sketch called for a `build-and-test.sh
# check nes-banking` per side before realrom-test.sh. realrom-test.sh now stages the
# extension itself (gradle stageExtensionForTests) before analyzing, so that separate build
# step is a no-op-with-extra-steps here and is deliberately NOT run.
declare -a ROWARGS
ROWARGS=()
[ -n "$ROWFLAG" ] && ROWARGS+=("$ROWFLAG")
[ -n "$ONLY_IDS" ] && ROWARGS+=(--only "$ONLY_IDS")
[ -n "$EXCEPT_IDS" ] && ROWARGS+=(--except "$EXCEPT_IDS")

declare -a SIDE_EXTID SIDE_INSTALL
declare -A DUMP_HASHES   # key "$label:$id" -> space-separated list of sha256 dump hashes across repeats
declare -A SEEN_IDS

for i in $(seq 0 $((N_SIDES - 1))); do
	label="${SIDE_LABEL[$i]}"
	root="${SIDE_ROOT[$i]}"
	side_extid=""
	side_install=""
	echo
	echo "############################################################"
	echo "## side $label  (root: $root, ref: ${SIDE_REF[$i]:-<dirty>})"
	echo "############################################################"

	for r in $(seq 1 "$REPEAT"); do
		rep_work="$AB_BASE/work-$label-$r"
		mkdir -p "$rep_work"
		log="$AB_BASE/log-$label-$r.txt"
		echo "-- side $label repeat $r/$REPEAT (work dir: $rep_work, log: $log) --"
		# shellcheck disable=SC2086
		REALROM_WORK_DIR="$rep_work" \
			bash "$root/tools/banktest/realrom-test.sh" check "${ROWARGS[@]}" \
			${ROMDIRS[@]:+"${ROMDIRS[@]}"} >"$log" 2>&1
		rc=$?
		cat "$log"

		extid_line="$(grep -m1 '^== installed extension: ' "$log" || true)"
		install_line="$(grep -m1 '^== ghidra install: ' "$log" || true)"
		this_extid="$(printf '%s' "$extid_line" | sed -n 's/^== installed extension: \([^ ]*\).*/\1/p')"
		this_install="$(printf '%s' "$install_line" | sed -n 's/^== ghidra install: \([^ ]*\).*/\1/p')"

		if [ "$r" -eq 1 ]; then
			side_extid="$this_extid"
			side_install="$this_install"
		elif [ "$this_extid" != "$side_extid" ] || [ "$this_install" != "$side_install" ]; then
			echo "ERROR: side $label's installed extension/identity CHANGED between repeats" \
				"($side_extid/$side_install -> $this_extid/$this_install). Repeats of the same" \
				"side must run the SAME build; something rebuilt or reinstalled mid-repeat." >&2
			exit 1
		fi

		# Collect a dump hash per id this repeat actually produced (PASS or FAIL rows --
		# anything with a dump file present; SKIP/filtered rows have none).
		for dumpfile in "$rep_work"/*.dump; do
			[ -f "$dumpfile" ] || continue
			id="$(basename "$dumpfile" .dump)"
			h="$(sha256sum "$dumpfile" | cut -d' ' -f1)"
			key="$label:$id"
			SEEN_IDS["$id"]=1
			if [ -z "${DUMP_HASHES[$key]:-}" ]; then
				DUMP_HASHES["$key"]="$h"
			else
				case " ${DUMP_HASHES[$key]} " in
					*" $h "*) ;;  # already recorded
					*) DUMP_HASHES["$key"]="${DUMP_HASHES[$key]} $h" ;;
				esac
			fi
			cp -f "$dumpfile" "$AB_BASE/${label}__${id}__r${r}.dump"
		done
	done

	SIDE_EXTID[$i]="$side_extid"
	SIDE_INSTALL[$i]="$side_install"
	echo "== side $label summary: extension identity=${side_extid:-UNKNOWN}" \
		"ghidra install=${side_install:-UNKNOWN} =="
done

# --- THE GRM-MEJ.2 GUARD, ENFORCED ------------------------------------------------------
echo
echo "== identity guard =="
GUARD_FAILED=0
for i in $(seq 0 $((N_SIDES - 2))); do
	j=$((i + 1))
	li="${SIDE_LABEL[$i]}"; lj="${SIDE_LABEL[$j]}"
	if [ "${SIDE_TOOLCHAIN[$i]}" -eq 1 ] || [ "${SIDE_TOOLCHAIN[$j]}" -eq 1 ]; then
		# --toolchain: source is deliberately identical, so ext_identity is EXPECTED to
		# match. The thing that must differ is the resolved Ghidra install (encodes the
		# version), since that's the only knob this variant turns.
		if [ -z "${SIDE_INSTALL[$i]}" ] || [ -z "${SIDE_INSTALL[$j]}" ]; then
			echo "ABORT: side $li or $lj has an UNKNOWN ghidra install path -- cannot verify the" \
				"toolchain guard. See the logs in $AB_BASE." >&2
			GUARD_FAILED=1
			continue
		fi
		if [ "${SIDE_INSTALL[$i]}" = "${SIDE_INSTALL[$j]}" ]; then
			echo "ABORT: sides $li and $lj resolved to the SAME Ghidra install" \
				"(${SIDE_INSTALL[$i]}) under --toolchain. The two sides are not actually" \
				"comparing different toolchains -- find out why before trusting anything" \
				"below." >&2
			GUARD_FAILED=1
		else
			echo "OK: sides $li/$lj resolved to different Ghidra installs" \
				"(${SIDE_INSTALL[$i]} vs ${SIDE_INSTALL[$j]}), as --toolchain requires."
			if [ "${SIDE_EXTID[$i]}" != "${SIDE_EXTID[$j]}" ]; then
				echo "   NOTE: extension identity ALSO differs (${SIDE_EXTID[$i]} vs" \
					"${SIDE_EXTID[$j]}) even though source was meant to be identical --" \
					"double check nothing else changed between the two worktrees."
			fi
		fi
	else
		if [ -z "${SIDE_EXTID[$i]}" ] || [ -z "${SIDE_EXTID[$j]}" ]; then
			echo "ABORT: side $li or $lj has an UNKNOWN installed-extension identity -- cannot" \
				"verify the two sides actually differ. See the logs in $AB_BASE." >&2
			GUARD_FAILED=1
			continue
		fi
		if [ "${SIDE_EXTID[$i]}" = "${SIDE_EXTID[$j]}" ]; then
			echo "ABORT: sides $li and $lj installed the IDENTICAL extension" \
				"(${SIDE_EXTID[$i]}). This is the grm-mej.2 failure mode -- a comparison" \
				"between a build and itself -- and the result below, if any, MUST NOT be" \
				"trusted. Check that the two refs actually differ in source, and that" \
				"neither side silently reused a stale build." >&2
			GUARD_FAILED=1
		else
			echo "OK: sides $li and $lj installed DIFFERENT extensions" \
				"(${SIDE_EXTID[$i]} vs ${SIDE_EXTID[$j]})."
		fi
	fi
done

if [ "$GUARD_FAILED" -eq 1 ]; then
	echo
	echo "AB-TEST: ABORTED -- identity guard failed, see above. Worktrees $([ "$KEEP_WORKTREES" -eq 1 ] && echo "kept" || echo "will be removed") at $AB_BASE." >&2
	exit 1
fi

# --- report -------------------------------------------------------------------------------
echo
echo "== per-id dump comparison (dump-vs-dump, never vs. golden) =="
ANY_DIFF=0
# Sort ids for stable output.
mapfile -t SORTED_IDS < <(printf '%s\n' "${!SEEN_IDS[@]}" | LC_ALL=C sort)
for id in "${SORTED_IDS[@]}"; do
	echo "-- $id --"
	for i in $(seq 0 $((N_SIDES - 1))); do
		label="${SIDE_LABEL[$i]}"
		key="$label:$id"
		hashes="${DUMP_HASHES[$key]:-}"
		if [ -z "$hashes" ]; then
			echo "   $label: no dump (row was SKIP/filtered on this side)"
			continue
		fi
		n_states=$(( $(printf '%s\n' $hashes | wc -l) ))
		if [ "$n_states" -gt 1 ]; then
			echo "   $label: NONDETERMINISTIC across $REPEAT repeat(s) -- $n_states distinct" \
				"dump states observed: $hashes"
		else
			echo "   $label: $hashes (stable across $REPEAT repeat(s))"
		fi
	done
	# Adjacent-pair dump diff, using repeat 1's copy of each side (representative; the
	# per-side NONDETERMINISTIC line above already flagged if repeat 1 isn't the whole story).
	for i in $(seq 0 $((N_SIDES - 2))); do
		j=$((i + 1))
		li="${SIDE_LABEL[$i]}"; lj="${SIDE_LABEL[$j]}"
		fi_="$AB_BASE/${li}__${id}__r1.dump"
		fj_="$AB_BASE/${lj}__${id}__r1.dump"
		if [ ! -f "$fi_" ] || [ ! -f "$fj_" ]; then
			echo "   $li vs $lj: cannot diff (row missing a dump on one side)"
			continue
		fi
		if diff -q "$fi_" "$fj_" >/dev/null 2>&1; then
			echo "   $li vs $lj: BYTE-IDENTICAL"
		else
			ANY_DIFF=1
			echo "   $li vs $lj: DIFFERS"
			diff -u "$fi_" "$fj_" | sed -n '1,40p'
		fi
	done
done

echo
if [ -n "$RAISE_SAMPLE" ]; then
	echo "== --raise-sample was set: ignore any PASS/FAIL line realrom-test.sh printed above" \
		"against the golden -- it is comparing a raised-SAMPLE dump against an unraised" \
		"golden and is meaningless. Only the dump-vs-dump comparison above is trustworthy. =="
fi

# --- grm-29a9 points 1-3: never let movement=NO do double duty for "compared zero rows" ---
# COMPARED is read out of the sides' OWN realrom-test.sh logs (repeat 1), not re-derived from
# ROWFLAG/--only/--except -- that is the actual row list each side attempted, filtered rows
# excluded, so it can't drift from what really ran even if row selection changes underneath
# this script later. SELECTED is the union of ids any side attempted at all (not filtered
# out); COMPARED is the subset of those with a dump on EVERY side, i.e. what the per-id table
# above actually diffed.
declare -A SELECTED_ID_SET
for i in $(seq 0 $((N_SIDES - 1))); do
	label="${SIDE_LABEL[$i]}"
	log1="$AB_BASE/log-$label-1.txt"
	[ -f "$log1" ] || continue
	while IFS= read -r id; do
		[ -n "$id" ] && SELECTED_ID_SET["$id"]=1
	done < <(grep -E '^-- [^ ]+ \(.*\): ' "$log1" | grep -v ': filtered out$' \
		| sed -E 's/^-- ([^ ]+) \(.*$/\1/')
done
SELECTED_IDS=()
if [ "${#SELECTED_ID_SET[@]}" -gt 0 ]; then
	# Guarded: printf over an EMPTY associative array's keys emits one blank line, which
	# mapfile would turn into a phantom selected id and make the counts below over-claim by
	# one -- in exactly the nothing-was-compared case these counts exist to report honestly.
	mapfile -t SELECTED_IDS < <(printf '%s\n' "${!SELECTED_ID_SET[@]}" | LC_ALL=C sort)
fi
N_SELECTED="${#SELECTED_IDS[@]}"

COMPARED_IDS=()
for id in "${SORTED_IDS[@]:-}"; do
	[ -n "$id" ] || continue
	all_present=1
	for i in $(seq 0 $((N_SIDES - 1))); do
		label="${SIDE_LABEL[$i]}"
		[ -n "${DUMP_HASHES[$label:$id]:-}" ] || { all_present=0; break; }
	done
	[ "$all_present" -eq 1 ] && COMPARED_IDS+=("$id")
done
N_COMPARED="${#COMPARED_IDS[@]}"

MISSING_IDS=()
for id in "${SELECTED_IDS[@]:-}"; do
	[ -n "$id" ] || continue
	miss=1
	for c in "${COMPARED_IDS[@]:-}"; do [ "$c" = "$id" ] && { miss=0; break; }; done
	[ "$miss" -eq 1 ] && MISSING_IDS+=("$id")
done
side_word="every side"; [ "$N_SIDES" -eq 2 ] && side_word="either side"

if [ "$N_COMPARED" -eq 0 ]; then
	echo
	echo "AB-TEST: movement=UNKNOWN (nothing compared -- $N_SELECTED id(s) selected, 0 produced" \
		"a dump on $side_word; see the per-id table above and the logs in $AB_BASE). This tier" \
		"was NOT meaningfully run; nothing about real-ROM movement was checked." >&2
	echo "Full logs and dumps kept at $AB_BASE until cleanup." >&2
	exit 2
fi

VERDICT="$([ "$ANY_DIFF" -eq 1 ] && echo YES || echo NO)"
if [ "$N_COMPARED" -lt "$N_SELECTED" ]; then
	echo "AB-TEST: identity guard OK; movement=$VERDICT (compared $N_COMPARED of $N_SELECTED" \
		"id(s); ${MISSING_IDS[*]} had no dump on $side_word)." \
		"Full logs and dumps kept at $AB_BASE until cleanup."
else
	echo "AB-TEST: identity guard OK; movement=$VERDICT." \
		"Full logs and dumps kept at $AB_BASE until cleanup."
fi
exit 0
