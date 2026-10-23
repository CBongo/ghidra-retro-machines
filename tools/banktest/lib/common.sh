# Shared helpers for the tools/banktest/*.sh drivers (bead grm-9mw).
#
# NOT executable and NOT a standalone script -- source it:
#
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   . "$SCRIPT_DIR/lib/common.sh"
#
# This is bash, not POSIX sh: it uses BASH_SOURCE, and its callers use arrays.
# It is written to be safe under the callers' `set -u` (every possibly-unset
# reference is spelled "${x:-}") and under `set -e` (every command that may
# legitimately fail is guarded).
#
# Sourcing establishes, in this order and independent of the caller's CWD:
#   REPO_ROOT           repo checkout root (git rev-parse; hard-fails outside a repo)
#   GRM_TARGET_VERSION  gradle.properties' ghidraTargetVersion (hard-fails if absent)
# and defines the functions below. Establishing the repo root FIRST is the point
# of doing it here: run-banktest.sh previously had to read gradle.properties
# through a hardcoded "$SCRIPT_DIR/../../" because it needed the version before
# it defined REPO_ROOT. That ordering constraint is now gone.

# Directory holding the banktest drivers (the parent of this lib/ dir). Resolved
# from BASH_SOURCE rather than $0 or the caller's SCRIPT_DIR so that sourcing
# works no matter who sources it or from where.
GRM_BANKTEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Repo root. `git rev-parse --show-toplevel` rather than a relative `cd ../..`:
# it fails loudly outside a checkout instead of silently resolving to whatever
# is two levels up. (The two forms name the same directory in-tree; git's spells
# it in native "D:/..." form, which bash handles transparently.)
REPO_ROOT="$(cd "$GRM_BANKTEST_DIR" && git rev-parse --show-toplevel)" || {
	echo "FAIL: could not resolve repo root from $GRM_BANKTEST_DIR" >&2
	exit 1
}

# The targeted Ghidra version is defined ONCE, in gradle.properties'
# ghidraTargetVersion (bead grm-9r7); every default install/headless path below
# derives from it, and the per-script GHIDRA_HEADLESS / GRM_GHIDRA_INSTALL
# overrides still win.
GRM_TARGET_VERSION="$(sed -n 's/^ghidraTargetVersion=//p' "$REPO_ROOT/gradle.properties")"
if [ -z "$GRM_TARGET_VERSION" ]; then
	echo "FAIL: ghidraTargetVersion not found in $REPO_ROOT/gradle.properties" >&2
	exit 2
fi

# Native (Windows) path form for arguments handed to analyzeHeadless.bat.
native() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi
}

# Read a gradle property, honouring gradle's own precedence: the machine-local
# ~/.gradle/gradle.properties (or $GRADLE_USER_HOME) wins over the repo's
# gradle.properties. Echoes the value; returns nonzero if the key is absent
# everywhere. (Deliberately not a full .properties parser -- no escape or
# line-continuation handling -- because the two keys we read are plain paths and
# a plain version string.)
grm_gradle_property() {
	local key="$1" file val
	for file in "${GRADLE_USER_HOME:-$HOME/.gradle}/gradle.properties" \
	            "$REPO_ROOT/gradle.properties"; do
		[ -f "$file" ] || continue
		val="$(sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//p" "$file" | tail -n1)"
		if [ -n "$val" ]; then printf '%s\n' "$val"; return 0; fi
	done
	return 1
}

# Default the Ghidra install dir by DERIVING it, exactly as build.gradle does:
# <ghidraInstallRoot>/ghidra_<GRM_TARGET_VERSION>_PUBLIC, where ghidraInstallRoot
# is machine-local (~/.gradle/gradle.properties) and the version comes from the
# repo. The GRM_GHIDRA_INSTALL env var still overrides outright.
#
# This used to hardcode `D:/ghidra_${GRM_TARGET_VERSION}_PUBLIC`, which worked
# only on the author's machine and put a developer drive letter in a public repo
# (grm-sp93). gradle.properties has documented the two-part convention all along
# -- "so no developer drive letter is committed" -- and build.gradle already
# implemented it; these scripts simply had not caught up.
#
# Refuses rather than guessing when ghidraInstallRoot is unset, matching
# realrom-test.sh's treatment of an unset GRM_ROM_DIR: a wrong install path
# produces a confusing downstream failure, while an absent one is diagnosable.
# (build-and-test.sh needs the install root itself, to export as
# GHIDRA_INSTALL_DIR for gradle and to read application.properties from; the
# runners only ever need the analyzeHeadless path below.)
grm_default_ghidra_install() {
	# ${VAR:-} rather than $VAR: callers run under `set -u`, where a bare dereference of an
	# unset variable is a fatal error, and "unset" is precisely the case this must handle.
	[ -n "${GRM_GHIDRA_INSTALL:-}" ] && return 0
	local root
	if ! root="$(grm_gradle_property ghidraInstallRoot)"; then
		echo "FAIL: cannot locate the Ghidra install." >&2
		echo "  Set ghidraInstallRoot=<dir holding ghidra_${GRM_TARGET_VERSION}_PUBLIC> in" >&2
		echo "  ${GRADLE_USER_HOME:-$HOME/.gradle}/gradle.properties (see README, 'Building')," >&2
		echo "  or export GRM_GHIDRA_INSTALL=<install dir> for this run." >&2
		exit 3
	fi
	root="${root%/}"; root="${root%\\}"   # "D:/" -> "D:", so the join adds exactly one slash
	GRM_GHIDRA_INSTALL="$root/ghidra_${GRM_TARGET_VERSION}_PUBLIC"
}

# Default the path to analyzeHeadless(.bat). Derives from GRM_GHIDRA_INSTALL
# (bead grm-k0h) rather than independently re-deriving from GRM_TARGET_VERSION,
# so that a caller who sets GRM_GHIDRA_INSTALL to a non-default install (e.g. a
# native A/B against a patched decompile.exe) gets analyzeHeadless from THAT
# install rather than silently launching the default one -- previously the two
# knobs were derived independently and GRM_GHIDRA_INSTALL was very nearly inert
# for the headless runners. GHIDRA_HEADLESS itself still overrides. Calls
# grm_default_ghidra_install() first (idempotent) so GRM_GHIDRA_INSTALL is
# resolved before this reads it, regardless of what the caller has already
# called -- ordering is load-bearing here, not just documentation.
#
# When neither var is set, GRM_GHIDRA_INSTALL derives from ghidraInstallRoot +
# GRM_TARGET_VERSION (see above) and GHIDRA_HEADLESS from that install's
# support/analyzeHeadless.bat.
#
# The early return matters now that grm_default_ghidra_install() refuses on an
# unresolvable install: a caller who supplies GHIDRA_HEADLESS outright has told
# us everything this function needs, and must not be failed for an install root
# that would never have been read.
grm_default_headless() {
	[ -n "${GHIDRA_HEADLESS:-}" ] && return 0   # ${VAR:-} for `set -u`; see above
	grm_default_ghidra_install
	GHIDRA_HEADLESS="$GRM_GHIDRA_INSTALL/support/analyzeHeadless.bat"
}

# Fall back to the per-worktree isolated settings base when the caller has not
# exported one. Default matches build-and-test.sh's SETTINGS_BASE derivation
# exactly (REPO_ROOT/build/ghidra-home), so the standalone scripts work after
# that install has run; if it has not, say so and leave BANKTEST_SETTINGS_BASE
# empty, which means "use the shared %APPDATA%/ghidra install".
#
# $1 is the build-and-test.sh chunk named in the note -- parameterized so each
# caller keeps its own wording rather than inheriting another script's chunk.
grm_settings_base_fallback() {
	local chunk="${1:-nes-banking}"
	if [ -z "${BANKTEST_SETTINGS_BASE:-}" ]; then
		if [ -d "$REPO_ROOT/build/ghidra-home" ]; then
			BANKTEST_SETTINGS_BASE="$REPO_ROOT/build/ghidra-home"
		else
			echo "NOTE: $REPO_ROOT/build/ghidra-home not found (run" \
				"'bash tools/banktest/build-and-test.sh check $chunk' first to install the" \
				"isolated extension); falling back to the shared %APPDATA%/ghidra install." >&2
			BANKTEST_SETTINGS_BASE=
		fi
	fi
}

# Isolation mechanism (Ghidra 12.1.2 source):
#   ApplicationUtilities.getDefaultUserSettingsDir honors -Dapplication.settingsdir
#   to relocate the user settings dir (and GhidraApplicationLayout.
#   findExtensionInstallationDirectories reads [settings dir]/Extensions first),
#   and PROPERTY_CACHE_DIR / -Dapplication.cachedir relocates the user cache
#   dir similarly. analyzeHeadless.bat appends GHIDRA_HEADLESS_JAVA_OPTIONS to
#   its VM args, so we can inject both properties per-invocation without
#   touching any install file.
# The settings/cache redirection is a no-op when BANKTEST_SETTINGS_BASE is unset/empty,
# which preserves the manual GUI-adjacent flow that runs against the shared %APPDATA%
# install.
#
# GRM_THREAD_PIN=1 also pins Ghidra's analysis thread pool to a single thread. That is OFF by
# default since grm-uioc (2026-10-13): after grm-kon2, check nes was 34/34 byte-identical
# pinned and unpinned at 12, 4 and 2 threads, the synthetic gate was SUITE OK unpinned, and
# the pin no longer saved or cost wall clock. Every pinned/unpinned split measured below
# turned out to be an analysis-ORDER race in our own analyzers (grm-4nr, grm-eyn, grm-v60.1,
# grm-kon2) that the pin only made rarer -- so a row that moves with thread count is a bug to
# fix, and the pin is now a diagnostic ("does it also move pinned?"), not a gate setting.
# GRM_THREAD_PIN is in both runners' candidate-cache keys, so a pinned run never serves a bless.
#
# History (why the pin existed, bead grm-nems): it was about REPRODUCIBILITY rather than
# isolation and applied unconditionally.
# SystemUtilities.getDefaultThreadPoolSize() sizes the pool from
# Runtime.availableProcessors() unless the `cpu.core.override` system property is set,
# and with the default multi-threaded pool the amount of code Ghidra disassembles for a
# given ROM VARIES BETWEEN RUNS: measured on tmnt, the same binary and same input yields
# either 2006 or 3426 base-space instructions, which moves counts in the pinned goldens.
# Pinning the pool removes that variation for most rows -- 29 of 33 were byte-identical
# across three full runs, and every row that moved moved toward MORE recovered code (tmnt
# and lwings, both re-blessed) -- at roughly 10% wall clock.
#
# This is a MITIGATION, not a fix. The underlying defect is that merely enabling our
# analyzer flips a race in Ghidra's own disassembly, and the shortfall happens before our
# analyzer is ever invoked; see grm-nems for the measurements and the open mechanism
# question. It does NOT address the dodge/ff1/rcproam/dragonpower bistable rows, which are
# a separate mechanism (grm-4nr) and still flap with the pool pinned.
#
# RE-MEASURED 2026-09-27 after grm-eyn's jump-table bound (which removed most phantom seeds):
# UNPINNED is now run-to-run reproducible too (33/34 rows byte-identical across two unpinned
# runs; only ff1 moves, as it does pinned) and tmnt no longer splits. But pinned vs unpinned
# still differ DETERMINISTICALLY on dodge (refs 2470 vs 2473) and lwings (bankComments 40 vs
# 37), so without the pin a golden would depend on the machine's CORE COUNT. The pin's job is
# then machine-independence of shared goldens. (grm-kon2 found the last such split; see above.)
grm_apply_settings_base() {
	local base_native
	if [ "${GRM_THREAD_PIN:-0}" = 1 ]; then
		export GHIDRA_HEADLESS_JAVA_OPTIONS="${GHIDRA_HEADLESS_JAVA_OPTIONS:-} -Dcpu.core.override=1"
		echo "== analysis thread pool PINNED to 1 (GRM_THREAD_PIN=1; diagnostic, grm-uioc) ==" >&2
	fi
	if [ -n "${BANKTEST_SETTINGS_BASE:-}" ]; then
		base_native="$(native "$BANKTEST_SETTINGS_BASE")"
		export GHIDRA_HEADLESS_JAVA_OPTIONS="${GHIDRA_HEADLESS_JAVA_OPTIONS:-} -Dapplication.settingsdir=$base_native -Dapplication.cachedir=$base_native/cache"
	fi
	grm_capture_packed_db_cache_state
}

# Packed-db cache state at the START of this run (bead grm-oa00): "empty" if the isolated
# -Dapplication.cachedir held nothing yet, "populated" if it did, "shared" when no isolated
# settings base is in use. Captured here, before any row runs, because the first row
# warms it. Before the analysis thread pool was pinned (-Dcpu.core.override=1, grm-nems), this
# was a silent input to real-ROM output: tmnt landed on refs.intoOverlay 0 cold and 44 warm,
# byte-identical within each side, and nothing recorded which side a run was on. Measured
# 2026-09-13 with the pin live: cold and warm produce byte-identical tmnt dumps, so the state
# no longer decides anything (that measurement was pinned; the pin is off by default since
# grm-uioc, so re-check cold vs warm if tmnt ever moves) -- it is printed (grm_packed_db_cache_note) purely so that if it
# ever does again, the run says so instead of the reader reconstructing it.
GRM_PACKED_DB_CACHE_STATE=""
grm_capture_packed_db_cache_state() {
	if [ -z "${BANKTEST_SETTINGS_BASE:-}" ]; then
		GRM_PACKED_DB_CACHE_STATE="shared (no isolated settings base; not attributable)"
	elif [ -d "$BANKTEST_SETTINGS_BASE/cache" ] && [ -n "$(ls -A "$BANKTEST_SETTINGS_BASE/cache" 2>/dev/null)" ]; then
		# "populated", deliberately not "warm": Ghidra invalidates entries by archive mtime, and
		# a build this run (stageExtensionForTests re-copies data/*.gdt) makes a populated
		# cache cold again for exactly the board archives that matter. Only the empty case is
		# an unambiguous claim.
		GRM_PACKED_DB_CACHE_STATE="populated at run start (cold anyway for any archive a build re-stamped this run)"
	else
		GRM_PACKED_DB_CACHE_STATE="empty at run start (cold; the first row unpacked it)"
	fi
}

grm_packed_db_cache_note() {
	echo "== packed-db cache at run start: ${GRM_PACKED_DB_CACHE_STATE:-unknown} =="
}

# True if PATH contains a '/'-separated segment starting with '.' (other than
# the leading-slash/root marker). Ghidra's ProjectLocator/NamingUtilities
# rejects any such segment in a project location (bead grm-hhd) -- this is used
# to detect REPO_ROOT paths that would trip it, e.g. an Agent-tool worktree
# under ".claude/worktrees/agent-<id>".
#
# A segment starts with '.' exactly when the path contains "/." or itself begins
# with '.', so this is a two-pattern case rather than an IFS='/' split loop --
# the split form would additionally glob-expand the unquoted path, and '[' is a
# legal character in a Windows directory name.
_grm_path_has_dot_segment() {
	case "$1" in
	.* | */.*) return 0 ;;
	esac
	return 1
}

# The TEMP-side stand-in for a repo-local scratch dir named TAG, keyed by REPO_ROOT so
# concurrent worktrees do not collide. Unconditional; clean.sh needs it to find a fallback
# dir from a non-dot checkout too.
_grm_temp_fallback_dir() {
	printf '%s\n' "${TMPDIR:-${TEMP:-/tmp}}/grm-$1-$(printf '%s' "$REPO_ROOT" | tr -c 'A-Za-z0-9' '_')"
}

# A scratch dir Ghidra will accept as (or as a parent of) a project location: $2, the
# repo-local path, unless REPO_ROOT has a dot-leading segment, in which case it is
# _grm_temp_fallback_dir $1 (bead grm-hhd). Silent; callers own any NOTE.
grm_dotsafe_dir() {
	if _grm_path_has_dot_segment "$REPO_ROOT"; then
		_grm_temp_fallback_dir "$1"
	else
		printf '%s\n' "$2"
	fi
}

# Where realrom-test.sh --keep-project keeps <id>/headless.gpr, and where
# tools/ghidra-mcp/serve.sh looks for it (bead grm-f0i0: the two must agree, fallback
# included). GRM_KEEP_PROJECT_DIR, when set, names this dir outright.
grm_kept_project_dir() {
	if [ -n "${GRM_KEEP_PROJECT_DIR:-}" ]; then
		printf '%s\n' "$GRM_KEEP_PROJECT_DIR"
	else
		printf '%s\n' "$(grm_dotsafe_dir kept-projects "$REPO_ROOT/build/kept-projects")/realrom"
	fi
}

# A fresh per-run work directory, REPO-LOCAL by default (bead grm-419).
#
# These scripts keep the work dir on failure and print its path so the dump, the
# diff and the analyzeHeadless log can be read -- that is the primary way a
# failing fixture gets diagnosed. Under $TMPDIR that path lies outside every
# configured agent working directory, so every such read costs a permission
# prompt; under build/ it does not. build/ is already gitignored and already
# holds the other per-worktree scratch (build/ghidra-home, build/banktest-cache,
# build/realrom-cache), so this keeps one run's artifacts with the worktree that
# produced them and lets `git clean`/`rm -rf build` collect them.
#
# Still one fresh directory per run, so concurrent runs cannot collide and the
# candidate-dump cache keys that deliberately exclude this volatile path (see
# run-banktest.sh's normalize_opts) are unaffected. Override the BASE with
# GRM_BANKTEST_WORK; the per-script REALROM_WORK_DIR / MEASURE_WORK_DIR still
# override the whole directory and take precedence over this.
#
# AUTOMATIC FALLBACK (bead grm-hhd): if REPO_ROOT itself contains a dot-leading
# segment -- e.g. an Agent-tool worktree at .../.claude/worktrees/agent-<id> --
# then $REPO_ROOT/build/banktest-work inherits that segment and EVERY headless
# fixture fails before it starts, with a stack trace that looks unrelated to
# whatever the caller changed. Detect that case and redirect the base outside
# the repo tree instead, under the platform temp dir, keyed off REPO_ROOT so
# concurrent worktrees still land in distinct directories and never collide.
# GRM_BANKTEST_WORK still overrides this fallback exactly like the normal case.
#
# $1 is a short tag naming the caller, so a kept directory says which run left it.
grm_work_dir() {
	local base
	base="$(grm_work_base)"
	if [ -z "${GRM_BANKTEST_WORK:-}" ] && _grm_path_has_dot_segment "$REPO_ROOT"; then
		echo "NOTE: REPO_ROOT ($REPO_ROOT) has a dot-leading path segment" \
			"(e.g. .claude/worktrees/...), which Ghidra's project-name validation" \
			"rejects; redirecting the banktest work dir to $base." \
			"Override with GRM_BANKTEST_WORK if you want it elsewhere." >&2
	fi
	mkdir -p "$base" || return 1
	mktemp -d "$base/${1:-run}.XXXXXXXX"
}

# The work BASE grm_work_dir() creates run dirs under -- factored out (bead grm-uqhd) so
# grm_prune_work_dirs and clean.sh resolve EXACTLY the same directory, dot-segment TEMP
# fallback (grm-hhd) included. Silent: grm_work_dir owns the fallback NOTE.
grm_work_base() {
	if [ -n "${GRM_BANKTEST_WORK:-}" ]; then
		printf '%s\n' "$GRM_BANKTEST_WORK"
	else
		grm_dotsafe_dir banktest-work "$REPO_ROOT/build/banktest-work"
	fi
}

# Retention for kept-on-failure work dirs (bead grm-uqhd). Run at the START of a runner.
# Under the work base, only dirs shaped like grm_work_dir's output (<tag>.XXXXXXXX) are
# candidates; per tag (realrom, banktest, ...) the newest GRM_WORK_KEEP_FAILURES (default 3)
# are always kept, and any older than GRM_WORK_KEEP_DAYS (default 7) are deleted. The age
# floor is what protects a concurrent run in the same worktree: its dir is minutes old.
# Prints one line, only when something was pruned. Never fails the caller.
grm_prune_work_dirs() {
	local base keep_days keep_n d tag n_dirs=0 kb=0 sz
	base="$(grm_work_base)"
	[ -d "$base" ] || return 0
	keep_days="${GRM_WORK_KEEP_DAYS:-7}"
	keep_n="${GRM_WORK_KEEP_FAILURES:-3}"
	case "$keep_days$keep_n" in *[!0-9]*|"") return 0 ;; esac
	local -A seen=()
	# Newest first, so the first keep_n per tag are the ones to protect.
	while IFS= read -r d; do
		[ -n "$d" ] || continue
		tag="${d%.*}"
		seen[$tag]=$(( ${seen[$tag]:-0} + 1 ))
		[ "${seen[$tag]}" -le "$keep_n" ] && continue
		# find -mtime +N: strictly older than N whole days. -maxdepth 0 tests $d itself.
		[ -n "$(find "$base/$d" -maxdepth 0 -mtime +"$keep_days" 2>/dev/null)" ] || continue
		sz="$(du -sk "$base/$d" 2>/dev/null | cut -f1)"
		kb=$((kb + ${sz:-0}))
		rm -rf "$base/$d" && n_dirs=$((n_dirs + 1))
	done < <(cd "$base" 2>/dev/null && ls -1dt -- *.???????? 2>/dev/null | grep -E '^[A-Za-z0-9_-]+\.[A-Za-z0-9]{8}$')
	[ "$n_dirs" -gt 0 ] &&
		echo "== pruned $n_dirs old work dir(s), $((kb / 1024)) MB, from $base (keep ${keep_n}/tag, ${keep_days}d) =="
	return 0
}

# LRU retention for a content-addressed candidate cache (bead grm-uqhd). $1 = cache dir.
# Deletes ONLY *.dump / *.crit entries not touched for GRM_CACHE_KEEP_DAYS (default 14);
# entries are touched on every hit (grm_touch_cache_entry) and rewritten by every check, so a
# live build's entries never age out. Dotfiles are never matched -- build/realrom-cache/
# .last-verified is the REALROM staleness stamp (GRM_REALROM_STAMP), not a cache entry.
grm_prune_cache() {
	local dir="$1" days="${GRM_CACHE_KEEP_DAYS:-14}" n=0
	[ -d "$dir" ] || return 0
	case "$days" in *[!0-9]*|"") return 0 ;; esac
	n="$(find "$dir" -maxdepth 1 -type f \( -name '*.dump' -o -name '*.crit' \) -mtime +"$days" -print -delete 2>/dev/null | wc -l)"
	[ "${n:-0}" -gt 0 ] && echo "== pruned $n stale cache file(s) from $dir (untouched ${days}d) =="
	return 0
}

# Mark a cache entry as recently used. $1 = path prefix without extension; touches whichever
# of .dump/.crit exist.
grm_touch_cache_entry() {
	local f
	for f in "$1.dump" "$1.crit"; do
		[ -f "$f" ] && touch "$f" 2>/dev/null
	done
	return 0
}

# Python interpreter for ext_identity()'s native zip-CRC read (bead grm-4w6). Resolved
# lazily (only when ext_identity actually runs) and cached in GRM_EXT_ID_PYTHON so repeat
# calls in one process don't re-probe PATH. run-banktest.sh already requires Python for its
# mk*.py generators (usually via its own PYTHON var, resolved separately) -- honor that
# var here too so the two never disagree about which interpreter is in play -- but this
# probe is independent, since realrom-test.sh has no such var and previously had no Python
# dependency at all: ext_identity() used to shell out to `unzip -v` + awk instead. That is
# the one new dependency this bead adds for realrom-test.sh; if no interpreter is found,
# caching is simply disabled (correctness over speed), exactly as when sha256sum/unzip were
# missing before.
grm_ext_id_python() {
	if [ -n "${GRM_EXT_ID_PYTHON:-}" ]; then
		printf '%s' "$GRM_EXT_ID_PYTHON"
		return 0
	fi
	local py
	if [ -n "${PYTHON:-}" ] && command -v "$PYTHON" >/dev/null 2>&1; then
		py="$PYTHON"
	elif command -v python3 >/dev/null 2>&1; then
		py=python3
	elif command -v python >/dev/null 2>&1; then
		py=python
	else
		return 1
	fi
	GRM_EXT_ID_PYTHON="$py"
	printf '%s' "$py"
}

# Atomically publish SRC as DEST via a sibling temp + rename (bead grm-z34): an interrupted
# or out-of-space write leaves the previous DEST intact rather than truncated, and a failed
# cp/mv is reported (nonzero) rather than silently treated as success. Sibling by
# construction (same directory as DEST), so mv is a same-filesystem rename, not a copy.
# Cleans up its temp on any failure so a half-written sibling never lingers to be picked up
# by a later run.
grm_atomic_publish() {
	local src="$1" dest="$2" tmp
	tmp="$dest.tmp.$$"
	if ! cp "$src" "$tmp"; then
		rm -f "$tmp"
		return 1
	fi
	if ! mv -f "$tmp" "$dest"; then
		rm -f "$tmp"
		return 1
	fi
	return 0
}

# Same publish discipline as grm_atomic_publish, but the content comes from stdin (e.g. a
# grep/awk pipeline) instead of an existing file.
grm_atomic_publish_stdin() {
	local dest="$1" tmp
	tmp="$dest.tmp.$$"
	if ! cat >"$tmp"; then
		rm -f "$tmp"
		return 1
	fi
	if ! mv -f "$tmp" "$dest"; then
		rm -f "$tmp"
		return 1
	fi
	return 0
}

# Real-ROM tier staleness (bead grm-6kv). realrom-test.sh writes GRM_REALROM_STAMP whenever
# rows actually ran -- including a FAIL, since megaman/smb3 fail by design on an unchanged
# tree and gating the stamp on a clean pass would mean it could never update in practice
# (see there for the full reasoning); only a SKIPPED run (no ROMs matched) leaves it
# untouched. Both realrom-test.sh and build-and-test.sh's default gate print this note so
# "nobody has run the real-ROM tier" is visible instead of silent -- the gap that let
# grm-mu7 destroy three pinned ROMs unnoticed for a day. Shared here rather than duplicated
# so the two call sites cannot drift on the message or the stamp format.
GRM_REALROM_STAMP="$REPO_ROOT/build/realrom-cache/.last-verified"
grm_realrom_staleness_note() {
	local head stamp_commit stamp_when behind
	head="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
	if [ ! -f "$GRM_REALROM_STAMP" ]; then
		echo "REALROM STALENESS: no realrom-test.sh run recorded for this worktree" \
			"yet ($GRM_REALROM_STAMP absent). Real-ROM regressions have never been checked here" \
			"-- see CLAUDE.md, 'Build & Test': tools/banktest/realrom-test.sh check is required" \
			"before committing changes that touch analysis behaviour."
		return
	fi
	stamp_commit="$(sed -n '1p' "$GRM_REALROM_STAMP")"
	stamp_when="$(sed -n '2p' "$GRM_REALROM_STAMP")"
	# Line 3 (bead grm-ughg) is the set list the run resolved. It is an ADDITION to a
	# previously two-line format, so an older stamp -- one exists in every live worktree --
	# reads as "unknown" rather than breaking. Reported because a five-row `core` run and a
	# full 33-row run are otherwise indistinguishable here, and treating them as equivalent
	# would let the cheap one silence the warning that exists to demand the expensive one.
	stamp_sets="$(sed -n '3p' "$GRM_REALROM_STAMP")"
	stamp_sets_note=" sets: ${stamp_sets:-unknown (pre-grm-ughg stamp)}."
	if [ "$stamp_sets" = core ]; then
		stamp_sets_note="$stamp_sets_note That was the CORE floor only (5 rows) -- it does NOT"
		stamp_sets_note="$stamp_sets_note satisfy the full-tier requirement for analysis changes."
	fi
	case "$stamp_sets" in
		*PARTIAL*)
			stamp_sets_note="$stamp_sets_note Rows were filtered or SKIPPED, so the named"
			stamp_sets_note="$stamp_sets_note set(s) were NOT covered in full -- if rows were"
			stamp_sets_note="$stamp_sets_note skipped, suspect the ROM dir list." ;;
	esac
	# Line 4 (bead grm-qp5x.3) names the decompiler build the run used, because the install
	# carries a locally patched decompile.exe and the megaman/wizwarr goldens are blessed on
	# it. Another ADDITION: an older three-line stamp reads as "unknown".
	stamp_decomp="$(sed -n '4p' "$GRM_REALROM_STAMP")"
	stamp_sets_note="$stamp_sets_note decompiler: ${stamp_decomp:-unknown (pre-grm-qp5x.3 stamp)}."
	if [ -n "$stamp_commit" ] && [ "$stamp_commit" = "$head" ]; then
		echo "REALROM STALENESS: last verified run was AT current HEAD ($stamp_commit," \
			"$stamp_when).$stamp_sets_note"
	else
		behind="?"
		if [ -n "$stamp_commit" ] && [ "$stamp_commit" != unknown ] && [ "$head" != unknown ]; then
			behind="$(git -C "$REPO_ROOT" rev-list --count "$stamp_commit..$head" 2>/dev/null || echo '?')"
		fi
		echo "REALROM STALENESS: last verified run was at commit ${stamp_commit:-unknown}" \
			"($stamp_when), $behind commit(s) behind current HEAD ($head).$stamp_sets_note" \
			"Changes since then have NOT been checked against real ROMs."
	fi
}

# Which DECOMPILER BINARY a run is about to use, by content (bead grm-qp5x.3). The install
# carries a locally patched decompile.exe (the GP-6936 three-hunk fix from grm-qp5x.2 --
# upstream issue #9655, PR pending) because stock 12.1.3 rewrites every 6502 JSR's return
# address into a join varnode and destroys bank-argument recovery on megaman/wizwarr. That
# patch ships in no Ghidra release, so a golden blessed on it is one a stock install CANNOT
# reproduce. This table plus the banner below exist so that a run always SAYS which build it
# ran on -- a stock-install failure on those rows then reads as "wrong decompiler", not as a
# regression to bisect. The candidate cache already keys on the same hash (toolchain_identity,
# grm-kt44), so swapping the binary can never serve the other build's cached dump.
#
# Hashes are of the whole file. The stock one is the MSVC binary Ghidra 12.1.3 ships; the
# patched one is the MinGW static build the ghidra-12-1-3-native-regression-gp6936 memory's
# recipe produces from the Ghidra_12.1.3_build tag plus the three hunks -- rebuild it and the
# hash will differ (MinGW builds are not reproducible), so add the new hash here rather than
# treating an UNKNOWN as suspect for that reason alone. Keep the stock exe beside the patched
# one in the install as decompile.exe.stock-<ver> so an A/B is one rename away.
#
# 12.1.4 (grm-rap8) changed no decompiler source -- Java or C++ -- between the two tags, so the
# 12.1.3 patched binary was carried into the 12.1.4 install as-is: same file, same hash. Its label
# names both versions for that reason. The 12.1.4 stock MSVC binary differs in bytes from 12.1.3's
# (build timestamps) but not in source, and still has the GP-6936 bug.
grm_decompiler_build_name() {
	case "${1:-}" in
		5ae40d01bf03e09ee89b65d1ca465537a1b5d2626cdcfae6e6a9f98ee2d8f536)
			echo "12.1.3 stock" ;;
		ea42e06df2a64f95188a12422a35a36cd48fd4a6f621e62b001e82f1bbbe923b)
			echo "12.1.4 stock" ;;
		1afff91d3130115546cf7904fb8c95047345155049c8b76661b307761e3820a1)
			echo "12.1.3/12.1.4 + GP-6936 local patch (grm-qp5x.3)" ;;
		bd0d7c43f04fca8413ae8ddf2ebe6edd661e6ccbf5228b23460e232568b96d9a)
			echo "12.1.3 + GP-6936 + lowest-target jump-table bound (grm-eyn candidate)" ;;
		27befd1a8ff1efb1e24e1dd33c24ce38c606a468b4f4569e92e0a94f972fa917)
			echo "12.1.3 stock + lowest-target jump-table bound (grm-eyn candidate, no GP-6936 patch)" ;;
		'')
			echo "unknown (no decompile binary found)" ;;
		*)
			echo "UNKNOWN build" ;;
	esac
}

# The decompile binary the install under GHIDRA_HEADLESS will launch, or empty. Same
# root-derivation as toolchain_identity(): GHIDRA_HEADLESS is the knob that selects the
# install, so this can never fingerprint an install the run does not use. Unlike that
# function this picks ONE platform directory -- the install ships every platform's binary
# (linux_x86_64, mac_*, win_x86_64), and only the one Ghidra launches here is the toolchain.
grm_decompiler_binary() {
	local headless root plat cand
	headless="${GHIDRA_HEADLESS:-}"
	[ -n "$headless" ] || return 0
	root="$(dirname "$(dirname "$headless")")"
	case "$(uname -s 2>/dev/null)" in
		MINGW*|MSYS*|CYGWIN*|Windows*) plat=win_x86_64 ;;
		Darwin) if [ "$(uname -m)" = arm64 ]; then plat=mac_arm_64; else plat=mac_x86_64; fi ;;
		*) if [ "$(uname -m)" = aarch64 ]; then plat=linux_arm_64; else plat=linux_x86_64; fi ;;
	esac
	for cand in "$root/Ghidra/Features/Decompiler/os/$plat/decompile.exe" \
	            "$root/Ghidra/Features/Decompiler/os/$plat/decompile"; do
		if [ -f "$cand" ]; then
			printf '%s' "$cand"
			return 0
		fi
	done
}

grm_decompiler_hash() {
	local bin
	bin="$(grm_decompiler_binary)"
	[ -n "$bin" ] || return 0
	# sha256sum prefixes the line with a backslash when the PATH needed escaping (a Windows
	# path with backslashes); the hash itself is unaffected, so strip it or the table misses.
	sha256sum "$bin" 2>/dev/null | cut -d' ' -f1 | tr -d '\\'
}

# One line naming the decompiler build: "== decompiler: 12.1.4 stock (ea42e06d...) ==".
# Printed by every runner beside the installed-extension banner, so a surprising real-ROM
# result can be attributed to the toolchain at a glance.
grm_decompiler_note() {
	local hash
	hash="$(grm_decompiler_hash)"
	echo "== decompiler: $(grm_decompiler_build_name "$hash") (${hash:-no hash}) =="
}

# Installed-extension identity banner (bead grm-4t2d). Shared for the same reason
# grm_realrom_staleness_note above is: two call sites, one message, no drift.
#
# WHY EVERY RUNNER ANNOUNCES THIS. Only build-and-test.sh builds and installs the extension;
# run-banktest.sh and realrom-test.sh analyze with whatever already sits in build/ghidra-home.
# That is the fast inner loop and the real-ROM tier respectively -- the two scripts people
# reach for most -- so the two easiest things to run are the two that can silently test code
# which is not in your working tree. Every failure mode is in the flattering direction: an A/B
# that forgot the rebuild returns byte-identical dumps and reads as "my change moved nothing"
# (it cost grm-mej.2 a committed, pushed, wrong zero-movement claim), and a stale install
# imitates a genuine regression convincingly enough to have cost grm-mlp2 a three-point bisect
# and a P1 filed against main in error (grm-7rct, retracted). Printing the identity turns all
# of that into a one-glance check. See the which-script-builds-the-extension bd memory.
#
# Args: $1 = identity (possibly empty); $2.. = caller-specific advice lines, printed indented.
grm_installed_extension_note() {
	local id="${1:-}"; shift || true
	if [ -z "$id" ]; then
		echo "== installed extension: UNKNOWN (not the isolated build/ghidra-home install) =="
		echo "   Results from an unidentified install cannot be attributed to a source state at" \
			"all. Run 'bash tools/banktest/build-and-test.sh check nes-banking' first."
		return
	fi
	echo "== installed extension: $id =="
	local line
	for line in "$@"; do
		echo "   $line"
	done
}

# Resolve the gradle binary (bead grm-ycv, generalized by grm-4t2d): GRADLE env var wins if
# set; otherwise prefer the committed wrapper (REPO_ROOT/gradlew), which pins the exact
# distribution+checksum in gradle/wrapper/gradle-wrapper.properties and needs nothing
# pre-installed on a fresh checkout; otherwise fall back to `gradle` on PATH; otherwise fail
# loudly rather than defaulting to some one-off developer install path. Sets GRADLE.
#
# Originally build-and-test.sh's own inline logic; factored out here once run-banktest.sh and
# realrom-test.sh needed the identical resolution for their own incidental gradle invocations
# (grm_ensure_extension_staged below) -- three copies of "which gradle" would have been three
# chances for the fallback order to drift.
grm_resolve_gradle() {
	[ -n "${GRADLE:-}" ] && return 0   # ${VAR:-} for `set -u`; explicit override wins outright
	if [ -x "$REPO_ROOT/gradlew" ]; then
		GRADLE="$REPO_ROOT/gradlew"
	elif command -v gradle >/dev/null 2>&1; then
		GRADLE="$(command -v gradle)"
	else
		echo "FAIL: no gradle binary found. Tried: \$GRADLE (unset), $REPO_ROOT/gradlew (missing" \
			"or not executable), 'gradle' on PATH (not found). Set GRADLE=/path/to/gradle or" \
			"restore the committed gradlew wrapper." >&2
		exit 1
	fi
}

# Build-by-default preflight (bead grm-4t2d option (e)). run-banktest.sh and realrom-test.sh
# used to analyze with whatever extension was already sitting in build/ghidra-home -- the fast
# inner loop and the real-ROM tier, i.e. the two scripts people reach for most, and therefore
# the two that could silently test code older than the working tree (grm-mej.2,
# grm-mlp2/grm-7rct; see AGENTS.md and the which-script-builds-the-extension bd memory). Both
# now call this before reading BANKTEST_SETTINGS_BASE, wrapping `gradle stageExtensionForTests`
# (build.gradle) -- a real Gradle task with real inputs/outputs, so it is genuinely UP-TO-DATE
# (a few seconds, not a full rebuild) when nothing relevant has changed, and genuinely rebuilds
# when it has.
#
# Callers must apply their OWN --no-build/GRM_SKIP_BUILD opt-out and GRM_EXTENSION_BUILT_THIS_RUN
# check before calling this (each script has its own wording for why it is or is not building,
# matching the existing grm_installed_extension_note pattern) -- this function does exactly one
# thing: run the task, or exit loudly.
grm_ensure_extension_staged() {
	grm_default_ghidra_install
	grm_resolve_gradle
	echo "== ensuring the isolated extension install is up to date (gradle stageExtensionForTests) ==" >&2
	if ! GHIDRA_INSTALL_DIR="$GRM_GHIDRA_INSTALL" "$GRADLE" -p "$REPO_ROOT" stageExtensionForTests; then
		echo "FAIL: gradle stageExtensionForTests -- see above for the underlying error" >&2
		exit 1
	fi
}

ext_identity() {
	# Content fingerprint of the installed extension, or non-zero if it cannot be
	# determined (=> the caller's candidate-dump cache is disabled). NOT a file
	# mtime/stamp: gradle rewrites the dist zip on every build (new timestamps,
	# identical bytecode), so an mtime-based id never matches across a
	# check->bless pair.
	#
	# The per-jar CRC read (bead grm-4w6) uses Python's zipfile module directly rather than
	# shelling out to `unzip -v` and awk-parsing its human-readable column layout: that
	# parse was brittle (depended on unzip's table format, and `$NF` truncated any entry
	# name containing a space) and needed the `unzip` binary on PATH. zipfile.ZipInfo.CRC
	# reads the same CRC-32 the zip format already stores per entry, so hashing the sorted
	# (CRC, name) pairs across the installed Extensions jars still yields an id that is
	# stable across a no-op rebuild yet changes the moment any compiled class or bundled
	# data file changes -- only the CRC *source* changed, not the key formula.
	#
	# MIGRATION NOTE: switching readers changes the emitted line format (e.g. spacing/case
	# of the hex CRC), which changes this function's output and therefore invalidates any
	# existing build/*-cache entries the first time it runs post-upgrade. Harmless: a cache
	# miss just re-imports once and repopulates under the new key.
	local base="${BANKTEST_SETTINGS_BASE:-}" jars loose out py
	[ -n "$base" ] || return 1
	py="$(grm_ext_id_python)" || return 1
	jars="$(find "$base" -type f -name '*.jar' -path '*/Extensions/*' 2>/dev/null | LC_ALL=C sort)"
	[ -n "$jars" ] || return 1
	# The compiled board descriptors ship LOOSE, as data/machines/*.map next to the jar --
	# only the two charset maps live inside it. Fingerprinting jars alone therefore missed
	# the single most common change in this repo: editing machines/nes-*.yaml recompiles a
	# .map, changes the block/overlay layout the dump records, and left the cache key
	# identical, so a bless could serve a candidate from before the descriptor change.
	# sha256sum (not mtime) for the same content-only reason the jar branch uses CRCs.
	# *.gdt IS DELIBERATELY EXCLUDED, and data/descriptor-sources.sha256 covers it instead
	# (bead grm-5jjs; the generating task is buildDescriptorSourceManifest in build.gradle,
	# whose comment carries the full reasoning). Ghidra's data-type-archive writer is NOT
	# deterministic: regenerating a .gdt from byte-identical input yields different bytes
	# (measured 2026-08-29, c128.gdt e8d3ddd0... -> c41e7a5f...). Hashing them made this
	# identity unstable across worktrees -- two builds of the SAME COMMIT never agreed --
	# which silently defeats any A/B that builds each side in its own tree, and needlessly
	# invalidated the candidate-dump cache.
	#
	# Excluding them ALONE would have been unsound, which is the part worth remembering: the
	# .map files reference types by NAME while the .gdt holds the DEFINITIONS, so renaming a
	# struct FIELD in machines/*.yaml leaves the .map byte-identical (measured) and moves no
	# jar either. Without the sources manifest, such an edit would be invisible to this whole
	# key while DescriptorApply.applyStructType really does apply those structs to memory.
	# The manifest is a deterministic sha256-per-source-file listing of machines/**, so it
	# catches exactly what the .gdt would have, and nothing that varies build to build.
	loose="$(find "$base" -type f -path '*/Extensions/*' ! -name '*.jar' ! -name '*.gdt' 2>/dev/null | LC_ALL=C sort)"
	out="$( {
		if [ -n "$jars" ]; then
			printf '%s\n' "$jars" | "$py" -c '
import sys, zipfile
for path in sys.stdin.read().splitlines():
    if not path:
        continue
    with zipfile.ZipFile(path) as zf:
        for zi in zf.infolist():
            print("%08x %s" % (zi.CRC, zi.filename))
' 2>/dev/null
		fi
		# One sha256sum over every loose file (NUL-separated), not a subshell+pipeline per file:
		# ~135 files cost ~4s of fork overhead on Windows (grm-x4y1.4). The emitted
		# "<hash> <path minus base>" lines match the per-file loop's, so no cache key moves.
		[ -z "$loose" ] || printf '%s\n' "$loose" | tr '\n' '\0' | xargs -0 sha256sum | while read -r h p; do
			p="${p#\*}"	# sha256sum's binary-mode marker
			printf '%s %s\n' "$h" "${p#"$base"}"
		done
	} | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
	[ -n "$out" ] || return 1
	printf '%s' "$out"
}

toolchain_identity() {
	# Content fingerprint of the GHIDRA INSTALL that will actually run the analysis, or
	# non-zero if it cannot be determined (=> the caller's candidate-dump cache is disabled).
	#
	# WHY (bead grm-kt44, the FOURTH omission in the family realrom-cache-key-invariant
	# documents): both candidate caches keyed on the ROM/fixture, the loader options, the dump
	# script and ext_identity() -- everything about THIS REPO -- and nothing about the
	# toolchain. Swapping decompile.exe, or pointing GHIDRA_HEADLESS at a different install
	# entirely, changes the dump completely and left the key untouched, so the cache served one
	# arm's dump for another. Found during grm-qp5x.1's native A/B, where five arms differed
	# ONLY in decompile.exe; the workaround was `rm -rf build/realrom-cache` between arms, which
	# works right up until someone forgets -- and it fails in the FLATTERING direction, as a
	# no-op diff that reads "my change is safe".
	#
	# Derived from GHIDRA_HEADLESS, not GRM_GHIDRA_INSTALL: GHIDRA_HEADLESS is the knob that
	# actually selects the install (grm-k0h, realrom-ab-wrong-install-trap), and an explicit
	# GHIDRA_HEADLESS wins over GRM_GHIDRA_INSTALL, so keying the latter could fingerprint an
	# install this run never launches. `<root>/support/analyzeHeadless(.bat)` is the layout
	# grm_default_headless builds and the one every documented override follows.
	#
	# HASH THE BINARIES, not the version string alone: a locally patched install has the same
	# application.version and is the exact case that motivated this bead. The version terms are
	# folded in as well so a same-named-binaries-different-release install (should one ever
	# exist) still separates. Paths are recorded RELATIVE to the install root for the same
	# reason ext_identity() records them relative to the settings base -- copying an install to
	# a new directory must not invalidate every cached candidate, only changing its contents
	# should.
	#
	# KNOWN LIMIT, stated rather than silently assumed: this covers the decompiler/sleigh
	# NATIVE binaries and the release identity, not the install's Java jars or its stock
	# .sla/.slaspec language files. A hand-patched Ghidra language in the install would still
	# be invisible here. That is a much rarer edit than swapping decompile.exe, and hashing the
	# whole install is far too slow to run per script invocation; if it ever bites, extend this
	# function rather than adding a fifth ad-hoc term at a call site.
	local headless root bins out
	headless="${GHIDRA_HEADLESS:-}"
	[ -n "$headless" ] || return 1
	root="$(dirname "$(dirname "$headless")")"
	[ -d "$root" ] || return 1
	bins="$(find "$root/Ghidra/Features/Decompiler/os" -type f \
		\( -name 'decompile' -o -name 'decompile.exe' \
		-o -name 'sleigh' -o -name 'sleigh.exe' \) 2>/dev/null | LC_ALL=C sort)"
	[ -n "$bins" ] || return 1
	out="$( {
		printf '%s\n' "$bins" | while IFS= read -r p; do
			printf '%s %s\n' "$(sha256sum "$p" | cut -d' ' -f1)" "${p#"$root"}"
		done
		# application.build.date is deliberately NOT included: it moves for reasons that have
		# nothing to do with what the toolchain computes, and the binaries above already carry
		# any real change.
		grep -E '^application\.(name|version|release\.name)=' \
			"$root/Ghidra/application.properties" 2>/dev/null | LC_ALL=C sort
	} | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
	[ -n "$out" ] || return 1
	printf '%s' "$out"
}

# --- headless timeout (beads grm-w9ev.5, grm-x4y1.2) ------------------------------------------
# One hung analyzeHeadless must not stall a gate forever. Shared by run-banktest.sh and
# realrom-test.sh; the callers differ only in their defaults, since a real-ROM row (median ~7s,
# worst ~52s) is far slower than a synthetic fixture (~5s).
#
#   grm_headless_timeout_init <default-base-s> <default-per-program-s>
#
# A headless invocation importing n programs gets GRM_HEADLESS_TIMEOUT_BASE + n *
# GRM_HEADLESS_TIMEOUT_PER_PROGRAM seconds. GRM_HEADLESS_TIMEOUT=S overrides the whole figure
# with a flat S seconds per invocation; 0 disables the timeout. BASE/PER are also env-overridable;
# the arguments are used only when the env var is unset. Sets TIMEOUT_BANNER for the run banner.
grm_headless_timeout_init() {
	GRM_HEADLESS_TIMEOUT_BASE="${GRM_HEADLESS_TIMEOUT_BASE:-$1}"
	GRM_HEADLESS_TIMEOUT_PER_PROGRAM="${GRM_HEADLESS_TIMEOUT_PER_PROGRAM:-$2}"
	local _v
	for _v in "${GRM_HEADLESS_TIMEOUT:-0}" "$GRM_HEADLESS_TIMEOUT_BASE" "$GRM_HEADLESS_TIMEOUT_PER_PROGRAM"; do
		case "$_v" in
			''|*[!0-9]*) echo "invalid headless timeout value '$_v': must be a non-negative integer (seconds)" >&2; exit 2 ;;
		esac
	done
	if [ -n "${GRM_HEADLESS_TIMEOUT:-}" ]; then
		if [ "$GRM_HEADLESS_TIMEOUT" -eq 0 ]; then
			TIMEOUT_BANNER="off (GRM_HEADLESS_TIMEOUT=0)"
		else
			TIMEOUT_BANNER="${GRM_HEADLESS_TIMEOUT}s flat per headless run (GRM_HEADLESS_TIMEOUT)"
		fi
	else
		TIMEOUT_BANNER="${GRM_HEADLESS_TIMEOUT_BASE}s + ${GRM_HEADLESS_TIMEOUT_PER_PROGRAM}s/program"
	fi
}

# Runs a headless command under the timeout, output to <log>. Returns the command's status, or
# 124 (after printing a TIMEOUT line) if it was killed for exceeding the limit.
#
#   run_headless_timed <n-programs> <label> <log> <needle> <command> [args...]
#
# GHIDRA_HEADLESS is analyzeHeadless.bat: cmd.exe -> java.exe. coreutils timeout / kill signal only
# the direct child and leave java.exe running (holding the project dir locked). Do NOT use
# `taskkill /T` here: it walks stale parent PIDs and can reach unrelated processes (an earlier
# draft is suspected of killing the agent session that ran it). The watchdog instead runs
# lib/kill-headless.ps1, which kills only java.exe/cmd.exe whose command line contains <needle>.
# <needle> is the run's own project dir, which lives under the per-run mktemp $WORK, so it matches
# this run's Ghidra and nothing else. GRM_HEADLESS_KILL_DRYRUN=1 makes the watchdog print what it
# would kill and kill nothing. The watchdog is a subshell torn down when the command finishes
# first, so no stray sleep outlives the call. Requires grm_headless_timeout_init to have run.
run_headless_timed() {
	local n="$1" label="$2" log="$3" needle="$4"
	shift 4
	local limit
	if [ -n "${GRM_HEADLESS_TIMEOUT:-}" ]; then
		limit="$GRM_HEADLESS_TIMEOUT"
	else
		limit=$((GRM_HEADLESS_TIMEOUT_BASE + n * GRM_HEADLESS_TIMEOUT_PER_PROGRAM))
	fi
	if [ "$limit" -eq 0 ]; then
		"$@" >"$log" 2>&1
		return $?
	fi
	local flag="$log.timedout"
	rm -f "$flag"
	"$@" >"$log" 2>&1 &
	local pid=$!
	(
		sleep "$limit" &
		sp=$!
		trap 'kill $sp 2>/dev/null; exit 0' TERM
		wait $sp
		if kill -0 "$pid" 2>/dev/null; then
			: >"$flag"
			if [ "${GRM_HEADLESS_KILL_DRYRUN:-0}" = 1 ]; then
				powershell.exe -NoProfile -ExecutionPolicy Bypass \
					-File "$(native "$GRM_BANKTEST_DIR/lib/kill-headless.ps1")" -Needle "$needle" -DryRun
			else
				powershell.exe -NoProfile -ExecutionPolicy Bypass \
					-File "$(native "$GRM_BANKTEST_DIR/lib/kill-headless.ps1")" -Needle "$needle"
				# Our own MSYS-level child only (no tree walk): reaps the job if anything is left.
				kill -9 "$pid" 2>/dev/null
			fi
		fi
	) &
	local wd=$!
	wait "$pid"
	local st=$?
	kill "$wd" 2>/dev/null
	wait "$wd" 2>/dev/null
	if [ -e "$flag" ]; then
		rm -f "$flag"
		echo "TIMEOUT: $label exceeded ${limit}s; killed its headless processes (matched by project dir)"
		return 124
	fi
	return $st
}

# Splits a batched analyzeHeadless log into one file per program (bead grm-w9ev.5; moved here from
# run-banktest.sh's flush_batch by grm-x4y1.3 so realrom-test.sh shares it).
#
#   grm_split_batch_log <batch-log> "<base>=<out-log> <base>=<out-log> ..."
#
# Cuts at each "IMPORTING: file:///.../<basename>" line (analysis output for a program follows its
# IMPORTING line, so it stays with it); anything before the first import (startup) goes to the
# first program. <out-log> paths must use forward slashes and contain no spaces (awk -v eats
# backslashes). Existing <out-log> files are the caller's to remove first.
grm_split_batch_log() {
	awk -v list="$2" '
		BEGIN { n = split(list, a, " "); for (i = 1; i <= n; i++) { k = index(a[i], "="); map[substr(a[i], 1, k - 1)] = substr(a[i], k + 1) } cur = ""; pre = "" }
		/IMPORTING: file:/ && !/Loaded [0-9]+ additional/ {
			line = $0; sub(/[ \t\r]*\(HeadlessAnalyzer\).*$/, "", line); sub(/^.*\//, "", line)
			if (line in map) { cur = map[line]; if (pre != "") { printf "%s", pre > cur; pre = "" } }
		}
		{ if (cur == "") pre = pre $0 "\n"; else print $0 > cur }
	' "$1"
}

# A script that threw (bead grm-h649). analyzeHeadless logs "REPORT SCRIPT ERROR" and then carries
# on: for a plain GhidraScript (every script here) a failed preScript aborts nothing, so the import
# still analyzes and the postScript still dumps, and the only trace of the failure is this line.
# Prints the offending lines (CR-stripped, at most 5) and succeeds when <log> has any.
#
#   grm_script_errors <log>
grm_script_errors() {
	local hits
	hits=$(sed 's/\r$//' "$1" | grep 'REPORT SCRIPT ERROR' | head -5) || return 1
	[ -n "$hits" ] || return 1
	printf '%s\n' "$hits"
}

# Strip anything that isn't [A-Za-z0-9._-]: analyzeHeadless.bat chokes on parentheses and spaces.
# Shared by realrom-test.sh and measure-overlay-scale.sh (bead grm-rx1i.11).
sanitize() {
	printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'
}

# --- chunk vocabulary (bead grm-rx1i.11) -------------------------------------------------
# The single source for chunk names. build-and-test.sh (front end: validation, usage, the
# headless/unit/opt-in split) and run-banktest.sh (headless runner) both read these.
# GRM_HEADLESS_CHUNKS run under run-banktest.sh; `unit` is JUnit only; GRM_OPTIN_CHUNKS are
# the opt-in tiers that `all` does NOT include. Order is the --list-chunks order.
GRM_HEADLESS_CHUNKS=(c64-banking c64-loader c64-recovery basic-petscii basic-dialects pet-loader
	snes-loader c128-loader nes-banking petscii-strings nes-text descriptors)
GRM_OPTIN_CHUNKS=(spc700-vectors spc700-dis-corpus spc-ipl-corpus snes-rom-corpus
	w65816-vectors 6502-vectors)

# grm_chunk_in <name> <array-elements...>: success when <name> is one of the elements.
grm_chunk_in() {
	local want="$1" c; shift
	for c in "$@"; do [ "$c" = "$want" ] && return 0; done
	return 1
}

# Build-by-default preflight shared by run-banktest.sh and realrom-test.sh (bead grm-rx1i.11;
# the build-by-default rule is grm-4t2d option (e)). Needs NO_BUILD (0/1) set by the caller's
# flag parsing and grm_default_headless already run. $1 = build-and-test.sh chunk named in the
# "no isolated install yet" hint. Sets EXT_NOTE_SUFFIX, EXT_ID and TOOLCHAIN_ID (empty => the
# caller's candidate-dump cache is disabled), and applies the settings base.
#
# THE ORDER IS LOAD-BEARING (bug found 2026-08-29 while building ab-test.sh): staging must run
# BEFORE grm_settings_base_fallback. The fallback decides whether to use the isolated install by
# testing whether build/ghidra-home EXISTS, and staging is what creates it. With the fallback
# first, a FRESH WORKTREE took the shared %APPDATA% branch, then staging installed into a
# build/ghidra-home the run was no longer pointed at: the extension under test was built
# correctly and then not used. Under --no-build the directory may legitimately still be absent,
# and the fallback's NOTE is then correct rather than misleading.
#
# GRM_SHARED_GHIDRA_INSTALL=1 (opt back in to the %APPDATA% install that only
# tools/install-gui.ps1 writes) was run-banktest-only until grm-rx1i.11, though its comment
# promised it for "all four runners" (17249b6); both runners now honour it.
grm_preflight() {
	EXT_NOTE_SUFFIX=""
	if [ "${GRM_SHARED_GHIDRA_INSTALL:-}" = 1 ]; then
		echo "NOTE: GRM_SHARED_GHIDRA_INSTALL=1 -- reading the shared %APPDATA%/ghidra install" \
			"instead of the isolated build/ghidra-home tree. Only tools/install-gui.ps1 writes" \
			"that install, so this run cannot be attributed to the current source state." >&2
	fi
	if [ "${GRM_EXTENSION_BUILT_THIS_RUN:-}" = 1 ]; then
		: # build-and-test.sh already built+staged for this run; do not double-build
	elif [ "${GRM_SHARED_GHIDRA_INSTALL:-}" = 1 ]; then
		EXT_NOTE_SUFFIX="shared-install"   # must not build: it would stage an install we do not read
	elif [ "${NO_BUILD:-0}" -eq 1 ] || [ "${GRM_SKIP_BUILD:-}" = 1 ]; then
		EXT_NOTE_SUFFIX="no-build"
	else
		grm_ensure_extension_staged
	fi
	if [ "${GRM_SHARED_GHIDRA_INSTALL:-}" != 1 ]; then
		grm_settings_base_fallback "$1"
	fi
	grm_apply_settings_base
	# ext_identity()/toolchain_identity() are also the cache-key terms; empty => caching disabled.
	EXT_ID="$(ext_identity)" || EXT_ID=""
	TOOLCHAIN_ID="$(toolchain_identity)" || TOOLCHAIN_ID=""
}

# Identity banners, printed after grm_preflight. $1 = advice style: "ab" (real-ROM: an A/B must
# see the extension line change between sides) or "bisect" (synthetic loop: warns about baselines
# and bisects taken through a --no-build run). $2 = what re-imports when caching is off
# ("row"/"fixture"). Order and content are the union of what the two runners printed before.
grm_print_identity_banners() {
	local style="$1" noun="$2" no_build_advice built_advice
	if [ "$style" = ab ]; then
		no_build_advice="(--no-build/GRM_SKIP_BUILD skipped the pre-flight build -- this run analyzed with whatever was already installed. For an A/B, that means YOU must rebuild between sides, and this line MUST change between them or you are comparing a build against itself.)"
		built_advice="(built and staged by THIS run via 'gradle stageExtensionForTests' before analyzing. For an A/B this now happens automatically on both sides -- this line should still change between them; if it does not, treat the comparison as unproven and find out why before trusting it.)"
	else
		no_build_advice="(--no-build/GRM_SKIP_BUILD skipped the pre-flight build -- this script analyzed with whatever was already installed. A surprising result may be a stale extension rather than your change; re-run without that flag/var to rebuild first, and treat any baseline or bisect taken through this run as unproven.)"
		built_advice="(built and staged by THIS run via 'gradle stageExtensionForTests' before analyzing, so it matches this working tree.)"
	fi
	# The note's job is to say WHICH state applied, so a surprising result is attributed correctly
	# rather than blamed on a stale build this run just fixed (grm-4t2d).
	case "${GRM_EXTENSION_BUILT_THIS_RUN:-}/${EXT_NOTE_SUFFIX:-}" in
		1/*) grm_installed_extension_note "$EXT_ID" \
			"(built and installed by build-and-test.sh for this run, so it matches this tree.)" ;;
		*/shared-install) grm_installed_extension_note "$EXT_ID" \
			"(GRM_SHARED_GHIDRA_INSTALL=1 -- this run does NOT build; it reads the shared %APPDATA%/ghidra install, which only tools/install-gui.ps1 ever writes, so it cannot be attributed to the current source state.)" ;;
		*/no-build) grm_installed_extension_note "$EXT_ID" "$no_build_advice" ;;
		*) grm_installed_extension_note "$EXT_ID" "$built_advice" ;;
	esac
	grm_decompiler_note
	grm_packed_db_cache_note
	# GHIDRA_HEADLESS -- not GRM_GHIDRA_INSTALL -- is what launches Ghidra, and the env var can
	# make the two disagree, so print both (bead grm-k0h).
	echo "== ghidra install: $GRM_GHIDRA_INSTALL (headless: $GHIDRA_HEADLESS) =="
	# On a native A/B (decompile.exe, sleigh.exe) THIS is the line that must differ between sides.
	if [ -n "$TOOLCHAIN_ID" ]; then
		echo "== ghidra toolchain: $TOOLCHAIN_ID =="
	else
		echo "== ghidra toolchain: UNKNOWN (could not fingerprint the install behind $GHIDRA_HEADLESS) =="
		echo "   Candidate-dump caching is DISABLED for this run; every $noun re-imports."
	fi
}
