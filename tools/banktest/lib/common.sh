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

# Default the Ghidra install dir from GRM_TARGET_VERSION; the GRM_GHIDRA_INSTALL
# env var still overrides. (build-and-test.sh needs the install root itself, to
# export as GHIDRA_INSTALL_DIR for gradle and to read application.properties
# from; the runners only ever need the analyzeHeadless path below.)
grm_default_ghidra_install() {
	GRM_GHIDRA_INSTALL="${GRM_GHIDRA_INSTALL:-D:/ghidra_${GRM_TARGET_VERSION}_PUBLIC}"
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
# Defaults are unchanged when neither var is set: GRM_GHIDRA_INSTALL still
# defaults to D:/ghidra_${GRM_TARGET_VERSION}_PUBLIC and GHIDRA_HEADLESS to
# that install's support/analyzeHeadless.bat.
grm_default_headless() {
	grm_default_ghidra_install
	GHIDRA_HEADLESS="${GHIDRA_HEADLESS:-$GRM_GHIDRA_INSTALL/support/analyzeHeadless.bat}"
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
# No-op when BANKTEST_SETTINGS_BASE is unset/empty, which preserves the manual
# GUI-adjacent flow that runs against the shared %APPDATA% install.
grm_apply_settings_base() {
	local base_native
	if [ -n "${BANKTEST_SETTINGS_BASE:-}" ]; then
		base_native="$(native "$BANKTEST_SETTINGS_BASE")"
		export GHIDRA_HEADLESS_JAVA_OPTIONS="${GHIDRA_HEADLESS_JAVA_OPTIONS:-} -Dapplication.settingsdir=$base_native -Dapplication.cachedir=$base_native/cache"
	fi
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
	local base="${GRM_BANKTEST_WORK:-}"
	if [ -z "$base" ]; then
		if _grm_path_has_dot_segment "$REPO_ROOT"; then
			local safe_root tmp_root
			safe_root="$(printf '%s' "$REPO_ROOT" | tr -c 'A-Za-z0-9' '_')"
			tmp_root="${TMPDIR:-${TEMP:-/tmp}}"
			base="$tmp_root/grm-banktest-work-$safe_root"
			echo "NOTE: REPO_ROOT ($REPO_ROOT) has a dot-leading path segment" \
				"(e.g. .claude/worktrees/...), which Ghidra's project-name validation" \
				"rejects; redirecting the banktest work dir to $base." \
				"Override with GRM_BANKTEST_WORK if you want it elsewhere." >&2
		else
			base="$REPO_ROOT/build/banktest-work"
		fi
	fi
	mkdir -p "$base" || return 1
	mktemp -d "$base/${1:-run}.XXXXXXXX"
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
	if [ -n "$stamp_commit" ] && [ "$stamp_commit" = "$head" ]; then
		echo "REALROM STALENESS: last verified run was AT current HEAD ($stamp_commit, $stamp_when)."
	else
		behind="?"
		if [ -n "$stamp_commit" ] && [ "$stamp_commit" != unknown ] && [ "$head" != unknown ]; then
			behind="$(git -C "$REPO_ROOT" rev-list --count "$stamp_commit..$head" 2>/dev/null || echo '?')"
		fi
		echo "REALROM STALENESS: last verified run was at commit ${stamp_commit:-unknown}" \
			"($stamp_when), $behind commit(s) behind current HEAD ($head)." \
			"Changes since then have NOT been checked against real ROMs."
	fi
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
	loose="$(find "$base" -type f -path '*/Extensions/*' ! -name '*.jar' 2>/dev/null | LC_ALL=C sort)"
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
		[ -z "$loose" ] || printf '%s\n' "$loose" | while IFS= read -r p; do
			printf '%s %s\n' "$(sha256sum "$p" | cut -d' ' -f1)" "${p#"$base"}"
		done
	} | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
	[ -n "$out" ] || return 1
	printf '%s' "$out"
}
