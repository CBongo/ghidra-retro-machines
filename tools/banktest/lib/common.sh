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

# Default the path to analyzeHeadless(.bat) from GRM_TARGET_VERSION; the
# GHIDRA_HEADLESS env var still overrides.
grm_default_headless() {
	GHIDRA_HEADLESS="${GHIDRA_HEADLESS:-D:/ghidra_${GRM_TARGET_VERSION}_PUBLIC/support/analyzeHeadless.bat}"
}

# Default the Ghidra install dir from GRM_TARGET_VERSION; the GRM_GHIDRA_INSTALL
# env var still overrides. (build-and-test.sh needs the install root itself, to
# export as GHIDRA_INSTALL_DIR for gradle and to read application.properties
# from; the runners only ever need the analyzeHeadless path above.)
grm_default_ghidra_install() {
	GRM_GHIDRA_INSTALL="${GRM_GHIDRA_INSTALL:-D:/ghidra_${GRM_TARGET_VERSION}_PUBLIC}"
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

ext_identity() {
	# Content fingerprint of the installed extension, or non-zero if it cannot be
	# determined (=> the caller's candidate-dump cache is disabled). NOT a file
	# mtime/stamp: gradle rewrites the dist zip on every build (new timestamps,
	# identical bytecode), so an mtime-based id never matches across a
	# check->bless pair. unzip -v's CRC-32 column depends only on entry content,
	# so hashing the sorted (CRC, name) pairs across the installed Extensions jars
	# yields an id that is stable across a no-op rebuild yet changes the moment
	# any compiled class or bundled data file changes.
	local base="${BANKTEST_SETTINGS_BASE:-}" jars loose out
	[ -n "$base" ] || return 1
	command -v unzip >/dev/null 2>&1 || return 1
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
		printf '%s\n' "$jars" | while IFS= read -r j; do
			unzip -v "$j" 2>/dev/null | awk '$7 ~ /^[0-9a-fA-F]{8}$/ {print $7, $NF}'
		done
		[ -z "$loose" ] || printf '%s\n' "$loose" | while IFS= read -r p; do
			printf '%s %s\n' "$(sha256sum "$p" | cut -d' ' -f1)" "${p#"$base"}"
		done
	} | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
	[ -n "$out" ] || return 1
	printf '%s' "$out"
}
