#!/usr/bin/env bash
# Agent-facing single entry point for the build+test loop (bead grm-r3h).
#
# Builds the extension, installs it into a per-git-worktree, per-agent
# isolated Ghidra "user settings dir" (NOT the shared %APPDATA% Extensions
# dir), and runs the banktest suite against that isolated install. This lets
# N agents in N git worktrees run the loop concurrently against one
# read-only Ghidra install without serializing on a single Extensions dir,
# and without an open Ghidra GUI locking files out from under a test run.
#
# Usage: build-and-test.sh [check|bless] [chunk ...]
#
# Environment overrides:
#   GRM_GHIDRA_INSTALL   Ghidra install dir (default D:/ghidra_12.1.2_PUBLIC).
#                        Exported as GHIDRA_INSTALL_DIR for the gradle build --
#                        build.gradle checks the GHIDRA_INSTALL_DIR env var
#                        FIRST, and the ambient one on this machine may point
#                        at a stale install, so we always override it here
#                        rather than inherit it.
#   GRADLE                gradle binary to use (default /d/gradle-8.13/bin/gradle)
#
# Isolation mechanism (verified against Ghidra 12.1.2 source; see comments
# below and in run-banktest.sh for citations): passing
# -Dapplication.settingsdir=<base> relocates Ghidra's user settings dir --
# and therefore where it looks for installed Extensions -- to
# <base>/<userdir>/<versionedName>. We point <base> at
# <repo>/build/ghidra-home, which is per-worktree (build/ is gitignored) and
# never touches the real %APPDATA%/ghidra directory.
#
# Headless project paths must contain no dot-prefixed path element and no
# parentheses (existing analyzeHeadless constraints; see run-banktest.sh).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR" && git rev-parse --show-toplevel)" || {
	echo "FAIL: could not resolve repo root from $SCRIPT_DIR" >&2
	exit 1
}

usage() {
	cat <<EOF
usage: $0 [check|bless] [chunk ...]

Chunks: c64-banking c64-loader c64-recovery basic-petscii basic-dialects pet-loader c128-loader nes-banking
        bit-algebra all

With no chunks, all is selected. Use --list-chunks to print this list.
EOF
}

list_chunks() {
	cat <<'EOF'
c64-banking   C64 banktest through banktest4 fixtures
c64-loader    C64 PRG placement/wrapping, ROM loading, and symbol toggles
c64-recovery  C64 emulation and decrypt/recovery fixtures
basic-petscii C64 BASIC headless fixture plus verifyPetsciiMapper
basic-dialects PET BASIC 4/C128 BASIC 7 token dialects plus C64 BASIC 2 regression
pet-loader    PET 4032 descriptor, PRG placement, IO types, and fixed ROM slots
c128-loader   C128 native BASIC PRG placement, fixed ROM slots, and MMU IO
nes-banking   NES banking and MMC fixtures
bit-algebra   verifyBitAlgebra (no extension build/install required alone)
all           Every chunk (the default)
EOF
}

if [ "${1:-}" = "--list-chunks" ]; then
	if [ "$#" -ne 1 ]; then
		echo "FAIL: --list-chunks cannot be combined with other arguments" >&2
		exit 2
	fi
	list_chunks
	exit 0
fi

MODE="check"
if [ "${1:-}" = "check" ] || [ "${1:-}" = "bless" ]; then
	MODE="$1"
	shift
fi

if [ "$#" -eq 0 ]; then
	REQUESTED_CHUNKS=(all)
else
	REQUESTED_CHUNKS=("$@")
fi

for chunk in "${REQUESTED_CHUNKS[@]}"; do
	case "$chunk" in
		c64-banking|c64-loader|c64-recovery|basic-petscii|basic-dialects|pet-loader|c128-loader|nes-banking|bit-algebra|all) ;;
		*)
			echo "FAIL: unknown chunk '$chunk'" >&2
			usage >&2
			exit 2
			;;
	esac
done

has_chunk() {
	local wanted="$1"
	local chunk
	for chunk in "${REQUESTED_CHUNKS[@]}"; do
		[ "$chunk" = "$wanted" ] && return 0
	done
	return 1
}

# Expand `all` here rather than handing it to the wrapper as one of several
# chunks: that keeps runner selection unambiguous and avoids duplicate work.
RUN_HEADLESS=0
RUNNER_CHUNKS=()
GRADLE_CHECKS=()
if has_chunk all; then
	RUN_HEADLESS=1
	RUNNER_CHUNKS=(all)
	GRADLE_CHECKS=(verifyPetsciiMapper verifyBitAlgebra)
else
	for chunk in c64-banking c64-loader c64-recovery basic-petscii basic-dialects pet-loader c128-loader nes-banking; do
		if has_chunk "$chunk"; then
			RUN_HEADLESS=1
			RUNNER_CHUNKS+=("$chunk")
		fi
	done
	if has_chunk basic-petscii || has_chunk basic-dialects; then
		GRADLE_CHECKS+=(verifyPetsciiMapper)
	fi
	if has_chunk bit-algebra; then
		GRADLE_CHECKS+=(verifyBitAlgebra)
	fi
fi

if [ "$MODE" = "bless" ] && [ "$RUN_HEADLESS" -ne 1 ]; then
	echo "FAIL: bless requires at least one headless chunk with golden output" >&2
	usage >&2
	exit 2
fi

GRM_GHIDRA_INSTALL="${GRM_GHIDRA_INSTALL:-D:/ghidra_12.1.2_PUBLIC}"
GRADLE="${GRADLE:-/d/gradle-8.13/bin/gradle}"

native() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi
}

# --- 1. Build and pure Gradle checks ------------------------------------
export GHIDRA_INSTALL_DIR="$GRM_GHIDRA_INSTALL"
if [ "$RUN_HEADLESS" -eq 1 ]; then
	GRADLE_TASKS=(buildExtension "${GRADLE_CHECKS[@]}")
	echo "== building extension and running selected Gradle checks (GHIDRA_INSTALL_DIR=$GRM_GHIDRA_INSTALL) =="
else
	GRADLE_TASKS=("${GRADLE_CHECKS[@]}")
	echo "== running selected Gradle checks (no extension build/install needed) =="
fi
"$GRADLE" -p "$REPO_ROOT" "${GRADLE_TASKS[@]}" || {
	echo "FAIL: gradle ${GRADLE_TASKS[*]}" >&2
	exit 1
}

# A bit-algebra-only selection has no headless fixture. It intentionally
# stops after the Gradle verification above, avoiding the extension loop.
if [ "$RUN_HEADLESS" -ne 1 ]; then
	exit 0
fi

# --- 2. Pick newest dist zip ----------------------------------------------
# NOTE: the zip's trailing name component is the gradle project name, which
# (absent a settings.gradle rootProject.name) defaults to the checkout
# directory's basename -- e.g. "ghidra-retro-machines" in the main tree, but
# something else (e.g. "grm-wt-r3h") in a differently-named git worktree.
# dist/ only ever holds this one extension's build output for a given
# worktree, so match broadly on "ghidra_*.zip" rather than hardcoding the
# suffix, so the script works in any worktree regardless of its directory name.
DIST_DIR="$REPO_ROOT/dist"
ZIP="$(ls -t "$DIST_DIR"/ghidra_*.zip 2>/dev/null | head -n1)"
if [ -z "$ZIP" ]; then
	echo "FAIL: no dist zip found in $DIST_DIR" >&2
	exit 1
fi
echo "== newest dist zip: $ZIP =="

# --- 3. Compute per-tree settings base / Extensions path -----------------
# ApplicationUtilities.getDefaultUserSettingsDir (Ghidra 12.1.2):
#   settings dir = <base>/<userdir>/<versionedName>
# ApplicationUtilities.getUserSpecificDirName:
#   userdir = "ghidra" if <base> is inside the user's home directory,
#             else "<username>-ghidra" (username = %USERNAME%)
# versionedName = lowercase(application.name) + "_" + application.version +
#                 "_" + application.release.name, read from
#                 <install>/Ghidra/application.properties (not hardcoded).
SETTINGS_BASE="$REPO_ROOT/build/ghidra-home"
mkdir -p "$SETTINGS_BASE"

APP_PROPS="$GRM_GHIDRA_INSTALL/Ghidra/application.properties"
if [ ! -f "$APP_PROPS" ]; then
	echo "FAIL: $APP_PROPS not found -- bad GRM_GHIDRA_INSTALL?" >&2
	exit 1
fi
app_prop() {
	sed -n "s/^$1=\(.*\)\$/\1/p" "$APP_PROPS" | tr -d '\r' | head -n1
}
APP_NAME="$(app_prop application.name)"
APP_VERSION="$(app_prop application.version)"
APP_RELEASE="$(app_prop application.release.name)"
if [ -z "$APP_NAME" ] || [ -z "$APP_VERSION" ] || [ -z "$APP_RELEASE" ]; then
	echo "FAIL: could not parse application.name/version/release.name from $APP_PROPS" >&2
	exit 1
fi
VERSIONED_NAME="$(echo "$APP_NAME" | tr '[:upper:]' '[:lower:]')_${APP_VERSION}_${APP_RELEASE}"

# Home-containment check: is SETTINGS_BASE inside $USERPROFILE? (case-insensitive,
# as Windows paths are). Compare native forms, normalized to forward slashes --
# native() (cygpath -m) always emits forward slashes, but $USERPROFILE is a raw
# Windows env var with backslashes, so it must be normalized too or the
# comparison silently falls through to the wrong branch.
SETTINGS_BASE_NATIVE="$(native "$SETTINGS_BASE")"
USERPROFILE_NATIVE="${USERPROFILE:-}"
USERPROFILE_NATIVE="${USERPROFILE_NATIVE//\\//}"
settings_lc="$(echo "$SETTINGS_BASE_NATIVE" | tr '[:upper:]' '[:lower:]')"
userprofile_lc="$(echo "$USERPROFILE_NATIVE" | tr '[:upper:]' '[:lower:]')"
userprofile_lc="${userprofile_lc%/}"
if [ -n "$userprofile_lc" ] && case "$settings_lc" in "$userprofile_lc"/*|"$userprofile_lc") true;; *) false;; esac; then
	USERDIR="ghidra"
else
	USERDIR="${USERNAME:-$(whoami)}-ghidra"
fi

SETTINGS_DIR="$SETTINGS_BASE/$USERDIR/$VERSIONED_NAME"
EXT_DIR="$SETTINGS_DIR/Extensions"
EXT_TARGET="$EXT_DIR/ghidra-retro-machines"
echo "== isolated settings dir: $SETTINGS_DIR =="

# --- 4. Install (skip if stamp matches) ----------------------------------
mkdir -p "$EXT_DIR"
STAMP_FILE="$SETTINGS_BASE/.install-stamp"
ZIP_STAMP="$(basename "$ZIP")|$(stat -c '%s %Y' "$ZIP" 2>/dev/null || stat -f '%z %m' "$ZIP")"

if [ -f "$STAMP_FILE" ] && [ "$(cat "$STAMP_FILE")" = "$ZIP_STAMP" ] && [ -d "$EXT_TARGET" ]; then
	echo "== extension already installed and up to date (stamp match); skipping unzip =="
else
	echo "== installing extension into $EXT_TARGET =="
	rm -rf "$EXT_TARGET"
	TMP_UNZIP="$(mktemp -d)"
	unzip -q "$ZIP" -d "$TMP_UNZIP" || {
		echo "FAIL: unzip $ZIP failed" >&2
		rm -rf "$TMP_UNZIP"
		exit 1
	}
	# The zip contains a single top-level dir named after the extension.
	SRC_DIR="$(find "$TMP_UNZIP" -mindepth 1 -maxdepth 1 -type d | head -n1)"
	if [ -z "$SRC_DIR" ]; then
		echo "FAIL: unexpected dist zip layout (no top-level dir) in $ZIP" >&2
		rm -rf "$TMP_UNZIP"
		exit 1
	fi
	mv "$SRC_DIR" "$EXT_TARGET"
	rm -rf "$TMP_UNZIP"
	echo "$ZIP_STAMP" >"$STAMP_FILE"
fi

if [ ! -d "$EXT_TARGET" ]; then
	echo "FAIL: sanity check failed, $EXT_TARGET does not exist after install" >&2
	exit 1
fi

# --- 5. Run selected headless chunks against the isolated settings dir -----
export BANKTEST_SETTINGS_BASE="$SETTINGS_BASE"
exec "$SCRIPT_DIR/run-banktest.sh" "$MODE" "${RUNNER_CHUNKS[@]}"
