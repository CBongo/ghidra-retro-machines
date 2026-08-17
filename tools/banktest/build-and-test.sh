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
# Usage: build-and-test.sh [check|bless] [--force-criteria] [chunk ...]
#
# bless refuses a fixture whose criteria failed and leaves its golden unchanged
# (bead grm-aqi); --force-criteria overrides that, and names every row it forced.
#
# Environment overrides:
#   GRM_GHIDRA_INSTALL   Ghidra install dir (default D:/ghidra_<ver>_PUBLIC, where <ver>
#                        is gradle.properties' ghidraTargetVersion).
#                        Exported as GHIDRA_INSTALL_DIR for the gradle build --
#                        build.gradle checks the GHIDRA_INSTALL_DIR env var
#                        FIRST, and the ambient one on this machine may point
#                        at a stale install, so we always override it here
#                        rather than inherit it.
#   GRADLE                gradle binary to use (default: the committed ./gradlew wrapper;
#                        falls back to `gradle` on PATH if the wrapper is missing)
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
# Establishes REPO_ROOT and GRM_TARGET_VERSION, and defines native() etc.
. "$SCRIPT_DIR/lib/common.sh"

usage() {
	cat <<EOF
usage: $0 [check|bless] [--force-criteria] [chunk ...]

Chunks: c64-banking c64-loader c64-recovery basic-petscii basic-dialects pet-loader c128-loader nes-banking
        petscii-strings unit spc700-vectors all

With no chunks, all is selected. Use --list-chunks to print this list.

--force-criteria  bless a fixture even though its criteria failed (bless only).
EOF
}

list_chunks() {
	cat <<'EOF'
c64-banking   C64 banktest through banktest4 fixtures
c64-loader    C64 PRG placement/wrapping, ROM loading, and symbol toggles
c64-recovery  C64 emulation and decrypt/recovery fixtures
basic-petscii C64 BASIC headless fixture
basic-dialects PET BASIC 4/C128 BASIC 7 token dialects plus C64 BASIC 2 regression
pet-loader    PET 4032 descriptor, PRG placement, IO types, and fixed ROM slots
c128-loader   C128 native BASIC PRG placement, fixed ROM slots, and MMU IO
nes-banking   NES banking and MMC fixtures
petscii-strings PetsciiStringAnalyzer C64 PRG fixture
unit          JUnit `gradle test` suite (all src/test/java; no extension build/install)
spc700-vectors Exhaustive SPC700 vector regression (needs GRM_SPC700_VECTORS; opt-in, not in `all`)
all           Every chunk (the default; does NOT include spc700-vectors -- see its own row)
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

# Passed straight through to run-banktest.sh, which owns the semantics; validated
# there too, so the two front ends cannot disagree about when it is legal.
RUNNER_FLAGS=()
while [ "$#" -gt 0 ]; do
	case "${1:-}" in
		--force-criteria) RUNNER_FLAGS+=("$1"); shift ;;
		*) break ;;
	esac
done
if [ "${#RUNNER_FLAGS[@]}" -gt 0 ] && [ "$MODE" != "bless" ]; then
	echo "FAIL: --force-criteria is only meaningful with bless" >&2
	usage >&2
	exit 2
fi

if [ "$#" -eq 0 ]; then
	REQUESTED_CHUNKS=(all)
else
	REQUESTED_CHUNKS=("$@")
fi

for chunk in "${REQUESTED_CHUNKS[@]}"; do
	case "$chunk" in
		c64-banking|c64-loader|c64-recovery|basic-petscii|basic-dialects|pet-loader|c128-loader|nes-banking|petscii-strings|unit|spc700-vectors|all) ;;
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
# The migrated verifiers (bead grm-32f.4) and the program-fixture/pure unit tests all live in
# the single JUnit `test` task. `test` is monolithic -- it runs the WHOLE src/test/java suite
# wherever invoked -- so rather than making every headless chunk pay for it, it is exposed as
# its OWN chunk, `unit` (bead grm-32f.5). Headless chunks run only their fixtures; `unit` runs
# only `gradle test` (no extension build/install); and the full `all` gate runs both. The
# suite is small and fast (~seconds; one AbstractGenericTest class bootstraps Application),
# so finer per-chunk --tests scoping was deliberately not added -- a chunk->test-class map
# would be fragile for negligible gain.
# spc700-vectors (bead grm-c9d.2) is deliberately NOT expanded by `all`, unlike every other
# chunk: it needs a large, user-supplied SPC700 vector clone (GRM_SPC700_VECTORS) this repo
# cannot ship, so -- exactly like the real-ROM tier -- it stays manual/opt-in rather than part
# of the default gate. It must be named explicitly to run.
RUN_HEADLESS=0
RUNNER_CHUNKS=()
RUN_JUNIT=0
RUN_SPC700_VECTORS=0
if has_chunk all; then
	RUN_HEADLESS=1
	RUNNER_CHUNKS=(all)
	RUN_JUNIT=1
else
	for chunk in c64-banking c64-loader c64-recovery basic-petscii basic-dialects pet-loader c128-loader nes-banking petscii-strings; do
		if has_chunk "$chunk"; then
			RUN_HEADLESS=1
			RUNNER_CHUNKS+=("$chunk")
		fi
	done
	if has_chunk unit; then
		RUN_JUNIT=1
	fi
fi
if has_chunk spc700-vectors; then
	RUN_SPC700_VECTORS=1
fi
GRADLE_CHECKS=()
[ "$RUN_JUNIT" -eq 1 ] && GRADLE_CHECKS+=(test)
[ "$RUN_SPC700_VECTORS" -eq 1 ] && GRADLE_CHECKS+=(spc700VectorTest)

if [ "$MODE" = "bless" ] && [ "$RUN_HEADLESS" -ne 1 ]; then
	echo "FAIL: bless requires at least one headless chunk with golden output" >&2
	usage >&2
	exit 2
fi

# Default install derives from gradle.properties' ghidraTargetVersion (the single source of
# truth for the targeted Ghidra version, bead grm-9r7); GRM_GHIDRA_INSTALL still overrides.
grm_default_ghidra_install
# Resolve the gradle binary (bead grm-ycv): GRADLE env var wins if set; otherwise prefer
# the committed wrapper (REPO_ROOT/gradlew), which pins the exact distribution+checksum in
# gradle/wrapper/gradle-wrapper.properties and needs nothing pre-installed on a fresh
# checkout; otherwise fall back to `gradle` on PATH; otherwise fail loudly rather than
# defaulting to some one-off developer install path.
if [ -n "${GRADLE:-}" ]; then
	: # explicit override wins
elif [ -x "$REPO_ROOT/gradlew" ]; then
	GRADLE="$REPO_ROOT/gradlew"
elif command -v gradle >/dev/null 2>&1; then
	GRADLE="$(command -v gradle)"
else
	echo "FAIL: no gradle binary found. Tried: \$GRADLE (unset), $REPO_ROOT/gradlew (missing" \
		"or not executable), 'gradle' on PATH (not found). Set GRADLE=/path/to/gradle or" \
		"restore the committed gradlew wrapper." >&2
	exit 1
fi

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

# A `unit`-only selection has no headless fixture. It intentionally
# stops after the Gradle `test` run above, avoiding the extension loop.
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
	# Repo-local staging (bead grm-419), which matters here beyond consistency:
	# EXT_TARGET lives under build/, so staging there too makes the mv below a
	# same-volume rename instead of a full copy+delete of the extension tree.
	TMP_UNZIP="$(grm_work_dir extinstall)"
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
	# Atomic + checked (bead grm-z34): a torn stamp write is not a correctness risk here
	# (the up-to-date check below is an exact string match, so a truncated stamp just
	# reads as "stale" and reinstalls next time), but it must still not be silently
	# swallowed -- an unreported failure to write the stamp gives no signal that every
	# future run will pay the reinstall cost it was meant to avoid.
	if ! grm_atomic_publish_stdin "$STAMP_FILE" <<<"$ZIP_STAMP"; then
		echo "FAIL: could not write $STAMP_FILE" >&2
		exit 1
	fi
fi

if [ ! -d "$EXT_TARGET" ]; then
	echo "FAIL: sanity check failed, $EXT_TARGET does not exist after install" >&2
	exit 1
fi

# --- 5. Run selected headless chunks against the isolated settings dir -----
export BANKTEST_SETTINGS_BASE="$SETTINGS_BASE"

# This gate does NOT run the real-ROM tier (bead grm-6kv): it needs user-supplied,
# hash-pinned ROMs the repo cannot ship, so it stays a separate, manual, pre-commit step
# (`bash tools/banktest/realrom-test.sh check`; see CLAUDE.md, "Build & Test"). Printing the
# staleness note here -- not just inside realrom-test.sh itself -- means a normal
# `build-and-test.sh check` surfaces "the real-ROM tier hasn't run since <commit>" even for
# someone who never invokes realrom-test.sh directly, instead of silently reporting a clean
# gate that never touched real cartridge idioms (grm_realrom_staleness_note, lib/common.sh).
grm_realrom_staleness_note

exec "$SCRIPT_DIR/run-banktest.sh" "$MODE" ${RUNNER_FLAGS[@]+"${RUNNER_FLAGS[@]}"} "${RUNNER_CHUNKS[@]}"
