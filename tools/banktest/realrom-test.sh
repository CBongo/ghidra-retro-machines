#!/usr/bin/env bash
# OPTIONAL, hash-pinned real-ROM regression tier for the NES board descriptors.
# Deliberately NOT a run-banktest.sh chunk and NOT invoked by build-and-test.sh's
# default gate (whose `all` selects every chunk) -- real ROMs are copyrighted and
# user-supplied, so this lives alongside measure-overlay-scale.sh and is invoked by
# hand:
#
#   bash tools/banktest/realrom-test.sh check  <romdir> [<romdir> ...]
#   bash tools/banktest/realrom-test.sh bless  <romdir> [<romdir> ...]
#
# (romdirs may also be supplied via GRM_ROM_DIR, space-separated.)
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
# Requires the isolated extension install from a prior
#   bash tools/banktest/build-and-test.sh check nes-banking
# (populates build/ghidra-home). Environment overrides mirror measure-overlay-scale.sh:
#   GHIDRA_HEADLESS         path to analyzeHeadless(.bat)
#   BANKTEST_SETTINGS_BASE  relocate Ghidra user-settings/Extensions dir (defaults to
#                            <repo>/build/ghidra-home)
#   GRM_ROM_DIR             default rom dir(s) if none given on the command line
set -u

MODE="${1:-}"
case "$MODE" in
	check|bless) shift ;;
	*)
		echo "usage: $0 check|bless <romdir> [<romdir> ...]" >&2
		exit 2
		;;
esac

ROM_DIRS=("$@")
if [ ${#ROM_DIRS[@]} -eq 0 ] && [ -n "${GRM_ROM_DIR:-}" ]; then
	# shellcheck disable=SC2206
	ROM_DIRS=($GRM_ROM_DIR)
fi
if [ ${#ROM_DIRS[@]} -eq 0 ]; then
	echo "usage: $0 $MODE <romdir> [<romdir> ...]   (or set GRM_ROM_DIR)" >&2
	exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REALROM_DIR="$SCRIPT_DIR/realrom"
MANIFEST="$REALROM_DIR/manifest.tsv"
EXPECTED_DIR="$REALROM_DIR/expected"

if [ ! -f "$MANIFEST" ]; then
	echo "ERROR: manifest not found: $MANIFEST" >&2
	exit 2
fi
mkdir -p "$EXPECTED_DIR"

# Default headless path derives from gradle.properties' ghidraTargetVersion (single
# source of truth); GHIDRA_HEADLESS still overrides.
GRM_TARGET_VERSION="$(sed -n 's/^ghidraTargetVersion=//p' "$REPO_ROOT/gradle.properties")"
GHIDRA_HEADLESS="${GHIDRA_HEADLESS:-D:/ghidra_${GRM_TARGET_VERSION}_PUBLIC/support/analyzeHeadless.bat}"

native() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi
}

# Same isolation as measure-overlay-scale.sh: point Ghidra's settings/Extensions dir at
# the per-worktree build/ghidra-home tree that build-and-test.sh populates.
if [ -z "${BANKTEST_SETTINGS_BASE:-}" ]; then
	if [ -d "$REPO_ROOT/build/ghidra-home" ]; then
		BANKTEST_SETTINGS_BASE="$REPO_ROOT/build/ghidra-home"
	else
		echo "NOTE: $REPO_ROOT/build/ghidra-home not found (run" \
			"'bash tools/banktest/build-and-test.sh check nes-banking' first to install the" \
			"isolated extension); falling back to the shared %APPDATA%/ghidra install." >&2
		BANKTEST_SETTINGS_BASE=
	fi
fi
if [ -n "${BANKTEST_SETTINGS_BASE:-}" ]; then
	base_native="$(native "$BANKTEST_SETTINGS_BASE")"
	export GHIDRA_HEADLESS_JAVA_OPTIONS="${GHIDRA_HEADLESS_JAVA_OPTIONS:-} -Dapplication.settingsdir=$base_native -Dapplication.cachedir=$base_native/cache"
fi

if ! command -v sha256sum >/dev/null 2>&1; then
	echo "ERROR: sha256sum not found on PATH (needed to hash-pin ROMs)." >&2
	exit 2
fi

# --- candidate-dump cache (bead grm-lne) --------------------------------
# Mirror build-and-test.sh's cache: `check` stashes each freshly imported dump
# so a follow-up `bless` reuses it instead of paying the ~1min+ real-ROM import
# again. Keyed by the pinned ROM sha, the loader options, the RealRomDump
# script, and the installed extension identity, so a rebuild or manifest edit
# forces a fresh import. Disabled (bless re-imports) when the extension identity
# is unknown (e.g. falling back to the shared %APPDATA% install).
CACHE_DIR="$REPO_ROOT/build/realrom-cache"

ext_identity() {
	# Content fingerprint of the installed extension jar(s); see the fuller note
	# in run-banktest.sh. NOT a file mtime/stamp -- gradle rewrites the dist zip
	# every build with identical bytecode, so an mtime-based id never matches
	# across a check->bless pair. unzip -v's CRC-32 column is content-only.
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

realrom_cache_key() {
	# args: rom_sha opts  ->  sha256 key on stdout, or empty if disabled
	local rom_sha="$1" opts="$2"
	[ -n "$EXT_ID" ] || { printf ''; return 0; }
	{
		printf 'rom:%s\n' "$rom_sha"
		printf 'opts:%s\n' "$opts"
		printf 'dumpscript:'; sha256sum "$SCRIPT_DIR/RealRomDump.java" | cut -d' ' -f1
		printf 'ext:%s\n' "$EXT_ID"
	} | sha256sum | cut -d' ' -f1
}

WORK="${REALROM_WORK_DIR:-$(mktemp -d)}"
mkdir -p "$WORK"
echo "== work dir: $WORK =="

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
echo "== indexing ROM dirs by sha256 =="
shopt -s nullglob nocaseglob
for dir in "${ROM_DIRS[@]}"; do
	if [ ! -d "$dir" ]; then
		echo "  WARN: not a directory, skipping: $dir" >&2
		continue
	fi
	count=0
	for f in "$dir"/*.nes; do
		[ -f "$f" ] || continue
		h="$(sha256sum "$f" | cut -d' ' -f1 | tr 'A-Z' 'a-z')"
		# First occurrence wins; a manifest pins one exact dump anyway.
		if [ -z "${ROM_BY_SHA[$h]:-}" ]; then
			ROM_BY_SHA[$h]="$f"
		fi
		count=$((count + 1))
	done
	echo "  $dir: hashed $count .nes file(s)"
done
shopt -u nullglob nocaseglob

# ------------------------------------------------------------------
# Walk the manifest.
# ------------------------------------------------------------------
declare -a ROW_ID ROW_STATUS ROW_DETAIL
n_pass=0; n_fail=0; n_skip=0; n_bless=0

import_and_dump() {
	# $1 id  $2 rom_path  $3 loader_opts  -> writes normalized dump to $4
	local id="$1" rom="$2" opts="$3" out="$4"
	local safe rom_copy proj log
	safe="$(sanitize "$id")"
	rom_copy="$WORK/${safe}.nes"
	cp -f "$rom" "$rom_copy"
	proj="$WORK/proj_${safe}"
	mkdir -p "$proj"
	log="$WORK/${safe}.log"

	# shellcheck disable=SC2086
	"$GHIDRA_HEADLESS" "$(native "$proj")" headless \
		-import "$(native "$rom_copy")" \
		-loader NesRomLoader \
		$opts \
		-scriptPath "$(native "$SCRIPT_DIR")" \
		-postScript RealRomDump.java \
		-deleteProject \
		>"$log" 2>&1
	local status=$?
	if [ $status -ne 0 ]; then
		echo "    analyzeHeadless exited $status (log: $log)" >&2
		return 1
	fi

	# Strip headless's "INFO RealRomDump.java> <msg> (GhidraScript)" wrapping, then carve
	# the REALROM block.
	sed 's/\r$//; s/^.*RealRomDump\.java> //; s/ (GhidraScript)[[:space:]]*$//' "$log" \
		| awk '/^=== REALROM BEGIN ===$/{c=1} c{print} /^=== REALROM END ===$/{c=0}' >"$out"

	if ! grep -q '^=== REALROM END ===$' "$out"; then
		echo "    no REALROM block produced (log: $log)" >&2
		return 1
	fi
	return 0
}

while IFS=$'\t' read -r id title sha mapper board golden opts || [ -n "${id:-}" ]; do
	# Skip blank lines and comments.
	case "${id:-}" in ""|\#*) continue ;; esac
	# Strip the CR off the row's LAST field. The manifest is checked out with CRLF endings on
	# Windows, and whichever field happens to be last on a row carries the \r into a path or an
	# argument -- which fails as a mystifying "golden not found" for a file that plainly exists.
	# Which field is last varies by row (the opts column is optional), so strip all of them.
	id="${id%$'\r'}"; title="${title%$'\r'}"; mapper="${mapper%$'\r'}"
	board="${board%$'\r'}"; golden="${golden%$'\r'}"; opts="${opts%$'\r'}"
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

	out="$WORK/${id}.dump"
	key="$(realrom_cache_key "$sha" "$opts")"
	cached="$CACHE_DIR/$key.dump"

	# bless fast path: reuse the candidate a prior check imported for this exact
	# ROM + opts + build, showing the golden diff before accepting it. The
	# cached dump was only stored after its sha recheck passed, so it is
	# known-good.
	if [ "$MODE" = bless ] && [ -n "$key" ] && [ -f "$cached" ]; then
		echo "-- $id ($title): reusing cached candidate from prior check (no re-import)"
		if [ -f "$golden_path" ]; then
			diff -u "$golden_path" "$cached" && echo "    no change vs golden"
		fi
		cp -f "$cached" "$golden_path"
		ROW_ID+=("$id"); ROW_STATUS+=("BLESS"); ROW_DETAIL+=("$golden (cached)")
		n_bless=$((n_bless + 1))
		echo "    blessed (from cache) -> $golden_path"
		continue
	fi

	echo "-- $id ($title): importing $(basename "$rom")"
	if ! import_and_dump "$id" "$rom" "$opts" "$out"; then
		ROW_ID+=("$id"); ROW_STATUS+=("FAIL"); ROW_DETAIL+=("import/dump error")
		n_fail=$((n_fail + 1))
		continue
	fi

	# Second-layer hash check: the SHA-256 Ghidra computed on the imported bytes must
	# equal the manifest pin (belt-and-suspenders over the index match).
	dumped_sha="$(sed -n 's/^REALROM sha256 //p' "$out" | head -n1 | tr 'A-Z' 'a-z')"
	if [ "$dumped_sha" != "$sha" ]; then
		ROW_ID+=("$id"); ROW_STATUS+=("FAIL")
		ROW_DETAIL+=("sha mismatch: dumped=$dumped_sha manifest=$sha")
		n_fail=$((n_fail + 1))
		echo "    FAIL: program sha256 $dumped_sha != manifest $sha"
		continue
	fi

	# Known-good candidate (sha recheck passed): stash it so a follow-up bless
	# reuses it without re-importing.
	if [ -n "$key" ]; then
		mkdir -p "$CACHE_DIR"
		cp -f "$out" "$cached"
	fi

	if [ "$MODE" = bless ]; then
		cp -f "$out" "$golden_path"
		ROW_ID+=("$id"); ROW_STATUS+=("BLESS"); ROW_DETAIL+=("$golden")
		n_bless=$((n_bless + 1))
		echo "    blessed -> $golden_path"
		continue
	fi

	# check mode
	if [ ! -f "$golden_path" ]; then
		ROW_ID+=("$id"); ROW_STATUS+=("FAIL"); ROW_DETAIL+=("missing golden $golden (bless first)")
		n_fail=$((n_fail + 1))
		echo "    FAIL: golden not found: $golden_path"
		continue
	fi
	if diff -u "$golden_path" "$out" >"$WORK/${id}.diff" 2>&1; then
		ROW_ID+=("$id"); ROW_STATUS+=("PASS"); ROW_DETAIL+=("")
		n_pass=$((n_pass + 1))
		echo "    PASS"
	else
		ROW_ID+=("$id"); ROW_STATUS+=("FAIL"); ROW_DETAIL+=("dump differs from golden")
		n_fail=$((n_fail + 1))
		echo "    FAIL: dump differs from golden (see $WORK/${id}.diff)"
		sed -n '1,40p' "$WORK/${id}.diff"
	fi
done < "$MANIFEST"

echo
printf '%-16s %-6s %s\n' "ID" "STATUS" "DETAIL"
for i in "${!ROW_ID[@]}"; do
	printf '%-16s %-6s %s\n' "${ROW_ID[$i]}" "${ROW_STATUS[$i]}" "${ROW_DETAIL[$i]}"
done
echo
echo "summary: pass=$n_pass fail=$n_fail skip=$n_skip bless=$n_bless   (work: $WORK)"

if [ "$n_fail" -gt 0 ]; then
	echo "REALROM $MODE: FAIL"
	exit 1
fi
if [ "$n_pass" -eq 0 ] && [ "$n_bless" -eq 0 ]; then
	echo "REALROM $MODE: SKIPPED (no matching ROMs supplied) -- nothing verified"
	exit 0
fi
echo "REALROM $MODE: OK"
exit 0
