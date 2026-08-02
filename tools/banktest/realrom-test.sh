#!/usr/bin/env bash
# OPTIONAL, hash-pinned real-ROM regression tier for the NES board descriptors.
# Deliberately NOT a run-banktest.sh chunk and NOT invoked by build-and-test.sh's
# default gate (whose `all` selects every chunk) -- real ROMs are copyrighted and
# user-supplied, so this lives alongside measure-overlay-scale.sh and is invoked by
# hand:
#
#   bash tools/banktest/realrom-test.sh check    [--gme|--all] [--only|--except <ids>] <romdir> ...
#   bash tools/banktest/realrom-test.sh bless    [--gme|--all] [--only|--except <ids>] <romdir> ...
#   bash tools/banktest/realrom-test.sh nominate <romdir> ...
#
# (romdirs may also be supplied via GRM_ROM_DIR, space-separated.)
#
# There are two row sets and the flags SELECT one rather than adding to it: no flag =
# realrom/manifest.tsv (the curated board-representative set), --gme = realrom/manifest-gme.tsv
# (game-music-extraction titles of interest), --all = both. Additive --gme was the first
# design and it was wrong: `bless --gme` then silently re-blessed all twelve curated goldens
# alongside the ones asked for. Every run announces the set it picked.
#
# `nominate` emits paste-ready manifest rows for a ROM dir -- hashing each dump, decoding its
# iNES mapper and resolving the claiming board -- and flags any mapper no shipped descriptor
# claims as a board gap. It needs no Ghidra install.
#
# --only/--except take comma-separated manifest ids and select which rows the run
# considers at all. --except exists for the recurring case this tier actually hits: one
# title is deliberately held back at a pre-regression golden (megaman, per grm-g73 and
# grm-hum) while every other title needs re-blessing, and blessing it would erase the
# record the bead depends on. Before these flags the only way to scope a bless was to
# stage the wanted ROMs into a separate directory, which is easy to get quietly wrong.
# An id that is not in the manifest is a hard ERROR, never a silent no-op: a typo in
# `--except megman` must not bless megaman. Filtered rows are omitted from the run and
# counted separately -- deliberately NOT reported as SKIP, which means "ROM absent".
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

USAGE="usage: $0 check|bless|nominate [--gme|--all] [--only <ids>|--except <ids>] <romdir> [<romdir> ...]
  (no set flag) realrom/manifest.tsv      -- the curated board-representative set
  --gme         realrom/manifest-gme.tsv  -- the game-music-extraction set ONLY
  --all         both manifests"

MODE="${1:-}"
case "$MODE" in
	check|bless|nominate) shift ;;
	*)
		echo "$USAGE" >&2
		exit 2
		;;
esac

# Row selection (see the header note). Empty ONLY_IDS means "every row"; EXCEPT_IDS is
# applied on top. Both are kept as comma-delimited strings with sentinel commas so a
# membership test is a plain substring match -- no associative arrays, matching the
# portability level of the rest of this script.
ONLY_IDS=""
EXCEPT_IDS=""
# Which manifest(s) this run considers. Default is the curated board-representative set.
# --gme SELECTS the game-music-extraction set instead of it, rather than adding to it: that
# set is a reference point for planning and an occasional thorough check, not a gate, and
# `bless --gme` meaning "also re-bless all twelve curated goldens" is a surprise that costs
# real work to undo. --all is the explicit way to ask for both.
MANIFEST_SET=core
while [ $# -gt 0 ]; do
	case "$1" in
		--gme)
			MANIFEST_SET=gme
			shift
			;;
		--all)
			MANIFEST_SET=all
			shift
			;;
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
			break
			;;
	esac
done

ROM_DIRS=("$@")
if [ ${#ROM_DIRS[@]} -eq 0 ] && [ -n "${GRM_ROM_DIR:-}" ]; then
	# shellcheck disable=SC2206
	ROM_DIRS=($GRM_ROM_DIR)
fi
if [ ${#ROM_DIRS[@]} -eq 0 ]; then
	echo "$USAGE   (or set GRM_ROM_DIR)" >&2
	exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REALROM_DIR="$SCRIPT_DIR/realrom"
MANIFEST="$REALROM_DIR/manifest.tsv"
GME_MANIFEST="$REALROM_DIR/manifest-gme.tsv"
EXPECTED_DIR="$REALROM_DIR/expected"

if [ ! -f "$MANIFEST" ]; then
	echo "ERROR: manifest not found: $MANIFEST" >&2
	exit 2
fi
MANIFESTS=()
case "$MANIFEST_SET" in
	core) MANIFESTS=("$MANIFEST") ;;
	gme)  MANIFESTS=("$GME_MANIFEST") ;;
	all)  MANIFESTS=("$MANIFEST" "$GME_MANIFEST") ;;
esac
if [ "$MANIFEST_SET" != core ] && [ ! -f "$GME_MANIFEST" ]; then
	echo "ERROR: --$MANIFEST_SET needs $GME_MANIFEST, which does not exist." >&2
	echo "       Populate it with: $0 nominate <romdir> [<romdir> ...]" >&2
	exit 2
fi
echo "== manifest set: $MANIFEST_SET (${#MANIFESTS[@]} file(s)) =="

# Ragged rows are a RENDERING defect, never a correctness one -- `read` treats a missing
# trailing field and an empty one identically -- so this warns and continues. It exists
# because the fix (a trailing tab on rows with no loader_opts) is invisible whitespace that
# editors and paste buffers strip, so without a reminder the GitHub table quietly degrades.
for m in "${MANIFESTS[@]}"; do
	ragged="$(tr -d '\r' < "$m" | awk -F'\t' '!/^#/ && NF && NF != 7 { printf "%s ", $1 }')"
	[ -z "$ragged" ] || {
		echo "NOTE: $(basename "$m") has rows that are not 7 fields wide: $ragged" >&2
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
all_manifests=("$MANIFEST")
[ -f "$GME_MANIFEST" ] && all_manifests+=("$GME_MANIFEST")
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
					[ "$MANIFEST_SET" = all ] ||
						echo "hint: this run covers the '$MANIFEST_SET' set only; --gme selects the" \
							"game-music-extraction titles, --all covers both" >&2
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
	nominate_known=("$MANIFEST")
	[ -f "$GME_MANIFEST" ] && nominate_known+=("$GME_MANIFEST")
	known_shas=" $(cat "${nominate_known[@]}" | tr -d '\r' |
		awk -F'\t' '!/^#/ && NF && $1 != "id" { printf "%s:%s ", tolower($3), $1 }')"

	echo "# Nominated rows -- review, then paste into realrom/manifest-gme.tsv."
	echo "# id is the containing directory name where the ROM sits in a per-title subdir"
	echo "# (your game-music-extraction shorthand), else the file's base name."
	n_new=0; n_known=0; n_unsupported=0; n_notines=0
	shopt -s nullglob nocaseglob
	for dir in "${ROM_DIRS[@]}"; do
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
	while IFS=$'\t' read -r g_id g_title g_sha _ _ g_golden _; do
		case "${g_id:-}" in ""|id|\#*) continue ;; esac
		g_path="$EXPECTED_DIR/${g_golden:-$g_id.dump}"
		[ -f "$g_path" ] || continue
		g_prog="$(awk '/^REALROM program /{print $3; exit}' "$g_path")"
		g_gsha="$(awk '/^REALROM sha256 /{print tolower($3); exit}' "$g_path")"
		g_want="$(printf '%s' "$g_sha" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
		if [ "$g_prog" != "$g_id.nes" ] || [ "$g_gsha" != "$g_want" ]; then
			mismatched="$mismatched  $g_id: $(basename "$g_path") says program=$g_prog sha=${g_gsha:0:12}...
"
		fi
	done < <(cat "${MANIFESTS[@]}" | tr -d '\r')
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
# Compute the extension identity once; empty => caching disabled for this run.
EXT_ID="$(ext_identity)" || EXT_ID=""

realrom_cache_key() {
	# args: id rom_sha opts  ->  sha256 key on stdout, or empty if disabled
	#
	# The id is part of the key because it is part of the OUTPUT: import_and_dump names the
	# ROM copy after it, so it reaches the dump as `REALROM program <id>.nes`. Leaving it out
	# meant renaming a row (wizwarr -> ironsword) left the key untouched, so a bless reused
	# the pre-rename candidate and wrote the old name straight back into the golden. Anything
	# that can change the dump has to be in here.
	local id="$1" rom_sha="$2" opts="$3"
	[ -n "$EXT_ID" ] || { printf ''; return 0; }
	{
		printf 'id:%s\n' "$id"
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
n_pass=0; n_fail=0; n_skip=0; n_bless=0; n_filtered=0

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

	# REALROM_EXTRA_POSTSCRIPT runs one more script (e.g. BankReachProbe.java) on the same
	# import, so a diagnostic does not cost a second ~1min+ analysis. Goldens are unaffected:
	# the awk carve below extracts only the REALROM block, and every other script fences its
	# own output. Give it its OWN invocation rather than piggybacking a routine run, though --
	# realrom_cache_key() above hashes RealRomDump.java only, so a `bless` (or a re-`check`)
	# can legitimately reuse a cached dump and never run the extra script at all.
	# shellcheck disable=SC2086
	"$GHIDRA_HEADLESS" "$(native "$proj")" headless \
		-import "$(native "$rom_copy")" \
		-loader NesRomLoader \
		$opts \
		-scriptPath "$(native "$SCRIPT_DIR")" \
		-postScript RealRomDump.java \
		${REALROM_EXTRA_POSTSCRIPT:+-postScript "$REALROM_EXTRA_POSTSCRIPT"} \
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
	# Skip blank lines, the bare header row, and comments. The manifest deliberately carries
	# no `#` preamble (GitHub's tabular viewer has no comment syntax and would render it as
	# rows) -- see realrom/README.md -- but a one-off comment stays legal.
	case "${id:-}" in ""|id|\#*) continue ;; esac

	# Row selection (--only/--except). Applied before any import work, so a filtered row
	# costs nothing. Filtered rows are counted but produce no ROW_* entry: they are not results.
	if { [ -n "$ONLY_IDS" ] && [ "${ONLY_IDS#*,$id,}" = "$ONLY_IDS" ]; } ||
		{ [ -n "$EXCEPT_IDS" ] && [ "${EXCEPT_IDS#*,$id,}" != "$EXCEPT_IDS" ]; }; then
		n_filtered=$((n_filtered + 1))
		echo "-- $id ($title): filtered out"
		continue
	fi
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
	key="$(realrom_cache_key "$id" "$sha" "$opts")"
	cached="$CACHE_DIR/$key.dump"

	# bless fast path: reuse the candidate a prior check imported for this exact
	# ROM + opts + build, showing the golden diff before accepting it. The
	# cached dump was only stored after its sha recheck passed, so it is
	# known-good.
	if [ "$MODE" = bless ] && [ -n "$key" ] && [ -f "$cached" ]; then
		# Assert the candidate is about THIS row before believing the key. A cache key is a
		# claim that nothing outside it can change the dump, and that claim has been wrong
		# twice: the id was missing (a rename reused the pre-rename candidate and wrote the
		# old name back into the golden) and the loose data/machines/*.map descriptors were
		# outside ext_identity. Both are fixed above; this check is what makes the NEXT
		# omission fail loudly instead of silently blessing a stale dump, which is the whole
		# failure mode this tier exists to prevent.
		cached_prog="$(awk '/^REALROM program /{print $3; exit}' "$cached")"
		cached_sha="$(awk '/^REALROM sha256 /{print tolower($3); exit}' "$cached")"
		if [ "$cached_prog" != "$id.nes" ] || [ "$cached_sha" != "$sha" ]; then
			echo "    stale cache entry ignored (program='$cached_prog' want='$id.nes'," \
				"sha='$cached_sha' want='$sha') -- re-importing" >&2
			rm -f "$cached"
		else
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
# Process substitution, NOT a pipe: the loop body appends to ROW_ID/ROW_STATUS/ROW_DETAIL
# and bumps the n_* counters, and a pipe would run it in a subshell that discards every
# result at `done` -- while still exiting 0. The `tr` is a second layer behind
# .gitattributes' `*.tsv text eol=lf`, covering a working-tree copy an editor rewrote with
# CRLF after checkout; a stray \r on the row's last field otherwise rides into a path.
done < <(cat "${MANIFESTS[@]}" | tr -d '\r')

echo
printf '%-16s %-6s %s\n' "ID" "STATUS" "DETAIL"
for i in "${!ROW_ID[@]}"; do
	printf '%-16s %-6s %s\n' "${ROW_ID[$i]}" "${ROW_STATUS[$i]}" "${ROW_DETAIL[$i]}"
done
echo
filtered_note=""
[ "$n_filtered" -gt 0 ] && filtered_note=" filtered=$n_filtered"
echo "summary: pass=$n_pass fail=$n_fail skip=$n_skip bless=$n_bless$filtered_note   (work: $WORK)"

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
