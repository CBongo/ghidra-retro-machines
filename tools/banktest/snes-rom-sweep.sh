#!/usr/bin/env bash
# Generic sweep driver: runs ONE postScript over a list of SNES ROM images through the same
# headless machinery realrom-test.sh uses (isolated per-worktree build/ghidra-home, the staged
# extension, shared timeouts, decompiler banners). It is a survey aid -- no manifest, golden or
# bless. A ROM that fails, times out or is refused is recorded and the sweep carries on.
#
#   bash tools/banktest/snes-rom-sweep.sh --script RtsTrickProbe.java [--list FILE] [--analysis]
#        [--limit N] [--out DIR] [--batch-size N] [--no-build]
#
# Output: <out>/sweep.tsv (idx, file, size, status ok|timeout|error, wall_s, log), <out>/logs/NNNN.log
# (that ROM's section of the headless log), <out>/list.txt (the ROMs, one path per line).
# Per-ROM wall time inside a batch is the gap between consecutive SweepStamp.java stamps (import +
# analysis + script); the first ROM of a batch also pays JVM startup. A refused ROM gets no stamp
# (status error, wall 0). The ROM dir is only read: each image is copied into the work dir first.
set -u

usage() {
	cat <<'USAGE'
usage: snes-rom-sweep.sh --script <Probe.java> [options]
  --script S      postScript in tools/banktest to run on each import (required)
  --list FILE     ROM paths, one per line. Default: the deduped corpus from
                  build/snes-rom-corpus/roms.tsv (accepted=yes, checksumValid=true, one file per
                  title, unheadered preferred), resolved against $GRM_SNES_ROM_DIR
  --analysis      run auto-analysis (default: -noanalysis)
  --limit N       only the first N ROMs of the list
  --out DIR       output dir (default build/snes-sweep/<timestamp>)
  --batch-size N  imports per analyzeHeadless JVM (default 10; 1 = one JVM per ROM). A batch that
                  fails or times out is re-run ROM by ROM
  --no-build      skip the pre-flight `gradle stageExtensionForTests`
Tier games first: build --list with tools/banktest/snes-sweep-list.py.
Timeouts: GRM_HEADLESS_TIMEOUT[_BASE|_PER_PROGRAM] as in realrom-test.sh (sweep default
200s + 330s/program). Environment is inherited, so probe switches (e.g. GRM_RTSP_PART) work.
USAGE
}

SCRIPT_NAME=""; LIST=""; ANALYSIS=0; LIMIT=0; OUT=""; BATCH_N=10; NO_BUILD=0
while [ $# -gt 0 ]; do
	case "$1" in
		--script) SCRIPT_NAME="${2:?--script needs a value}"; shift 2 ;;
		--list) LIST="${2:?--list needs a value}"; shift 2 ;;
		--analysis) ANALYSIS=1; shift ;;
		--limit) LIMIT="${2:?--limit needs a value}"; shift 2 ;;
		--out) OUT="${2:?--out needs a value}"; shift 2 ;;
		--batch-size) BATCH_N="${2:?--batch-size needs a value}"; shift 2 ;;
		--no-build) NO_BUILD=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) echo "ERROR: unknown argument '$1'" >&2; usage >&2; exit 2 ;;
	esac
done
[ -n "$SCRIPT_NAME" ] || { echo "ERROR: --script is required" >&2; usage >&2; exit 2; }
case "$BATCH_N$LIMIT" in *[!0-9]*) echo "ERROR: --batch-size and --limit must be integers" >&2; exit 2 ;; esac
[ "$BATCH_N" -ge 1 ] || { echo "ERROR: --batch-size must be >= 1" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
[ -f "$SCRIPT_DIR/$SCRIPT_NAME" ] || { echo "ERROR: $SCRIPT_DIR/$SCRIPT_NAME not found" >&2; exit 2; }

[ -n "$OUT" ] || OUT="$REPO_ROOT/build/snes-sweep/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/logs"

# ---- the ROM list ----------------------------------------------------------------------------
if [ -z "$LIST" ]; then
	TSV="$REPO_ROOT/build/snes-rom-corpus/roms.tsv"
	[ -f "$TSV" ] || {
		echo "ERROR: $TSV is missing. Create it with: bash tools/banktest/build-and-test.sh check snes-rom-corpus" >&2
		exit 2
	}
	[ -n "${GRM_SNES_ROM_DIR:-}" ] || { echo "ERROR: GRM_SNES_ROM_DIR is unset" >&2; exit 2; }
	dirs=()
	if [[ "$GRM_SNES_ROM_DIR" == *";"* ]]; then
		IFS=';' read -r -a dirs <<<"$GRM_SNES_ROM_DIR"
	else
		read -r -a dirs <<<"$GRM_SNES_ROM_DIR"
	fi
	# One file per title: accepted=yes and checksumValid=true; an unheadered copy (copier=no) beats a headered.
	tr -d '\r' <"$TSV" | awk -F'\t' '
		NR == 1 { next }
		$4 == "yes" && $12 == "true" {
			t = $14
			if (!(t in best)) { best[t] = $1; cop[t] = $5; order[++n] = t }
			else if (cop[t] != "no" && $5 == "no") { best[t] = $1; cop[t] = $5 }
		}
		END { for (i = 1; i <= n; i++) print best[order[i]] }' >"$OUT/names.txt"
	: >"$OUT/list.txt"
	while IFS= read -r nm; do
		found=""
		for d in "${dirs[@]}"; do
			d="${d#"${d%%[![:space:]]*}"}"; d="${d%"${d##*[![:space:]]}"}"
			if [ -f "$d/$nm" ]; then found="$d/$nm"; break; fi
		done
		if [ -n "$found" ]; then echo "$found" >>"$OUT/list.txt"; else echo "WARN: $nm not found in \$GRM_SNES_ROM_DIR" >&2; fi
	done <"$OUT/names.txt"
else
	[ -f "$LIST" ] || { echo "ERROR: list file $LIST not found" >&2; exit 2; }
	tr -d '\r' <"$LIST" | grep -v '^[[:space:]]*$' >"$OUT/list.txt"
fi
if [ "$LIMIT" -gt 0 ]; then head -n "$LIMIT" "$OUT/list.txt" >"$OUT/list.lim" && mv -f "$OUT/list.lim" "$OUT/list.txt"; fi
mapfile -t ROMS <"$OUT/list.txt"
[ "${#ROMS[@]}" -gt 0 ] || { echo "ERROR: empty ROM list" >&2; exit 2; }

# ---- headless setup (same helpers as realrom-test.sh) ------------------------------------------
grm_default_headless
grm_preflight snes-loader
grm_print_identity_banners ab row
grm_headless_timeout_init 200 330
WORK="$(grm_work_dir sweep)" || exit 1
trap 'rm -rf "$WORK"' EXIT
echo "== sweep: ${#ROMS[@]} ROM(s), script $SCRIPT_NAME, analysis=$ANALYSIS, batch=$BATCH_N, timeout $TIMEOUT_BANNER =="
echo "== out: $OUT   work: $WORK =="

ARGS=(-loader SnesRomLoader)
[ "$ANALYSIS" = 1 ] || ARGS+=(-noanalysis)
ARGS+=(-scriptPath "$(native "$SCRIPT_DIR")" -postScript "$SCRIPT_NAME" -postScript SweepStamp.java)

printf 'idx\tfile\tsize\tstatus\twall_s\tlog\n' >"$OUT/sweep.tsv"
now_ms() { date +%s%3N; }
num() { printf '%04d' "$(($1 + 1))"; }

# record <idx> <status> <wall_ms>
record() {
	local idx="$1" st="$2" ms="$3" f
	f="${ROMS[$idx]}"
	printf '%s\t%s\t%s\t%s\t%d.%03d\t%s\n' "$(num "$idx")" "$(basename "$f")" "$(stat -c %s "$f")" "$st" \
		"$((ms / 1000))" "$((ms % 1000))" "logs/$(num "$idx").log" >>"$OUT/sweep.tsv"
}

# classify <log>: ok | error (no stamp = the script never ran, e.g. the loader refused the image)
classify() {
	if [ ! -s "$1" ] || ! grep -q 'SWEEPSTAMP' "$1" || grm_script_errors "$1" >/dev/null; then echo error; else echo ok; fi
}

# stage_rom <idx>: copy the ROM under a plain name into the work dir, print its native path
stage_rom() {
	local c
	c="$WORK/$(num "$1").sfc"
	cp -f "${ROMS[$1]}" "$c"
	native "$c"
}

run_solo() {
	local idx="$1" n log proj t0 t1 st status
	n="$(num "$idx")"
	log="$OUT/logs/$n.log"
	proj="$WORK/proj_$n"; mkdir -p "$proj"
	t0="$(now_ms)"
	run_headless_timed 1 "rom $n" "$log" "$(native "$proj")" \
		"$GHIDRA_HEADLESS" "$(native "$proj")" headless -import "$(stage_rom "$idx")" "${ARGS[@]}" -deleteProject
	st=$?
	t1="$(now_ms)"
	if [ "$st" -eq 124 ]; then status=timeout
	elif [ "$st" -ne 0 ]; then status=error
	else status="$(classify "$log")"; fi
	record "$idx" "$status" "$((t1 - t0))"
	echo "  [$n] ${ROMS[$idx]##*/}: $status ($(((t1 - t0) / 1000))s)"
	rm -rf "$proj" "$WORK/$n.sfc"
}

run_batch() { # <first-idx> <count>
	local first="$1" cnt="$2" i n proj blog pairs="" t0 st prev stamp status
	local imports=()
	if [ "$cnt" -eq 1 ] || [ "$BATCH_N" -le 1 ]; then
		for ((i = first; i < first + cnt; i++)); do run_solo "$i"; done
		return
	fi
	proj="$WORK/proj_b$first"; blog="$WORK/b$first.log"; mkdir -p "$proj"
	for ((i = first; i < first + cnt; i++)); do
		n="$(num "$i")"
		imports+=(-import "$(stage_rom "$i")")
		pairs="$pairs $n.sfc=${OUT//\\//}/logs/$n.log"
		rm -f "$OUT/logs/$n.log"
	done
	t0="$(now_ms)"
	run_headless_timed "$cnt" "batch@$((first + 1))" "$blog" "$(native "$proj")" \
		"$GHIDRA_HEADLESS" "$(native "$proj")" headless "${imports[@]}" "${ARGS[@]}" -deleteProject
	st=$?
	if [ "$st" -ne 0 ]; then
		echo "  batch@$((first + 1)) exited $st; re-running its $cnt ROM(s) one by one"
		for ((i = first; i < first + cnt; i++)); do run_solo "$i"; done
		rm -rf "$proj"
		return
	fi
	grm_split_batch_log "$blog" "$pairs"
	prev="$t0"
	for ((i = first; i < first + cnt; i++)); do
		n="$(num "$i")"
		status="$(classify "$OUT/logs/$n.log")"
		stamp="$(grep -o 'SWEEPSTAMP [0-9]*' "$OUT/logs/$n.log" 2>/dev/null | tail -1 | cut -d' ' -f2)"
		if [ -n "$stamp" ]; then
			record "$i" "$status" "$((stamp - prev))"
			echo "  [$n] ${ROMS[$i]##*/}: $status ($(((stamp - prev) / 1000))s)"
			prev="$stamp"
		else
			record "$i" "$status" 0
			echo "  [$n] ${ROMS[$i]##*/}: $status"
		fi
		rm -f "$WORK/$n.sfc"
	done
	rm -rf "$proj"
}

idx=0; total=${#ROMS[@]}
while [ "$idx" -lt "$total" ]; do
	cnt=$((total - idx)); [ "$cnt" -le "$BATCH_N" ] || cnt="$BATCH_N"
	run_batch "$idx" "$cnt"
	idx=$((idx + cnt))
done

ok=$(awk -F'\t' 'NR > 1 && $4 == "ok"' "$OUT/sweep.tsv" | wc -l)
echo "== sweep done: $ok/$total ok; see $OUT/sweep.tsv =="
exit 0
