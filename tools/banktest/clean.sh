#!/usr/bin/env bash
# Full reset of the disposable banktest scratch under build/ (bead grm-uqhd), short of
# `rm -rf build` -- which would also destroy build/ghidra-home (the staged extension +
# Ghidra user settings) and force a restage. This script NEVER touches build/ghidra-home.
#
# Usage: bash tools/banktest/clean.sh [--dry-run]
#
# Removes (reporting the size of each first):
#   - the work base       build/banktest-work (or the dot-segment TEMP fallback / the
#                         GRM_BANKTEST_WORK override, whichever grm_work_base resolves)
#   - build/banktest-cache        candidate-dump cache (check -> bless fast path)
#   - build/realrom-cache         real-ROM candidate cache -- ENTRIES ONLY (*.dump/*.crit).
#                         Dotfiles survive: .last-verified is the REALROM staleness stamp
#                         (GRM_REALROM_STAMP), not cache, and deleting it would make the
#                         tier read "never run" for a reason that is not true.
#   - build/kept-projects         --keep-project analysis projects (and the TEMP fallback)
#                         NB: tools/ghidra-mcp/serve.sh serves from these; they are re-made
#                         by `realrom-test.sh check <set> --only <id> --keep-project`.
#   - build/mcp-project           serve.sh's served project copies (and the TEMP fallback);
#                         serve.sh re-copies on every start. Stop any server first.
#
# --dry-run prints the same report and deletes nothing.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

DRY=0
case "${1:-}" in
	"") ;;
	--dry-run) DRY=1 ;;
	-h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
	*) echo "usage: clean.sh [--dry-run]" >&2; exit 2 ;;
esac

# du over the 9,000-file banktest-cache is slow-ish on Windows but finishes; -sk is portable.
size_kb() { du -sk "$1" 2>/dev/null | cut -f1; }

total_kb=0
report() { # $1 label  $2 path
	local kb
	kb="$(size_kb "$2")"
	printf '  %-60s %8s MB\n' "$1" "$(( ${kb:-0} / 1024 ))"
	total_kb=$((total_kb + ${kb:-0}))
}

WORK_BASE="$(grm_work_base)"
KEPT="$REPO_ROOT/build/kept-projects"
KEPT_FALLBACK="$(_grm_temp_fallback_dir kept-projects)"
# serve.sh's project copies (grm-f0i0), repo-local or at the same dot-segment fallback.
MCP_PROJ="$REPO_ROOT/build/mcp-project"
MCP_PROJ_FALLBACK="$(_grm_temp_fallback_dir mcp-project)"
[ -n "${GRM_KEEP_PROJECT_DIR:-}" ] && KEPT_OVERRIDE="$GRM_KEEP_PROJECT_DIR" || KEPT_OVERRIDE=""

targets=()
for d in "$WORK_BASE" "$REPO_ROOT/build/banktest-cache" "$KEPT" "$KEPT_FALLBACK" \
	"$MCP_PROJ" "$MCP_PROJ_FALLBACK"; do
	[ -d "$d" ] && targets+=("$d")
done

if [ "$DRY" = 1 ]; then echo "== clean.sh --dry-run: nothing will be deleted =="; else echo "== clean.sh =="; fi
for d in "${targets[@]+"${targets[@]}"}"; do report "$d" "$d"; done
RR_CACHE="$REPO_ROOT/build/realrom-cache"
rr_files=()
if [ -d "$RR_CACHE" ]; then
	# Entries only: never dotfiles, never anything not matching the entry patterns.
	while IFS= read -r f; do rr_files+=("$f"); done \
		< <(find "$RR_CACHE" -maxdepth 1 -type f \( -name '*.dump' -o -name '*.crit' \))
	rr_kb="$(find "$RR_CACHE" -maxdepth 1 -type f \( -name '*.dump' -o -name '*.crit' \) -exec du -sk {} + 2>/dev/null | awk '{s+=$1} END{print s+0}')"
	printf '  %-60s %8s MB (%d entries; .last-verified preserved)\n' "$RR_CACHE" "$(( ${rr_kb:-0} / 1024 ))" "${#rr_files[@]}"
	total_kb=$((total_kb + ${rr_kb:-0}))
fi
echo "  total: $((total_kb / 1024)) MB"
[ -n "$KEPT_OVERRIDE" ] && echo "  (GRM_KEEP_PROJECT_DIR=$KEPT_OVERRIDE is caller-owned and is NOT cleaned)"
echo "  build/ghidra-home is never touched."

if [ "$DRY" = 1 ]; then
	echo "== dry run: nothing deleted =="
	exit 0
fi

for d in "${targets[@]+"${targets[@]}"}"; do rm -rf "$d"; done
[ "${#rr_files[@]}" -gt 0 ] && rm -f -- "${rr_files[@]}"
echo "== cleaned =="
exit 0
