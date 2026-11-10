#!/usr/bin/env bash
# Build a decompile.exe with MinGW from a Ghidra decompiler C++ tree (grm-gipk.25; recipe in the
# ghidra-12-1-3-native-regression-gp6936 bd memory). Git bash; the result is a Windows binary.
#
# Usage: tools/decompiler/build.sh <decompile/cpp dir> <output exe> [<build log>]
#   <decompile/cpp dir>  e.g. "$GRM_GHIDRA_SRC/Ghidra/Features/Decompiler/src/decompile/cpp", or a
#                        scratch copy that tools/decompiler/apply75ey.py has patched
#   <output exe>         where to copy the built binary (its sha256 is printed; add new builds to
#                        grm_decompiler_build_name in tools/banktest/lib/common.sh)
# Env: MINGW_BIN = directory holding mingw32-make.exe (default: whatever is on PATH);
#      MINGW_SH  = sh.exe for make's SHELL (default: `command -v sh`); JOBS (default 8).
# Place the result in a shadow install with tools/banktest/mkshadow.ps1, never in the real one.
set -u
cpp="${1:?usage: build.sh <decompile/cpp dir> <output exe> [log]}"
out="${2:?usage: build.sh <decompile/cpp dir> <output exe> [log]}"
log="${3:-${out}.build.log}"
make_bin=mingw32-make.exe
[ -z "${MINGW_BIN:-}" ] || make_bin="$MINGW_BIN/mingw32-make.exe"
sh_exe="${MINGW_SH:-$(command -v sh)}"
"$make_bin" -C "$cpp" ghidra_opt -j"${JOBS:-8}" SHELL="$sh_exe" \
	ADDITIONAL_FLAGS="-static -static-libgcc -static-libstdc++" > "$log" 2>&1
rc=$?
echo "exit=$rc (log: $log)"
grep -E "error|warning" "$log" | head -40
tail -3 "$log"
if [ "$rc" -eq 0 ]; then
	cp -f "$cpp/ghidra_opt" "$out" 2> /dev/null || cp -f "$cpp/ghidra_opt.exe" "$out"
	sha256sum "$out"
fi
exit "$rc"
