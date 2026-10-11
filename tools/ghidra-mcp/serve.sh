#!/usr/bin/env bash
# Serve one real-ROM row's analyzed project over pyghidra-mcp, so an agent can ask Ghidra cheap
# "what is at X / what does Y reach" questions against EXACTLY the analysis the tier tested
# (bead grm-haj3). See tools/ghidra-mcp/README.md for the full workflow.
#
#   bash tools/ghidra-mcp/serve.sh start <row>   # foreground; launch it as a background task
#   bash tools/ghidra-mcp/serve.sh stop
#
# Prerequisite: bash tools/banktest/realrom-test.sh check <set> --only <row> --keep-project
#
# Isolation (all three matter; each failure mode is SILENT):
# - The server opens a COPY of the kept project. pyghidra-mcp re-runs auto-analysis with default
#   options on any program not flagged analyzed, and saves the project on a clean exit.
# - Extensions load from a SNAPSHOT of build/ghidra-home, not build/ghidra-home itself: a live JVM
#   holds the extension jars locked on Windows, and every runner's stageExtensionForTests must be
#   able to replace them. A wrong settingsdir falls back to %APPDATA% without any error.
# - -Dapplication.settingsdir reaches the embedded JVM through JAVA_TOOL_OPTIONS (PyGhidra does not
#   read GHIDRA_HEADLESS_JAVA_OPTIONS, which is how the runners isolate).
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../banktest/lib/common.sh"

VENV="$REPO_ROOT/build/pyghidra-mcp-venv"
SNAP="$REPO_ROOT/build/mcp-ghidra-home"
PORT="${GRM_MCP_PORT:-8765}"
PYGHIDRA_MCP_VERSION=0.2.7   # the version grm-haj3's acceptance ran against

case "$(uname -s 2>/dev/null)" in
	MINGW*|MSYS*|CYGWIN*) VENV_BIN="$VENV/Scripts"; EXE=.exe ;;
	*) VENV_BIN="$VENV/bin"; EXE= ;;
esac

stop_server() {
	# Kill the whole tree: the harness stopping the background shell leaves pyghidra-mcp, its
	# python and decompile.exe alive, still holding the snapshot jars.
	if [ -n "$EXE" ]; then
		powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='pyghidra-mcp.exe'\" |
			Where-Object { \$_.CommandLine -match '--port $PORT\b' } |
			ForEach-Object { taskkill /PID \$_.ProcessId /T /F | Out-Null; 'stopped pid ' + \$_.ProcessId }"
	else
		pkill -f "pyghidra-mcp .*--port $PORT\b" && echo "stopped" || echo "no server on port $PORT"
	fi
}

cmd="${1:-}"; row="${2:-}"
case "$cmd" in
	stop) stop_server; exit 0 ;;
	start) [ -n "$row" ] || { echo "usage: $0 start <row>" >&2; exit 2; } ;;
	*) echo "usage: $0 start <row> | stop" >&2; exit 2 ;;
esac

kept="$REPO_ROOT/build/kept-projects/realrom/$row"
[ -f "$kept/headless.gpr" ] || {
	echo "FAIL: no kept project at $kept -- run:" >&2
	echo "  bash tools/banktest/realrom-test.sh check nes --only $row --keep-project" >&2
	exit 3
}
[ -d "$REPO_ROOT/build/ghidra-home" ] || { echo "FAIL: build/ghidra-home missing; run a gate first" >&2; exit 3; }

# (Re)build the venv when it is missing or was built for a different pin: bumping
# PYGHIDRA_MCP_VERSION is the whole upgrade. uv when present (much faster), else venv + pip.
pin_stamp="$VENV/.grm-pyghidra-mcp-version"
if [ ! -x "$VENV_BIN/pyghidra-mcp$EXE" ] || [ "$(cat "$pin_stamp" 2>/dev/null)" != "$PYGHIDRA_MCP_VERSION" ]; then
	echo "== (re)building $VENV for pyghidra-mcp $PYGHIDRA_MCP_VERSION =="
	rm -rf "$VENV"
	if command -v uv >/dev/null 2>&1; then
		uv venv -q "$VENV"
		uv pip install -q --python "$VENV_BIN/python$EXE" "pyghidra-mcp==$PYGHIDRA_MCP_VERSION"
	else
		python -m venv "$VENV"
		"$VENV_BIN/python" -m pip install -q "pyghidra-mcp==$PYGHIDRA_MCP_VERSION"
	fi
	echo "$PYGHIDRA_MCP_VERSION" > "$pin_stamp"
fi

# Snapshot minus logs (old application/script logs run ~50 MB each and are irrelevant).
rm -rf "$SNAP"
(cd "$REPO_ROOT/build/ghidra-home" && find . -type f ! -name '*.log*' -print0) |
	while IFS= read -r -d '' f; do
		mkdir -p "$SNAP/$(dirname "$f")"
		cp -f "$REPO_ROOT/build/ghidra-home/$f" "$SNAP/$f"
	done
proj="$REPO_ROOT/build/mcp-project/$row"
rm -rf "$proj"; mkdir -p "$(dirname "$proj")"
cp -rf "$kept" "$proj"

grm_default_ghidra_install
GHIDRA_HEADLESS="$GRM_GHIDRA_INSTALL/support/analyzeHeadless.bat"   # only so the note can find decompile
grm_decompiler_note
# ext_identity is path-sensitive, so compare both sides computed the same way, from REPO_ROOT.
snap_id="$(BANKTEST_SETTINGS_BASE="$SNAP" ext_identity || true)"
staged_id="$(BANKTEST_SETTINGS_BASE="$REPO_ROOT/build/ghidra-home" ext_identity || true)"
if [ -n "$snap_id" ] && [ "$snap_id" = "$staged_id" ]; then
	snap_match="matches build/ghidra-home"
else
	snap_match="DOES NOT MATCH build/ghidra-home ($staged_id) -- do not trust answers"
fi
grm_installed_extension_note "$snap_id" \
	"(snapshot; $snap_match. The server holds THESE jars, not the staged ones.)"

snap_native="$(native "$SNAP")"
export GHIDRA_INSTALL_DIR="$(native "$GRM_GHIDRA_INSTALL")"
# cpu.core.override=1: the same analysis-thread pin the runners apply (grm-nems).
export JAVA_TOOL_OPTIONS="-Dapplication.settingsdir=$snap_native -Dapplication.cachedir=$snap_native/cache -Dcpu.core.override=1"
echo "== serving $row on http://127.0.0.1:$PORT/mcp (stop: bash tools/ghidra-mcp/serve.sh stop) =="
exec "$VENV_BIN/pyghidra-mcp$EXE" -t streamable-http --port "$PORT" --no-symbols \
	--project-path "$(native "$proj/headless.gpr")"
