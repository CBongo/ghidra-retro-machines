# Asking Ghidra questions through pyghidra-mcp

Agent-driven, on demand, from git bash; **no MCP registration** in any Claude Code or Codex config
(configured servers start at session start, before anyone knows which ROM to open). Bead
`grm-haj3` has the design history and the acceptance run.

Use it for **static** questions about one real-ROM row's analysis: "what is at `X`", "does
Ghidra have a function at `Y`", "can routine `A` reach `B` through direct control flow",
"decompile `Z`". It does **not** answer runtime questions ("which bank is live at `$9067`"):
those stay with the human and an emulator, per `AGENTS.md`.

## Workflow

```bash
# 1. Analyze the row and keep its project (the exact analysis the tier tests).
bash tools/banktest/realrom-test.sh check nes --only blmaster --keep-project

# 2. Start the server. It runs in the foreground, so launch it as a BACKGROUND task, then wait
#    for "Uvicorn running" in its output.
bash tools/ghidra-mcp/serve.sh start blmaster

# 3. Ask. (serve.sh creates build/pyghidra-mcp-venv on first use -- with uv when installed --
#    and rebuilds it whenever PYGHIDRA_MCP_VERSION in serve.sh changes: that bump IS the upgrade.)
build/pyghidra-mcp-venv/Scripts/python tools/ghidra-mcp/query.py tools
build/pyghidra-mcp-venv/Scripts/python tools/ghidra-mcp/query.py disassemble \
    '{"binary_name":"blmaster.nes","address":"e953","count":40}'
build/pyghidra-mcp-venv/Scripts/python tools/ghidra-mcp/closure6502.py blmaster.nes d3 e692 e953

# 4. ALWAYS stop it before you finish.
bash tools/ghidra-mcp/serve.sh stop
```

(`Scripts/` is the Windows venv layout; elsewhere it is `bin/`.)

## Things that fail silently, and how `serve.sh` handles them

- **Wrong extension or decompiler.** `serve.sh` prints the decompiler build (by sha256) and the
  snapshot's extension identity, the same banners the runners print. A `megaman`/`wizwarr`-style
  answer on a banner that says `stock` is the missing GP-6936 patch.
- **Settings-dir fallback.** `-Dapplication.settingsdir` reaches PyGhidra's embedded JVM only
  through `JAVA_TOOL_OPTIONS`. If it did not take, Ghidra falls back to `%APPDATA%` with no
  error. Verified on 2026-10-10 by probing jar locks: only the snapshot's jars were held.
- **Locked jars.** A live JVM locks the extension jars on Windows, so the server loads them from
  a snapshot (`build/mcp-ghidra-home`) and `stageExtensionForTests` stays free to replace
  `build/ghidra-home`'s.
- **Modified projects.** pyghidra-mcp re-runs auto-analysis (default options) on a program not
  flagged analyzed, and saves on clean exit, so it serves a copy (`build/mcp-project/<row>`).
- **Orphaned servers.** Stopping the background shell that ran `serve.sh start` does NOT stop
  the server: `pyghidra-mcp`, its python and `decompile.exe` live on, holding the snapshot.
  `serve.sh stop` kills the whole process tree.

## `closure6502.py` limits

It follows direct flow only, over **instructions Ghidra has already created**: pyghidra-mcp's
`disassemble` lists existing instructions and does not decode raw bytes (it silently returns the
NEXT instruction when the start is undisassembled; the walker detects that and flags the target
as a blind spot). It does follow targets itself rather than trusting existing references. It
cannot see into undisassembled banks (blmaster's `W8000_M3_B5` has no instructions at all) and
does not follow indirect jumps, push-dispatch or banked-window targets; it flags them instead.
Treat a "no path" result as "no path through fixed-bank direct flow", and report the flagged
unknowns with it. Use `STOP=` to cut non-returning exits (a restart `JMP`) that would otherwise
make everything reachable.
