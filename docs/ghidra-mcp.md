# Querying Ghidra through MCP

**This project lets an agent ask Ghidra questions about one analyzed real-ROM row, such as
"what is at `X`" or "can routine `A` reach `B`", by serving that row's tested project through
[pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp).** This document explains the
mechanism and the reasoning behind its shape. The commands are in
[`tools/ghidra-mcp/README.md`](../tools/ghidra-mcp/README.md); the design history and
acceptance run are on bead `grm-haj3`.

## Why it exists

The analyzers in this project answer questions about bank switching by static analysis. When an
agent needs a fact about one specific ROM to make progress ("does Ghidra have a function at
`c183`?", "can anything `e953` calls overwrite the save slot `$D3`?"), the only routes used to be:

- build a bespoke probe script, run a headless import, and read its output (a build/measure/
  interpret cycle per question), or
- stop and ask the owner, who answers from a disassembler in minutes.

`AGENTS.md` routed these questions to the owner because the probe route cost more than it was
worth. A queryable Ghidra session changes that: once a row's project is analyzed and kept, each
question is one call that returns in about a second. `AGENTS.md`'s stop-and-ask list now sends
**static** questions about a real-ROM row here. Runtime questions ("which bank is live at
`$9067`?") and real hand reverse engineering stay with the owner.

## What MCP is, briefly

The [Model Context Protocol](https://modelcontextprotocol.io) is a JSON-RPC protocol through which
a client (usually an AI agent's host) calls named **tools** that a **server** exposes. Each tool
has a typed argument schema and returns structured content. Transports include stdio (the client
spawns the server and talks over its pipes) and **streamable HTTP** (the server listens on a port).

pyghidra-mcp is an MCP server that embeds Ghidra in a Python process through
[PyGhidra](https://pypi.org/project/pyghidra/) (JPype, which runs the JVM in-process) and exposes
Ghidra operations as tools. Those this project uses most:

| Tool | Returns |
|---|---|
| `list_project_binaries`, `list_project_binary_metadata` | Programs in the project; language, loader properties, analysis counts |
| `disassemble` | Existing listing instructions from an address forward (see the caveat below) |
| `decompile_function` | Pseudo-C for a function, by name or address |
| `list_xrefs`, `search_symbols_by_name` | References to an address or symbol; symbol search by regex |
| `read_bytes` | Raw memory bytes |

It also has editing tools (`rename_function`, `set_comment`, ...) and `save`; this project does not
rely on them.

## The shape: agent-driven, on demand, no registration

The obvious setup, registering pyghidra-mcp as an MCP server in Claude Code's or Codex's
configuration, does not fit. Hosts start configured servers **when the session starts**, before
anyone knows which ROM to look at, and pyghidra-mcp binds to one project at launch. So the
server is not registered anywhere. An agent starts it from git bash when a question comes up,
queries it with a small client script, and stops it:

```
realrom-test.sh check --only <row> --keep-project
        │  imports + analyzes the row exactly as the tier does, and keeps the project
        ▼
build/kept-projects/realrom/<row>/headless.gpr      (the analysis the golden was taken from)
        │  serve.sh start <row>: copies it, snapshots build/ghidra-home, launches the server
        ▼
pyghidra-mcp ── streamable HTTP on 127.0.0.1:8765 ──► query.py / closure6502.py
   │ embedded JVM (PyGhidra)
   ├─ extension jars from build/mcp-ghidra-home     (snapshot)
   └─ decompile.exe from the Ghidra install          (the locally patched build)
        │
serve.sh stop: kills the process tree; the background start task exits 0
```

There is no CLI client in pyghidra-mcp's PyPI release, so `tools/ghidra-mcp/query.py` is a minimal
one built on the `mcp` Python library, which the server already depends on.

## Answering about the analysis the tier tested

An answer is only useful if it describes the same analysis the real-ROM tier checks. Five things
could silently break that, and each is handled structurally rather than by convention.

### 1. The same project, not a fresh import

pyghidra-mcp can import a binary itself (`import_binary`), but that uses Ghidra's automatic
loader choice with default options, which can differ from the row's import (loader, descriptor,
`.tbl`, symbol options). So `realrom-test.sh --keep-project` keeps the project the row's dump was
taken from, and the server opens that project.

### 2. A copy of the project

pyghidra-mcp runs `analyzeAll` with default options (plus symbol-server setup) on any program not
flagged as analyzed, and saves every program on a clean exit. To keep the kept project exactly as
the tier left it, `serve.sh` serves a copy at `build/mcp-project/<row>`.

### 3. Our extension, from an isolated settings dir

Ghidra loads extensions from its **user settings dir**, not from the install. The runners isolate
that dir per worktree (`build/ghidra-home`) by passing `-Dapplication.settingsdir` through
`GHIDRA_HEADLESS_JAVA_OPTIONS`, which `analyzeHeadless` reads. PyGhidra does not read that
variable. It builds JVM arguments only from the install's `support/launch.properties` plus its
own additions. The HotSpot JVM, however, reads **`JAVA_TOOL_OPTIONS`** when it is created, and
that applies to a JVM embedded through JNI too. `serve.sh` sets the settings dir, cache dir and the
analysis thread pin (`-Dcpu.core.override=1`, the runners' `grm-nems` pin) that way.

If the settings dir is wrong, Ghidra falls back to `%APPDATA%` **without any error**, and this
machine has an `%APPDATA%` copy of the extension too. "It ran" therefore proves nothing. The
acceptance run checked it directly: while the server was up, only the snapshot's jars were locked
(probed by trying to open each copy exclusively), Ghidra's log was written inside the snapshot,
and the `%APPDATA%` log was untouched.

### 4. A snapshot, so the build is never blocked

On Windows a running JVM holds its jars locked. If the server loaded extensions from
`build/ghidra-home` directly, the next `stageExtensionForTests` (which every runner invokes) could
not replace them. `serve.sh` therefore copies `build/ghidra-home` (minus its multi-megabyte logs) to
`build/mcp-ghidra-home` and points the server there. Acceptance check 2 confirmed it: with the
server running, a source change followed by `run-banktest.sh check nes-banking` restaged the
extension and passed.

### 5. The patched decompiler

The install carries a locally patched `decompile.exe` for GP-6936 (see
`.claude/rules/realrom-tier.md`); without it, `megaman`/`wizwarr` answers would be wrong.
pyghidra-mcp takes the install from `GHIDRA_INSTALL_DIR`, which `serve.sh` sets from the same
`ghidraInstallRoot` + `ghidraTargetVersion` resolution the runners use.

`serve.sh` prints the same identity banners as the runners: the decompiler build by sha256, and
the snapshot's extension identity, stating whether it matches `build/ghidra-home`. (Both
identities are computed from the same path spelling, because `ext_identity` is path-sensitive.)

## Lifecycle

`serve.sh start <row>` runs in the foreground, so an agent launches it as a background task and
waits for `Uvicorn running`. On first use it builds `build/pyghidra-mcp-venv` (with
[uv](https://docs.astral.sh/uv/) when installed, else `venv` + pip) at the version pinned in
`PYGHIDRA_MCP_VERSION`, and rebuilds it whenever that pin changes, so an upgrade is a one-line
edit.

Stopping needs care, for two reasons:

- **Stopping the background task does not stop the server.** It kills the bash wrapper only;
  `pyghidra-mcp.exe`, its Python and `decompile.exe` keep running and keep the snapshot locked.
  `serve.sh stop` kills the whole tree, matching on `pyghidra-mcp.exe` and our `--port`. That
  filter matters: the owner's Ghidra GUI also runs as `python … -m pyghidra`, and a name-only
  match would kill it.
- **A forced kill reads as a failure.** pyghidra-mcp's only graceful shutdown is Ctrl+C, which
  Windows cannot easily deliver to a background process. So `stop` first writes
  `build/mcp-stop-requested.<port>`. `start` waits on the server as a child (it does not `exec`
  into it), and when the server exits it returns 0 if the marker exists, or the server's own
  status if not. A requested stop reads as success; a crash still reads as a failure.

## Reachability walks: `closure6502.py`

Many of the questions this answers are reachability questions: "can anything this routine calls
write `$D3`, or reach `e692`?". `closure6502.py` answers them as a graph walk over MCP calls:

- From the given roots it follows every **direct** control-flow target itself (`JSR`/`JMP`
  absolute, branches, fall-through) instead of trusting the references analysis already created,
  and prints the first path found to the target.
- It flags anything it cannot follow or that could change the answer: indirect `JMP`, `PHA`/`RTS`
  push-dispatch, writes to the given zero-page slot, indirect stores, and targets in the banked
  window below `$C000` (which bank runs there is not a static fact).
- `STOP="<addr> ..."` marks non-returning exits, such as a restart `JMP`, so they do not make
  everything reachable.

**Caveat: it walks existing instructions, not raw bytes.** pyghidra-mcp's `disassemble` iterates
the listing's existing instructions from an address forward. When the start address was never
disassembled it does not decode anything; it silently returns the **next** instruction. The
walker checks the first returned address and reports a mismatch as a blind spot instead of
walking from the wrong place. A bank Ghidra never reached (blmaster's `W8000_M3_B5` has no
instructions at all) is invisible to it. A "no path" result means "no path through instructions
Ghidra created, in fixed-bank direct flow", and should be reported with its flags.

### Worked example: blmaster's `$D3` save slot (`grm-zsxz`)

`FUN_e9b8` saves the live bank into `$D3` at `e9bb`, calls `ea3a`, `eb51` and `e953`, then
restores from `$D3`. The question was whether anything in between can run `e692 STA $D3`, which
would make the restore unsound.

1. `closure6502.py blmaster.nes d3 e692 e953`: 14 blocks, no flags. `e953` is a run-length decoder
   that writes to `$2007`, not a dispatch loop.
2. Widening the roots to the whole span (`ea3a eb51 e953`) reached `e692` through one path that
   ends in `f270 JMP c24f`, a restart that never returns to the restore.
3. With `STOP=f270`: 72 blocks, no path to `e692`, no `$D3` write. The remaining flags were the
   banked calls `$bfe5/$bfe8/$bff1` and two `STA ($CE),Y` indirect stores.
4. The owner settled both from a disassembler: only bank 5 has code at those addresses in PRG mode
   3, and it leaves the shadows alone; `$CE/$CF` is only ever loaded with non-zero-page addresses.

The tool handled the mechanical part in minutes and handed exactly the undecidable remainder to a
human. The record is in the `## Answered` table of `docs/human-research-todo.md`.

## Maintenance notes

- **Upgrading pyghidra-mcp:** bump `PYGHIDRA_MCP_VERSION` in `serve.sh`, rerun the three
  acceptance checks on `grm-haj3` (correct extension and decompiler, staging still works with the
  server up, a known answer still comes back), and note the result on a bead.
- **Retargeting Ghidra:** nothing to change here. The install, version, and settings-dir name all
  derive from `gradle.properties` and `ghidraInstallRoot`, as for the runners.
- **Everything it writes is under `build/`** (gitignored): the venv, the snapshot, project copies
  and the stop marker. Deleting them is always safe; `serve.sh` recreates them.
