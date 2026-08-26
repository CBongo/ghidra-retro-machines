# Agent Instructions

**This file is the always-on instruction core for EVERY agent on this project** — Claude Code,
Codex/ChatGPT, or anything else. Nothing here is optional and nothing here is agent-specific.
`CLAUDE.md` imports this file and adds the Ghidra/build/test detail that only Claude Code loads;
if you are reading `CLAUDE.md` and not this file, read this file too.

This project uses **bd** (beads) for issue tracking. Run `bd prime` for full workflow context.

> **Architecture in one line:** Issues live in a local Dolt database
> (`.beads/dolt/`); cross-machine sync uses `bd dolt push/pull` (a
> git-compatible protocol), stored under `refs/dolt/data` on your git
> remote — separate from `refs/heads/*` where your code lives.
> `.beads/issues.jsonl` is a passive export, not the wire protocol.
>
> See [SYNC_CONCEPTS.md](https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md)
> for the one-screen overview and anti-patterns (don't treat JSONL as the
> source of truth; don't `bd import` during normal operation; don't
> reach for third-party Dolt hosting before trying the default).

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
```

## Run commands through git bash, not PowerShell

**Git bash is the normal shell for this project — reach for the Bash tool first.** Nearly all
the tooling here is POSIX shell (`tools/banktest/*.sh`, the gradle invocations, `bd`), the
documented command lines throughout this file are written for it, and the permission
allowlist is tuned for that route — so a bash call is far more likely to run without
prompting than the PowerShell equivalent of the same thing.

Three practical consequences:

- **Never prefix a command with `cd` to the repo root.** Your shell already starts at the repo
  root and its working directory persists between calls, so `cd <repo root> && <cmd>` is pure
  overhead — and it *costs* you, because the `cd` turns an otherwise-allowlisted command into a
  compound one the permission matcher can no longer clear. This was measured at ~200 needless
  prompts across 50 sessions, the single largest source of them. Just run `<cmd>`. When you
  genuinely need a different directory, prefer a tool that takes one (`git -C <dir> …`,
  `bash tools/… <path>`) over `cd`.
- **Long or multi-line arguments go in a file, not on the command line.** Prompts to approve a
  wall of inline text get rejected. Write the text to a scratchpad file and pass it by path:
  `bd comment <id> --file notes.txt`, `git commit -F msg.txt`.
- PowerShell is still the right tool for genuinely Windows-shaped work (`%APPDATA%` paths,
  `tools/install-gui.ps1`, registry, ACLs). Use it there and nowhere else.

## Stop and ask when a human would be more efficient

**If you hit work where human analysis is likely cheaper or better than spending agent tokens,
STOP and ASK before proceeding.** State what you'd do, roughly what it would cost, what the
human alternative is, and let the user choose. They may take it on themselves, hand it back, or
split it. Do not silently grind through it, and do not silently skip it.

This is not a suggestion to be timid — most work is yours to do. It is about a specific class of
task where the economics genuinely invert:

- **Hand reverse-engineering a specific ROM.** Answering "where does the bank number at this
  store come from?" costs a human with a disassembler minutes, and costs an agent a
  build/measure/interpret cycle per question — with a worse answer, because the human can also
  say what the game is *doing*. The `grm-8iy.5` def-use passes are the worked example.
- **Ground truth that needs an emulator.** "Is bank 6 actually live at `$9067` at runtime?" is
  one breakpoint for a human and unanswerable by static analysis.
- **A yes/no that needs a handful of addresses read.** If the next step is "does Ghidra create a
  function at `c183`?", ask — don't build a probe.
- **Licensing, sourcing, and product judgment.** Which community disassembly to ingest, submodule
  vs. committed artifacts, whether a board is worth shipping. These need a decision, not analysis.
- **Anything needing the user's identity.** Upstream GitHub issues and PRs, CLA agreements.
- **A measure/interpret loop that isn't converging.** Two rounds of "run the probe, read the
  numbers, still unclear" is the signal. Say so and ask rather than starting round three.

When the user takes a task on, record the result with `bd comment` on the owning bead and note
open human-side work in `docs/human-research-todo.md` — that file is the running TODO for work
that is deliberately *not* agent work.

`docs/human recon notes.txt` is the user's own raw record of hand reverse-engineering, kept to
share with others. **Agents must NEVER modify it** — read it, quote it into beads, ask questions
about it, but leave the file alone. Read its preamble before using anything in it: the notes were
collected over time, may not match current code, and are a basis for questions to the user rather
than ground truth. It may be committed and pushed at any time.

**When one of those items comes back answered, retire it — do not check it off.** Delete the item
from its section and add a row to the `## Answered` table at the bottom of that file. Never mark it
`- [x]`: the numbered sections hold only open questions, and a checked box both reads as open work
and loses the finding from the archive. The file's own preamble states the procedure; read it
before editing, and read to the bottom of the file so you see the table's format.

Counter-signal, so this does not become an excuse: implementation, refactoring, test writing,
running the gates, reading this codebase, and tracing existing code are agent work. Do them.

## Only `build-and-test.sh` builds the extension

**`tools/banktest/build-and-test.sh` is the ONLY runner that builds and installs.**
`run-banktest.sh`, `realrom-test.sh`, and `measure-overlay-scale.sh` analyze with whatever is
already installed in the isolated per-worktree `build/ghidra-home` — they do not rebuild. Since
the two you reach for most are both non-building, a result from either can reflect a build older
than your working tree, and **every** way that fails is in the flattering direction: an A/B whose
two sides run the same binary comes back byte-identical and reads as "my change moved nothing";
a stale build imitates a genuine regression convincingly, and can also produce a false pass. Run
`build-and-test.sh` first whenever the answer depends on your current source. See the
`which-script-builds-the-extension` bd memory and `grm-4t2d`.

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

## Testing

**Read [docs/testing.md](docs/testing.md) before writing or hunting for tests.** Short
version: the end-to-end golden-image suite (`bash tools/banktest/build-and-test.sh check`)
is the acceptance gate. A JUnit layer (`gradle test`, `src/test/java`) also exists as of
`grm-32f.1` for pure logic and `ProgramBuilder` fixtures — but it is opt-in and does not
replace the E2E gate. Don't add a bespoke `main()`+`JavaExec` verifier when a JUnit `@Test`
fits; don't `bless` a golden diff you haven't reviewed.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:7510c1e2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->

<!-- BEGIN BEADS CODEX SETUP: generated by bd setup codex -->
## Beads Issue Tracker

Use Beads (`bd`) for durable task tracking in repositories that include it. Use the `beads` skill at `.agents/skills/beads/SKILL.md` (project install) or `~/.agents/skills/beads/SKILL.md` (global install) for Beads workflow guidance, then use the `bd` CLI for issue operations.

### Quick Reference

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
bd prime                # Refresh Beads context
```

### Rules

- Use `bd` for all task tracking; do not create markdown TODO lists.
- Run `bd prime` when Beads context is missing or stale.
- Keep persistent project memory in Beads via `bd remember`; do not create ad hoc memory files.
<!-- END BEADS CODEX SETUP -->
