# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

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


## Build & Test

> **See [docs/testing.md](docs/testing.md) for the full testing strategy** — the three test
> tiers (pure JUnit / `ProgramBuilder` JUnit / E2E golden image), when to use each, the
> bless-review discipline, and the chunk map. The essentials are below.

The full acceptance gate is:

```bash
bash tools/banktest/build-and-test.sh check
```

It runs every headless golden fixture plus `verifyPetsciiMapper` and
`verifyBitAlgebra`; use it before commits and for issue acceptance. `bless`
updates selected golden files only after reviewing the diff:

```bash
bash tools/banktest/build-and-test.sh bless c64-banking
```

For the development loop, select one or more chunks (these are not substitutes
for the full default gate):

```bash
bash tools/banktest/build-and-test.sh check c64-banking c64-loader
bash tools/banktest/build-and-test.sh check bit-algebra  # skips extension build/install
bash tools/banktest/build-and-test.sh --list-chunks
```

Chunk/source-area mapping:

- `c64-banking`: `banktest` through `banktest4` C64 fixtures.
- `c64-loader`: C64 PRG placement/wrapping, ROM loading, and symbol toggles.
- `c64-recovery`: C64 emulation and decrypt/recovery fixtures.
- `basic-petscii`: C64 BASIC headless fixture and `verifyPetsciiMapper`.
- `basic-dialects`: C64 BASIC 2 regression plus PET BASIC 4 and C128 BASIC 7 token-dialect fixtures.
- `pet-loader`: PET 4032 descriptor, PRG placement, IO typing, and fixed ROM slots.
- `c128-loader`: C128 native BASIC PRG placement, fixed ROM slots, and MMU I/O.
- `nes-banking`: NES banking and MMC fixtures.
- `bit-algebra`: `verifyBitAlgebra` only.
- `all`: every chunk; the default when no chunk is supplied.

There is deliberately no `quick` alias or cache-backed project mode: headless
projects are created fresh, and a correct cache would need explicit invalidation
rules. Use targeted chunks for safe iteration instead.

For any headless chunk, this builds the extension (`gradle buildExtension`), installs the
dist zip into a **per-git-worktree, isolated** Ghidra "user settings dir" under
`build/ghidra-home` (gitignored), then runs the banktest regression suite against that
isolated install. It **never touches the shared `%APPDATA%/ghidra/.../Extensions` dir** —
so an open Ghidra GUI can't lock it out from under you, and parallel agents can't clobber
each other's installed extension.

Parallelization rules:
- One agent per `git worktree` (`git worktree add <path> <ref>`); never two agents sharing
  one working tree.
- Gradle caches under `~/.gradle` are shared across worktrees and gradle file-locks them
  itself — safe to build concurrently.
- The shared Ghidra install (`D:/ghidra_<ver>_PUBLIC` per gradle.properties'
  `ghidraTargetVersion`, override via `GRM_GHIDRA_INSTALL`)
  is read-only to this loop.

The manual GUI install (delete+unzip the dist zip into
`%APPDATA%/ghidra/<version>/Extensions/`) is a separate, user-facing step — only needed when
you want the interactive Ghidra GUI to see the new build; it is not part of the agent test
loop.

## Architecture Overview

_Add a brief overview of your project architecture_

## Reading Ghidra source code

Frequent task. **The targeted Ghidra version is defined ONCE, in `gradle.properties`'
`ghidraTargetVersion`** (`<ver>` below). By convention the install lives at
`D:/ghidra_<ver>_PUBLIC` and the source checkout is kept on tag `Ghidra_<ver>_build`;
build.gradle hard-fails if the resolved install's version disagrees. Use, in order of
preference:

1. **Local full checkout `D:\git\ghidra`** — primary source: fast navigation
   (Grep/Read/Glob) AND version-exact, since it is kept checked out on the
   `Ghidra_<ver>_build` tag. **READ-ONLY: never `git fetch`/`checkout`/modify it** — the
   user manages its state. If version exactness matters, sanity-check first:
   `git -C D:/git/ghidra describe --tags` should print `Ghidra_<ver>_build`; if it prints
   something else, fall back to source #2/#3 for API-sensitive details (and mention the
   mismatch to the user).
2. **The install `D:\ghidra_<ver>_PUBLIC`** — always matches what we compile against.
   `Ghidra/Features/Base/lib/**` has *extracted* `.java` files (grep/read them
   directly). Most other modules ship `lib/<Module>-src.zip` instead — list/read with
   `unzip -l` / `unzip -p <zip> path/To/File.java` (Bash). Fallback/cross-check.
3. **GitHub MCP** (`mcp__github__get_file_contents`, repo `NationalSecurityAgency/ghidra`,
   ref `Ghidra_<ver>_build`) — tag-exact single files without touching the local checkout.

Always confirm version-sensitive APIs against the targeted version (source #2 or #3), not memory or web
docs: 12.x broke 11.x-era APIs (e.g. `charset_info.xml`/`CharsetInfo` →
`charset_info.json`/`ghidra.util.charset.CharsetInfoManager`; the classic 6-arg
`Loader.load` → `ImporterSettings`).

## Conventions & Patterns

_Add your project-specific conventions here_
