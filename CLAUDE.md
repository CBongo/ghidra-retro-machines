# Project Instructions for AI Agents

@AGENTS.md

**Read `AGENTS.md` — it is the always-on instruction core, it applies to you, and the rules in it
are not repeated here.** The `@AGENTS.md` line above imports it; if for any reason it did not
load, open `AGENTS.md` yourself before doing anything else. It carries: run commands through git
bash and never prefix with `cd`; stop and ask when a human would be more efficient; never modify
`docs/human recon notes.txt`; only `build-and-test.sh` builds the extension; use `bd` for all task
tracking; and the session-completion/push protocol.

This file adds the Claude-specific and Ghidra-specific detail on top of that core: build and test
mechanics, the opt-in tiers, reading Ghidra source, and loader conventions.

<!-- The "Run commands through git bash" and "Stop and ask when a human would be more
     efficient" sections moved verbatim to AGENTS.md on 2026-08-26 (grm-yaat) so Codex/ChatGPT
     sessions get them too. Do not re-add them here — edit AGENTS.md instead. -->

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

**Gradle comes from the committed wrapper (`./gradlew`, 9.7.1 since grm-arkj); the test scripts
prefer it over any `gradle` on PATH.** Gradle 9.x is both floor and ceiling for now: 8.13 cannot
create the `:test` task on JDK 25 (which the machine `JAVA_HOME` may point at for Ghidra-master
work), and Ghidra 12.1.3's own `support/buildExtension.gradle:54` calls `Task.project` at
execution time, which Gradle 10 removes. Do not bump past 9 until upstream fixes that.

**Do not prefix gradle invocations with `GHIDRA_INSTALL_DIR=…`.** Plain `gradle <task>` is
correct: the install dir resolves from `ghidraInstallRoot` (machine-local
`~/.gradle/gradle.properties`, "where Ghidra installs live") composed with
`gradle.properties`' `ghidraTargetVersion` ("which version this project targets"), so it
stays correct across a retarget with nothing outside the repo to update.

Precedence is the stock Ghidra skeleton's, unchanged — `GHIDRA_INSTALL_DIR` env var, then
`-P`, then `ghidraInstallRoot`. An inline `GHIDRA_INSTALL_DIR=<path>` prefix therefore
*overrides* correct resolution rather than helping it, and pins the very thing that goes
stale: a session snapshots the environment at startup and cannot correct it in place.

**If the version guard fires complaining about a stale `GHIDRA_INSTALL_DIR`, blank it for
that run** — do not restart, and do not paste a version-pinned path:

```bash
GHIDRA_INSTALL_DIR= gradle <task>      # empty value is falsy -> falls through to ghidraInstallRoot
```

The `tools/banktest` scripts export their own `GHIDRA_INSTALL_DIR` derived from
`ghidraTargetVersion`, so they are unaffected either way.

The full acceptance gate is:

```bash
bash tools/banktest/build-and-test.sh check
```

It runs every headless golden fixture plus the JUnit `test` suite (which as of
`grm-32f.4` holds the migrated bit-algebra/petscii/charset/map-compiler/descriptor
verifiers); use it before commits and for issue acceptance. `bless`
updates selected golden files only after reviewing the diff:

```bash
bash tools/banktest/build-and-test.sh bless c64-banking
```

`bless` **refuses** any fixture whose criteria failed — that golden is left byte-identical, the
row is named in a `REFUSED to bless` summary line, and the suite exits nonzero (`grm-aqi`). The
fresh-import and cached-candidate routes share one code path, so they always agree. Override
only when a criterion has gone stale by intent, and fix the criterion separately:
`bless --force-criteria <chunk>`. See docs/testing.md for the reasoning.

For the development loop, select one or more chunks (these are not substitutes
for the full default gate):

```bash
bash tools/banktest/build-and-test.sh check c64-banking c64-loader
bash tools/banktest/build-and-test.sh check unit  # JUnit suite; skips extension build/install
bash tools/banktest/build-and-test.sh --list-chunks
```

Chunk/source-area mapping:

- `c64-banking`: `banktest` through `banktest4` C64 fixtures.
- `c64-loader`: C64 PRG placement/wrapping, ROM loading, and symbol toggles.
- `c64-recovery`: C64 emulation and decrypt/recovery fixtures.
- `basic-petscii`: C64 BASIC headless fixture.
- `basic-dialects`: C64 BASIC 2 regression plus PET BASIC 4 and C128 BASIC 7 token-dialect fixtures.
- `pet-loader`: PET 4032 descriptor, PRG placement, IO typing, and fixed ROM slots.
- `snes-loader`: SNES cartridge loader -- header detection, static LoROM layout, byte-mapped
  mirrors, IO typing, and the reset entry point. Its two fixtures are the SAME cartridge with
  and without a 512-byte copier header, so a copier-detection regression (which shifts every
  offset in the image) cannot pass by matching one golden.
- `c128-loader`: C128 native BASIC PRG placement, fixed ROM slots, and MMU I/O.
- `nes-banking`: NES banking and MMC fixtures.
- `petscii-strings`: `PetsciiStringAnalyzer` C64 PRG fixture.
- `nes-text`: NES `.tbl` text-table loader option + `TblStringAnalyzer` fixture (`nestbltest`).
- `unit`: the JUnit `gradle test` suite (all `src/test/java`; no extension build/install).
- `snes-rom-corpus`: `SnesRomHeader.parse` surveyed over a local SNES cartridge collection
  (`GRM_SNES_ROM_DIR`); opt-in, reporting only, not in `all`.
- `all`: every chunk; the default when no chunk is supplied.

**The real-ROM tier is separate, opt-in, and takes NO paths — just run it:**

```bash
bash tools/banktest/realrom-test.sh check            # core floor, 5 rows, ~46s
bash tools/banktest/realrom-test.sh check nes         # full NES tier, 33 rows -- romdirs from GRM_ROM_DIR
bash tools/banktest/realrom-test.sh check snes        # full SNES tier, 13 rows -- romdirs from GRM_SNES_ROM_DIR
bash tools/banktest/realrom-test.sh check all         # everything, every platform, 46 rows
bash tools/banktest/realrom-test.sh --list-sets       # print the table below
```

No prior `build-and-test.sh` run is required (bead grm-4t2d option (e)): `realrom-test.sh`
stages the isolated extension itself before analyzing, the same way `run-banktest.sh` does — see
"The runners build by default" below. Pass `--no-build` (or set `GRM_SKIP_BUILD=1`) to skip that
and analyze with whatever is already installed instead.

_Set selection, platforms, SNES rows, nominate: see `.claude/rules/realrom-tier.md` (loads when you touch the files it covers)._

**`tools/banktest/realrom-test.sh check nes` is REQUIRED before committing any change that
touches analysis behaviour** (`BoardBankAnalyzer`, any `BankSwitchStrategy`, `StoredValueScanner`, or
similar), alongside `build-and-test.sh check` — not a substitute for it, an addition to it. This
is not optional-nice-to-have: `build-and-test.sh check`'s synthetic goldens, by construction, only
contain idioms someone already thought of, and grm-mu7 (2026-08-04) shipped a broken guard that
passed the full synthetic gate cleanly while destroying three pinned real ROMs (kicarus, dodge,
cv2) — caught only because an unrelated task happened to run the real-ROM tier a day later. See
bead `grm-6kv` for the incident and the ruling that keeps this a required *local* step rather than
a redesigned gate (the tier cannot be a hard CI gate: it needs user-supplied, hash-pinned ROMs the
repo cannot ship). `core` is a floor added *beneath* that requirement for changes that previously
owed the tier nothing at all; it is not a substitute for `nes` on an analysis-behaviour change.


_Staleness stamps, PARTIAL runs, `GRM_ROM_DIR`, the patched decompiler, the refuse-when-unset rule: see `.claude/rules/realrom-tier.md` (loads when you touch the files it covers)._

_The SPC700/6502 vector tiers and the SPC700 `.dis` corpus tier: see `.claude/rules/opt-in-language-tiers.md` (loads when you touch the files it covers)._

_The SNES ROM header corpus tier: see `.claude/rules/snes-rom-corpus.md` (loads when you touch the files it covers)._

There is deliberately no `quick` alias or cache-backed project mode: headless
projects are created fresh, and a correct cache would need explicit invalidation
rules. Use targeted chunks for safe iteration instead.

For any headless chunk, this builds the extension (`gradle buildExtension`), stages it into a
**per-git-worktree, isolated** Ghidra "user settings dir" under `build/ghidra-home` (gitignored,
via the `stageExtensionForTests` Gradle task), then runs the banktest regression suite against
that isolated install. It **never touches the shared `%APPDATA%/ghidra/.../Extensions` dir** —
so an open Ghidra GUI can't lock it out from under you, and parallel agents can't clobber
each other's installed extension.

### The runners build by default (`run-banktest.sh`/`realrom-test.sh`, bead grm-4t2d)

`run-banktest.sh` and `realrom-test.sh` used to analyze with whatever was already staged in
`build/ghidra-home` — a stale-build result was possible and, worse, indistinguishable from a real
regression (see `AGENTS.md`'s "The runners build by default" section and the
`which-script-builds-the-extension` bd memory for the incident history). Both scripts now run
`gradle stageExtensionForTests` before analyzing, honouring an explicit opt-out:

```bash
bash tools/banktest/run-banktest.sh check --no-build nes-banking
GRM_SKIP_BUILD=1 bash tools/banktest/realrom-test.sh check nes
```

`stageExtensionForTests` (`build.gradle`) has real Gradle inputs (compiled classes, `data/`,
`ghidra_scripts/`, the packaging manifest) and outputs (the staged `Extensions/ghidra-retro-machines`
dir), so it is genuinely `UP-TO-DATE` when nothing relevant changed — the common case costs a few
seconds, not a rebuild. It deliberately does **not** key its up-to-date check on the dist zip
(`buildExtension`'s output): that Zip task's bytes are unstable across rebuilds (embedded
timestamps) even when the content is not, which is exactly the kind of perpetual-staleness bug
this task exists to avoid. It is named `stageExtensionForTests`, never `installExtension` — that
name is reserved, in spirit, for `tools/install-gui.ps1`, the real user-facing installer that
writes into the shared `%APPDATA%` Ghidra install and that agents must never run.

Parallelization rules:
- One agent per `git worktree` (`git worktree add <path> <ref>`); never two agents sharing
  one working tree.
- Gradle caches under `~/.gradle` are shared across worktrees and gradle file-locks them
  itself — safe to build concurrently.
- The shared Ghidra install (`<ghidraInstallRoot>/ghidra_<ver>_PUBLIC`, composed from your
  machine-local `~/.gradle/gradle.properties` and gradle.properties' `ghidraTargetVersion`;
  override via `GRM_GHIDRA_INSTALL`) is read-only to this loop.

The GUI install (delete+unzip the dist zip into `%APPDATA%/ghidra/<version>/Extensions/`) is a
separate, user-facing step — only needed when you want the interactive Ghidra GUI to see the
new build; it is **not** part of the agent test loop, so the GUI keeps running whatever build
was last installed there until you refresh it. Run it yourself with:

```powershell
.\tools\install-gui.ps1              # gradle buildExtension, then destructive reinstall
.\tools\install-gui.ps1 -SkipBuild   # install the newest dist zip as-is
.\tools\install-gui.ps1 -WhatIf      # resolve and report paths, install nothing
```

It refuses to run while Ghidra is open (a live install holds locks on its own jars; `-Force`
overrides) and always reinstalls rather than skipping — you invoke it when you want a fresh
copy. Restart Ghidra afterwards. Agents should not run it: it writes outside the repo, into
the user's shared `%APPDATA%` install.

## Architecture Overview

_Add a brief overview of your project architecture_

_Reading Ghidra source code, and loader validation conventions: see `.claude/rules/ghidra-source-and-loaders.md` (loads when you touch the files it covers)._
