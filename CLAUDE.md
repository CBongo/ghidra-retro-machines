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
- `c128-loader`: C128 native BASIC PRG placement, fixed ROM slots, and MMU I/O.
- `nes-banking`: NES banking and MMC fixtures.
- `petscii-strings`: `PetsciiStringAnalyzer` C64 PRG fixture.
- `unit`: the JUnit `gradle test` suite (all `src/test/java`; no extension build/install).
- `all`: every chunk; the default when no chunk is supplied.

**The real-ROM tier is separate, opt-in, and takes NO paths — just run it:**

```bash
bash tools/banktest/build-and-test.sh check nes-banking   # once, for the isolated install
bash tools/banktest/realrom-test.sh check --all           # romdirs come from GRM_ROM_DIR
```

**Use `--all`, and note that the manifests do NOT accumulate.** No flag = `manifest.tsv`, the
curated board-representative set (12 rows). `--gme` = `manifest-gme.tsv` *only* (19 rows).
`--all` = both. This trips people because a bare `check` looks like "the real-ROM tier" and is
actually a third of it — and *every* title this project discusses constantly (wizwarr, blmaster,
cv2, tmnt, smb2, rcransom, ff1, dodge, rcproam) lives in the **GME** set, so a bare `check` never
touches one of them. Sharpest illustration: all three ROMs the grm-mu7 incident below destroyed —
kicarus, dodge, cv2 — are GME rows, so a bare `check` would not have caught the very regression
this requirement exists to prevent.

**`tools/banktest/realrom-test.sh check --all` is REQUIRED before committing any change that
touches analysis behaviour** (`BoardBankAnalyzer`, any `BankSwitchStrategy`, `StoredValueScanner`, or
similar), alongside `build-and-test.sh check` — not a substitute for it, an addition to it. This
is not optional-nice-to-have: `build-and-test.sh check`'s synthetic goldens, by construction, only
contain idioms someone already thought of, and grm-mu7 (2026-08-04) shipped a broken guard that
passed the full synthetic gate cleanly while destroying three pinned real ROMs (kicarus, dodge,
cv2) — caught only because an unrelated task happened to run the real-ROM tier a day later. See
bead `grm-6kv` for the incident and the ruling that keeps this a required *local* step rather than
a redesigned gate (the tier cannot be a hard CI gate: it needs user-supplied, hash-pinned ROMs the
repo cannot ship).

Both `realrom-test.sh` and `build-and-test.sh check` print a `REALROM STALENESS:` line naming the
commit (or "absent") of the last real-ROM run *that actually verified rows* — including a run that
ended `FAIL` on the two known-baseline rows above, since the point is "did anyone run this
lately", not "did it pass"; only a run that matched no ROMs at all leaves the stamp untouched. A
gate that never ran that tier says so out loud instead of reporting a quiet green. Do not treat a
stale/absent stamp as informational only — if it names a commit behind changes you are about to
commit that touch analysis behaviour, run the tier before committing, per the paragraph above.

`GRM_ROM_DIR` is set per machine (`.claude/settings.local.json`, gitignored) and holds **several
space-separated dirs**, because the curated manifest is split across more than one and the driver
indexes each at **depth 1 only**. The driver reads it as `ROM_DIRS=($GRM_ROM_DIR)` — unquoted,
so it splits on *any* whitespace with no escaping: multiple dirs separated by spaces work, but a
**single directory whose own name contains a space cannot be represented** this way (pass it on
the command line instead, where each argument is a distinct dir regardless of its contents). So:
**never conclude "this machine doesn't have the ROM" from a `SKIP`** — suspect the dir list first,
and look at the dirs the driver prints beside the skip count. `smb3` was blessed 2026-08-16 once a
hand pass established that its two remaining warnings are honest (`FUN_c542` really is a
bank-switch helper — `c5f5` is inside its body — so the output was right and the golden was two
lines stale). The long-standing "golden correct, output wrong; never bless it" rule was written
before `grm-67g` closed the `ca23`/`ca2e` half of that diff, and no longer applies.

**Two rows fail on an unchanged tree because of Ghidra 12.1.3, not because of this repo**
(`grm-9wl6`, measured 2026-08-22): `megaman` on the curated manifest and `wizwarr` on the GME set.
Holding the source byte-identical and flipping only `ghidraTargetVersion` puts both back on their
goldens exactly, so the goldens are right and the 12.1.3 output is degraded. **Neither may be
blessed** — there is no stable value to pin (wizwarr varies in *which* call sites lose their bank
argument; megaman's `bankComments` moved 161 vs 160 on consecutive runs). The owner's standing
decision as of 2026-08-22 is to leave them failing and documented until upstream moves, so treat
a `megaman`/`wizwarr` failure matching those signatures as attributed, not as yours, before
bisecting your own commits. Note this supersedes the older "`megaman` flaps at ~20% from `grm-g73`
jitter" line: that flap is real but it is a *12.1.2* phenomenon, and on 12.1.3 the row fails every
run. See `realrom-12-1-3-toolchain-fails` and `grm-qp5x`, and the **`realrom-current-fails`** bd
memory for the current, authoritative row list — that memory is the single place a row's status
lives, is revised as rows get fixed or reclassified, and supersedes any older summary including
this one. (It replaced `realrom-expected-baseline-fails`, which was only half-authoritative: it
was never itself updated when a *later* memory superseded its `megaman` paragraph, so it named a
jitter signature that no longer applies while still calling itself current. Its durable method
content — invocation, manifest-set semantics, cache and A/B mechanics — now lives in
`realrom-howto`, which carries no row-status content and so cannot rot the same way.) To
decide whether some *other* movement is yours, re-run the row against a stashed baseline and diff
the two `build/banktest-work/realrom.*/<id>.diff` files.

When `GRM_ROM_DIR` is unset and no romdir is passed, `realrom-test.sh` refuses to run (nonzero
exit, loud stderr message) rather than silently doing nothing — it never reports a clean gate for
a tier that did not execute.

**The exhaustive SPC700 vector tier (`spc700-vectors` chunk) has the same standing as the
real-ROM tier**: opt-in, needs user-supplied data (`GRM_SPC700_VECTORS`, a full clone of
`https://github.com/SingleStepTests/spc700`), refuses loudly (fails, not skips) when unset, and
is excluded from `all` because this repo cannot ship the clone — but it is routine local
verification, not a ceremonial final check, whenever that env var is configured. It runs the full
upstream suite (1000 cases/opcode, 256,000 total, ~15s measured) against
`spc700-vector-baseline-exhaustive.txt`, a separate baseline from the `unit` chunk's 32-case/opcode
sample (`spc700-vector-baseline.txt`) — the sample is fast enough for every run but narrow enough
to miss edge cases (e.g. a page-boundary condition occurring in only 11 of 1000 upstream cases for
one opcode) that the full suite catches. Reach for `bash tools/banktest/build-and-test.sh check
spc700-vectors` after any change touching `data/languages/spc700*.sinc`, not only before closing
out work on it. See `docs/testing.md`'s p-code semantic vector harness section for the two test
classes' baseline-regeneration switches.

**The SPC700 disassembly-text corpus differential (`spc700-dis-corpus` chunk) is a REPORTING
tier, not a gate** — the third opt-in tier, and the one with the weakest claim on you. It needs
`GRM_SPC700_DIS_CORPUS` (the project owner's game-music-extraction `snes/` directory) and
Assume-*skips* when unset rather than refusing loudly, because unlike the other two it asserts
almost nothing. It compares our disassembly text against ten hand-annotated listings of real
shipped drivers and writes per-row TSVs to `build/spc700-dis-corpus/` for triage.

**Those listings are NOT an oracle — a disagreement is a question, not a verdict, and which side
is wrong is open every time.** Never "fix" the language to match a `.dis` file, and never add
golden-file assertions over them. Reach for it after a change to `data/languages/spc700*.sinc`
that could move decode text (mnemonic, operand form, length), which the vector tiers do not
cover at all. 31,404 instructions, 254/256 opcodes, 55 residual rows, none of them ours (bead
`grm-uy9s`) — and the residue is concentrated entirely in the two earliest listings, which an
earlier version of that disassembler got wrong. See docs/testing.md for the breakdown.

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

## Reading Ghidra source code

Frequent task. **The targeted Ghidra version is defined ONCE, in `gradle.properties`'
`ghidraTargetVersion`** (`<ver>` below). By convention the install lives at
`<ghidraInstallRoot>/ghidra_<ver>_PUBLIC` — `ghidraInstallRoot` being the machine-local
value in `~/.gradle/gradle.properties` — and the source checkout is kept on tag
`Ghidra_<ver>_build`; build.gradle hard-fails if the resolved install's version disagrees.

Both locations are per-machine, so **neither is spelled as a literal path here** (`grm-sp93`).
Read them from the environment: `$GRM_GHIDRA_SRC` for the source checkout and
`$GRM_GHIDRA_INSTALL` for the install, both set in `.claude/settings.local.json`. Use, in
order of preference:

1. **Local full checkout `$GRM_GHIDRA_SRC`** — primary source: fast navigation
   (Grep/Read/Glob) AND version-exact, since it is kept checked out on the
   `Ghidra_<ver>_build` tag. **READ-ONLY: never `git fetch`/`checkout`/modify it** — the
   user manages its state. If version exactness matters, sanity-check first:
   `git -C "$GRM_GHIDRA_SRC" describe --tags` should print `Ghidra_<ver>_build`; if it prints
   something else, fall back to source #2/#3 for API-sensitive details (and mention the
   mismatch to the user). If `$GRM_GHIDRA_SRC` is unset, ask rather than guessing a path.
2. **The install `$GRM_GHIDRA_INSTALL`** — always matches what we compile against.
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

### Loader validation: `load()` is authoritative, `validateOptions()` is GUI-only

`Loader.validateOptions()` is called **only** from the interactive GUI import dialogs
(`ImporterDialog`, `AddToProgramDialog`, `LoadLibrariesOptionsDialog`). It is not called from
`analyzeHeadless`, the `ProgramLoader` API, `GhidraScript.importFile`/`importFileAsBinary`, or
even the GUI's own batch importer (`ImportBatchTask`) — verified at 12.1.3 and traced back
through the 11.4-era sources, so this is longstanding behaviour, **not** a 12.x regression
(grm-vsg). Never treat it as a safety gate for anything reachable headlessly, which in this repo
means everything the banktest harness imports.

Every loader here therefore treats `load()` as the sole authoritative validation point:

- Any check that must hold for correctness — a referenced file exists and is the right size, an
  option string parses and resolves against the descriptor, a board/mapper id is known — must be
  enforced, or independently re-verified, inside `load()`. Not only in `validateOptions()`.
- `validateOptions()` may still implement the same check for early GUI rejection, which is a
  better experience than importing and then degrading. **Factor the check into a shared helper so
  the two call sites cannot drift** — `NesRomLoader.placementError()` is the worked example, used
  by `validateOptions` to reject and by `load` as the headless safety net.
- On a violation detected in `load()`, prefer a clear `MessageLog` message plus refusing to
  populate the affected region over either throwing or proceeding with guessed data.
  `AbstractCbmPrgLoader.createRomBlock()` is the model: a ROM file of the wrong size logs what it
  found versus what it expected and leaves the block uninitialized.

Note the harness consequence, which has bitten before: `analyzeHeadless` exits 0 even when a
loader rejects a file, so a "this bad input is refused" test must assert on log content and the
absence of a committed program, never on exit status (see the `headless-rejection-exit-zero` bd
memory and `run-banktest.sh`'s `run_reject()`).
