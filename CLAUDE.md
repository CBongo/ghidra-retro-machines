# Project Instructions for AI Agents

@AGENTS.md

**Read `AGENTS.md` — it is the always-on instruction core, it applies to you, and the rules in it
are not repeated here.** The `@AGENTS.md` line above imports it; if for any reason it did not
load, open `AGENTS.md` yourself before doing anything else. It carries: run commands through git
bash and never prefix with `cd`; stop and ask when a human would be more efficient; never edit (but
always commit when changed) `docs/human recon notes.txt`; only `build-and-test.sh` builds the
extension; use `bd` for all task tracking; and the session-completion/push protocol.

This file adds the Claude-specific and Ghidra-specific detail on top of that core: build and test
mechanics, the opt-in tiers, reading Ghidra source, and loader conventions.

<!-- The "Run commands through git bash" and "Stop and ask when a human would be more
     efficient" sections moved verbatim to AGENTS.md on 2026-08-26 (grm-yaat) so Codex/ChatGPT
     sessions get them too. Do not re-add them here — edit AGENTS.md instead. -->


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

**The real-ROM tier is separate, opt-in, and takes NO paths — just run it:**

```bash
bash tools/banktest/realrom-test.sh check            # core floor, 5 rows, ~46s
bash tools/banktest/realrom-test.sh check nes         # full NES tier, 34 rows -- romdirs from GRM_ROM_DIR
bash tools/banktest/realrom-test.sh check snes        # full SNES tier, 13 rows -- romdirs from GRM_SNES_ROM_DIR
bash tools/banktest/realrom-test.sh check all         # everything, every platform, 47 rows
bash tools/banktest/realrom-test.sh --list-sets       # print the table below
bash tools/banktest/realrom-test.sh coverage [SET]    # read-only: which rows have RAN at this build (not "passed")
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

`run-banktest.sh` and `realrom-test.sh` stage the extension themselves; the rule and opt-outs are in
`AGENTS.md`. _Why `stageExtensionForTests` is shaped the way it is: see
`.claude/rules/stage-extension.md` (loads when you touch `build.gradle` or `tools/banktest/`)._

Parallelization rules:
- One agent per `git worktree` (`git worktree add <path> <ref>`); never two agents sharing
  one working tree.
- Gradle caches under `~/.gradle` are shared across worktrees and gradle file-locks them
  itself — safe to build concurrently.
- The shared Ghidra install (`<ghidraInstallRoot>/ghidra_<ver>_PUBLIC`, composed from your
  machine-local `~/.gradle/gradle.properties` and gradle.properties' `ghidraTargetVersion`;
  override via `GRM_GHIDRA_INSTALL`) is read-only to this loop.

**Agents must never run `tools/install-gui.ps1`** — it writes outside the repo, into the user's
shared `%APPDATA%` Ghidra install. _How the GUI install works: see `.claude/rules/gui-install.md`._

_Reading Ghidra source code, and loader validation conventions: see `.claude/rules/ghidra-source-and-loaders.md` (loads when you touch the files it covers)._
