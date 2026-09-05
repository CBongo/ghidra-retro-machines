# Testing strategy

**If you are an agent looking for JUnit: read this first.** For most of this project's
history there was **no JUnit and no `gradle test`**, and agents repeatedly burned time
hunting for scaffolding that did not exist. That has changed as of `grm-32f.1` (a JUnit unit
layer now exists), but the **end-to-end golden-image suite remains the acceptance
authority** — it is what gates commits and issue acceptance. Know both, and know which tier
a given test belongs in.

## The three tiers

| Tier | What | How it runs | Use it for |
|---|---|---|---|
| **1. Pure JUnit** | `@Test` on pure logic, no Ghidra runtime | `gradle test` (`src/test/java`) | Logic with no `Program`/`Instruction`: `BankState` algebra, `MapCompiler` descriptor parsing, bit math |
| **2. Program-fixture JUnit** | `AbstractGenericTest` + `ProgramBuilder` | `gradle test` (`src/test/java`) | Loader/analyzer/strategy logic that needs a real `Program`/`Instruction` but not the full import pipeline |
| **3. E2E golden image** | Real loaders + `analyzeHeadless` + behavior-dump diff | `tools/banktest/build-and-test.sh` (bash, out-of-process) | Acceptance: the real import + analysis pipeline end to end. **The gate.** |

Tiers 1–2 are **additive**, not a replacement for Tier 3: `gradle test` runs them directly,
and `build-and-test.sh` also runs them as part of the acceptance gate via the `unit` chunk
(pulled in by `unit` or `all`; see status below). Tier 3 is the authority and always runs. A
change is not accepted until Tier 3 is green.

The project **used** to carry a set of bespoke `main()`+`System.exit` verifiers
(`verifyBitAlgebra`, `verifyMapCompiler`, `verifyDescriptorComposition`, `verifyPetsciiMapper`,
`verifyCharsets`) wired as `JavaExec` tasks. As of `grm-32f.4` they are **all migrated to
JUnit** `@Test` classes under `src/test/java` (`BitAlgebraEquivalenceTest`, `MapCompilerTest`,
`DescriptorCompositionTest`, `PetsciiMapperTest`, `RetroCharsetProviderTest`) and run by the
`test` task, which gives per-assertion reporting instead of first-mismatch `System.exit`. Add
new pure checks as Tier-1 JUnit — do not reintroduce a bespoke `main()` verifier.

## How long the gates actually take

Measured 2026-08-31 on the 33-row real-ROM corpus (bead `grm-yfma`). Quote these rather than
guessing, and **re-measure before quoting them elsewhere** — they are one machine's numbers, and
while the rows are hash-pinned the hardware is not.

| Gate | Wall clock | Notes |
|---|---|---|
| `build-and-test.sh check` (all chunks) | ~5–6½ min | includes the `unit` JUnit suite |
| `realrom-test.sh check --all` (33 rows) | ~6–6½ min | four consecutive runs: 6m36s, 6m13s, 6m10s, 6m21s |
| one real-ROM row | median **7s**, mean 10s, max 52s | from dump timestamps across one full run |

**Both gates are minutes, not hours.** This section exists because the opposite was written down
and believed: `AGENTS.md` said the real-ROM tier "is hours" (~50x high), resting on a `~1min+`
per-import figure repeated in four places that was approximately the *worst* row stated as typical.
Neither was ever measured.

That mattered in practice, which is why the correction is recorded rather than quietly applied. A
wrong cost estimate inside an instruction file changes what agents *do*: faced with an ambiguous
result whose decisive experiment was one more `--all` run, an agent priced that run at "multi-hour",
declined it, and substituted four cheap targeted probes — which all landed on the same side of what
turned out to be a coin flip and nearly caused a row to be misfiled. The run it declined would have
cost six minutes. **When a full run is the decisive experiment, run it.**

The corollary for the opt-in tiers: the real-ROM tier being ~6 minutes is why
`realrom-test.sh check --all` is a *required local step* before committing analysis-behaviour
changes rather than a ceremonial occasional check, and why the SPC700 vector tier (~15s) is
routine verification rather than a final gate.

## Tier 3 — the E2E golden-image suite (the acceptance authority)

This is the load-bearing suite. It lives in `tools/banktest/` and works like this:

1. **Generators** (`tools/banktest/mk*.py`, e.g. `mknesbanktest.py`, `mkbanktest.py`,
   `mkpetsciistringtest.py`) synthesize small test PRGs/ROMs with known, hand-designed
   banking/loader behavior.
2. **`build-and-test.sh check`** builds the extension (`gradle buildExtension`, which also
   runs the bespoke verifiers), stages it via `gradle stageExtensionForTests` into a
   **per-git-worktree isolated** Ghidra user-settings dir under `build/ghidra-home`
   (gitignored; never touches the shared `%APPDATA%/ghidra` install, so an open GUI or a
   parallel agent can't clobber it), then runs the fixtures. As of bead `grm-4t2d`,
   `run-banktest.sh` and `realrom-test.sh` stage the extension themselves too (build by
   default, with a `--no-build`/`GRM_SKIP_BUILD` opt-out) rather than requiring a prior
   `build-and-test.sh` run — see AGENTS.md's "The runners build by default" section.
3. Each fixture imports its ROM headless with the **real loader** (`analyzeHeadless -loader
   NesRomLoader` etc.), runs default auto-analysis, and executes `VerifyBankTest.java` as a
   post-script.
4. **`VerifyBankTest.java`** asserts per-fixture `CRITERION` checks and emits a normalized
   behavior **dump** (blocks, overlay references, switch comments, bookmarks) that is diffed
   against the committed golden in `tools/banktest/expected/<name>.dump` — one golden per
   fixture; new fixtures land often enough that a count here would drift, so count them
   directly: `ls tools/banktest/expected/*.dump | wc -l`.

Run the full gate before every commit and for issue acceptance:

```bash
bash tools/banktest/build-and-test.sh check
```

### Bless discipline (important)

`bless` regenerates selected golden dumps:

```bash
bash tools/banktest/build-and-test.sh bless c64-banking
```

**A diff in `expected/*.dump` is a behavior change that needs review — never an
auto-accept.** Read the diff first and confirm the new behavior is intended; only then
bless, and only the specific chunk you reviewed. Blessing to make a red suite green without
understanding the diff defeats the entire suite.

> **`bless` fails closed on criteria failures (`grm-aqi`).** A fixture whose `SUITE PASS`
> criteria failed is **refused**: its golden is left byte-identical, the row is named in a
> `REFUSED to bless` summary line, and the suite exits nonzero. The other rows in the same
> run still bless normally. Both routes — a fresh import and a reused cached candidate —
> take the same code path (`bless_candidate`), so they cannot decide differently.
>
> The reasoning is worth knowing, because it is *not* "failures are bad". `bless` exists to
> accept **dump movement**, a judgment you form while reading the diff. A criteria failure is
> a different claim — the fixture's own asserted invariants are violated — and one you
> probably never evaluated when you typed `bless`. It also leaves **no trace in the
> artifact**: the golden holds only the `BANKDUMP` section, never the `SUITE` verdict, so a
> blessed-over-a-failure oracle is indistinguishable from a good one afterwards and `git
> diff` cannot reveal it. The pre-`grm-aqi` mitigations (prints FAIL, exits nonzero) all
> lived in terminal scrollback.
>
> Override with `--force-criteria`, which blesses anyway and reports every row it forced.
> The legitimate use is a criterion that has gone *stale* because you deliberately changed
> what it asserts, and you intend to fix the criterion separately:
>
> ```bash
> bash tools/banktest/build-and-test.sh bless --force-criteria nes-banking
> ```
>
> Structural failures (headless exited nonzero, no `BANKDUMP` section) have always refused
> and still do — `--force-criteria` does not reach them, since there is no trustworthy dump
> to bless. Golden writes are atomic (temp + rename), so an interrupted bless leaves the old
> oracle intact rather than a truncated one.

> **Candidate cache (`grm-lne`).** A `check` run stashes each freshly imported dump in a
> content-addressed cache under `build/` (gitignored), and a following `bless` reuses it
> instead of re-running the `analyzeHeadless` import — so the normal
> review-then-bless loop imports once, not twice (biggest win on the real-ROM tier, where a
> full 33-row run is ~6 min; see "How long the gates actually take" below).
> The cache key folds in the fixture bytes, loader + options, the dump script, and a
> **content** fingerprint of the installed extension jar (CRC-based, not an mtime, since
> gradle rewrites the dist zip every build). Any of those changing forces a fresh import, so
> a stale candidate is never blessed; `bless` still prints the `expected/*.dump` diff before
> accepting. It is a pure speedup with no workflow change — clear it any time with
> `rm -rf build/banktest-cache build/realrom-cache`.

### Chunks (partitioning — `grm-32f.2`)

For the dev loop, run only the chunk(s) relevant to your change; the **full suite still gates
final acceptance and commits**. `build-and-test.sh --list-chunks` prints the current set:

| Chunk | Covers |
|---|---|
| `c64-banking` | C64 `banktest`–`banktest4` fixtures |
| `c64-loader` | C64 PRG placement/wrapping, ROM loading, symbol toggles |
| `c64-recovery` | C64 emulation and decrypt/recovery fixtures |
| `basic-petscii` | C64 BASIC headless fixture |
| `basic-dialects` | PET BASIC 4 / C128 BASIC 7 token dialects + C64 BASIC 2 regression |
| `pet-loader` | PET 4032 descriptor, PRG placement, IO types, fixed ROM slots |
| `snes-loader` | SNES cartridge loader: header detection (plain and copier-headered twins of the same image), static LoROM layout, byte-mapped mirrors, IO typing, reset entry point |
| `c128-loader` | C128 native BASIC PRG placement, fixed ROM slots, MMU IO |
| `nes-banking` | NES banking and MMC fixtures |
| `petscii-strings` | `PetsciiStringAnalyzer` C64 PRG fixture |
| `unit` | the JUnit `gradle test` suite (all `src/test/java`; no extension build/install needed alone) |
| `spc700-vectors` | exhaustive SPC700 p-code vector regression, 1000 cases/opcode (256,000 total) vs. the `unit` chunk's 32/opcode sample (`gradle spc700VectorTest`); needs `GRM_SPC700_VECTORS`, refuses loudly otherwise; opt-in, **not** included by `all` (see below), but routine (not just ceremonial) whenever the env var is configured — same standing as the real-ROM tier — and worth an explicit run after any SPC700 `.sinc` change, since the sample chunk can and does miss narrow edge cases (page-boundary wraps and the like) that the full suite catches |
| `spc700-dis-corpus` | SPC700 *disassembly text* differential against nine hand-annotated `.dis` listings of real drivers (`gradle spc700DisCorpusTest`); needs `GRM_SPC700_DIS_CORPUS`, Assume-skips otherwise; opt-in, **not** included by `all`. A reporting tier, not a gate — the listings are leads, not an oracle. See its own section below |
| `w65816-vectors` | exhaustive W65816 p-code vector regression, 10,000 cases/opcode/mode (5,120,000 total, both native and emulation mode) vs. the `unit` chunk's PARTIAL 16-opcode/32-case sample (`gradle w65816VectorTest`); needs `GRM_W65816_VECTORS`, refuses loudly otherwise; opt-in, **not** included by `all`. See its own section below — in particular, the known-unverified `p` bits and the sample's partial opcode coverage |
| `all` | every chunk (the default when no chunk is given) — **except** `spc700-vectors`, `spc700-dis-corpus`, and `w65816-vectors`, which must be named explicitly |

**The shipped `ghidra_scripts/` front-ends are regression-tested inside these chunks, and nowhere
else.** The GUI plugins are untestable here (see below), so a headless fixture that drives the
script as a `-preScript`/`-postScript` is the only coverage either one has — which also means the
chunk holding it is not the one you would guess from the script's subject:

| Script | Fixture | Chunk | Driven as |
|---|---|---|---|
| `RunFromElsewhereTransfer.java` | `rfemanual` | `c64-recovery` | `-preScript` (before auto-analysis, so the manual carve precedes `CopyLoopAnalyzer`'s) |
| `FixSkipInstructions.java` | `nesskiptest` | `nes-banking` | `-postScript` (the offcut conflict it repairs does not exist until after disassembly) |
| `tools/banktest/AssertBankOrderIndependence.java` | `nesskiptest` | `nes-banking` | second `-postScript`, run POST-verify (after `VerifyBankTest.java`'s dump) so it perturbs the program only once the golden-compared artifact is already taken (bead grm-q39f) |
| `tools/banktest/SetAnalyzerEnabled.java` | `nesbanktest` (via `run_census`) | `nes-banking` | `-preScript`, forces "NES Bank State" off before auto-analysis on the census's "off" leg (bead grm-8uaz) |
| `tools/banktest/BaseSpaceCensus.java` | `nesbanktest` (via `run_census`) | `nes-banking` | `-postScript`, on BOTH of `run_census`'s imports, counting base-space instructions/functions and reporting the analyzer's current on/off state |

Each also asserts on the script's own verdict line by grepping the headless log, because that line
falls outside the `BANKDUMP` markers and so is invisible to `VerifyBankTest`.
`AssertBankOrderIndependence.java` is the one exception to the "shipped `ghidra_scripts/`" framing
above: it lives in `tools/banktest/` alongside `VerifyBankTest.java`, not in `ghidra_scripts/`,
because it is a test-only assertion over `BankCommentProvenance`'s order-independence property
rather than a user-facing front-end — but it is wired into `nesskiptest` the same way, via
`run_one`'s new post-verify argument slot, and is listed here for the same reason.
`SetAnalyzerEnabled.java` and `BaseSpaceCensus.java` are the same kind of test-only pair, living
in `tools/banktest/` for the same reason.

### The ANALYZER-OFF CENSUS (`run_census`, bead grm-8uaz) — a property, not a golden

`run_census` (in `run-banktest.sh`, wired into `nes-banking` as `run_census nesbanktest ...`)
imports the SAME image TWICE — once with "NES Bank State" left at its default (on), once with it
forced off via `SetAnalyzerEnabled.java` as a `-preScript` — running `BaseSpaceCensus.java` as a
`-postScript` on both, and asserts an inequality: enabling our analyzer must never REDUCE how
much *base-space* code Ghidra's own pipeline disassembled (instructions and functions counted
outside any overlay space). This is not hypothetical — `grm-nems` measured `tmnt` reaching 3426
base-space instructions / 117 functions with the analyzer disabled and only 2006 / 67 with it
enabled, on a cold cache, and nothing anywhere asserted that regression before this fixture
existed.

**There is deliberately no golden file and no `bless` for this fixture.** Every other golden in
this suite pins a recorded BEHAVIOR that should stay byte-identical until someone deliberately
reviews and accepts a diff. This fixture's property is the opposite shape: a pure inequality
(`instrs_on >= instrs_off`, `functions_on >= functions_off`) that must hold on every run, not a
value to capture once and diff against forever. A golden here would invite exactly the failure
mode `grm-nems` fell into — a stale, blessed pair of numbers nobody is checking the *relationship*
between — so `run_census` runs its own two imports and its own assertion unconditionally, in both
`check` and `bless` mode, outside `run_one`'s cache/candidate machinery entirely.

The fixture also guards against its own vacuity: it fails loudly, distinctly from a property
violation, if the two runs' `CENSUS analyzer` lines do not actually show `true` on the "on" leg
and `false` on the "off" leg — without that check, a typo'd analyzer name would silently compare
analyzer-on against analyzer-on and report a permanently green result that proves nothing.

```bash
bash tools/banktest/build-and-test.sh check nes-banking c64-banking   # dev loop subset
```

There is deliberately **no `quick` alias and no cache-backed mode**: headless projects are
created fresh (a correct cache would need explicit invalidation rules). Use targeted chunks
instead. See the project `CLAUDE.md` "Build & Test" section for the parallelization rules
(one agent per git worktree; the shared Ghidra install is read-only to the loop).

## Tiers 1–2 — the JUnit unit layer (`grm-32f.1`)

`gradle test` runs a standard JUnit4 suite under `src/test/java`, using **Ghidra's own
shipped test scaffolding** — no GhidraDev/Eclipse tooling required. It runs headless against
the binary install. Reference tests from the spike:

- `src/test/java/retromachines/BankStateTest.java` — Tier 1, pure logic, zero Ghidra imports.
- `src/test/java/gdtbuilder/MapCompilerTest.java` — Tier 1, `MapCompiler` via
  `TemporaryFolder` + `assertThrows` (the migrated `verifyMapCompiler`); its sibling
  `DescriptorCompositionTest`, plus `BitAlgebraEquivalenceTest`, `PetsciiMapperTest`, and
  `RetroCharsetProviderTest`, are the other migrated verifiers (`grm-32f.4`).
- `src/test/java/retromachines/BankStrategyProgramTest.java` — Tier 2, `AbstractGenericTest`
  + `ProgramBuilder`, exercising the real `RegisterWriteBankSwitchStrategy` →
  `StoredValueScanner` path against a built `LDA #imm ; STA $01` fixture.

```bash
gradle test
```

(With `ghidraInstallRoot` set in `~/.gradle/gradle.properties` per the README's "Building"
section, the install dir resolves from `ghidraTargetVersion` — no env var or `-P` needed.)

### Constraints (do not rediscover these the hard way)

- **Use a shipped language: `new ProgramBuilder("Test", "6502:LE:16:default")`. Do NOT use
  `ToyProgramBuilder`** — its `Toy:*:builder` language is source-only and absent from the
  binary install (`LanguageNotFoundException`).
- **JUnit 4** (not 5): `import org.junit.*`; the Gradle task uses `useJUnit()`, not
  `useJUnitPlatform()` (Gradle 8.5 / Java 21).
- The `test` source set gets its own classpath in `build.gradle` (mirrors the `gdtBuilder`
  pattern): `testImplementation` = Ghidra `fileTree` (carries `AbstractGenericTest`,
  `ProgramBuilder`, and gson) + `sourceSets.main.output` + `sourceSets.gdtBuilder.output` +
  `org.yaml:snakeyaml` (Ghidra ships none; `MapCompiler` needs it) + `junit` + `hamcrest`.
- Tier-2 tests bootstrap Ghidra's `Application` (~1.5 s/class); Tier-1 pure tests are ~instant.
- Extend `AbstractGenericTest` (headless). Avoid `AbstractGuiTest`/`TestEnv` (headed) and
  `TestResources`-backed helpers (`getTestDataDir()`) — that module isn't in the install.

### Status

The `test` suite **is run by `build-and-test.sh`** (it replaced the retired `verify*`
`JavaExec` tasks in `grm-32f.4`). As of `grm-32f.5` it has its **own chunk, `unit`**: run
`build-and-test.sh check unit` to run just `gradle test` (no extension build/install), and the
full `all` gate runs it alongside every headless fixture. Headless chunks (`basic-petscii`,
`nes-banking`, …) run **only** their fixtures — they no longer drag in the JUnit suite — so a
targeted dev loop stays fast. `test` itself is still monolithic (the whole `src/test/java`
suite runs whenever `unit`/`all` is selected); the suite is small and fast (~seconds; one
`AbstractGenericTest` class bootstraps `Application`), so finer per-`--tests` scoping was
deliberately skipped. It stays **out of `buildExtension`'s `dependsOn`** — `buildExtension` is
packaging-only and the gate invokes `test` explicitly. Tier 3 remains the acceptance
authority; the JUnit suite is an additional gate, not a replacement.

### P-code semantic vector harness (`grm-c9d.2`)

`src/test/java/retromachines/vectors/` is a language-agnostic harness that steps Ghidra's
interpreted `PcodeEmulator` one instruction at a time and compares the resulting
register/memory state against a SingleStepTests-shaped JSON vector (`VectorCase`/
`VectorParser`/`VectorRunner`). Its first consumer is SPC700 (vendored in `grm-c9d.1`); `grm-o9k`
reuses it against the 65x02 suites for the ADC/RRA flag bug.

Because it is meant to report — not hide — failures against a spec known to be broken while it
is being fixed, it does not use plain JUnit assertions for the SPC700 opcode-by-opcode result:
it compares against a committed per-opcode baseline (`OpcodeBaseline`,
`src/test/resources/spc700-vector-baseline.txt`), this project's bless idiom applied to a defect
list instead of a golden dump. A baseline `FAIL` row is not a test failure; only a *regression*
(an opcode moving `PASS` → `FAIL`) or the harness measuring fewer opcodes / zero failures than
the baseline expects is. See `OpcodeBaseline`'s class doc for the exact rules, and its own
header comment for how to regenerate it.

Two SPC700 test classes split by cost and gating, each with its own committed baseline (the
per-opcode PASS/FAIL ratios differ at different case counts, so the two files cannot share one —
see `Spc700VectorExhaustiveTest`'s class doc):

- `Spc700VectorSampleTest` (the `unit` chunk) runs the vendored 8192-case sample
  (`src/test/resources/spc700-vectors/`, 32 cases/opcode; provenance in that directory's
  `MANIFEST.txt` and in `NOTICE`) against `spc700-vector-baseline.txt`. Regenerate with
  `gradle test -Dgrm.spc700.regenerateBaseline=true --tests '*Spc700VectorSampleTest'`.
- `Spc700VectorExhaustiveTest` (its own `spc700-vectors` chunk, **not** included by `all`) runs
  the full upstream suite — 1000 cases/opcode, 256,000 cases total (measured directly across all
  256 upstream files) — against a full clone named by `GRM_SPC700_VECTORS`, comparing against
  `spc700-vector-baseline-exhaustive.txt`. Refuses loudly (fails, does not skip) when that
  variable is unset, mirroring `tools/banktest/realrom-test.sh`'s "never report a clean gate for
  a tier that did not execute" rule. Regenerate the clone with `git clone --depth 1
  https://github.com/SingleStepTests/spc700 <dir>`; regenerate the vendored sample with
  `python3 tools/spc700/sample-vectors.py --source <dir>`; regenerate this baseline with
  `gradle spc700VectorTest -Dgrm.spc700.regenerateExhaustiveBaseline=true` (a *different* `-D`
  property from the sample test's, forwarded to this task's own forked worker in `build.gradle` —
  Gradle does not forward `-D` properties across Test tasks automatically, only within one task's
  own config block, so each baseline-regeneration switch needs its own explicit forwarding line).

  **Routine, not ceremonial** (grm-c9d.3 increment 6): now that a full vector clone is cheap to
  keep around locally and the run itself takes on the order of 15 seconds (measured at ~58
  µs/case), reach for this tier as part of routine local verification whenever
  `GRM_SPC700_VECTORS` is configured — the same standing as the real-ROM tier
  (`tools/banktest/realrom-test.sh`), not only as a final check before closing out a body of work.
  It stays out of `all` for the same reason the real-ROM tier does: it needs a large, user-supplied
  clone this repo cannot ship, so it cannot be a hard CI gate. The sample tier's 32 cases/opcode
  (3.2% of the full suite) is what runs by default and in CI; it is fast but can and does miss
  narrow edge cases the full suite catches — e.g. `dp=0xFF` page-wrap behavior occurs in only 11
  of `BA`'s 1000 upstream cases, so a 32-case sample has under a 1-in-3 chance of ever exercising
  it. When in doubt whether a change is fully correct rather than merely sample-clean, run this
  tier.

Both SPC700 test classes Assume-skip (green, not red) rather than fail while the SPC700
language itself is unavailable in a given worktree — see their class docs. `VectorHarness6502Test`
(also `unit`) proves the harness mechanics — including that it actually detects a corrupted
expectation — against Ghidra's stock `6502:LE:16:default`, with no dependency on SPC700 at all.

### W65816 vector harness (`grm-9nxj.3`)

`W65816VectorHarnessSupport`/`W65816VectorSampleTest`/`W65816VectorExhaustiveTest` are the
65816 analogue of the SPC700 classes just above, against
`https://github.com/SingleStepTests/65816` (256 opcodes x native/emulation mode, 10,000
cases/opcode/mode, 5,120,000 cases total). Reusing the same generic `VectorRunner` for a
context-sensitive, bank-addressed CPU needed two additions to `VectorRunner` itself (bead
grm-wrmf's `withContextProvider`, and grm-9nxj.3's sibling `withCounterAddressProvider`) plus
per-case adaptation in `W65816VectorHarnessSupport` — see that class's Javadoc for the full
reasoning; the essentials:

- **Context is per-case, not static.** `658xx.sinc` decodes on `ctx_MF`/`ctx_XF`/`ctx_EF`, not
  program registers, and the corpus carries the case's mode in `p`'s bits 5/4 plus a separate
  `e` scalar. `W65816VectorHarnessSupport` derives the decode context from those per case. In
  emulation mode (`e=1`) it FORCES `ctx_MF=ctx_XF=1` rather than trusting `p`'s bits 5/4 — real
  hardware cannot be in emulation mode with a 16-bit accumulator or index registers, so this
  only guards against ever asking the decoder for a combination no genuine 65816 state produces.
- **The program counter is banked.** Confirmed directly against the real corpus: a case's `ram`
  entries are keyed at the full 24-bit address `(pbr<<16)|pc`, not at `pc` alone. Feeding
  `pc` alone to the decoder (as `VectorRunner` always did before this bead) would fetch from
  bank 0 every time regardless of `pbr` — wrong for nearly every case, since the corpus
  randomizes `pbr`. `withCounterAddressProvider` fixes this.
- **`p` cannot be compared wholesale.** The language models N/V/D/I/Z/C as separate registers
  (`NF VF DF IF ZF CF`) with no packed status register at all — unlike SPC700's single `PSW`
  byte. `W65816VectorHarnessSupport` splits each case's `p` into synthetic
  `p_n/p_v/p_d/p_i/p_z/p_c` fields that map onto those real registers before handing the case to
  `VectorRunner`. **Bits 5 (M) and 4 (X in native mode / B in emulation mode) are NEVER
  compared** — M has no program register in this language at all (only a context field, which
  the interpreted `PcodeEmulator` has no post-step read-back for), and bit 4's meaning is
  mode-dependent in a way a single static field mapping cannot switch per case. This is a
  permanent, documented gap (see the class's Javadoc), not an oversight — an unverified bit that
  looks verified would be worse than stating the gap.
- **Register mapping**, verified against `658xx.sinc`'s `define register` lines rather than
  assumed: `pc->PC`, `s->SP`, `a->C` (the corpus's accumulator field is the full 16-bit
  register — `A`/`B` are only its 8-bit halves), `x->X`, `y->Y`, `dbr->DBR`, `d->DP`, `pbr->PBR`.
  All eight names exist in the language.
- **`OpcodeBaseline` rows are keyed `<OPCODE-HEX>.<N|E>`**, one row per (opcode, mode) rather
  than one row per opcode — the corpus partitions native and emulation mode into separate case
  populations (grm-wrmf's point 2), so e.g. `A9.N` and `A9.E` are independent rows with
  independent pass ratios.
- `WAI` (`0xCB`) and `STP` (`0xDB`) are `NOT_APPLICABLE_OPCODES`, mirroring SPC700's
  `SLEEP`/`STOP` — both legitimately halt the processor with no correct post-single-step state.
- `MVN` (`0x54`) and `MVP` (`0x44`) are `NOT_APPLICABLE` too, for a different and less obvious
  reason (`grm-9nxj.4`): **the corpus caps those cases at 100 cycles**, so their "final" state is
  a *partial* block transfer, not a completed instruction. Every other sampled opcode carries its
  natural cycle count (2–8); these carry exactly 100 in all 128 sampled cases, and decoding one
  confirms it (100 cycles ÷ 7 per byte = 14 bytes moved, `A` down 14, `X`/`Y` up 14, mid-block).
  This language moves the whole block in one p-code step, which is right for analysis and cannot
  match a truncation — **do not "fix" the semantics to chase these rows green.**
- The **break flag is seeded but never compared.** In emulation mode `p` bit 4 is `B`, which the
  language does back with a real register (`BF`), and `PHP`/`BRK` push it into memory where the
  corpus *does* compare it — so it must be seeded. It is deliberately left out of the comparison:
  `XCE` in native mode *ends* emulated, so a final state carrying `p_b` would demand a flag the
  initial state never seeded. Which `p` bits are verifiable is mode-dependent per **state**, not
  per case.

**FULL OPCODE COVERAGE, at fewer cases each than SPC700's sample.** `Spc700VectorSampleTest`
samples all 256 SPC700 opcodes at 32 cases per file; `W65816VectorSampleTest` samples all 256
65816 opcodes in BOTH modes (512 files) at **8 cases per file** — 4,096 cases, 4.9 MB, close to
the SPC700 sample's 6.5 MB footprint. The trade is deliberate: 65816 cases are roughly 4x larger
(more registers, 24-bit addresses), and now that a full clone drives `w65816-vectors`, DEPTH
comes from the exhaustive tier while the always-on sample buys BREADTH. Regenerate with
`--opcodes` naming all 256 and `--n 8`; `MANIFEST.txt` records the exact list and count.

(Until `grm-9nxj.4`'s second pass this sample covered only 17 opcodes, and the caveat here read
"an opcode absent from the baseline is untested, not passing." That caveat is retired: every
opcode is now in the baseline. The lesson it taught is not — a *missing* row and a *passing* row
look identical if you only skim the tally.)

**EXPECT FAILURES in both baselines.** Exactly like SPC700 before `grm-c9d.3`, this language's
p-code semantics had never been checked against an oracle when this tier was built. `grm-9nxj.4`'s
two passes have since taken the sample baseline from 8 passing rows to 28 PASS / 4 N/A / 2 red;
the two remaining red rows (`PLP.N`, `RTI.N`) throw on the language's own
`unknown_native_status_pull` pcodeop and stay sequenced behind `grm-9nxj.5`. A baseline `FAIL` row records reality; only a *regression*
(a row moving `PASS` → `FAIL`) is a hard failure, per `OpcodeBaseline`'s rules.

**Unmeasured runtime/heap.** `w65816VectorTest`'s `maxHeapSize` (`2g`) is a placeholder scaled up
from `spc700VectorTest`'s measured `512m`, not a measured value — no full corpus clone was
available while building this tier. Re-measure (and update this paragraph) the first time
`w65816-vectors` is actually run to completion against a real clone.

Regenerate the vendored sample with `python3 tools/w65816/sample-vectors.py --source
<full-clone-dir>` (or, for the loose one-file-at-a-time flow used the first time, `--source
<scratch-dir> --loose`); regenerate `w65816-vector-baseline.txt` with `gradle test
-Dgrm.w65816.regenerateBaseline=true --tests '*W65816VectorSampleTest'`; regenerate the
exhaustive baseline with `gradle w65816VectorTest -Dgrm.w65816.regenerateExhaustiveBaseline=true`
against `GRM_W65816_VECTORS`.

### Disassembly-text corpus differential (`grm-uy9s`)

The vector harness above covers SPC700 *semantics* and says nothing about the decode side —
which mnemonic, which operand form, which length. `Spc700DisCorpusTest` (its own
`spc700-dis-corpus` chunk, **not** included by `all`) covers that half, against ten
hand-annotated disassembly listings of real shipped SPC700 drivers in the project owner's
game-music-extraction working tree, named by `GRM_SPC700_DIS_CORPUS`:

```bash
GRM_SPC700_DIS_CORPUS=<snes dir> bash tools/banktest/build-and-test.sh check spc700-dis-corpus
```

**These listings are not an oracle, and this must never become a golden-file test over them.**
The 2000–2001 disassembler that produced them is not presumed more accurate than Ghidra's, so a
disagreement is a question with both sides open, not a failure — the opposite of the vector
tier, where SingleStepTests *is* an oracle because its expected state is machine-generated. The
class therefore reports (per-row TSVs under `build/spc700-dis-corpus/`) and asserts only what is
ours to get right regardless of who is correct about the mnemonics: that every byte sequence the
listings call code disassembles at all, and that the parse stays sound. It Assume-skips when the
variable is unset rather than refusing loudly, because unlike the vector tier there is no green
here worth protecting.

The comparison is seeded from each listing's own code/data separation — the seed set is exactly
the addresses it marks as instructions, with `followFlow` off — so row-to-row alignment stays
exact and the disassembler never wanders into a pointer table. That makes it a test of the
decode table rather than of flow recovery. `DisListing`'s doc has the line grammar; the
normalizer's doc in `Spc700DisCorpusTest` records exactly which spelling differences are folded
(radix, the `!` absolute marker, bit-index punctuation, the tool's `<d>`/`<s>` annotations) and
why each is a spelling difference rather than a decode dispute.

Across all ten listings: **31,404 instructions compared, 254 of 256 opcodes exercised, 55
residual disagreements, none of them ours.** Six of the ten listings agree on every single
instruction. The residue is 13 deliberate overlapping-instruction sites (a short opcode whose
immediate operand *is* the next instruction, used to skip it — the ff3 listing annotates these
by hand as "pseudo op to skip instruction") and 42 errors in the listings themselves, all of
them in `ff2spc.txt` and `ff3spc.dis`.

That concentration is the finding, not a coincidence: **the two earliest titles were produced by
an earlier, buggier version of the same disassembler, and the corpus dates the fixes.** ff2 (May
2000) reverses the operand order of every `dp,dp` form — its own `<d>`/`<s>` annotations make
the claim explicit and unambiguous, and the vector suite settles it (case `09 0000` writes the
*second* operand byte's address, which is what we print). ff3 (Feb 2001) has that right but
still prints the bit instructions' raw 16-bit operand instead of splitting it into a 3-bit index
and 13-bit address; the project owner confirms the correctly-split lines in that file are his own
hand corrections. Both files compute a short branch with offset exactly `0x7F` one page low — a
sign test written `>= 0x7F` instead of `>= 0x80` — while getting `0x7E` and every negative offset
right, and by fzero (Aug 2001) that is fixed too. ff2 additionally mis-decodes a handful of
individual opcodes (`5A` as `MOVW` rather than `CMPW`, `3B` as `ROR` rather than `ROL`, `BE` as
`DAS YA` rather than `DAS A`, `A7` dropping the `+X`) that no later listing gets wrong.

`tools/spc700/extract-upload-blocks.py` pulls the driver's upload stream straight out of a SNES
ROM — the `length, address, data…` block format nearly every SNES driver hands the SPC700,
terminated by a zero length and the execution address. It writes the stream verbatim, matching
the `*spc.bin` convention already in that tree, or `--image` for the flat 64K SPC memory image.
ff2 has no `.bin` of its own, so its listing was checked against a fresh extraction from
`ff2.smc` (block table at `04/8683`, per that title's `work.txt`): eight blocks matching the
title's `notes.txt` exactly, and 4,521 bytes of listing agreeing with the ROM byte for byte with
zero disagreements.

A by-product worth as much as the comparison: `<title>-datamap.tsv` extracts each listing's
code/data map — contiguous data regions with the section heading that introduces them and the
per-entry index labels (`vcmd dispatch table (D2-FF)`, `table for CPU cmds 80-8F and F0-FF`,
`opcode length table`). A fresh Ghidra import of an SPC image has nothing like it.

## When to add which

- **Pure function, no `Program`/`Instruction`** (mask algebra, descriptor parsing, string
  tables) → **Tier 1** JUnit in `src/test/java`.
- **Logic over a `Program`/`Instruction`/`Listing`** but not the whole import pipeline (a
  strategy's `computeSwitch`, an analyzer method, `StoredValueScanner` recovery) → **Tier 2**
  `AbstractGenericTest` + `ProgramBuilder`.
- **The real loader + import + auto-analysis pipeline end to end**, or anything whose value is
  out-of-process fidelity (overlay realization, reference retargeting across the real
  analyzer schedule, dump-level regression) → **Tier 3**: a generator + fixture + criteria in
  `VerifyBankTest.java` + a golden dump. Tier 3 is **not** replaceable by in-JVM fixtures and
  stays the acceptance authority.
- **Reworking behavior of an existing fixture** → change the code, run the chunk, review the
  `expected/*.dump` diff, and bless it deliberately.

## Analysis runs single-threaded (`grm-nems`)

Every headless invocation the banktest scripts make — both tiers — carries
`-Dcpu.core.override=1`, exported unconditionally by `grm_apply_settings_base`
(`tools/banktest/lib/common.sh`). This pins Ghidra's analysis thread pool to one thread.

**Why:** with the default pool, *the amount of code Ghidra disassembles for a given ROM
varies between runs.* Measured on `tmnt` (bead `grm-nems`): the same binary and the same
input yield either 2006 or 3426 base-space instructions, and the smaller outcome loses 44
overlay references, 103 overlay instructions and 6 bank comments from the dump. That is not
noise around the edges of a golden — it is a different analysis.

**What it bought, measured over three full `check --all` runs:** `tmnt` and `lwings` became
stable and were re-blessed (both gained recovered code; `tmnt` also picked up the `grm-daix`
format lines in the same re-bless). The synthetic gate did not move at all — `build-and-test.sh
check` was `SUITE OK` before and after — so this is a real-ROM-tier effect in practice. Cost is
roughly 10% wall clock: 6m42 versus the ~6m10–6m36 baseline.

**What it did NOT fix, and do not expect it to:** `dodge`, `ff1`, `rcproam` and `dragonpower`
still vary run to run with the pool pinned. That is a *separate* mechanism (`grm-4nr`,
`grm-g73`) and pinning the pool is not evidence about it either way.

**It is a mitigation, not a fix.** The underlying defect is that merely *enabling* our analyzer
flips a race in Ghidra's own disassembly — the shortfall happens before our analyzer is ever
invoked, and our analyzer neither deletes nor suppresses anything. `grm-nems` carries the
measurements and the open mechanism question.

**If you run `analyzeHeadless` by hand** and compare against a golden, pass the same property or
your result is not comparable:

```bash
GHIDRA_HEADLESS_JAVA_OPTIONS="-Dcpu.core.override=1" analyzeHeadless ...
```

A useful general check when a row moves unexpectedly, and the one that produced the finding: run
it with `NES Bank State` disabled (a `-preScript` calling
`setAnalysisOption(currentProgram, "NES Bank State", "false")`) and compare base-space
instruction and function counts against the enabled run. **Enabled should never be lower.**

## Optional real-ROM tier (`grm-zai`, hash-pinned)

Tiers 1–3 use synthetic inputs so the whole gate ships in-repo. The **real-ROM tier** is a
separate, opt-in regression net that runs the shipped NES board descriptors against *actual
commercial cartridges* — the fidelity check synthetic fixtures can't give (real games pass
bank numbers through tables/helpers, hit ~191 overlays, etc.). It is **not** part of the
default gate: ROM binaries are copyrighted and user-supplied, so nothing here runs in CI and
it is never a `run-banktest.sh` chunk (whose `all` would otherwise pull it in).

- **Driver:** `tools/banktest/realrom-test.sh check|bless|nominate [--gme|--all]
  [--only|--except <ids>] [--no-build] <romdir> [<romdir> …]` (or `GRM_ROM_DIR`). Lives
  alongside `measure-overlay-scale.sh` and reuses the same `build/ghidra-home` isolation. As
  of bead `grm-4t2d` it stages the extension itself (build by default) before analyzing, so
  no prior `build-and-test.sh` run is required; `measure-overlay-scale.sh` is the one script
  in this family that still needs one, since it was not in scope for that change.
- **Several romdirs are normal, and a `SKIP` usually means one is missing.** Dirs are indexed at
  **depth 1 only** — a title one directory down is invisible — so a collection split across two
  places needs both named, and the curated set on the primary dev machine does. `GRM_ROM_DIR`
  holds them space-separated and is the intended way to supply them; set it once per machine
  (it is machine-local, so it belongs in your environment or `.claude/settings.local.json`,
  never committed) and every invocation below can then omit the paths entirely. **Read a `SKIP`
  as "this run did not look everywhere" before reading it as "this machine lacks the ROM"** —
  the driver prints the dir list it actually used alongside the skip count for exactly this
  reason, and the `gme-rom-location` bd memory records where each set lives.
- **Two row sets, selected not accumulated.** `realrom/manifest.tsv` is the curated minimum
  (one representative title per shipped board) and is the default; `realrom/manifest-gme.tsv`
  is an expanded reference set of titles of interest to the parent game-music-extraction
  project, chosen by `--gme`; `--all` runs both. The flags *select*, because `--gme` also
  re-blessing the curated twelve is a costly surprise. The expanded set is deliberately not a
  gate: a reference point for planning and an occasional thorough check, since each row costs
  a headless import (~7s median, worst ~52s — see "How long the gates actually take"). Ids
  must be unique across both files — checked repo-wide
  regardless of which set a run selected — because an id names a golden *and* names the ROM
  copy the import sees, so a duplicate would let one row silently overwrite another's golden.
- **Candidate cache correctness.** `bless` may reuse a candidate a prior `check` imported.
  Its key must cover *everything that can change the dump*: the row id (it becomes the ROM
  copy name and lands in the dump as `REALROM program <id>.nes`), the ROM hash, the loader
  options, `RealRomDump.java`, and the installed extension — where "extension" includes the
  **loose `data/machines/*.map` descriptors**, not just the jars, since a board descriptor
  edit changes the very layout the dump records. A reused candidate is additionally asserted
  to name this row and this ROM before it is accepted, so the next key omission fails loudly
  instead of blessing a stale dump.
- **`nominate`** hashes a ROM dir, decodes each iNES mapper (mirroring `NesRomLoader`'s NES 2.0
  and `DiskDude!`-archaic handling) and resolves the claiming board from the shipped
  descriptors' `ines_mappers`, emitting paste-ready rows. It needs no Ghidra install. A mapper
  no descriptor claims is reported as a **board gap** — the most useful signal the expanded
  set produces, and a candidate for a new descriptor rather than a test failure.
- **Row selection:** `--only`/`--except` take comma-separated manifest ids. `--except` is the
  one that earns its keep: this tier's recurring shape is *one title held back at a known-good
  golden while every other title needs re-blessing* — `megaman` has been that title twice
  (grm-g73, then grm-hum), and blessing it would erase the record the bead depends on. An id not
  in the manifest is a hard **error**, never a silent no-op, because a typo in
  `--except megman` must not bless megaman. Filtered rows are reported as `filtered=N`, not as
  `SKIP` — `SKIP` means the ROM was absent, which is a different fact.
- **`megaman` flaps on 12.1.2 (grm-g73) — but on 12.1.3 it fails every run, for a different
  reason.** Read both halves; the second supersedes the first on any current tree.

  On **12.1.2**, two identical imports of the same ROM against the same build produce one of two
  dumps, differing *only* in these lines and always moving in opposite directions:

  ```
  REALROM count refs.intoOverlay    1704  <->  1703
  REALROM count instrs.inOverlay    7429  <->  7431
  ```

  So the row flaps PASS/FAIL with nothing changed. **The rule: if those two lines are the only
  diff, it is grm-g73, not a regression — any other line moving is real.** It is *not* held back
  any more (grm-hum blessed it at 1704/7429); it simply flaps. The harness deliberately does not
  retry the row or tolerate the delta: a golden whose diff you can trust is what this tier is
  *for*, and special-casing a noisy row would weaken that guarantee for every other row.

  On **12.1.3 — which is what `ghidraTargetVersion` pins today — that flap description no longer
  applies**, and treating it as current will misattribute a failure in both directions. A
  controlled A/B (grm-9wl6, 2026-08-22) holding source byte-identical and flipping only
  `ghidraTargetVersion` puts `megaman` back on its golden's classic pole exactly, so the golden is
  right and the 12.1.3 output is degraded: `refs` moves to ~1744 and `bankComments` to 160/161/162
  — and `bankComments` is unstable *against itself* across consecutive 12.1.3 runs, so there is no
  stable value to pin. `wizwarr` (GME set) is the same story. **Neither may be blessed**; the
  owner's standing decision is to leave both failing and documented until upstream moves.

  Because expected pass/fail counts go stale faster than anything else in this document, they are
  deliberately **not** stated here. The `realrom-current-fails` bd memory is the single
  authoritative list of which rows are expected to fail and why; `realrom-12-1-3-toolchain-fails`
  carries the full experiment, and `realrom-howto` the method. See also `grm-qp5x`.
- **Scripted A/B (`tools/banktest/ab-test.sh`, grm-5jjs):** attributing a real-ROM row's
  behaviour to a specific commit (or to a Ghidra toolchain change, via `--toolchain`) used to be
  a hand-run stash/rebuild/diff procedure with an easy-to-forget rebuild step in the middle.
  `ab-test.sh` scripts it: each side gets its own throwaway `git worktree` and therefore its own
  isolated `build/ghidra-home`, so a stale-build comparison is structurally impossible rather
  than a discipline to remember. It asserts the two sides' installed-extension identities differ
  before trusting the comparison, supports `--repeat N` for sticky/nondeterministic rows
  (`bistable-golden-sticky-states`), `--raise-sample N` for line-level attribution, and warns
  against single-row `--only` selections that can mask order-dependent movement (`grm-82u3`,
  the `tmnt` case above). Run `tools/banktest/ab-test.sh --help` for the full flag reference.
  One caveat found while verifying it: its identity guard uses `ext_identity()`
  (`lib/common.sh`), which was observed to differ across two builds of the *same* commit built
  in two different worktree paths even though the resulting dumps were byte-identical — so an
  `ext_identity()` mismatch does not by itself prove the sides differ in source. The
  dump-vs-dump diff the script prints is the trustworthy signal; treat the identity line as a
  sanity check, not a proof.

  The cause is **grm-eyn**: Ghidra's switch recovery over-reads several of this ROM's jump
  tables, planting spurious computed-jump targets that act as disassembly seeds. Because 6502
  instruction alignment is 1, a spurious seed and the legitimate instruction flow produce two
  different, self-consistent decodings of the same bytes, and whichever lands first wins. There
  is no configuration workaround — forcing single-threaded analysis
  (`-Dcpu.core.override=1`) changes the values and lowers the rate but does not remove it.
  Diagnose with `tools/banktest/DeterminismProbe.java`.
- **Hash-pinned identity:** `tools/banktest/realrom/manifest.tsv` — documented in
  `tools/banktest/realrom/README.md`, which also explains why the manifest carries no `#`
  preamble — pins each title by whole-file
  **SHA-256**. The driver hash-indexes the supplied dir(s) and matches by content, so it is
  filename-independent (sidesteps the parenthesis-rename and bad-dump-header traps) and a ROM
  that is absent or a *different* dump **SKIPs** — never a spurious FAIL. Only a present,
  hash-matched ROM whose dump differs from its golden FAILs. A run that matches nothing exits 0
  (`SKIPPED`), so the tier is safe to ship for users without ROMs.
- **Copyright-safe goldens:** `RealRomDump.java` (name-agnostic, read-only) emits only *derived*
  metadata — block/overlay layout, overlay-space/ref/comment/warning counts, the program
  SHA-256, the SHA-256 of the **PRG slice** alone (the per-game identity key a curated
  descriptor is written against), and a bounded, sorted **sample** of `bank -> …` comments,
  cross-bank overlay refs, and warning bookmarks. **No ROM bytes and no disassembled
  instructions**, so `expected/*.dump` is committable though the ROMs are not.
- **Bless discipline:** same as Tier 3 — regenerate with `bless`, review the `expected/*.dump`
  diff, commit deliberately. Because ROMs aren't in the repo, only someone with the pinned dump
  can re-bless.
