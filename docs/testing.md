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

Tiers 1–2 are **additive and opt-in today** (`gradle test`; not yet run by the acceptance
gate — see status below). Tier 3 is the authority and always runs. A change is not accepted
until Tier 3 is green.

The project **used** to carry a set of bespoke `main()`+`System.exit` verifiers
(`verifyBitAlgebra`, `verifyMapCompiler`, `verifyDescriptorComposition`, `verifyPetsciiMapper`,
`verifyCharsets`) wired as `JavaExec` tasks. As of `grm-32f.4` they are **all migrated to
JUnit** `@Test` classes under `src/test/java` (`BitAlgebraEquivalenceTest`, `MapCompilerTest`,
`DescriptorCompositionTest`, `PetsciiMapperTest`, `RetroCharsetProviderTest`) and run by the
`test` task, which gives per-assertion reporting instead of first-mismatch `System.exit`. Add
new pure checks as Tier-1 JUnit — do not reintroduce a bespoke `main()` verifier.

## Tier 3 — the E2E golden-image suite (the acceptance authority)

This is the load-bearing suite. It lives in `tools/banktest/` and works like this:

1. **Generators** (`tools/banktest/mk*.py`, e.g. `mknesbanktest.py`, `mkbanktest.py`,
   `mkpetsciistringtest.py`) synthesize small test PRGs/ROMs with known, hand-designed
   banking/loader behavior.
2. **`build-and-test.sh check`** builds the extension (`gradle buildExtension`, which also
   runs the bespoke verifiers), installs the dist zip into a **per-git-worktree isolated**
   Ghidra user-settings dir under `build/ghidra-home` (gitignored; never touches the shared
   `%APPDATA%/ghidra` install, so an open GUI or a parallel agent can't clobber it), then
   runs the fixtures.
3. Each fixture imports its ROM headless with the **real loader** (`analyzeHeadless -loader
   NesRomLoader` etc.), runs default auto-analysis, and executes `VerifyBankTest.java` as a
   post-script.
4. **`VerifyBankTest.java`** asserts per-fixture `CRITERION` checks and emits a normalized
   behavior **dump** (blocks, overlay references, switch comments, bookmarks) that is diffed
   against the committed golden in `tools/banktest/expected/<name>.dump` (31 goldens today).

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

### Chunks (partitioning — `grm-32f.2`)

For the dev loop, run only the chunk(s) relevant to your change; the **full suite still gates
final acceptance and commits**. `build-and-test.sh --list-chunks` prints the current set:

| Chunk | Covers |
|---|---|
| `c64-banking` | C64 `banktest`–`banktest4` fixtures |
| `c64-loader` | C64 PRG placement/wrapping, ROM loading, symbol toggles |
| `c64-recovery` | C64 emulation and decrypt/recovery fixtures |
| `basic-petscii` | C64 BASIC headless fixture + the JUnit `test` suite |
| `basic-dialects` | PET BASIC 4 / C128 BASIC 7 token dialects + C64 BASIC 2 regression |
| `pet-loader` | PET 4032 descriptor, PRG placement, IO types, fixed ROM slots |
| `c128-loader` | C128 native BASIC PRG placement, fixed ROM slots, MMU IO |
| `nes-banking` | NES banking and MMC fixtures |
| `petscii-strings` | `PetsciiStringAnalyzer` C64 PRG fixture + the JUnit `test` suite |
| `bit-algebra` | the JUnit `test` suite only (no extension build/install needed alone) |
| `all` | every chunk (the default when no chunk is given) |

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
GHIDRA_INSTALL_DIR=D:/ghidra_<ver>_PUBLIC gradle test
```

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

As of `grm-32f.4` the `test` suite **is run by `build-and-test.sh`** (in place of the retired
`verify*` `JavaExec` tasks): the full `all` gate runs it, as do the `basic-petscii`,
`basic-dialects`, `petscii-strings`, and `bit-algebra` chunks. It stays **out of
`buildExtension`'s `dependsOn`** — `buildExtension` is packaging-only and the gate invokes
`test` explicitly. The task is still monolithic (it runs the whole `src/test/java` suite
wherever invoked); making test selection **per-chunk** (so, e.g., `nes-banking` runs only the
relevant tests) is tracked as `grm-32f.5`. Tier 3 remains the acceptance authority; the JUnit
suite is an additional gate, not a replacement.

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
