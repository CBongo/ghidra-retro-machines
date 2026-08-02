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
   against the committed golden in `tools/banktest/expected/<name>.dump` (38 goldens today).

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

> **Candidate cache (`grm-lne`).** A `check` run stashes each freshly imported dump in a
> content-addressed cache under `build/` (gitignored), and a following `bless` reuses it
> instead of re-running the expensive `analyzeHeadless` import — so the normal
> review-then-bless loop imports once, not twice (biggest win on the ~1min+ real-ROM tier).
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
| `c128-loader` | C128 native BASIC PRG placement, fixed ROM slots, MMU IO |
| `nes-banking` | NES banking and MMC fixtures |
| `petscii-strings` | `PetsciiStringAnalyzer` C64 PRG fixture |
| `unit` | the JUnit `gradle test` suite (all `src/test/java`; no extension build/install needed alone) |
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

## Optional real-ROM tier (`grm-zai`, hash-pinned)

Tiers 1–3 use synthetic inputs so the whole gate ships in-repo. The **real-ROM tier** is a
separate, opt-in regression net that runs the shipped NES board descriptors against *actual
commercial cartridges* — the fidelity check synthetic fixtures can't give (real games pass
bank numbers through tables/helpers, hit ~191 overlays, etc.). It is **not** part of the
default gate: ROM binaries are copyrighted and user-supplied, so nothing here runs in CI and
it is never a `run-banktest.sh` chunk (whose `all` would otherwise pull it in).

- **Driver:** `tools/banktest/realrom-test.sh check|bless|nominate [--gme|--all]
  [--only|--except <ids>] <romdir> [<romdir> …]` (or `GRM_ROM_DIR`). Lives alongside
  `measure-overlay-scale.sh` and reuses the same `build/ghidra-home` isolation, so run
  `build-and-test.sh check nes-banking` once first.
- **Two row sets, selected not accumulated.** `realrom/manifest.tsv` is the curated minimum
  (one representative title per shipped board) and is the default; `realrom/manifest-gme.tsv`
  is an expanded reference set of titles of interest to the parent game-music-extraction
  project, chosen by `--gme`; `--all` runs both. The flags *select*, because `--gme` also
  re-blessing the curated twelve is a costly surprise. The expanded set is deliberately not a
  gate: a reference point for planning and an occasional thorough check, since each row costs
  a ~1min+ headless import. Ids must be unique across both files — checked repo-wide
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
  one that earns its keep: this tier's recurring shape is *one title deliberately held back at
  a pre-regression golden while every other title needs re-blessing* — `megaman` has been that
  title twice (grm-g73, then grm-hum), and blessing it would erase the record the bead depends
  on. An id not in the manifest is a hard **error**, never a silent no-op, because a typo in
  `--except megman` must not bless megaman. Filtered rows are reported as `filtered=N`, not as
  `SKIP` — `SKIP` means the ROM was absent, which is a different fact.
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
