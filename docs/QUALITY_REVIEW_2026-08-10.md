# Project quality review — 2026-08-10

## Executive summary

The project has a strong quality baseline: its descriptor build pipeline is intentionally
separated from the shipped extension, the banking algorithms contain unusually good invariant
comments, and 312 JUnit tests plus 48 synthetic golden dumps exercise the system at several
levels. The main quality risk is not a lack of tests; it is contract drift across boundaries:
compiler versus runtime validation, 16 KiB file-format units versus 8 KiB mapper units, and test
harness criteria versus golden-file mutation.

This review found no P0 issue. The four P1 findings should be fixed before relying on the affected
placement/recovery paths or blessing changed goldens. The P2 findings are bounded hardening or
maintainability work. Existing Beads issues are called out separately and were not duplicated.

## Review contract

- Scope: production Java, descriptor compiler/runtime boundary, loaders and bank analysis,
  recovery/materialization, JUnit and end-to-end tests, build/release tooling, and primary docs.
- Method: independent read-only reviews of correctness, architecture, and test/tooling, followed
  by orchestrator verification against the cited code.
- Severity:
  - **P0** — data loss, security compromise, or broadly unusable release.
  - **P1** — wrong user-visible results or corruption of the acceptance baseline in a supported
    path; address before the next related release.
  - **P2** — meaningful latent correctness, reliability, or maintenance risk.
  - **P3** — documentation, ergonomics, or longer-horizon design debt.
- Repository state at review start: clean `main`, equal to `origin/main`, at `4af9bfe`.
- No production or test code was changed by this review.

## Finding index

| ID | Bead | Priority | Area | Summary |
|---|---|---:|---|---|
| QR-01 | `grm-aqi` | P1 | Test harness | `bless` overwrites a golden even when fixture criteria fail |
| QR-02 | `grm-n5f` | P1 | NES loader | Placement validation uses 16 KiB units for 8 KiB mapper banks |
| QR-03 | `grm-v6o` | P1 | Bank analysis | Partially-known bank values wrongly defeat an explicit override |
| QR-04 | `grm-0p7` | P1 | Recovery | Offset-only recovery names collide across overlay spaces |
| QR-05 | `grm-p7i` | P2 | Descriptor pipeline | Compiler accepts layouts that runtime silently discards |
| QR-06 | `grm-7j5` | P2 | NES registry | Duplicate mapper ownership is order-dependent |
| QR-07 | `grm-w3m` | P2 | Analyzer lifecycle | Count-only cache fingerprint can miss same-count code changes |
| QR-08 | `grm-sf6` | P2 | Descriptor pipeline | Strategy names and general address ranges are under-validated |
| QR-09 | `grm-z34` | P2 | Tooling | Harness writes are not fail-closed or atomic |
| QR-10 | `grm-e7w` | P2 | Build/release | Acceptance gate is neither repository-reproducible nor CI-enforced |
| QR-11 | `grm-vid` | P3 | Documentation | Testing, support, and map-format docs have drifted from reality |
| QR-12 | `grm-ft8` | P3 | Maintainability | Core orchestration classes have accumulated too many responsibilities |

## Detailed findings

### QR-01 — P1 — Never bless a failing candidate

**Bead:** `grm-aqi`

**Evidence**

- `tools/banktest/run-banktest.sh:311-314` records a missing `SUITE PASS` but continues.
- `tools/banktest/run-banktest.sh:325-328` then copies the dump into `expected/` unconditionally.
- The cache-hit path copies first at `tools/banktest/run-banktest.sh:256` and checks the cached
  criteria only afterward at lines 258-260.
- This conflicts with the acceptance contract in `docs/testing.md:55-66`.

**Impact**

`build-and-test.sh bless ...` can replace a known-good committed golden with output whose explicit
criteria failed. The command eventually exits nonzero, but the destructive baseline change has
already happened and can be committed accidentally.

**Implementation guidance**

1. Parse and validate the complete candidate before caching or blessing it.
2. Require a complete dump, exactly one terminal suite verdict, and `SUITE PASS`.
3. Apply the same validation to cached candidates before showing a diff or copying.
4. Write to a temporary sibling and atomically rename only after all checks pass.

**Acceptance checks**

- A stub candidate containing `SUITE FAIL` returns nonzero and leaves the golden byte-identical.
- A failed cached candidate is rejected without touching the golden.
- A passing candidate still supports the documented check/review/bless flow.

### QR-02 — P1 — Validate placement banks in each window's units

**Bead:** `grm-n5f`

**Evidence**

- `src/main/java/retromachines/NesRomLoader.java:307-318` compares every placement bank with
  `header.prgBanks()`, whose diagnostic explicitly describes 16 KiB banks.
- Mode-dependent mapper windows are evaluated from descriptor expressions and their own lengths at
  `NesRomLoader.java:700-735`. MMC3 PRG windows are 8 KiB.

**Impact**

A valid 32 KiB MMC3 image has four 8 KiB PRG banks but only two iNES 16 KiB units. Overrides that
name bank 2 or 3 are therefore rejected even though the loader can realize those banks. The
advertised placement escape hatch fails on valid input.

**Implementation guidance**

Derive the legal bank set per named window from its compiled `maps` expression, window length,
layout mode, state-field width, and actual PRG byte size. Validate each `window:bank` pair against
that set rather than a global header count.

**Acceptance checks**

- A 32 KiB MMC3 fixture accepts valid 8 KiB banks 0-3 and rejects bank 4.
- Existing UxROM/CNROM placement validation remains correct for their units.
- GUI `validateOptions` and the headless `load` safety check share the same result.

### QR-03 — P1 — Require full bank-field knowledge before ignoring an override

**Bead:** `grm-v6o`

**Evidence**

- `src/main/java/retromachines/BoardBankAnalyzer.java:3647-3658` says the override applies when
  dataflow did not pin the switchable bank.
- Line 3652 currently treats the field as known when **any** field bit is known:
  `(knownMask & positionedMask) != 0`.
- `valueIn(effective)` consequently fills remaining unknown bits from the initial state before an
  overlay reference is selected.

**Impact**

For multi-bit MMC1/MMC3 bank fields, one recovered bit suppresses an explicit user placement and
can create a confident reference into the wrong overlay bank.

**Implementation guidance**

Use full-mask containment:
`(knownMask & fieldMask) == fieldMask`. Keep the existing rule that complete flow information wins
over the override, and annotate provenance only when the override actually supplies the bank.

**Acceptance checks**

- A fixture with only one known bit of `r6`, `r7`, or `prg_bank` uses the override.
- A fully known field continues to override the user value with dataflow.
- A fully unknown field and no override retains the existing conservative fallback/diagnostic.

### QR-04 — P1 — Make recovery identity address-space aware

**Bead:** `grm-0p7`

**Evidence**

- `src/main/java/retromachines/TransferMaterializer.java:143-145` names and deduplicates a recovered
  block only as `COPY_<offset>`.
- `src/main/java/retromachines/C64DecryptLoopAnalyzer.java:253-258` does the same with
  `DECRYPTED_<offset>`.
- Ghidra overlay spaces legitimately contain different bytes at the same CPU offset.

**Impact**

After materializing a target at a given offset in one overlay space, a distinct transfer or
decrypt target at the same offset in another bank is silently skipped as “already recovered.”

**Implementation guidance**

Make the idempotence key explicit and space-aware, preferably `(destination space, range,
source/specification)` rather than relying only on a display name. Include a sanitized space token
in generated block names, while preserving stable reruns for the same recovery.

**Acceptance checks**

- Two overlay spaces with the same destination offset both materialize distinct bytes.
- Re-running the same specification remains idempotent.
- Names are deterministic and legal Ghidra block/space names.

### QR-05 — P2 — Enforce the runtime layout contract in MapCompiler

**Bead:** `grm-p7i`

**Evidence**

- `tools/gdtbuilder/src/main/java/gdtbuilder/MapCompiler.java:607-639` accepts every nonempty
  `when` map whose keys name state fields.
- `src/main/java/retromachines/DescriptorSupport.java:936-956` requires exactly one common field
  and unique values; otherwise it logs and discards all layouts.

**Impact**

A descriptor can compile and ship successfully but lose all intended mode-dependent windows at
runtime. This is a latent descriptor-authoring trap rather than a defect in current MMC maps.

**Implementation guidance**

At compile time require one `when` key per layout, the same mode field in all layouts, unique mode
values, and values fitting the declared field width. Consolidate normalization so compiler and
runtime cannot acquire separate contracts again.

**Acceptance checks**

- Multi-key, mixed-key, duplicate-value, and out-of-width fixtures fail compilation with the
  descriptor context in the message.
- Every successfully compiled layout is accepted by `DescriptorSupport.planWindows`.
- All shipped descriptors compile unchanged.

### QR-06 — P2 — Make mapper ownership unique and deterministic

**Bead:** `grm-7j5`

**Evidence**

- `src/main/java/retromachines/NesBoardRegistry.java:62-67` returns the first claiming board.
- Boards come from an unsorted resource scan at lines 81-109.
- Per-file build tasks at `build.gradle:307-353` have no collection-level duplicate mapper or board
  ID validation.

**Impact**

A future conflicting descriptor makes the loader's default hardware model depend on resource
enumeration order. Current shipped descriptors do not contain a duplicate claim.

**Implementation guidance**

Add a descriptor-registry validation task that builds `mapper -> descriptor` and `id -> descriptor`
maps and fails on duplicates, including duplicates inside one descriptor. Sort runtime registry
results as defense in depth and report a runtime conflict prominently rather than choosing first.

**Acceptance checks**

- Conflicting descriptors fail the build and name both files and IDs.
- Duplicate entries within one `ines_mappers` list fail.
- Every shipped mapper resolves to exactly one board in deterministic order.

### QR-07 — P2 — Replace the count-only analyzer cache fingerprint

**Bead:** `grm-w3m`

**Evidence**

- `src/main/java/retromachines/BoardBankAnalyzer.java:157-160` packs only the function count and
  instruction count.
- Lines 217-226 skip a whole-program rerun when those counts and map path match.
- The comment at lines 130-146 assumes relevant changes always move a count, but replacing,
  relocating, or retyping code/functions can preserve both counts.

**Impact**

Within the same open Program, a same-count edit can leave bank annotations and overlay references
stale because the analyzer reports a redundant rerun and skips analysis.

**Implementation guidance**

Prefer a lifecycle signal tied to Ghidra's modification/change events or a robust content/version
stamp over scanning the whole Program. If no reliable stamp is available, remove the skip cache
before relying on a count-only surrogate. Keep the separate entry/exit fixpoint test for detecting
the analyzer's own structural additions.

**Acceptance checks**

- A Program fixture changes instruction bytes or a function entry while preserving both counts;
  the next invocation runs and updates its result.
- A truly unchanged redundant invocation can still be skipped if a sound signal exists.
- Cancellation never records a completed stamp.

### QR-08 — P2 — Close descriptor validation gaps

**Bead:** `grm-sf6`

**Evidence**

- `MapCompiler.java:823-855` accepts any mechanism strategy spelling. Runtime logs and skips an
  unknown strategy at `BoardBankAnalyzer.java:464-489`.
- Ordinary regions merely copy `start`/`end` at `MapCompiler.java:222-265`; windows copy or derive
  them at lines 504-524 without checking inverse, zero, negative, or overflowed ranges.
- The more recent `copied_from` path already performs the expected containment/range checks at
  lines 318-336.

**Impact**

Typos and invalid geometry can survive the build and become disabled banking, partial imports, or
weaker loader-time diagnostics.

**Implementation guidance**

1. Validate strategy names against an explicit vocabulary. Preserve documented deferred names only
   with intentional, tested behavior.
2. Centralize range/size validation and apply it to regions, windows, subregions, physical sizes,
   and layout windows, including addition overflow and applicable address-space bounds.

**Acceptance checks**

- An unknown strategy fails compilation; every documented strategy is implemented or explicitly
  marked deferred.
- Inverse ranges, zero/negative sizes, overflow, and out-of-owner subregions fail with context.
- Current descriptors compile unchanged.

### QR-09 — P2 — Make harness writes fail closed and atomic

**Bead:** `grm-z34`

**Evidence**

- Major drivers use `set -u` only: `tools/banktest/run-banktest.sh:43`,
  `build-and-test.sh:33`, `realrom-test.sh:99`, and `measure-overlay-scale.sh:36`.
- State-changing operations such as `run-banktest.sh:319-328` do not check `mkdir`/`cp` before
  reporting a cached or blessed result.

**Impact**

A permission, full-disk, or interrupted write can leave a missing/partial artifact while the
harness prints success. This compounds QR-01 around the acceptance baseline.

**Implementation guidance**

Audit intentional nonzero operations (`diff`, probes, optional `grep`) and then either enable
`set -euo pipefail` with explicit guards or check every state-changing command. Use temporary
sibling files and atomic rename for goldens, cache entries, and install stamps.

**Acceptance checks**

- A read-only expected directory or injected failing copy returns nonzero and never prints
  `blessed`.
- An interrupted write cannot leave a truncated golden at the final path.
- Expected nonzero `diff` and probe paths retain their documented behavior.

### QR-10 — P2 — Make the acceptance contract reproducible and enforceable

**Bead:** `grm-e7w`

**Evidence**

- The repository has no Gradle wrapper, dependency lockfile, or Gradle verification metadata.
- `tools/banktest/build-and-test.sh:147` defaults to machine-specific
  `/d/gradle-8.13/bin/gradle`; this review's first two gate attempts failed before compilation until
  Git Bash and the installed Gradle executable were pinned explicitly.
- `build.gradle:123-132,250,272-274` resolves build/test dependencies from Maven Central.
- No tracked CI workflow enforces the acceptance gate described by `docs/testing.md:16,146-156`.

**Impact**

A clean contributor or CI machine cannot reproduce the build from repository metadata alone, and
merges/releases can bypass the documented gate. Dependency version strings are pinned, but the
resolved toolchain and artifacts are not independently verified.

**Implementation guidance**

Commit the Gradle wrapper with distribution checksum, enable dependency locking and verification,
and make the harness prefer the wrapper. Add CI using a pinned Ghidra 12.1.2 source/install with
verified retrieval, run the full synthetic gate, and retain logs on failure. Keep copyrighted
real-ROM checks explicitly opt-in.

**Acceptance checks**

- A clean machine can run one documented command without a developer-specific path.
- Offline-cache reruns resolve exactly the locked and verified artifacts.
- Protected merge/release automation requires the synthetic acceptance gate.

### QR-11 — P3 — Repair documentation drift

**Bead:** `grm-vid`

**Evidence**

- `docs/testing.md:18-20` says JUnit is not run by the gate, while lines 146-156 say it is.
- `docs/testing.md:47` says 38 goldens; 48 `tools/banktest/expected/*.dump` files exist.
- `docs/MAP_FORMAT.md:332-338` says source-backed symbols are not implemented, while
  `MapCompiler.java:1070-1115` loads them with inline-address precedence.
- `README.md:11-23` still describes two machines and open M3 exit work despite shipping PET/C128
  descriptors, loaders, and dedicated test chunks.
- `tools/banktest/realrom-test.sh:160-163` whitespace-splits `GRM_ROM_DIR`, so the environment
  form cannot represent the space-containing paths discussed later in that same script/docs.

**Impact**

Contributors receive conflicting instructions about the gate, supported systems, generated
symbols, and ROM path configuration.

**Implementation guidance and acceptance**

Update the named docs from executable behavior, replace volatile counts with generated output or
remove “today” counts, and define an unambiguous multi-path environment format (for example a
newline-delimited `GRM_ROM_DIRS`) with a path-containing-spaces test.

### QR-12 — P3 — Split orchestration from domain logic incrementally

**Bead:** `grm-ft8`

**Evidence**

- `src/main/java/retromachines/BoardBankAnalyzer.java` is 4,303 lines and combines descriptor
  parsing, strategy discovery, dataflow, helper inference, mirror discovery, annotation,
  reference mutation, caching, and context stamping.
- `DescriptorSupport.java` is 1,177 lines across resource I/O, memory realization, expression and
  state parsing, naming, permissions, and identity hashing.
- The main golden verifier is 3,962 lines and the NES fixture generator is 2,884 lines.

**Impact**

Changes cross large coupled surfaces and tests increasingly reach internal helpers instead of a
small stable model boundary. This raises review cost even though current coverage is strong.

**Implementation guidance**

Extract without behavior changes, in this order: immutable descriptor/board model; strategy
registry/factory; dataflow engine that returns facts; Ghidra mutation/annotation adapter; focused
descriptor resource/expression/memory modules. Refactor the golden verifier and generator by
fixture family only after production boundaries stabilize.

**Acceptance checks**

- No intentional golden churn.
- Existing full gate remains green after each extraction.
- Extracted model/dataflow components have direct tests without a full analyzer invocation.

## Already-tracked issues not duplicated

- `grm-hap`: declarative PRG/map debt (inert formats, `load_target`, P6510 special case, derived
  PRG properties).
- `grm-w8a`: duplicated emulation-recovery fixture/verifier with missing criteria.
- `grm-dfj`: NES 2.0 exponent-form PRG size handling.
- `grm-o9k`: inherited ADC/RRA carry and overflow semantics.
- Known real-ROM analysis gaps and the Mega Man nondeterminism remain tracked in their existing
  Beads issues; this review does not reinterpret them as new regressions.

## Strengths worth preserving

- The build-only YAML/GDT toolchain keeps SnakeYAML out of the shipped runtime extension.
- Descriptor input tracking accounts for includes, generated sources, and builder outputs.
- Loader paths reject truncated PRG data before mapping/vector reads.
- Bank-state merges and conservative fallbacks are documented with domain-specific invariants.
- Test layering is proportionate: pure logic, Ghidra `ProgramBuilder`, synthetic headless goldens,
  and an optional hash-pinned real-ROM tier.
- The end-to-end harness isolates Ghidra state per worktree and its candidate cache keys include
  fixture, loader options, scripts, and extension content.
- Copyright and provenance are handled explicitly for ROMs, generated metadata, and vendored SLEIGH
  semantics.

## Suggested implementation order

1. QR-01, because a failing test must never rewrite its oracle.
2. QR-02 and QR-03 together, sharing an MMC3 placement regression fixture.
3. QR-04, with cross-space materialization tests.
4. QR-05, QR-06, and QR-08 as one descriptor-validation hardening series.
5. QR-07, preserving the current fixpoint behavior while replacing only invalidation logic.
6. QR-09 and QR-10 as test-infrastructure hardening.
7. QR-11, then the incremental QR-12 refactor.

Each implementation should run the narrowest relevant JUnit/chunk during development and the full
`tools/banktest/build-and-test.sh check` gate before completion. Review any golden diff before a
targeted bless; QR-01 should land before blessing unrelated behavior changes.

## Verification result

The full documented synthetic acceptance gate completed successfully on the reviewed revision:

```text
Git Bash + GRADLE=/d/gradle-8.13/bin/gradle.bat
tools/banktest/build-and-test.sh check
BUILD SUCCESSFUL
SUITE OK (check)
elapsed: 292.2 seconds
```

All generated headless dumps matched their committed goldens. The Gradle `test` task was reported
up-to-date during that run, so the unit layer was also executed afresh with
`gradle test --rerun-tasks`: all nine Gradle tasks executed and the build completed successfully in
87.4 seconds.
