---
paths:
  - "src/main/java/**"
  - "src/test/java/**"
  - "ghidra_scripts/**"
  - "build.gradle"
  - "gradle.properties"
---

# Reading Ghidra source; loader conventions

<!-- Moved verbatim from CLAUDE.md (grm-yaat). Loaded only when a file matching the paths above is read. -->

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
