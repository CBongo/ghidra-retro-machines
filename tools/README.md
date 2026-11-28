# tools/ index

**Look here before writing a script.** One line per tool; the detail lives in the tool's own
header or in the README named at the end of each group. Run Python as `python -I tools/<path>`
and shell scripts from git bash, both from the repo root. ROM locations come from the
environment (`GRM_ROM_DIR`, `GRM_SNES_ROM_DIR`, `GRM_C64_ROM_DIR`, `GRM_SPC_SNAP_DIR`), never
hardcoded.

## I want to know... -> use

| Question | Tool |
|---|---|
| What is at address X: owning function, comment, refs in and out, what flow disassembled it | `banktest/SiteStateProbe.java` (`GRM_SITES`); on a kept project, pyghidra-mcp (`ghidra-mcp/`) |
| Every symbol and namespace at a site | `banktest/SymbolNamespaceProbe.java` |
| How did disassembly reach a site (was it only a phantom seed?) | `banktest/ReachProbe.java` |
| Why did a bank switch not resolve: store never seen, call unresolved, or nobody consumes it | `banktest/BankReachProbe.java`, `HelperShapeProbe.java`, `BankConsumerProbe.java` |
| Which references land in a different bank than the locally proven one | `banktest/BankContextProbe.java` |
| Which computed jumps have no recovered table, and what are the targets | `banktest/JumpTableProbe.java`, `DispatchTargetProbe.java` |
| Switch-label kinds and counts across a run; diff two decompiler builds | `banktest/SwitchLabelCensus.java`, then `banktest/slc-summary.py` |
| Which offset-label switch sites get their index from where | `recon/offset_label_classify.py` (with `banktest/IndexBackChainProbe.java`) |
| Parameter and return census (A/X/Y/carry/ZP in and out) | `banktest/ParamReturnCensusProbe.java`, then `recon/param_return_census.py` |
| Which functions got an inferred signature, per row | `banktest/ParamReturnCommitCount.java` |
| Review a real-ROM golden diff: counts vs cap slide vs real change, one verdict | `banktest/dumpdiff.py <golden\|row-id> <new.dump>` (`--commit REV <row>` for a past bless) |
| Where did a gate's time go: per-program import/analysis/script, top analyzers | `banktest/headless-phase-times.py --since 'YYYY-MM-DD HH:MM:SS' --analyzers N` |
| Which of OUR methods is a slow row's CPU going to (JFR profile of one import) | `banktest/jfr-hot-frames.py <rec>.jfr --callers K` (recipe in its docstring) |
| Compare two builds, commits or toolchains on real ROMs | `banktest/ab-test.sh`; per-address diffs via `InstructionListDump`, `FunctionListDump`, `CallSiteListDump` |
| Which analyzer created, changed or removed a code unit or function | `banktest/CodeUnitWatchProbe.java`, `FunctionWatchProbe.java` (prescripts) |
| Does auto-analysis settle, or loop forever in the GUI (an analyzer re-queuing itself) | `banktest/ReanalysisFixpointProbe.java` (postscript; replays the GUI's event-driven re-analysis) |
| Set a boolean or enum analyzer option for a report-only A/B (e.g. stock behaviour as the before side) | `banktest/SetAnalyzerOption.java` (prescript) |
| Where is a pinned row's ROM image; decode its bytes | `banktest/dis6502.py --find <row-id>`, or `dis6502.py <rom> <map> <start> <end>` |
| Where does this byte pattern occur (wildcards, captures) across the ROM corpus | `recon/romscan.py` |
| Bytes, disassembly or a jump table at a golden/bead block name (`PRG_LO_B5:a734`, `W8000_M3_B31::8000`), no hand file-offset math | `banktest/dis6502.py <row-id> <block>:<addr> [-n N \| --bytes N \| --words N \| --jumptable N [--split HI] [--plus1]]`; `<row-id> --blocks` lists the row's windows (NES; mapping in `banktest/blockmap.py`, needs PyYAML) |
| Who reads or writes a RAM cell, who calls a routine | `recon/cellxref.py` |
| Is a fixed-bank call target the same code in every switchable bank | `recon/bankdiff.py` |
| Why is a function flagged no-return | `banktest/NoReturnProbe.java`, `NoReturnEvidenceProbe.java`, `NoReturnFlagCensus.java` |
| Does the decompiler complete a function; what does it print | `banktest/DecompileSiteProbe.java`, `DecompileDump.java` |
| Which `decompile.exe` did Ghidra actually launch | `banktest/WhichDecompiler.java` |
| Can routine A reach B through direct flow (static, on a kept project) | `ghidra-mcp/closure6502.py` |
| Is a bistable golden flipping, and where | `banktest/DeterminismProbe.java` |
| 65816 direct-page, data-bank, decimal-mode or width questions | `banktest/DpCensusProbe.java`, `DpLossProbe.java`, `DbrCensusProbe.java`, `DecimalCensusProbe.java`, `W65816WidthDump.java` |
| Run one postScript across the whole SNES collection | `banktest/snes-rom-sweep.sh` (list from `snes-sweep-list.py`) |
| Draft an upstream issue or PR from a bead | `upstream-draft.py <bead>` |

## Gates and runners (tools/banktest/)

Real-ROM tier detail: `banktest/realrom/README.md`; testing strategy: `docs/testing.md`.

- `build-and-test.sh` - the acceptance gate: build, stage, run every headless fixture chunk plus
  JUnit (`check|bless [chunk...]`, `--list-chunks`).
- `run-banktest.sh` - synthetic-fixture runner (goldens in `expected/`); builds by default,
  `--no-build` to skip.
- `realrom-test.sh` - hash-pinned real-ROM tier (`check|bless|coverage|ids [SET...]`); rows,
  sets and platforms are the `realrom/*.tsv` tables.
- `dumpdiff.py` - classifies a real-ROM dump diff for bless review (count movement, sample-window
  cap slide, real content change, one verdict); grm-2a2a.12.
- `headless-phase-times.py` - per-program phase times (import/analysis/postScript/save) and
  Ghidra's per-analyzer times, from the isolated install's timestamped application.log; works
  for any runner after the fact; grm-949h.
- `jfr-hot-frames.py` - charges each JFR CPU sample to the first project frame on its stack
  (Ghidra's leaf frames say nothing about which analyzer drove them); grm-949h.1.
- `ab-test.sh` - real-ROM A/B of two commits or toolchains, one worktree per side, dump-vs-dump
  diff.
- `snes-rom-sweep.sh` - run ONE postScript over the SNES collection (survey aid, no golden);
  list from `snes-sweep-list.py`.
- `measure-overlay-scale.sh` - MMC3 overlay-scale measurement for `OverlayScaleMeasure.java`
  (does NOT build).
- `clean.sh` - bound or reset banktest scratch under `build/` (never touches
  `build/ghidra-home`).
- `lib/common.sh` - shared shell helpers for every runner (source it; do not copy from it).
  `lib/bless-record.awk` formats bless records; `lib/kill-headless.ps1` is the timeout
  watchdog's killer.
- `mk*test.py` and `bankgen.py` - synthetic fixture generators for the `run-banktest.sh`
  chunks; `bankgen.py` holds the shared helpers (iNES header writer etc.).
- `Verify*.java`, `Assert*.java`, `Seed*.java`, `Set*.java` - fixture criteria and pre/post
  scripts used by `run-banktest.sh`.
- `*RealRomDump.java`, `RealRomDumpSupport.java`, `ExtractContainerMember.java`,
  `SweepStamp.java` - per-platform dump scripts the real-ROM tier runs.

## Probes (read-only postScripts in tools/banktest/)

Run with `REALROM_EXTRA_POSTSCRIPT=<Name>.java bash tools/banktest/realrom-test.sh check <set>
--only <id>`. Inputs and what each answers are the "Narrow probes" table in
`banktest/realrom/README.md`. Shared helpers: `ProbeSupport.java`.

- Site and flow: `SiteStateProbe`, `ReachProbe`, `DispatchTargetProbe`, `JumpTableProbe`,
  `FlowOverrideProbe`, `RefsIntoRangeProbe`, `RetargetedRefProbe`, `IndexBackChainProbe`,
  `SymbolNamespaceProbe`.
- Watchers (prescript): `CodeUnitWatchProbe` (which analyzer changed a code unit),
  `FunctionWatchProbe` (which analyzer created, removed or resized a function).
- GUI re-analysis fixpoint: `ReanalysisFixpointProbe` (postscript).
- Bank analysis: `BankContextProbe`, `BankConsumerProbe`, `BankReachProbe`, `HelperShapeProbe`,
  `MapperWriteCensus`, `CopyEvidenceProbe`, `WindowCallCoverageProbe`, `BaseSpaceCensus`,
  `PlausibilityCensus`.
- No-return: `NoReturnProbe`, `NoReturnEvidenceProbe`, `NoReturnFlagCensus`,
  `DispatchRepairProbe`.
- 65816: `DpCensusProbe`, `DpLossProbe`, `DbrCensusProbe`, `DecimalCensusProbe`,
  `W65816ConflictProbe`, `W65816TableDump`, `W65816WidthDump`, `RtiTargetProbe`.
- Decompiler: `DecompileSiteProbe` (also writes debug XML), `DecompileDump`,
  `SwitchLabelCensus`, `WhichDecompiler`.
- Listings and diffing: `InstructionListDump`, `FunctionListDump`, `CallSiteListDump`,
  `InstructionCensus`, `ProgramInfoDump`, `DeterminismProbe`, `RtsTrickProbe`,
  `ParamReturnCensusProbe`.
- Summarizers for probe output: `banktest/slc-summary.py` (SwitchLabelCensus),
  `banktest/rtsp-summary.py` (RtsTrickProbe sweep), `recon/param_return_census.py`
  (ParamReturnCensusProbe).

## Recon (tools/recon/; byte-level surveys, leads not verdicts)

Detail and worked examples: `recon/README.md`.

- `rom6502.py` - shared 6502 decode (uses dis6502's table); re-exports `parse_ines`/`cpu_of` from
  `banktest/romlib.py`; not a CLI.
- `reqscan.py`, `reqrank.py` - corpus scan and ranking for request/fulfil bank switching.
- `cellxref.py` - who reads or writes a RAM cell, who calls a routine, across all PRG banks.
- `bankdiff.py` - is a fixed-bank call target the same code in every switchable bank?
- `inlinejtscan.py`, `twolevelscan.py`, `popretscan.py` - byte-shape scans: inline jump tables,
  two-level ZP pointer dispatch, pop-return helpers.
- `offset_label_classify.py` - classify offset-label switch sites by where the index comes from.
- `param_return_census.py` - per-platform table from `ParamReturnCensusProbe` output.
- `indexed_data_range_census.py` - census of `IndexedDataRangeProbe` output: which evidence
  (guard / loop / family) proves an indexed data read's range (`grm-9nxj.41.1`).
- `w65816_stack_wrap_census.py` - 65816 vector cases that wrap the 16-bit S in native mode.

## Decoders and vector harnesses

- `banktest/dis6502.py` - THE 6502 disassembler and opcode table; `--find <row-id>` resolves a
  pinned ROM; `<row-id> <block>:<addr>` reads by the loader's block name (grm-2a2a.5, rules in
  `banktest/blockmap.py`, one resolver per platform in `RESOLVERS`, NES only so far). Import it,
  do not write another.
- `banktest/romlib.py` - THE manifest reader and ROM locator (`rom_dirs`, `manifest_rows`,
  `find_path`/`find_many`/`find_sha`, `parse_ines`, `cpu_of`); import it, do not re-split
  `GRM_ROM_DIR` or re-parse `manifest*.tsv`. Not a CLI.
- `vectors/sample-vectors.py --cpu {mos6502,w65816,spc700}` - vendor a sample of the SingleStepTests
  suites (consumed by JUnit). `spc700/extract-upload-blocks.py` - SPC700 upload stream from a
  SNES ROM.
- No 65816 or SPC700 disassembler lives in tools/: use the Ghidra listing (probes) or
  pyghidra-mcp.
- `upstream/W65C02ZpVectorProbe.java` - runs SingleStepTests/65x02 vector files through a
  Ghidra CHECKOUT's own 6502/65C02 language (for stock-vs-patched numbers on an upstream
  language PR); copied into the checkout untracked, never committed there (`grm-0xl1`).

## Static queries on a kept real-ROM project (tools/ghidra-mcp/)

Detail: `ghidra-mcp/README.md`.

- `serve.sh` - start or stop a pyghidra-mcp server for one row; `query.py` - call one MCP tool;
  `closure6502.py` - direct-flow reachability closure.

## Decompiler build and experiments (tools/decompiler/)

- `build.sh` - MinGW `decompile.exe` build (git bash). `apply75ey.py` - base patch set.
  `apply-hf5h11.py`, `apply-hf5h11-c13.py`, `apply-hf5h20.py`, `apply-hf5h21.py` - stacked
  candidate patches. `apply-hf5h31.py` and `apply-9nxj44.py` - experimental, not installed.
- `debugxml-replay.py`, `debugxml-dispatch.py`, `trialnorm-census-replay.py`,
  `sinc-adcsbc-binary-only.py`, `heritage_trace.py` - decomp_dbg replay and diagnostics.
- `wsl-datatests.sh` (WSL only) - decompiler datatests; `memwatch.ps1` - memory watchdog for
  experimental builds; `banktest/mkshadow.ps1` - junction-shadow install for decompiler A/B.

## GUI install and machine setup (PowerShell; agents never run install-gui.ps1)

- `install-gui.ps1` - install the extension into the user's GUI Ghidra.
- `upgrade-bd.ps1` - pinned bd CLI upgrade.

## Misc

- `gdtbuilder/` - GDT/PETSCII/screencode compiler sources built by gradle.
- `gensymbols/gen_c64ref_symbols.py` - c64ref to symbol YAML.
- `forth/forthhex2desc.py` - ACS Forth tables to `machines/games/acs.yaml`.
- `upstream-draft.py <bead>` - paste-ready upstream draft from a bead.
