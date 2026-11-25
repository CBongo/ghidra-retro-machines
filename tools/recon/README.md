# tools/recon -- ROM recon scripts (kept, not throwaway)

Hand-reverse-engineering aids for pinned NES ROMs and the wider ROM corpus. They are
**recon**: byte-level and linear-decode heuristics that produce leads for a human or a pyghidra-mcp
walk, never classifications to bless. Every script's docstring lists its false-negative limits
(no NMI-vs-main-loop placement, no indirect jumps, helper entries guessed by walking back to
RTS/JMP, byte-pattern writer counts include data coincidences).

All of them share one 6502 decode table: `tools/banktest/dis6502.py`, via `rom6502.py` here.
Run with `python -I tools/recon/<script>.py` from the repo root. ROM paths come from arguments, or
`--find <row-id>` (a pinned manifest row, resolved from `$GRM_ROM_DIR` by `tools/banktest/romlib.py`, like `dis6502.py --find`).
For a plain disassembly use `tools/banktest/dis6502.py`.

| Tool | Bead | What it does |
|---|---|---|
| `reqscan.py` | grm-5tl.20.2 | Corpus scan (`.nes` dirs or `--rom-dir`): finds mapper-register store helpers in the fixed bank, their call-site argument kinds and the writers of the RAM cells they read. Writes a JSON (an output, do not commit). |
| `reqrank.py` | grm-5tl.20.2 | Rankings over that JSON: `adj`, `callargs`, `readclear`, `asrc` modes ("which titles request a bank in RAM and fulfil it later"). |
| `cellxref.py` | grm-5tl.20.1, .20.2 | `--grep CELL` readers+writers with context, `--writers CELL` writers only, `--summary CELL` writers grouped by the source of the stored value with the next call after each (the class A vs D test in `docs/bank-source-idioms.md`), `--calls ADDR` JSR sites, across every bank of one ROM. |
| `bankdiff.py` | grm-5tl.20.1 | For fixed-bank calls into the switchable window: is the callee identical / different / not code in each bank (direct-flow closure); per-bank dispatch targets with `--detail`; `--reach` checks raw call patterns the linear sweep missed. Fixed-last-16K layouts. |
| `inlinejtscan.py` | grm-gipk.26 | Byte-shape scan for JSR-inline-jump-table dispatchers (double indirect load, low byte parked in a ZP cell / on the stack / in X), the three variants `InlineJumpTableDispatch` accepts. `<rom.nes>` or `--row <row-id>`. |
| `twolevelscan.py` | grm-gipk.23 | Byte-shape scan for the two-level zero-page pointer dispatch ending in `JMP (zp)` (cv3 bank 20). `--all-rows`, `--find <row-id>` or ROM paths. |
| `romscan.py` | grm-2a2a.8 | General byte-pattern scanner: hex bytes, `??`, `[a9\|b0-b7]`, `{name}` captures (reused name = same byte), `*N` gaps; over pinned rows (`--row`, `--set`), `--corpus` (every image in the dirs) or `--file`. Prints row, PRG offset, bank, CPU address, captures; `--dis N`, `--count`. NES first; SNES is raw offsets. Replaces per-bead scratch scanners. |
| `popretscan.py` | grm-ed6h | Survey of 6502 pop-return helpers (`PLA/PLA/RTS`, a routine that returns to its caller's caller, so a JSR to it does not fall through); hits classed `pure`/`cond`/`uses`. |
| `offset_label_classify.py` | grm-hf5h.11 | Classifies switch sites that still print byte-offset labels by where the index comes from (stride, back-chain evidence). Inputs: a `SwitchLabelCensus` log dir and `IndexBackChainProbe` output. |
| `param_return_census.py` | grm-etbh | Aggregates `ParamReturnCensusProbe` `.prc` files into a per-platform table of callee, caller and confirmed parameter/return evidence (`--md` for Markdown). |
| `w65816_stack_wrap_census.py` | grm-9nxj.44 | Counts 65816 SingleStepTests vector cases whose native-mode stack access wraps at the 16-bit S boundary (default `$GRM_W65816_VECTORS/v1`). |
| `rom6502.py` | both | Shared helpers (decode, chain-back, formatting; re-exports `parse_ines`/`cpu_of`/`find_rom` from `tools/banktest/romlib.py`); not a CLI. |

Worked example (Metroid, mapper 1):

```bash
python -I tools/recon/cellxref.py --find metroid_u --grep 24          # writers of the request cell $24
python -I tools/recon/bankdiff.py --find metroid_u --noreturn c27c,8024 --sumbanks 1-5
python -I tools/recon/reqscan.py scan.json --rom-dir --only Metroid   # then: reqrank.py asrc scan.json
```
