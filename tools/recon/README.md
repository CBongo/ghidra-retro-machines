# tools/recon -- ROM recon scripts (kept, not throwaway)

Hand-reverse-engineering aids for pinned NES ROMs and the wider ROM corpus. They are
**recon**: byte-level and linear-decode heuristics that produce leads for a human or a pyghidra-mcp
walk, never classifications to bless. Every script's docstring lists its false-negative limits
(no NMI-vs-main-loop placement, no indirect jumps, helper entries guessed by walking back to
RTS/JMP, byte-pattern writer counts include data coincidences).

All of them share one 6502 decode table: `tools/banktest/dis6502.py`, via `rom6502.py` here.
Run with `python -I tools/recon/<script>.py` from the repo root. ROM paths come from arguments, or
`--find <row-id>` (a pinned manifest row, resolved from `$GRM_ROM_DIR` like `dis6502.py --find`).
For a plain disassembly use `tools/banktest/dis6502.py`.

| Tool | Bead | What it does |
|---|---|---|
| `reqscan.py` | grm-5tl.20.2 | Corpus scan (`.nes` dirs or `--rom-dir`): finds mapper-register store helpers in the fixed bank, their call-site argument kinds and the writers of the RAM cells they read. Writes a JSON (an output, do not commit). |
| `reqrank.py` | grm-5tl.20.2 | Rankings over that JSON: `adj`, `callargs`, `readclear`, `asrc` modes ("which titles request a bank in RAM and fulfil it later"). |
| `cellxref.py` | grm-5tl.20.1, .20.2 | `--grep CELL` readers+writers with context, `--writers CELL` writers only, `--summary CELL` writers grouped by the source of the stored value with the next call after each (the class A vs D test in `docs/bank-source-idioms.md`), `--calls ADDR` JSR sites, across every bank of one ROM. |
| `bankdiff.py` | grm-5tl.20.1 | For fixed-bank calls into the switchable window: is the callee identical / different / not code in each bank (direct-flow closure); per-bank dispatch targets with `--detail`; `--reach` checks raw call patterns the linear sweep missed. Fixed-last-16K layouts. |
| `rom6502.py` | both | Shared helpers (iNES parse, decode, chain-back, formatting); not a CLI. |

Worked example (Metroid, mapper 1):

```bash
python -I tools/recon/cellxref.py --find metroid_u --grep 24          # writers of the request cell $24
python -I tools/recon/bankdiff.py --find metroid_u --noreturn c27c,8024 --sumbanks 1-5
python -I tools/recon/reqscan.py scan.json --rom-dir --only Metroid   # then: reqrank.py asrc scan.json
```
