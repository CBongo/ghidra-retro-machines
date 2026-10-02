---
paths:
  - "data/languages/**"
  - "src/test/java/**"
---

# Opt-in language tiers: SPC700 vectors, 6502 vectors, SPC700 .dis corpus

<!-- Moved verbatim from CLAUDE.md (grm-yaat). Loaded only when a file matching the paths above is read. -->

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

**The NMOS 6502 vector tier (`6502-vectors` chunk) is the same shape, for the bundled
`6502:LE:16:undoc` language** (`6502core.sinc` + `6510_illegal.sinc`, i.e. the core every
C64/C128 language here shares): needs `GRM_6502_VECTORS`, a clone of
`https://github.com/SingleStepTests/65x02` (~5.8 GB; only its `6502/v1/` directory is read),
refuses loudly when unset, excluded from `all`, 2,560,000 cases in ~1m10s measured. **Run it after
any change to `data/languages/6502core.sinc`, `6510_illegal.sinc` or `6510port.sinc`** — it is
what validated decimal mode (grm-hzv8) and what found the inherited SBC-carry and zero-page
pointer-wrap bugs on its first run. Its baseline pins 14 known FAIL rows (stack fidelity,
`JMP ($xxFF)`, the unstable `SH*`/`TAS` opcodes — bead `grm-m9nu`); a new FAIL row or a changed
ratio is a regression to explain. The NES boards run on stock Ghidra's `6502:LE:16:default`, so
nothing this tier checks reaches the NES corpus, and nothing that moves the NES corpus can be
attributed to these languages.

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
