# MMC3 overlay-scale measurement

> **Status: measured 2026-07-22 (bead `grm-6a7.3`).** Manual, CI-excluded per repo
> convention — real commercial ROMs never enter the test suite. This is the quantitative
> evidence the banked-memory RFC ([`rfc-banked-memory.md`](rfc-banked-memory.md), = posted
> Ghidra Discussion #9349) flagged as still owed: how far the overlay mechanism blows up at
> real-cartridge scale, and whether that cost is compute time or something else.

## Headline

Loading a real MMC3 cartridge creates **one overlay address space per alternate PRG bank
per switchable window** — a deterministic `3N − 1` overlay spaces for N in-range 8 KiB
banks, entirely at load time and independent of any analysis. A 512 KiB MMC3 game
(**191 overlay spaces**) is a **~27× blow-up** over the UxROM baseline (**7**). The cost is
**not** analysis time — Ghidra analyzes all 191-overlay programs in ~1 s — it is the 191
sibling address spaces a human must navigate, plus the fact that most cross-bank control
flow stays statically unresolved regardless of how many spaces exist.

## Method

Real ROMs imported headless through this extension's `NesRomLoader` with default
auto-analysis (which includes the `NES Bank State` analyzer, `BoardBankAnalyzer`). The
loader auto-selects the descriptor from the iNES mapper byte — no override — so mapper 4
→ `nes-mmc3.map`, mapper 2 → `nes-uxrom.map`. Counts come from a read-only post-script,
[`tools/banktest/OverlayScaleMeasure.java`](../tools/banktest/OverlayScaleMeasure.java),
driven by [`tools/banktest/measure-overlay-scale.sh`](../tools/banktest/measure-overlay-scale.sh)
against the per-worktree isolated extension install in `build/ghidra-home`. See
[Reproduction](#reproduction) for the exact command. Ghidra 12.1.2.

`refs → overlay` = references whose target lands in an overlay space (program-state truth,
counted by the post-script). `warn` = WARNING bookmarks the banking analyzer raised at
bank-switch sites whose state it could not resolve. Analysis time is the auto-analysis
`Total Time` line; the `NES Bank State` column is that analyzer's own slice of it.

## Results

| Title | Mapper | PRG | 8 KiB banks (N) | Overlay blocks | Overlay spaces | Base blocks | refs → overlay | warn | Analysis | NES Bank State |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Contra (U) | 2 UxROM | 128K | 8 (@16K) | **7** | 7 | 5 | 0 | 0 | ~1 s | 0.014 s |
| Super Mario Bros. 3 (PRG 1) (U) | 4 MMC3 | 256K | 32 | **95** | 95 | 8 | 871 | 50 | ~2 s | 0.304 s |
| Crystalis (U) | 4 MMC3 | 256K | 32 | **95** | 95 | 8 | 0 | 12 | ~1 s | 0.027 s |
| Mega Man 4 (U) | 4 MMC3 | 512K | 64 | **191** | 191 | 8 | 177 | 2 | ~1 s | 0.082 s |

Non-overlay address spaces are a fixed ~8 (the 6502 language spaces plus the base `ram`
space) across every program; overlay spaces are purely additive on top of that.

## The `3N − 1` law

`machines/nes-mmc3.yaml` declares four 8 KiB PRG windows across two `prg_mode` layouts.
`NesRomLoader` realizes each switchable window's home bank in base space and every other
in-range bank as an overlay:

- **`WA000`** (bank `r7`) — identical in both layouts → invariant switchable → `N − 1` overlays.
- **`WE000`** (fixed last bank) — invariant fixed → 0 overlays.
- **`W8000`** — mode-varying (`r6` switchable in mode 0, second-last fixed in mode 1) → `N` overlays.
- **`WC000`** — mode-varying (second-last fixed in mode 0, `r6` switchable in mode 1) → `N` overlays.

Total `= (N − 1) + 0 + N + N = 3N − 1`. Measured exactly: N=32 → 95, N=64 → 191. UxROM's
single switchable 16 KiB window gives the baseline `N − 1` (8 banks → 7). The count is a
property of the descriptor and the ROM size — it exists before a single instruction is
disassembled and cannot be reduced without the RFC's core hook.

## What the numbers say

1. **The overlay explosion is deterministic and unavoidable.** You pay `3N − 1` address
   spaces at load time for every MMC3 cartridge, whether or not any analysis succeeds. At
   512 KiB that is 191 spaces; MMC5's finer banking would be multiples of this.

2. **Compute time is not the ceiling.** Full auto-analysis of the 191-overlay Mega Man 4
   took ~1 s; the banking analyzer's own slice was 0.082 s. Import + analysis wall-clock
   is flat (~5 s, JVM-startup-dominated) from the 7-overlay baseline to the 191-overlay
   worst case. Any assumption that large banked ROMs are *slow* to load is wrong — the pain
   is structural, not temporal.

3. **Static resolution into the overlays is wildly idiom-dependent — and often near zero.**
   `refs → overlay` ranged from 871 (SMB3) to **0** (Crystalis), for two same-size MMC3
   games. Crystalis raised 12 unresolved-bank-state warnings and resolved *no* cross-bank
   references into its 95 overlay spaces; Contra (UxROM) resolved none into its 7. The
   `3N − 1` spaces exist regardless — so in the common case the overlays are mostly empty
   scaffolding the analyst must still page through, and the banked code they represent
   stays disconnected from the call graph. This is precisely the gap the RFC's core hook
   closes by making *default* resolution bank-aware instead of relying on the analyzer to
   hand-patch references after the fact.

4. **Navigability is the felt cost.** A single Mega Man 4 program presents 191 sibling
   overlay spaces (`W8000_M0_B1`, `WA000_B2`, `WC000_M1_B0`, …) in the program tree, the
   space list, and every Go-To dialog — one per alternate bank, most with little or no
   inbound reference. This is the "block count explodes with bank count" prediction of the
   vision doc's L4 discussion, now quantified.

## Evidence for the RFC

This is the missing quantitative row under the RFC's "Motivating case": the C64 loader
showed the *mechanism* limitation qualitatively; MMC3 at commercial scale shows the
*magnitude* — 191 overlay spaces per program, ~27× the discrete-mapper baseline, with
cross-bank flow still statically unresolved in the typical case. Analysis speed is a
non-issue, which sharpens the ask: the problem the core hook solves is representational
and navigational, not performance.

> **Note on the "SMB3 = 512K/64-bank" framing.** Earlier RFC/vision prose (and the bead
> title) assumed *Super Mario Bros. 3* is a 512 KiB / 64-bank / ~191-overlay case. Its PRG
> is 256 KiB (32 banks → 95 overlays); that figure conflated total ROM (PRG + 128 KiB CHR)
> with PRG. The genuine 512 KiB / 64-bank / 191-overlay MMC3 title measured here is
> **Mega Man 4**. Kirby's Adventure (the third named acceptance title) was not available.

## Reproduction

After installing the extension into the isolated per-worktree Ghidra home
(`bash tools/banktest/build-and-test.sh check nes-banking`):

```bash
bash tools/banktest/measure-overlay-scale.sh \
  "H:/emulators/nes/roms/Contra (U).nes" \
  "H:/emulators/nes/roms/Super Mario Bros 3 (PRG 1) (U).nes" \
  "H:/emulators/nes/roms/Crystalis (U) [o1].nes" \
  "H:/emulators/nes/roms/Mega Man 4 (U).nes"
```

The runner copies each ROM to a parenthesis-free path (analyzeHeadless rejects
parentheses), imports it with `-loader NesRomLoader`, runs `OverlayScaleMeasure.java` as a
post-script, and prints one row per ROM plus per-ROM log paths. These numbers are the
intended "before" baseline for a future comparison against a Ghidra build carrying the
RFC's proposed bank-context hook.
