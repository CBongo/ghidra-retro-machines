# Does the overlay/banking abstraction apply to the SNES?

Bead: `grm-9nxj.6`. Decides the memory-model half of `grm-9nxj` (SNES machine target) before any
loader work assumes an answer. Written 2026-09-04.

Claims are tagged **[verified]** (measured this session against local ROMs, the local disassembly
corpus, or the 12.1.3 source) or **[reported]** (external, URL given).

---

## 0. Recommendation

**Plain LoROM/HiROM/ExHiROM should NOT use the overlay/window machinery.** The reason that
machinery exists does not apply here: it exists because a 16-bit address space cannot hold every
bank at once, and the 65816 language gives us a real 24-bit space in which every bank already has
a distinct address. Cartridge layout is a *static* map, read from the header at import.

**The descriptor still earns its place** — regions, IO typing, symbols, vectors, formats and
placement rules are all exactly what it is for. What SNES does not need is `windows[]`,
`occupants[]`, `banking.states[]` and the analyzer mechanisms.

**Two exceptions, both deferrable.** Address-space *mirroring* is a real problem that neither
overlays nor plain blocks solve for free (§3), and MMC-style enhancement carts — SA-1 above all —
genuinely do switch banks at runtime and map cleanly onto the existing mechanism machinery when we
get to them (§4).

The decision I need from you is in §6, and it is about mirrors, not about overlays.

---

## 1. Why the usual reason for overlays is absent **[verified]**

On the C64 and NES, a window is a 16-bit address range whose contents change: `$8000-$BFFF` holds
bank 3 now and bank 7 later, and both must be representable. Ghidra has one address per address,
so the second occupant becomes an overlay block. That is the whole motivation, recorded in
`docs/SCHEMA.md`'s mapping table (`memory.windows[].occupants[]` → "one **overlay** `MemoryBlock`
per occupant").

The 65816 does not have that problem. `data/languages/658xx.sinc` declares:

```
define space bus       type=ram_space       size=3  default;
```

A 24-bit space is 16 MB, and the largest SNES cartridge is 8 MB (ExHiROM; 4 MB is the practical
ceiling for everything else). **Every byte of ROM, WRAM, SRAM and IO has its own address with room
to spare.** Nothing has to share an address with anything, so nothing needs an overlay.

## 2. Cartridge layout is a static, header-declared map **[verified]**

Parsed all 11 SNES ROMs in the local corpus, taking the header at whichever of `$7FC0`/`$FFC0`/
`$40FFC0` scores best on title printability plus the checksum/complement pair. **All 11 validate**
(`checksum ^ complement == 0xFFFF`), so these readings are not guesses:

| ROM | bytes | copier hdr | header at | map mode | chipset | ROM |
|---|---|---|---|---|---|---|
| `chrono.smc` | 4,194,816 | yes | `$FFC0` | `31` HiROM+FastROM | ROM+RAM+battery | 4 MB |
| `f_fan3.fig` | 3,146,240 | yes | `$FFC0` | `31` HiROM+FastROM | ROM+RAM+battery | 4 MB |
| `seiken3e.smc` | 4,194,816 | yes | `$FFC0` | `31` HiROM+FastROM | ROM+RAM+battery | 4 MB |
| `som1.smc` | 2,097,664 | yes | `$FFC0` | `21` HiROM | ROM+RAM+battery | 2 MB |
| `ff5e.smc` | 2,621,952 | yes | `$FFC0` | `21` HiROM | ROM+RAM+battery | 2 MB |
| `ff2.smc` | 1,049,088 | yes | `$7FC0` | `20` LoROM | ROM+RAM+battery | 1 MB |
| `lufia.smc` | 1,049,088 | yes | `$7FC0` | `20` LoROM | ROM+RAM+battery | 1 MB |
| `lemmings.smc` | 1,048,576 | **no** | `$7FC0` | `20` LoROM | ROM | 1 MB |
| `fzero.smc` | 524,800 | yes | `$7FC0` | `20` LoROM | ROM+RAM+battery | 512 KB |
| `gradius3.smc` | 524,800 | yes | `$7FC0` | `20` LoROM | ROM | 512 KB |
| `mario.smc` | 524,800 | yes | `$7FC0` | `20` LoROM | ROM+RAM+battery | 512 KB |

Three things follow:

1. **LoROM vs HiROM is a lookup, not a judgment** — confirming `grm-9nxj`'s 2026-08-17 correction.
   Six LoROM, five HiROM, and the map-mode byte says which. Detection still needs the
   header-location search above, because the header's address depends on the mapping it declares.
2. **The copier header is per-file, not per-title**: 10 of 11 carry the 512-byte header, `lemmings`
   does not (it is exactly 1 MB). `size % 0x400 == 0x200` detects it, and matches the note already
   in `grm-9nxj`.
3. **Not one enhancement chip in the corpus.** Every title is plain ROM or ROM+RAM+battery. So for
   100% of the ROMs this project can currently test against, the static-map answer is complete and
   §4 is hypothetical.

## 3. The real problem is mirroring, and it is not solved by either default **[verified]**

The SNES maps the same physical ROM at two address ranges: banks `$80-$FF` mirror `$00-$7F`, the
high copy being the FastROM path. WRAM's first 8 KB is likewise mirrored into `$0000-$1FFF` of
most banks. Mirrors are not banks — nothing switches — but they do mean one physical byte has
several addresses, which is the mirror image (so to speak) of the problem overlays solve.

**Both halves are live in real code.** Counting long-form (24-bit) operands across the 62-listing
corpus:

| | count | share naming a bank ≥ `$80` |
|---|---|---|
| long-form operands (`LDA/STA/JSL/…` with a 6-hex-digit address) | 190,486 | **49.9%** |
| `JSL`/`JML` targets only (the cleaner signal — no data reads, less data-decoded-as-code noise) | 9,444 | **40.3%** |

Per-file the high-mirror share ranges from 44% to 75%. So there is no "the code lives at `$00`"
simplification available: **materializing only the low half would leave two of every five call
targets pointing at unmapped memory.** This is the finding that makes the mirror question
load-bearing rather than cosmetic.

Three ways to model it, and this is the actual decision:

**(a) Byte-mapped mirror blocks.** Ghidra's `Memory.createByteMappedBlock(name, start,
mappedAddress, size, …)` creates a block whose bytes *are* another block's bytes — exactly a
hardware mirror. One canonical ROM block per bank plus mapped mirrors over `$80-$FF`. This repo
already uses the call once (`TransferMaterializer.java:376`), and the independent reference
implementation does exactly this for SNES: `joshleaves/ghidra-snes`'s `MemoryMap` creates "mapped
mirrors pointing back to the canonical blocks", via `MemoryMapUtils`' `createByteMappedBlock`
**[reported]**. Cost: every mirrored range is disassembled and analyzed *again*, so a routine
reachable through both halves becomes two functions with two sets of references and two decompiler
views.

**Code does disassemble inside a byte-mapped block [verified].** This was the open question when
the section was first drafted, and it is now measured rather than assumed: `ByteMappedMirrorTest`
writes `A9 12 EA` to a canonical block at `$008000`, creates a byte-mapped block at `$808000` over
it, disassembles *only* at the mirror's addresses, and gets `LDA #$12` / `NOP` at
`$808000`/`$808002`. So (a) is viable, and that test stays in the suite: if a future Ghidra stopped
allowing it, a loader built on mirrors would silently lose two of every five call targets, and the
test is what would say so.

**(b) Canonical blocks only, plus reference retargeting.** Materialize `$00-$7D` once and retarget
mirror-range references back to it. This project already owns that machinery in another form:
`MosConstantReferenceAnalyzer` retargets computed references to a base, and `grm-r6f`
(reference-precedence retargeting) is the same idea generalized. Cost, and it is the serious one:
data references are retargetable, but *execution* in the mirror is not merely a reference — 40% of
`JSL` targets are flow, and flow that lands in unmapped memory does not get disassembled at all.
Retargeting would have to happen at disassembly time, which is a much deeper hook than the data-ref
case.

**(c) Hybrid: pick the canonical half per ROM, mirror the other.** The reset vector is always in
bank `$00`, but a FastROM title jumps to the `$80` half early and stays there. Choosing per ROM
means the canonical half is where most execution actually happens, with (a) covering the rest.
More logic, and the choice is only as good as the heuristic that makes it.

## 4. Where the existing machinery genuinely does apply **[reported]**

Not for plain cartridges — but MMC-style enhancement carts are real bank switching:

- **SA-1** carries a Super MMC with four bank registers, `CXB`/`DXB`/`EXB`/`FXB` at
  `$2220-$2223`, each selecting a 1 MB ROM block into one of `$00-$1F`, `$20-$3F`, `$80-$9F`,
  `$A0-$BF` (`$8000-$FFFF`), with an analogous HiROM-side mapping. That is textbook
  `banking.mechanisms[]` plus a computed window (`maps: ROM[bank * 0x100000]`) — **no schema change
  needed**. Worth knowing before anyone gets excited: SA-1 titles in practice leave the four
  registers at the identity mapping, so even here the payoff is mostly correctness-under-
  weirdness rather than new information. Sources:
  [Super Famicom Development Wiki](https://wiki.superfamicom.org/sa-1-registers),
  [jsgroth's SNES coprocessor writeup](https://jsgroth.dev/blog/posts/snes-coprocessors-part-4/).
- **S-DD1 and SPC7110** map ROM through bank registers in a similar spirit.
- **SuperFX/GSU is NOT this.** It is a second processor with its own program bank register and its
  own memory view; the right shape for it is the SPC700 one — extract to a separate `Program`
  (`grm-1.7.3`) — not banking. Sources: [SnesLab Super FX](https://sneslab.net/wiki/Super_FX),
  [SNESdev memory map](https://snes.nesdev.org/wiki/Memory_map).

None of this is urgent: §2 shows the local corpus contains zero enhancement carts, so this is the
answer to "does the abstraction still have a job on SNES" (yes, later, unchanged) rather than
something to build now.

## 5. What the descriptor is still for

Dropping windows does not mean dropping the descriptor. A SNES machine descriptor still declares:

- `memory.regions[]` — WRAM (`$7E-$7F`, 128 KB), the LowRAM mirror, SRAM, and the ROM regions per
  mapping mode.
- IO typing — `$2100-$21FF` (PPU/APU) and `$4200-$43FF` (CPU/DMA), which is precisely the "IO
  naming comes from the descriptor, not the language" split already applied when the language was
  vendored (its pspec deliberately drops upstream's SNES register symbols).
- `symbols[]` and the CPU vectors, `types[]` for the register blocks, and `formats` for
  `.smc`/`.sfc`/`.fig` plus the copier-header rule from §2.

So `grm-9nxj`'s loader scope narrows to: parse and validate the header, choose the mapping, lay out
static blocks, decide the mirror policy (§3), and type the IO.

## 6. Ruling (owner, 2026-09-04) — and the measurement that reshapes it

**Ruled: (c), a per-ROM canonical half with the other half mirrored.** Also ruled: write the
overlay non-application into `docs/SCHEMA.md` (done — see its "When windows do not apply" note).

Measured *after* the ruling, because (c) needs a rule for *choosing* the canonical half and the
obvious candidate was the header's FastROM bit: **the header does not predict it.** Counting
`JSL`/`JML` targets per title and pairing each with its map-mode byte:

| title | map mode | FastROM bit | `JSL`/`JML` into `$80+` |
|---|---|---|---|
| `sd3` | `31` | yes | **89.3%** |
| `som` | `21` | **no** | 59.5% |
| `ct` | `31` | yes | 48.0% |
| `ff3` | `31` | yes | 46.0% |
| `ff5` | `21` | no | 46.7% |
| `lufia` | `20` | no | 36.6% |
| `lem` | `20` | no | 11.1% |
| `mario` | `20` | no | 0.7% |
| `gradius3` | `20` | no | 0.3% |

Two things fall out, and both matter for how (c) gets built:

1. **The FastROM bit is not the discriminator.** `som` declares no FastROM and calls high 59.5% of
   the time; `ct` and `ff3` declare FastROM and sit at ~47%. Nothing in the header separates these.
2. **For half the corpus there is no canonical half to pick.** Four titles are within a few points
   of 50/50. Only `gradius3`, `mario`, `lem` (low) and `sd3` (high) are decisively one-sided, so on
   the rest, whichever half is chosen, roughly half the call targets land in the mirror anyway.

**So (c) should be built as hybrid-by-OPTION, not hybrid-by-heuristic.** Concretely: physical bytes
live once; both halves are materialized, the non-canonical one as byte-mapped mirrors (§3, verified
disassemblable); and *which* half is canonical is a loader option, defaulting to the half holding
the reset vector's target. That honours the ruling — the canonical half is chosen per ROM — without
inventing a discriminator the evidence says does not exist, and it degrades to (a) when the option
is left alone. A later analyzer pass could propose a better default from measured call targets,
which is the only thing that actually predicts this; that would be its own bead, not loader work.

## 7. Settled, for the loader's scope

- No `windows[]`/`occupants[]`/`banking.states[]` for plain LoROM/HiROM/ExHiROM.
- Static block layout from the header; copier-header detection via `size % 0x400 == 0x200`.
- Both halves materialized, non-canonical half byte-mapped; canonical half a loader option.
- Descriptor keeps regions, IO typing, symbols, vectors, types and formats (§5).
- Enhancement carts (SA-1 and friends) reuse the existing mechanism machinery unchanged, later
  (§4); SuperFX is a separate-`Program` problem, not banking.
