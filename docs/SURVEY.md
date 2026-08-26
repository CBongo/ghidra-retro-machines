# Ghidra Retro System Loader — Prior-Art Survey & Design Notes

*Deliverable of bead `gib.1.1` (2026-07-03) — the founding survey, produced while this
project incubated in [game-music-extraction](https://github.com/CBongo/game-music-extraction)
and migrated here at repo-birth. Bead IDs cited below (`gib.*`) are that incubation-era
numbering; `gib.2`/`gib.3` (Ghidra core banked-memory proposal, MCP tooling) remain
tracked in GME.*

## Vision (context)

A Ghidra extension: a **descriptor-driven loader** that sets up a complete retro game
system architecture in one step — ROM/RAM regions, IO chip registers, banked memory,
symbol labels, data types — so analysis starts from a fully annotated system instead of a
flat binary. **Initial target: Commodore 64** (supports GME's `c64/` music RE). Later:
NES, SNES, PS1. A parallel track (`gib.2`) proposes first-class banked-memory support to
upstream Ghidra.

## Verdict: build new

**Contribute-vs-reinvent resolved: build a new extension.** RetroGhidra (the plausible
contribution target) has ~29 loaders but all uniformly shallow — parse header, create
memory block, set entry point. Nothing in it (or anywhere else surveyed) models IO
registers, hardware memory maps, or banking; no project uses overlay address spaces. Its
one-Java-class-per-format, constants-in-code architecture would fight a descriptor layer,
not host it. Use it only as Ghidra-API boilerplate reference; consider upstreaming our
shallow format-detection pieces to it later as goodwill (Apache 2.0 both ways, maintainer
merges external PRs).

## Prior-art catalog

### C64-specific

| Project | What it has | Take |
|---|---|---|
| [RetroGhidra](https://github.com/hippietrail/RetroGhidra) | Thin `CommodorePrgLoader` (single CODE block), `C64CrtLoader` (3 labels), D80 filesystem | API boilerplate reference only |
| [c64_ghidra](https://github.com/c64cryptoboy/c64_ghidra) | Working `C64BinLoader.java` (PRG load-addr detection, override, zp/stack blocks); `c64LabelAddrs.py` — 74 KB KERNAL/BASIC ROM+RAM symbol tables | **No license** → learn from it, don't lift code/data; regenerate labels from primary sources or ask author |
| [ghidra-c64helpers](https://github.com/grue74/ghidra-c64helpers) (fork) | **6510 processor definition** (bundle-able into our extension); PETSCII visualizer | 6510 def resolves the no-6510-in-tree gap; PETSCII feeds string detection (`gib.1.4`) |
| [C64LoaderWV](https://github.com/zeroKilo/C64LoaderWV) | `.d64` loader | Relevant when we do disk images, not PRG MVP |
| [c128_ghidra](https://github.com/inbarraz/c128_ghidra) | C128 extension of c64_ghidra approach | Shows what an extended descriptor must cover |
| [Dan Sanderson — Crossroads pt. 2](https://dansanderson.com/mega65/crossroads-part-2/) | Manual workflow: ROM dumps as overlay blocks, symbol import, ~38 hand-edited cross-region refs | **Our requirements doc, written by someone else** — the manual procedure this loader automates |

### 6502-family banking prior art (NES/SNES)

| Project | Banking approach | Take |
|---|---|---|
| [GhidraNes](https://github.com/kylewlacy/GhidraNes) | Separate non-overlapping blocks per bank (bank 1 at fake `$18000`) | 40+ mappers; shows mapper-coverage scale; loses runtime-address correspondence |
| [Ghidra-SMB3INES-Loader](https://github.com/fortenbt/Ghidra-SMB3INES-Loader) | **Overlay blocks** for swappable banks + 11,500 injected symbols | Best published overlay + symbol-injection example; flow analysis still breaks at overlay boundaries |
| [ghidra-snes-loader](https://github.com/achan1989/ghidra-snes-loader) | LoROM/HiROM detection, canonical banks + mirrors | Best address-space modeling; study for SNES phase |

### The three banking patterns in the wild (all painful)

1. **Overlay blocks at the same virtual address** — hardware-truthful; Ghidra cross-block
   flow analysis breaks.
2. **Separate blocks at fake addresses** — no conflicts; loses correspondence with runtime
   addresses.
3. **Manual annotation after flat load** — ~38 hand edits for one small program.

**Nobody automates descriptor-driven setup. That is the confirmed gap this extension fills.**

## In-tree findings (local Ghidra source checkout)

- Languages: `6502:LE:16:default` and `65C02` exist; **no 6510**. ISA is identical; plan:
  bundle a 6510 language in the extension (extensions may ship `data/languages`;
  ghidra-c64helpers proves it). The 6510 language is also the natural home for the
  bank-context register, since `$00`/`$01` are on-die.
  > **Since acted on, and partly superseded.** The language was bundled in `grm-bk6`
  > (`6510:LE:16:default`), and `grm-azg` added the opt-in `6510:LE:16:undoc` /
  > `6502:LE:16:undoc` variants carrying the undocumented NMOS opcodes. But the
  > bank-context idea above was **rejected** by the 2026-07-07 design correction: the port
  > is on the die, so modeling it as a register belongs in the language, yet what its bits
  > *mean* is board wiring (C64 PLA vs. 1551 drive control). The language therefore names
  > the port anonymously (`PORT`/`PORTDDR`) and encodes no banking meaning at all;
  > per-system interpretation lives in the machine descriptor and bank analyzer. See the
  > header of `data/languages/6510port.sinc`.
- Loader API: `ghidra.app.util.opinion` — `Loader` → `AbstractProgramLoader` →
  `AbstractProgramWrapperLoader`. Closest templates: `BinaryLoader`,
  `MotorolaHexLoader`. No console loaders in-tree.
- ARM precedent for flow-tracked context: `TMode` context field
  (`Ghidra/Processors/ARM/data/languages/ARM.sinc:90`), propagated via `globalset`,
  user-overridable via Set Register Values.

## Upstream Ghidra: banked memory is an open, unclaimed problem

No first-class support, no prior proposal, cross-architecture demand:

- Discussion [#6651](https://github.com/NationalSecurityAgency/ghidra/discussions/6651) —
  banked ROM (HD6305): context-register workaround attempted, **jumps still resolve
  wrong**; no maintainer response
- Discussion [#5913](https://github.com/NationalSecurityAgency/ghidra/discussions/5913) —
  C166 banked registers: no clean solution
- Issue [#7052](https://github.com/NationalSecurityAgency/ghidra/issues/7052) — 8051 code
  banking: Triage, dormant
- Issue [#2546](https://github.com/NationalSecurityAgency/ghidra/issues/2546) — 6502 385K
  banked ROM: 64K cap; can't xref between separately imported files
- Issue [#864](https://github.com/NationalSecurityAgency/ghidra/issues/864) — 6502 default
  blocks conflict with C64 PRG zero page/stack
- Issue [#1332](https://github.com/NationalSecurityAgency/ghidra/issues/1332) — MIPS
  overlays (not a 6502-only problem)

**Why the naive context-register approach fails (#6651):** `TMode` changes how *fixed
bytes* decode; a bank register must change *which bytes exist* at an address — and
Ghidra's memory model never consults Sleigh context during address resolution.

**Proposal shape (`gib.2`):** reuse the proven TMode machinery (flow-tracked context via
`globalset`, existing user-override UI) and add the one missing core hook:
**context-aware address resolution** mapping context-register state → overlay/block
selection. Extension/core split: mechanism interpretation (recognizing bank-switch writes,
computing new state) lives in the *extension* as an analyzer that sets context registers;
core stays generic and mapper-free — a maintainer-friendly pitch that also serves the
8051/C166/MIPS users above.

## Architecture decisions (made 2026-07-03)

1. **MVP input: PRG** (2-byte load-address header).
2. **Banking: overlay address spaces** — today's ceiling. IO always needed by music code;
   KERNAL/BASIC rarely needed by music code itself but frequently involved in *loader*
   code paths. Overlay pain points feed the `gib.2` upstream proposal.
3. **ROMs (copyright):** symbol-only labels by default; labeled memory-map slots so users
   pull their own dumps via File → Add To Program; optional ROM-path loader options later.
4. **Evolving descriptor schema from day one** (not hardcode-C64-first). Solo until baked.
5. **Bank switching = MECHANISM + INITIAL STATE.**
   - *Mechanism* is code-shaped: a named, parameterized strategy selected by the
     descriptor (C64: "write to `$01`"; NES: the Mapper — several categories of
     register-access handling, e.g. MMC1's serial 5-write loads). Mirrors emulator
     mapper-class architecture.
   - *Initial state* is pure data (C64 PRG default `#$37` — BASIC+KERNAL+IO active,
     CHARROM inactive; later GAME/EXROM lines). Container formats often carry it:
     `.crt` header bytes 0x18/0x19 store EXROM/GAME; iNES headers store mapper/submapper.
   - Runtime bank swaps (C64 `$01` rewrites, NES mapper writes) make static-only
     configuration insufficient → flow-tracked context is a *requirement*.
   - C64 is the deliberately simple end-to-end POC of the mechanism plumbing.

## Design principles

- **Descriptor-driven:** system knowledge (regions, named bank configurations, symbols
  with provenance, IO register structs, text encodings) lives in data; game files
  self-describe where containers allow.
- **Emulators are a primary source of truth.** Accuracy-focused emulators (VICE, Mesen2,
  bsnes) are executable, battle-tested encodings of exactly the knowledge this extension
  models. Use them to **validate design** (our mechanism+initial-state split mirrors
  emulator mapper classes; divergence from how emulators model the same hardware is a
  signal to re-examine — the same reconcile-against-authority stance GME takes with
  vgmtrans), **validate code** (cross-check against emulator source; run programs live and
  compare observed bank/memory state against our static model's predictions), and **mine
  data** (VICE label files, mapper documentation, emulator test ROMs as fixtures).
  *Licensing caution:* most emulators are GPL — an oracle, not a code quarry; read and
  verify, never copy source into the extension.
- **Licensing hygiene for data:** prefer clean upstream sources (mist64/c64ref) over
  unlicensed or book-derived label collections.

## Descriptor data sources (for `gib.1.2`)

- [mist64/c64ref](https://github.com/mist64/c64ref) — canonical structured C64 reference
  (`src/kernal/`, `src/c64io/`, `src/c64mem/`); adapt its Python generator to emit YAML.
  **The upstream to consume.**
- [sajattack/c64-asm-labels](https://github.com/sajattack/c64-asm-labels) — whole-map
  labels in ACME/KickAss/radare2/VICE-`.sym`. *Check license* — derived from "Mapping the
  Commodore 64."
- VICE `.sym` format (`al <hexaddr> .<label>`) — de-facto C64 symbol interchange.
- KickAssembler built-in `MOS6526_CIA`/`MOS6581_SID`/`MOS6569_VICII` structs — IO offset
  cross-check.
- [c64-wiki Memory Map](https://www.c64-wiki.com/wiki/Memory_Map) — the `$0001`
  LORAM/HIRAM/CHAREN bank-configuration table to encode as named bank states.

## Adjacent tooling

- **Ghidra MCP servers** (`gib.3`, P3): bethington/ghidra-mcp is active (Apache 2.0, 256
  tools) but assumes an already-loaded binary and targets modern platforms. Potentially
  useful *after* our loader works (agent-driven verification of blocks/labels). HN
  criticisms: tool-count bloat degrades LLM tool use.
- **String detection** (`gib.1.4`, P3): PETSCII vs screen codes (two different C64
  mappings, each shifted/unshifted); NES/SNES per-game tile tables via the ROM-hacking
  community's `.tbl` format. Integration point: Ghidra's pluggable Java `Charset` for
  string data types.

## Bead map

| Bead | Carries |
|---|---|
| `gib` | Parent epic; three tracks (scripts / core contributions / extension incubators); emulator-oracle principle |
| `gib.1` | Extension incubator epic; architecture decisions; migration procedure |
| `gib.1.1` | This survey (closed) |
| `gib.1.2` | Descriptor schema design — data sources, mechanism+initial-state, schema requirements |
| `gib.1.3` | C64 loader POC — overlays, 6510 bundling note |
| `gib.1.4` | Generalized string detection (future) |
| `gib.2` | Upstream first-class banked memory — evidence trail, TMode analogy, proposal shape |
| `gib.3` | Ghidra MCP tooling investigation |
