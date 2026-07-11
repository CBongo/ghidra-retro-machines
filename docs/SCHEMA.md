# System Descriptor Schema — Design Notes (schema 2)

*Schema 1 was the deliverable of bead `gib.1.2` (2026-07-03), incubated in
game-music-extraction and migrated here at repo-birth. Schema 2 (bead `grm-os4`,
2026-07-08) is the machine-independence generalization designed in
[vision-board-banking.md](vision-board-banking.md) §5: the bank state became a named
field tuple, the single mechanism became a list of strategy instances, and physical
backing spaces / computed windows / mode-dependent layouts were added for the NES
mapper tier. Companion worked examples: [`machines/c64.yaml`](../machines/c64.yaml)
(enumerated truth-table style) and the UxROM/MMC3 validation sketches in
[`machines/sketches/`](../machines/sketches/) (computed style; compiled by the
`validateSketches` Gradle task, never shipped). Schema remains **evolving** — the
`schema:` version field gates breaking changes; `MapCompiler` accepts only the current
version.*

## Purpose

One YAML descriptor per system drives the loader with **zero hard-coded system knowledge
in Java**. The descriptor answers: what exists at every address, which addresses are
banked and by what mechanism, what the hardware registers are called and shaped like, and
where the symbol/type data came from.

## Design principles

1. **Data, not code — except mechanisms.** Regions, bank states, symbols, types, ROM
   slots are pure data. Bank-switch *mechanisms* are code-shaped: the descriptor selects
   a named strategy (implemented in the extension) and parameterizes it. This mirrors
   emulator architecture (mapper classes keyed by iNES number) — deliberate, per the
   emulators-as-oracle principle.
2. **Mechanism + initial state.** Per the `gib.1.2` design decision: the mechanism
   defines the state space and transitions; the initial state picks the start point.
   Container formats may override initial state (`.crt` EXROM/GAME bytes, iNES headers).
3. **Provenance on all imported knowledge.** Every symbol/type source records where it
   came from and its license. Prevents the c64_ghidra trap (great data, no license).
4. **Copyright-safe ROM slots.** System ROMs are declared as *slots* (size, location,
   known checksums) that users fill with their own dumps; symbols and entry points apply
   even when the slot is empty (uninitialized block + labels).
5. **The descriptor describes hardware truth; the loader decides representation.**
   E.g. mirrors are declared as facts (`repeat_to`); whether the loader models them as
   repeated structs, aliased blocks, or comments is loader policy, not descriptor data.

## Top-level shape

```yaml
schema: 2            # descriptor-schema version (MapCompiler rejects others)
system: {...}        # identity + CPU/language binding
physical: [...]      # OPTIONAL: physical backing spaces (ROM laid out once; NES PRG)
memory:              # the address map
  regions: [...]     #   always-visible ranges
  windows: [...]     #   banked ranges: enumerated occupants OR computed maps:
  layouts: [...]     #   OPTIONAL: mode-dependent window sets (MMC1/MMC3 PRG modes)
banking: {...}       # OPTIONAL: state tuple + mechanisms + initial state
rom_images: {...}    # copyright-safe slots for system ROMs
symbols: [...]       # label/entry-point sources with provenance
types: [...]         # register-struct sources with provenance
formats: {...}       # file formats the loader accepts for this system
validation: {...}    # emulator-oracle cross-check metadata
```

`banking:` is optional (a bankless board like NES NROM omits it), but windows with
enumerated `occupants:` require it — the states table is what picks an occupant.

`system.board` carries container-registry keys: `ines_mappers` lists the iNES mapper
numbers a NES board descriptor serves, letting the loader resolve header → board from
data (`machines/nes-nrom.yaml` is the worked example; the registry is a scan of bundled
descriptors, so new boards need no Java).

## Section semantics → Ghidra mapping

| Descriptor construct | Ghidra realization |
|---|---|
| `memory.regions[]` | one `MemoryBlock` each (initialized for loaded file content, uninitialized otherwise) |
| `memory.windows[].occupants[]` | one **overlay** `MemoryBlock` per occupant in the window's range; the state-selected default occupant may be the non-overlay "home" block |
| `physical[]` | a physical backing space the banked content lives in **once** (interim realization: overlay blocks per resolved window slice; first-class realization is the RFC's resolution hook — vision doc §6 L4) |
| `memory.windows[].maps` | window contents computed from bank state: a slice of a physical space at the expression's offset |
| `memory.layouts[]` | window *sets* selected by mode fields (MMC1/MMC3 PRG modes); same window schema inside |
| `banking.state[]` | sub-fields of the bank **context register** (lives in the bundled processor language, TMode-style); `RegisterValue`'s value+mask storage gives per-bit partial knowledge |
| `banking.states[]` | enumerated truth table: packed context-register values → occupant per window; analyzer sets the register flow-wise on mechanism writes |
| `banking.mechanisms[]` | configuration for the bank analyzer's **strategy** classes (the L2 code library — register-write, memory-latch, select-data, serial-shift, io-port, mode-register) |
| `rom_images` | uninitialized block + applied symbols by default; initialized from user-supplied file via loader option or File → Add To Program |
| `symbols[]` | labels; `kind: entry` additionally creates a function + external entry point (works on empty ROM slots) |
| `types[]` | `DataTypeManager` structs/enums; applied at declared addresses; `repeat_to` applies at each mirror |
| `formats` | `Loader` opinion + header parsing + placement rule |

## Bank state: a named field tuple

`banking.state` declares the abstract bank-state tuple as an ordered list of named
fields — the sub-fields of the machine's bank context register:

```yaml
banking:
  state:                      # first field = bit 0 (LSBs), next field above it
    - { name: LORAM,  bits: 1 }
    - { name: HIRAM,  bits: 1 }
    - { name: CHAREN, bits: 1 }
```

C64 needs three 1-bit fields; NES MMC3 needs `{prg_mode: 1, R6: 6, R7: 6}`. Everywhere
a whole state value is expressed (`initial_state`, `states` rows), the descriptor uses
per-field values (`{ LORAM: 1, HIRAM: 1, CHAREN: 1 }`) and `MapCompiler` computes the
packed integer for the runtime (field order defines the bit packing). `initial_state`
also accepts an already-packed integer.

## Mechanisms: a list of strategy instances

`banking.mechanisms` is a list — a board can have several (MMC3: a select-data pair
*and* a mode bit in the same physical register). Each entry names a **strategy** (the
per-mechanism-*class* code in the extension), gives it strategy-specific `params`
(passed through to the .map opaquely, numbers normalized), and declares which state
fields it feeds via `sets` (validated against `banking.state`):

```yaml
banking:
  mechanisms:
    - strategy: register-write            # C64: STA $01 (and friends)
      params: { address: 0x0001, mask: 0x07 }
      sets: [LORAM, HIRAM, CHAREN]
```

The strategy vocabulary (vision doc §5.2) is deliberately small: `register-write`,
`memory-latch`, `select-data`, `serial-shift`, `io-port`, `mode-register`. Two have
implementations today; the others are schema-validated names whose analyzer support
lands with the MMC milestones. This mirrors emulator architecture (mapper classes
keyed by iNES number) — deliberate, per the emulators-as-oracle principle.

- **`register-write`** — the state changes on a store to one fixed port (C64 `$01`).
  Params: `address`, `mask` (which stored bits are state bits), and optional `register`
  (the port's name when the CPU models it on-die). The mechanism reads back what was
  stored, so value recovery may fall back to the tracked in-state. The `register` param
  bridges the two ways a port can be modeled: on stock 6502 `$01` is memory-mapped, so
  `STA $01` references address `$0001`; the bundled **6510** language models the on-die
  port as the `PORT` register, so `STA $01` decodes to `PORT = A` with no memory
  reference — the strategy recognizes the write either way (address or register), and the
  register clause is simply ignored when the loaded language lacks it (the 6502 fallback).
  This is the L1 "mechanism register" of the vision doc: modeling the port as a register
  makes the bank-switch idiom ordinary register dataflow. Note the language is
  system-neutral — it names the port anonymously and encodes no banking meaning; the
  descriptor supplies that.
- **`memory-latch`** — a store *anywhere* in a range latches the bank; the write hits a
  mapper register, not the ROM at that address (NES discrete mappers; GB MBC and SMS
  are the same shape). Params: `start`/`end` (the latch range), `mask` and `shift`
  (field extraction from the written byte — GxROM's PRG bits 4-5 are
  `{ shift: 4, mask: 0x3 }`), `bus_conflict` (boards without bus isolation AND the
  driven value with the ROM byte at the written address; when the store target is
  constant and bank-invariant the analyzer applies that AND, turning the ROM byte's 0
  bits into *known* zeros). The latch is write-only — reads of the range read ROM —
  so value recovery resolves plain absolute loads of bank-invariant ROM bytes to
  constants instead of consulting the in-state. Constraint: the field a memory-latch
  `sets` must currently be the **first** field of `banking.state` (the recovered value
  lands at state bits `[0, width)`); multi-latch boards will add a placement param.

## Banked windows: enumerated or computed

A **window** is an address range whose contents depend on bank state. It carries
exactly one of:

- **`occupants:` (enumerated)** — multiple candidate occupants (RAM under ROM, ROM,
  IO...), with a `banking.states` truth table assigning one occupant per window per
  state. Viable when the state space is small: C64 has 8 PLA combinations → 8 rows.
  Rows are keyed by state-field values plus window names; `MapCompiler` computes each
  row's packed `value` and validates that every state field and every enumerated
  window is assigned:

  ```yaml
  states:
    - { LORAM: 1, HIRAM: 1, CHAREN: 1, LOROM: BASIC, CHARIO: IO, HIROM: KERNAL }
  ```

  This is pure data and trivially cross-checkable against the c64-wiki table and VICE.

- **`maps:` (computed)** — the window shows a slice of a `physical:` space at an
  offset computed from state fields. NES mappers have state spaces far too large to
  enumerate (a 6-bit bank register is 64 "states" per window); an expression replaces
  the table:

  ```yaml
  physical:
    - { name: PRG, image: prg_rom }       # the ROM file, laid out once
  windows:
    - name: PRG_LO                        # switchable
      start: 0x8000
      end: 0xBFFF
      maps: PRG[bank * 0x4000]
      on_write: mechanism                 # stores into this range are mapper writes
    - name: PRG_HI                        # fixed
      start: 0xC000
      end: 0xFFFF
      maps: PRG[last]                     # last bank in the image
  ```

Windows accept `size:` as an alternative to `end:`. Computed windows may carry a
window-level `on_write:` (there is no occupant to hang it on); `on_write: mechanism`
marks stores into the range as bank-switch events, doubling as the analyzer's
watch-list. YAML note: inside a flow mapping (`{ ... }`) the `maps:` value must be
quoted (`maps: "PRG[R6 * 0x2000]"`) — `[` is a YAML flow indicator.

**How computed windows are realized** (loader + `BoardBankAnalyzer`): a fixed window
(constant expression) is one base-space block. A switchable window (expression uses a
state field) follows the same home-in-base principle as enumerated windows: the
`initial_state` bank's slice is the base-space block named after the window, and every
other in-range field value `v` becomes an overlay block `<window>_B<v>`. The bank
engine then (a) retargets references whose tracked effective state selects a non-home
bank into that bank's overlay, kicking disassembly/function creation at cross-bank
flow targets; (b) clamps the state of instructions physically inside `<window>_B<v>`
to `field = v` (execution implies mapping); (c) leaves *writes* into
`on_write: mechanism` windows alone — those are latch pokes, already modeled by the
strategy. Bank values whose slice falls outside the image simply get no block. A
switchable window must reference exactly one state field for overlay naming to work;
multi-field windows are rejected with a log message (MMC3's mode-swapped windows are
an M3 problem).

Real code switches banks through helpers (`LDA #bank / JSR SelectBank` — often an
indexed bus-conflict table store inside). The engine detects every function containing
a recognized mechanism write and treats calls to it as switch sites: the helper's own
constant result when it has one, else the immediate register argument recovered at the
call site, else explicitly unknown (WARNING bookmark naming the helper). Sites whose
bank argument is loaded from a memory variable (stage-driven dispatch, e.g.
Castlevania) are genuinely static-unresolvable and keep the ambiguity marker.

### The expression mini-language

Deliberately tiny, validated by `MapCompiler` at build time, evaluated by the bank
engine at analysis time: integers (decimal or `0x` hex), declared state-field names,
the keywords `last` / `second_last` (byte offsets of the last / second-to-last
window-sized bank, relative to the image's end), operators `+ - *`, parentheses. The
window-relative CPU offset is added implicitly by the contiguous block mapping, so it
is not an expression term. **If a board needs more, that is a signal to add a strategy
or a schema feature, not to grow a Turing tarpit** (vision doc §5.3). Guard this in
review — in particular, keep this keyword set in lockstep with the runtime evaluator
(`DescriptorSupport.ExprParser`); a keyword the compiler accepts but the runtime cannot
resolve compiles clean yet silently fails to place its window.

## Mode-dependent layouts

Some mappers switch entire window *arrangements*, not just occupants (MMC1 control,
MMC3 `$8000` bit 6). `memory.layouts[]` holds window sets selected by state fields;
`memory.windows` keeps the windows present in every mode:

```yaml
memory:
  layouts:
    - when: { prg_mode: 0 }
      windows:
        - { name: W8000, start: 0x8000, size: 0x2000, maps: "PRG[R6 * 0x2000]" }
        # ...
    - when: { prg_mode: 1 }               # $8000 and $C000 swap roles
      windows:
        - { name: W8000, start: 0x8000, size: 0x2000, maps: "PRG[second_last]" }
        # ...
```

`when:` keys must be declared state fields. See `machines/sketches/nes-mmc3.yaml` for
the full worked example.

## Initial state

Initial state comes from `banking.initial_state` (per-field map or packed integer),
overridable per-format (e.g. a future `.crt` format entry derives EXROM/GAME from
header bytes 0x18/0x19).

## Block permissions: kind defaults + sparse overrides

Every place a `kind` appears (`memory.regions[]`, window `occupants[]`, IO `subregions[]`)
derives its Ghidra `MemoryBlock` permissions from that `kind` alone, unless overridden:

| `kind` | readable | writable | executable | volatile |
|---|---|---|---|---|
| `ram` | yes | yes | yes | no |
| `rom` | yes | no | yes | no |
| `io`  | yes | yes | no | **yes** |

RAM is r+w+x because C64 code routinely runs from RAM. ROM is r+x, not writable — write-
through to the RAM beneath (`on_write`, below) is a separate concern from block
permissions. IO is r+w, not executable, and marked **volatile**: chip registers have side
effects on access (VIC/SID/CIA, the P6510 port), so Ghidra should not assume reads are
idempotent or cacheable.

Optional boolean fields `readable:`, `writable:`, `executable:` override one attribute of
the kind default without changing the kind. They are **sparse overrides for hardware
quirks**, not required fields — omit them entirely when the kind default already holds.
Example: CHARGEN is `kind: rom` (font glyph data, r+x by default) but the bytes are never
executed as code, so it declares `executable: false`:

```yaml
- { name: CHARGEN, kind: rom, image: chargen, on_write: RAM_D000, executable: false }
```

**Design rule — override vs. new kind:** a single-attribute deviation from an existing
kind's defaults (like CHARGEN above) is an override. If a hardware region needs *multiple*
coordinated behavior changes (e.g. a different combination of r/w/x *and* a different
`on_write` policy *and* different volatility), that's a sign it's really a distinct
behavioral cluster and deserves its own `kind`, not a pile of overrides on an existing one.
Overrides are for one-off exceptions; new kinds are for repeated behavior patterns.

## Load-time image target (`load_target`)

Optional boolean field on `memory.regions[]` entries, omitted (== `false`) unless the
region is where a machine's load-time image gets carved into (e.g. C64's `RAM_MAIN`, which
a `.prg`'s load address/length split around at import time). MapCompiler passes it through
only when present in the source YAML, exactly like `readable`/`writable`/`executable`, and
**rejects a descriptor that sets it on more than one region** — a build-time error, since
"which region is the load target" must be unambiguous.

`load_target` is not required — a descriptor with zero `load_target: true` regions is
valid (NES boards have none: PRG banks load as ROM windows, not into a RAM region). Whether
a loader *needs* a load target is a property of that loader, not the schema; a loader that
does (`C64PrgLoader`) logs clearly when the descriptor doesn't provide one rather than
falling back to a hardcoded region name.

`MapCompiler` passes these three fields through to the compiled `.map` verbatim, only when
present in the YAML (no defaults are ever written into the JSON — the loader is the single
place that knows the kind→default table and applies overrides on top of it).

## Read/write asymmetry (`on_write`)

Bank mapping differentiates **read and write targets**. On the C64, when BASIC/KERNAL
ROM is mapped, only *reads* hit ROM — the 6510's write line always reaches the RAM
underneath. In the `$D000` window the split varies with bank state: IO mapped → reads
*and* writes hit the chips; CHARGEN mapped → reads hit ROM, writes fall through to RAM.

This is modeled as a property of the **occupant**, not the state — "writes under this
occupant go to X" is hardware truth independent of which state selected it, so the
per-state variance falls out automatically:

```yaml
occupants:
  - { name: RAM_D000, kind: ram }                                  # on_write: self
  - { name: CHARGEN,  kind: rom, image: chargen, on_write: RAM_D000 }
  - { name: IO,       kind: io }                                   # on_write: self
```

`on_write` takes one of:
- *(omitted)* — writes hit this occupant (default for `ram`/`io`)
- **occupant name** — write-through (C64 RAM-under-ROM)
- **`mechanism`** — writes are bank-mechanism events, not memory writes (NES: stores
  into PRG-ROM ranges *are* mapper register writes; this doubles as the analyzer's
  watch-list for mechanism activity)
- **`none`** — open bus, writes vanish (C64 Ultimax-mode ROMH, later)

**Ghidra realization**: ROM overlay blocks get R+X (not W); the RAM-under block stays
writable. But Ghidra resolves a reference to *one* address space — it cannot send a
`LDA $A000` and a `STA $A000` in the same bank state to different blocks. Loader-policy
mitigation: an analyzer annotates stores into ROM-mapped ranges with a reference to the
`on_write` target. **This is additional `gib.2` evidence**: the proposed context-aware
address resolution hook must be *access-type-aware* — `(context, address, access) →
block` — because even perfect per-context overlay selection cannot represent
write-under-ROM.

## Symbols: sets and provenance

Symbol sources are named sets the user can toggle at import (music-driver RE usually
wants KERNAL entry points but *not* BASIC zero-page variables — games reuse that RAM).
Each source carries `provenance` (upstream project, license, generation date). Bulk sets
are generated files (from mist64/c64ref via an adapted generator — clean license); small
critical sets (KERNAL jump table) may be inline in the descriptor.

`kind: entry` symbols (e.g. `CHROUT` at `$FFD2`) become functions with entry points even
when the KERNAL ROM slot is empty — calls from game code then resolve to named stubs
instead of dangling into the void.

## Types: struct, flags, and enum kinds

`types[]` entries become `DataTypeManager` data types, built at Gradle time by
`GdtBuilder` (`tools/gdtbuilder`) into the machine's `.gdt` archive — see "Resolved
decisions" below. Every entry has `name:` and `kind:`; `kind:` selects one of:

- **`struct`** — a register/memory-layout structure. Fields either inline
  (`fields: [{offset, name, size|type, comment}]`) or pulled from an external
  `source: <file>.yaml` (a file with a top-level `fields:` list, optionally `size:`) —
  see `MOS6526_CIA` in `machines/c64.yaml` / `machines/generated/c64ref-cia.yaml`. A
  field's `type:` may reference another `types[]` entry by name (cross-references are
  topologically ordered, so declaration order doesn't matter).
- **`flags`** — a bitmask enum. `bits: [{bit, name, comment}]`; each member's value is
  derived as `1 << bit`, so members are inherently non-overlapping single-bit flags. See
  `R6510_PORT_BITS`.
- **`enum`** — a sequential-value enum for closed value sets that are *not* bit flags
  (opcode tables, tokenizer byte tables, mode-select constants). `values: [{value, name,
  comment}]`; **`value:` is required on every entry** — unlike `flags`, there is no
  implicit 0..N-1 assignment, because these tables commonly start at a nonzero base
  (e.g. BASIC tokens start at `$80`). A type-level `size:` (bytes; default 1) sets the
  enum's underlying storage size. Duplicate member names or duplicate values within one
  enum fail the build with a clear message (Ghidra's `EnumDataType` would otherwise
  silently overwrite or alias them rather than erroring).

  Like `struct`, an `enum` may pull its values from an external file instead of an
  inline `values:` list, to let multiple archives/dialects share one transcription:
  `source: <file>.yaml` + `lists: [name, ...]`. The source file has a top-level
  `lists:` map of named value-entry lists; the type's `lists:` names one or more of
  them to concatenate, in order. This is how `BASIC_V2_TOKEN` in `machines/c64.yaml`
  pulls its 76 members from `machines/generated/basic-tokens.yaml`'s `basic2-base`
  list — a later dialect (PET BASIC 4, C128 BASIC 7) adds a sibling extension list to
  that same shared file plus one new `types:` entry (`lists: [basic2-base,
  basicN-ext]`) in its own machine YAML, without re-transcribing or forking the base
  list. See the header comment in `machines/generated/basic-tokens.yaml` for the full
  dialect-fork model (BASIC 2/3.5/4/7 share `$80-$CB`; each dialect assigns different
  keywords to the same `$CC+` byte values above that; C128 BASIC 7 additionally has
  two-byte prefix tokens, planned as separate per-prefix enums, not yet implemented).

  Member names should be the literal keyword/mnemonic where Ghidra's enum member
  naming accepts it — verified empirically (`GdtBuilder`, ghidra 12.1.2): `EnumDataType`
  stores member names as plain strings with no symbol-style character restriction, so
  punctuation such as `#`, `(`, `$`, and single-character operator tokens (`+`, `=`,
  `<`, ...) work directly as member names. One caveat found empirically: plain YAML
  scalars that are YAML 1.1 boolean literals (`ON`, `OFF`, `YES`, `NO`, `TRUE`,
  `FALSE`, `Y`, `N`, ...) must be quoted (`"ON"`) or the YAML parser hands `GdtBuilder`
  a `Boolean` instead of a `String`. `comment:` should always repeat the exact
  keyword/mnemonic regardless of what the member name ended up being, so a listing or
  decompiler hover is unambiguous.

## Scaling preview (what will force schema revisions)

- **NES**: the PRG side landed in schema 2 (computed windows, physical spaces,
  layouts, mechanisms list — validated by the UxROM/MMC3 sketches). Still open: the
  CHR/PPU address space is a *second* bus — additional `physical` spaces with their own
  windows (vision doc §5.4), deliberately deferred until code-RE milestones land. The
  board/mapper registry (many parameterizations sharing strategies) is grm-9ux.
- **SNES**: mirroring at scale (LoROM mirrors across dozens of banks) — `repeat_to` may
  need a stride/pattern form. 65816 already has banked addressing in the language.
- **PS1**: no banking, but KSEG mirrors and a BIOS slot; mostly exercises `rom_images` +
  `symbols`.

## Resolved decisions (2026-07-03 review)

1. **Structs: YAML canonical, `.gdt` generated at build time — from the start.** A build
   task (Gradle, Ghidra jars on classpath, `FileDataTypeManager.createFileArchive()`)
   emits the archive from YAML; the loader *only ever consumes `.gdt`* via the standard
   archive API — no YAML parsing in the runtime extension. Rules: the `.gdt` is a build
   artifact (never committed, never hand-edited; CI always regenerates — a release with a
   stale archive is a silent bug). Bonus deliverable: the archive is usable in stock
   Ghidra without the extension — the first published C64 hardware-struct `.gdt`.
   KickAssembler built-ins remain the offset cross-check.
2. **Symbols: YAML canonical + VICE `.sym` importer.** YAML carries what `.sym` can't
   (provenance/license, `kind: entry|vector`, comments — needed for empty-ROM-slot entry
   stubs). The importer accepts community label files and users' own assembler output
   (cc65 `-Ln`, KickAssembler `--vicesymbols`).
3. **Descriptor ↔ language agreement: load-time check.** At import, the loader verifies
   the selected language actually declares `banking.context_register`; fails with a clear
   error naming both sides. Catches field version-skew, needs no build infrastructure.

## Validation (emulator oracle)

- Bank state table cross-checked against VICE: monitor `bank` command names and the
  `$01` semantics in VICE source (`c64mem.c` / `c64pla.c`).
- IO struct offsets cross-checked against KickAssembler built-ins and mist64/c64ref
  `src/c64io/`.
- Future automated check: run a test PRG in VICE, dump memory/bank state at breakpoints,
  compare against what the static model predicts (`gib.1.3` acceptance material).
