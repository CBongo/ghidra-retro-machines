# Machine map format (`.map`)

## Purpose

The `.map` file is a **build-time-compiled** JSON rendering of a machine descriptor YAML
(e.g. `machines/c64.yaml`). It exists so the runtime extension's loader can read the
memory-map / banking / symbol facts it needs **without a YAML parser bundled in the
shipped extension**.

JSON was chosen — rather than shipping the YAML directly — because Ghidra already bundles
[gson](https://github.com/google/gson) (`Ghidra/Framework/Generic/lib/gson-2.13.2.jar`),
which is on the classpath of every Ghidra extension for free. The build-time compiler
(`tools/gdtbuilder/src/main/java/gdtbuilder/MapCompiler.java`, Gradle tasks `buildC64Map` /
`buildMap`) parses the YAML with snakeyaml (a build-only dependency, see build.gradle) and
re-emits it as JSON with gson. The runtime loader (a later task, grm-974) parses that JSON
with the same Ghidra-bundled gson — no new dependency either at build time or at load time.

`MapCompiler` is a plain YAML-in/JSON-out translator: unlike `GdtBuilder` (which
constructs Ghidra `DataType` objects and therefore must bootstrap
`Application.initializeApplication`), `MapCompiler` never touches a Ghidra runtime class.

The `.map` file is a **generated build artifact** — like `.gdt`, it is never committed
(see `.gitignore`: `data/machines/*.map`). It is produced fresh by `gradle buildMap` (or
transitively by `gradle buildExtension`) into `data/machines/<id>.map`, and bundled into
the extension zip alongside the corresponding `.gdt`.

## Schema

```
{
  "system":  { "id", "name", "language" },
  "physical"?: [ { "name", "image"?, "size"?, "comment"? } ],
  "regions": [ { "name", "start", "end", "kind", "type"?, "image"?, "comment"?,
                 "readable"?, "writable"?, "executable"?,
                 "copied_from"?: [ { "name", "start", "end", "source", "source_addr",
                                     "entry"?, "disassemble"?, "create_function"?,
                                     "comment"? } ] } ],
  "windows": [ { "name", "start", "end",
                 // exactly one of:
                 "occupants": [ { "name", "kind", "image"?, "on_write"?,
                    "readable"?, "writable"?, "executable"?,
                    "subregions"?: [ { "name", "start", "end"?, "size"?, "repeat_to"?,
                                       "kind"?, "type"?, "comment"?,
                                       "readable"?, "writable"?, "executable"? } ] } ],
                 "maps": { "space", "expr" }, "on_write"? } ],
  "layouts"?: [ { "when": { "<stateField>": <int>, ... },
                  "windows": [ /* same shape as windows[] */ ] } ],
  "banking"?: { "initial_state", "initial_state_expr"?, "context_register"?, "bank_wrap"?,
                "state":      [ { "name", "bits" } ],
                "mechanisms": [ { "strategy", "params": { ... }, "sets": [...] } ],
                "states"?:    [ { "value", "<windowName>": "<occupantName>", ... } ] },
  "rom_images": { "<imageName>": { "size", "occupant" } },
  "symbols": [ { "set", "default": <bool>, "region"?,
                 "entries": [ { "addr", "name", "kind", "comment"? } ] } ],
  "formats"?: { "<formatName>": { /* loader-policy metadata */ } }
}
```

### `system`

Pass-through of the descriptor's `system.id` / `system.name` / `system.cpu.language`.
This is the Ghidra language ID (e.g. `"6510:LE:16:default"`) the loader should target.

`board`, when present, carries the descriptor's board-registry keys — currently
`ines_mappers`, the iNES mapper numbers this board serves. `NesRomLoader` builds its
board registry by scanning every bundled `machines/*.map` for this key (vision doc §3.1:
boards are chosen like languages, from data), so adding a NES board is adding a
descriptor — no Java changes. The `system.id` doubles as the user-override key for the
loader's "NES Board" import option.

### `regions`

Direct translation of `memory.regions[]` — the always-visible (non-banked) parts of the
address space. `type`, when present, names a struct/enum defined in the companion `.gdt`
archive (e.g. `R6510`); `comment` is documentation only. `readable`/`writable`/`executable`
are optional sparse permission overrides — see below and `docs/SCHEMA.md`.

`image`, when present on a fixed `kind: rom` region, names the corresponding
`rom_images` slot. This optional reverse link is the bankless counterpart of an
enumerated ROM occupant's `image`; the ROM slot's `occupant` target remains authoritative.
A loader creates the region uninitialized when the user has supplied no ROM and
initializes the same block when the slot is populated.

`copied_from`, when present, is the region's list of **boot-copy hints** (grm-1.7.1.2): each
entry declares that the destination sub-range `[start, end]` of *this* region is a verbatim
copy of `source_addr` in the block named by `source`. `source` is resolved in the same name
space `on_write` uses — a declared region **or** a window occupant (on the C64 the CHRGET
source, `KERNAL`, is an occupant, not a region). `entry` optionally names a mid-range
disassembly start for a headered payload; `disassemble` / `create_function` are the payload's
code directives (both default false); `comment` is documentation. All four address keys are
compiled to plain JSON integers.

`MapCompiler` fails the build if `source` names nothing declared, if `end < start`, if the
range escapes its owning region, or if `entry` falls outside the range — a typo would
otherwise be indistinguishable at runtime from the legitimate "user supplied no ROM" case,
since `DescriptorCopyHintAnalyzer` ignores a hint whose source bytes are unreadable
(`docs/smc-inplace-vs-overlay.md` §6).

`prg_placeable` is an optional boolean marking a non-`ram` region that a CBM PRG may still
legitimately land in — the C64's `P6510` on-die port at `$00/$01` is the case it exists for.
There is no field naming a single fixed image-carve region: a PRG's header-selected image may
span ordinary RAM regions, RAM-under-ROM/I/O occupants and the `$FFFF` wrap boundary, so the
CBM loaders derive destinations from every `kind: ram` region, every `prg_placeable` region
and `kind: ram` window occupants instead. NES boards have neither, because their PRG banks are
ROM windows rather than a RAM image. (A `load_target` boolean served the fixed-region role
until grm-hap retired it as unread; see `docs/SCHEMA.md`.)

### `physical`

Present only for descriptors with a `physical:` section (schema v2): named physical
backing spaces (e.g. NES `PRG`) that computed windows map into. `image` names the
content source (a container payload like the iNES PRG-ROM, or a `rom_images` slot);
`size` is usually absent — it comes from the loaded container's header.

### `windows`

Direct translation of `memory.windows[]` — banked address ranges whose contents depend
on the current banking state. A window carries exactly one of `occupants` (enumerated)
or `maps` (computed).

**Computed windows** (`maps`) show a slice of a physical space:
`"maps": { "space": "PRG", "expr": "bank * 0x4000" }`. The expression was validated by
MapCompiler at build time (grammar: integers, state-field names, `last`/`second_last`,
`+ - * >>`, parentheses — see `docs/SCHEMA.md`) but is passed through as a
string; the bank engine evaluates it at analysis time. A computed window may carry a
window-level `on_write` (typically `"mechanism"`: stores into the range are bank-switch
events, not memory writes). The YAML `size:` alternative to `end:` is resolved at
compile time — the map always carries `end`.

`>>` (added bead `grm-hsv.2`, for MMC1's 32K PRG mode, which ignores `prg_bank`'s LSB:
`(prg_bank >> 1) * 0x8000`) is a logical right-shift on the running `long` accumulator,
binding at the SAME precedence as `*` (left-associative) — deliberately not C's
looser-than-`+-` shift precedence, since this grammar has no case needing the
distinction and one rule ("`*`, `>>` chain left-to-right, both bind tighter than `+ -`")
is simpler to state than importing C's historical quirk. Parenthesize explicitly when a
specific grouping with `*` matters.

**Enumerated windows** (`occupants`): each occupant may carry:

- `image`: names a `rom_images` slot (ROM occupants).
- `on_write`: the occupant name that writes are redirected to while this occupant is
  mapped for reads (read/write asymmetry — see `docs/SCHEMA.md`). The loader is
  responsible for interpreting this; MapCompiler only passes it through unchanged.
- `subregions`: for `io`-kind occupants that are themselves subdivided (chip registers,
  etc). Each subregion carries `start` plus either `end` or `size`, an optional
  `repeat_to` (register-mirroring end address — also passed through for the loader to
  interpret, not expanded here), and an optional `type`/`kind`/`comment`.

Occupants and subregions may also carry `readable`/`writable`/`executable` — see next.

### Permission overrides (`readable`/`writable`/`executable`)

Optional booleans on any region, occupant, or subregion. The loader derives a block's
permissions from its `kind` (`ram`→r+w+x, `rom`→r+x, `io`→r+w, non-executable and marked
volatile); these three fields override one attribute at a time for hardware quirks that
don't fit the kind's default (e.g. CHARGEN is `kind: rom` but its glyph data is never
executed, so it sets `executable: false`). **MapCompiler passes them through only when
present in the source YAML — it never emits kind-derived defaults into the JSON.** The
kind→default table and the override-vs-new-kind design rule are documented in
`docs/SCHEMA.md`.

### `layouts`

Present only for descriptors with `memory.layouts:` (schema v2): mode-dependent window
sets. Each entry carries `when` — the state-field values that select this layout (e.g.
MMC3's `{ "prg_mode": 0 }`) — and `windows`, identical in shape to the top-level
`windows[]`. Windows in `memory.windows` are present in every mode; layout windows only
when their `when` matches the current bank state. Every layout's `when` must name the
same single `banking.state` field (the "mode field"); a layout window defined
identically (same start/end/`maps`/`on_write`) across every layout is hoisted and
behaves exactly like a top-level `memory.windows[]` entry.

**Runtime behavior.** `NesRomLoader` realizes each layout window's instances with
"home-in-base" placement per mode: the home mode's home bank is the plain base-space
block `NAME`; every other instance is an overlay. A **mode-varying window** (its
`maps`/`on_write`/shape differ across at least one layout) always carries the `_M<mode>`
qualifier once it leaves the home mode+bank — there is no bare `NAME_B<bank>` form for
these, because the same bank number under a different mode is unrelated content and the
name must say so:

| Instance | Block/overlay name |
| --- | --- |
| Home mode, home bank (or a fixed expr) | `NAME` (base space) |
| Home mode, non-home bank | `NAME_M<mode>_B<bank>` |
| Non-home mode, fixed expr | `NAME_M<mode>` |
| Non-home mode, bank `<bank>` | `NAME_M<mode>_B<bank>` |

A layout window whose definition (start/end/`maps`/`on_write`) is **identical across
every mode** is hoisted (see above) and named exactly like a flat top-level
`memory.windows[]` entry instead — plain `NAME` for the home bank, `NAME_B<bank>` for a
non-home bank, **never** `_M<mode>`-qualified, since there is nothing mode-specific to
distinguish (confirmed by the goldens: `nesmodetest.dump` shows mode-varying
`W8000_M0_B1` even though mode 0 is the home mode; `nesmmc3test.dump` shows hoisted
`WA000_B3` with no mode qualifier at all).

`BoardBankAnalyzer` consumes the same normalized plan (`DescriptorSupport.planWindows`)
to retarget references and clamp bank state to residence: an instruction physically
inside a `NAME_M<mode>` or `NAME_M<mode>_B<bank>` overlay has the mode field (and, for
the latter, the bank field) forced known from the overlay it's found in, and a
reference landing in a layout window's offset range is retargeted through a two-level
lookup — the mode field picks which layout's instance covers the offset, then (for a
switchable instance) the bank field picks which of that instance's per-bank overlays is
the target — using the same home-in-base skip rule as `memory.windows[]` (a reference
that resolves to the home mode's home bank needs no overlay reference at all). The
single-mode-field constraint above is a hard runtime requirement, not just a build-time
one: the analyzer skips `memory.layouts[]` entirely (logging why) if it can't determine
one mode field the same way the loader did.

### `banking`

Omitted entirely for descriptors without a `banking:` section (schema v2 makes it
optional — a bankless board like NES NROM has none). When present:

- `initial_state` — the packed initial bank-state value. The YAML may express it as a
  per-field map (`{ LORAM: 1, HIRAM: 1, CHAREN: 1 }`); MapCompiler packs it (first
  `state` field = bit 0, each subsequent field the bits above).
- `initial_state_expr` *(optional)* — `fieldName -> expression` for fields whose seed is
  **image-relative** and therefore cannot be packed at build time (bead `grm-y0ml`;
  `nes-mmc5.map`'s `{"bank_5117": "(image_size >> 13) - 1"}` is the only shipped instance).
  The expression grammar is the `maps:` one restricted to a single identifier,
  `image_size` (the image's size in bytes); see docs/SCHEMA.md's "Initial state" for why
  it is not `last`. Absent for every descriptor whose `initial_state` is literals-only,
  which keeps those `.map` files byte-identical to the pre-`grm-y0ml` output.
  **`initial_state` remains complete and authoritative on its own**: a field carried here
  contributes 0 to it, so a consumer that ignores this key still gets a usable state (the
  approximation that shipped before the key existed). The loader resolves each expression
  against the real image, width-checks the result, and publishes the resolved packed value
  in the `Retro Machines.Initial State` program property, which the analyzer prefers.
- `bank_wrap` *(optional, bead `grm-p25h`)* — the board's bank-number truncation policy:
  "this board's bank registers are wider than the cartridge decodes, and the hardware drops
  the high bits". Absent on every board but MMC5 today, and absence means nothing is ever
  wrapped, so those `.map` files stay byte-identical. Two forms, distinguished by JSON type:
  - the **string** `"image"` — the analyzer *derives* the mask from the window's **realized**
    bank set (the overlays the loader actually created — never a header field, which the
    analyzer does not have), applying it only when that set is exactly `{0 … n-1}` with `n` a
    power of two, and declining otherwise. Derivation is inference, so it is guarded.
  - a **number** (e.g. `31`) — an explicit mask, applied unconditionally as `v & mask`. It is
    a *stated hardware fact* about how many address lines the cartridge wires, not an
    inference, so the guard above deliberately does **not** apply to it. `MapCompiler`
    validates it at build time instead: `mask + 1` must be a power of two, and the mask must
    fit some declared `banking.state` field.

  Placement is unaffected either way: no extra overlay is created for an out-of-range bank
  value, and the annotation always shows both the raw and the canonical bank.
- `context_register` *(optional)* — the Ghidra *language* context register name (which
  some processor modules expose for the disassembler/decompiler's own use), as opposed
  to `mechanisms` below, which is analyzer configuration. When omitted, or when the
  selected language does not expose the named register, only context stamping is skipped;
  descriptor-driven bank analysis still uses `state`, `mechanisms`, and `initial_state`.
- `state[]` — the ordered bank-state field tuple (`{ "name": "LORAM", "bits": 1 }`,
  ...): fields of the abstract bank state, whether or not a context register is present.
  Replaces schema v1's flat `state_bits` name list; a 1-bit-per-field tuple is equivalent
  to the old form, and multi-bit fields (NES bank registers) are why the change was made.
- `mechanisms[]` — how a bank-aware static analyzer (e.g. `C64BankingAnalyzer`)
  recognizes and interprets writes that change the banking state. A list (schema v1 had
  a single optional `mechanism`) because boards can have several — MMC3 has a
  select-data register pair *and* a mode bit in the same physical register. Each entry:
  `strategy` (which analyzer strategy class interprets it: `register-write`,
  `memory-latch`, `select-data`, `serial-shift`, `io-port`, `mode-register` —
  `register-write`, `memory-latch`, `select-data`, and `serial-shift` are implemented
  today; the rest belong to later milestones), `params` (strategy-specific, passed through from the YAML
  with numbers normalized to decimal ints and map keys stringified), and `sets` (which
  `state` fields this mechanism feeds, validated at compile time). For C64's
  register-write, `params.address`/`params.mask` mean: the state changes when the CPU
  writes to `address` (1, i.e. `$01`); the new state is the written byte ANDed with
  `mask` (7 — bits 0-2 are LORAM/HIRAM/CHAREN; bits 3-5 are cassette-port lines). MMC3's
  `select-data` mechanism (`SelectDataBankSwitchStrategy`, bead `grm-6a7.1`) is the
  richest shipped example of a multi-field mechanism: one physical even/odd register
  pair (`params.start`/`params.end`, recognized by address parity, not two fixed
  addresses) feeds FOUR `sets` fields at once (`select`, `prg_mode`, `r6`, `r7`) —
  `params.select_field`/`select_mask`/`select_shift` say where the register-select index
  sits in the byte a select (even-address) write recovers; `params.mode_field` (optional)
  and `mode_mask`/`mode_shift` say where a co-emitted mode bit sits in that *same* byte
  (MMC3 folds its "mode register" into the select write itself — no separate
  `mode-register` mechanism instance); `params.targets` maps a select value to the
  `state` field a data (odd-address) write targets when that value was last selected
  (`{"6":"r6","7":"r7"}` — a data write whose select value has no `targets` entry, e.g.
  MMC3's CHR registers 0-5, is a no-op on every tracked field by design). Every field name
  a multi-field mechanism's params reference must also appear in `sets` — the analyzer
  computes each such field's field-local `(lsb, width)` from the `state` tuple's packing
  and injects it into `params._field_layout` (an analyzer-runtime addition, not something
  MapCompiler writes) before configuring the strategy, so a strategy never has to
  hand-duplicate offsets that must stay in lockstep with `state`'s declared order.
  MMC1's `serial-shift` mechanism (`SerialShiftBankSwitchStrategy`, bead `grm-hsv.1`)
  models a bit-serial shift register: five consecutive bit-7-clear writes anywhere in
  `params.start`/`params.end` each contribute one bit (LSB first) of a byte that commits
  on the fifth write, and a bit-7-*set* write to any address in range resets the shifter
  instead. `params.targets` maps the 5th write's OWN ADDRESS bits 14:13 within the range
  (0-3 — not a fixed constant; real games write non-canonical addresses inside a
  register's 8 KiB window) to `{fields: [{name, shift, bits}, ...]}`: a MULTI-field
  deposit from the one reassembled 5-bit value (MMC1 target 0 splits into `mirroring`
  and `prg_mode`; target 3 is `prg_bank`; targets 1/2, CHR0/CHR1, are recognized but
  omitted — same no-poison contract as `select-data`'s untracked CHR registers).
  `params.reset` maps field name to a literal value deposited on a bit-7-set write
  (MMC1: `{prg_mode: 3}` — every other field, including `mirroring`, survives a reset
  untouched). The strategy's primary recognizer is a STATIC instruction-shape walk of
  the fully-unrolled `STA/LSR A/STA/LSR A/.../STA` commit chain every surveyed
  commercial mapper-1 game actually emits (never the counted `STA/LSR/DEY/BNE` loop
  some references present as canonical) — see the class javadoc for the exact
  backward/forward walk and its bit-7 resolution shortcut (an `LSR A`-preceded store's
  bit 7 is known clear by construction, since `LSR` always shifts in a 0, so it never
  needs — and must not use — the generic backward value scanner, which does not model
  shifts bit-wise). A JSR'd switch-helper wrapping a chain (the dominant commercial
  idiom — `LDA #bank / JSR SwitchBank`) deposits the call-site argument through the
  helper's own commit-site target's `targets` field list, not across the whole
  mechanism window (`BankSwitchStrategy.depositHelperArgument`; a helper committing to
  an unconfigured CHR target is a verified no-op at its call sites).
  A `memory-latch` mechanism (`MemoryLatchBankSwitchStrategy`) latches on a store
  *anywhere* in `params.start`/`params.end`, extracting the field with `params.mask`/
  `shift` (GxROM's PRG bits 4-5 = `{shift: 4, mask: 0x3}`) and optionally ANDing the
  driven value with a constant, bank-invariant ROM byte at the store target when
  `params.bus_conflict` is set (boards without bus isolation, e.g. UxROM). Optional
  `params.addr_mask`/`addr_match` restrict the latch to writes whose address satisfies
  `(offset & addr_mask) == addr_match` — a register-file board (Bandai FCG/LZ93D50,
  mappers 16/157/159, bead `grm-9ty`) mirrors many registers across one range and
  decodes the target from low address bits, so the PRG register (`{addr_mask: 0x000F,
  addr_match: 0x0008}`, register `$8`) latches while its CHR/mirroring/IRQ siblings in
  the same range do not.
- `states[]` — the enumerated truth table, present only for boards with
  enumerated-occupant windows: one row per reachable state, each row being `value` (the
  packed state — computed by MapCompiler from the YAML row's per-field values) plus one
  key per window name (`LOROM`/`CHARIO`/`HIROM` for C64) mapping to the occupant name
  active in that window for that state. Boards whose windows are all computed (`maps`)
  have no `states` key.

#### Schema v1 → v2 migration diff (c64.map, reviewed 2026-07-08)

Regenerating `c64.map` from the schema-2 `c64.yaml` reproduces the v1 output
byte-identically **except** for one hunk inside `banking` (bead `grm-os4` acceptance —
diff reviewed and intentional):

- `"state_bits": ["LORAM", "HIRAM", "CHAREN"]` became
  `"state": [{"name":"LORAM","bits":1}, {"name":"HIRAM","bits":1}, {"name":"CHAREN","bits":1}]`
- `"mechanism": {"strategy":"register-write","address":1,"mask":7}` became
  `"mechanisms": [{"strategy":"register-write","params":{"address":1,"mask":7},"sets":["LORAM","HIRAM","CHAREN"]}]`

`regions`, `windows`, `states` rows, `rom_images`, and `symbols` are byte-identical.
The `.gdt` is unaffected (GdtBuilder reads only the descriptor's `types:` section,
which schema v2 does not touch; note `.gdt` archives are not byte-reproducible between
builds regardless — Ghidra embeds per-build IDs). `C64BankingAnalyzer` was updated in
the same change to read the v2 keys.

### `rom_images`

Direct translation of `rom_images:` — named ROM slots the loader can populate (from user
input or `known_sha1` matching). `occupant` is the target block name: it may name either a
banked-window occupant (the original schema-2 use) or an always-visible `kind: rom`
region. When it names a region, the slot size must equal the region. If the region also
declares the optional reverse `image` link, it must name that slot. The existing key
remains unchanged so descriptor loaders can treat window occupants and fixed regions
uniformly.

### `formats`

When a descriptor has top-level `formats:`, MapCompiler preserves that mapping in the
compiled map. Numeric YAML scalars are normalized to JSON integers, but the tree is
otherwise loader-policy data, descriptor-defined rather than hard-coded in the compiler.
The key is omitted when the source descriptor has no formats.

What lives under `formats.prg` today, and who reads it:

| key | consumer |
| --- | --- |
| `placement: load_address` | `MapCompiler.usesLoadAddressPlacement` — gates the PRG/RAM placement-coverage check |
| `basic.token_enum`, `basic.prefix_enums`, `basic.petscii_variant` | `C64BasicAnalyzer` (all three CBM machines) |
| `comment` | documentation |

`extensions` and `header` keys used to sit here and were never read — `AbstractCbmPrgLoader`
hardcodes the `.prg` suffix test and the 2-byte little-endian load address, on purpose, since
that suffix test is a cheap early-out ahead of a descriptor parse that would otherwise run once
per file Ghidra probes. They were removed in grm-hap; `machines/c64.yaml` records the detail,
including why the declared `.p00` extension was actively wrong rather than merely inert.

### `symbols`

Each entry in the descriptor's `symbols:` list becomes one output set carrying `set`,
`default` (converted from the YAML `on`/`off` string to a JSON boolean), an optional
`region`, and `entries[]`. `entries[]` is assembled from up to two sources, merged in this
order:

1. The set's `inline:` list (a hand-curated seed), if present.
2. A `source:` file (bulk symbol data, e.g. generated from mist64/c64ref — see
   `machines/generated/`), if present and readable. The file must have a top-level
   `entries:` list; if the referenced file does not exist, `MapCompiler` prints a warning
   and falls back to the inline entries only (the build still succeeds).

**Inline entries take precedence over `source:` entries at the same address**: entries are
deduplicated by `addr`, first occurrence wins, and inline is always processed first — so an
address named inline is never overwritten by the generated source, and an inline list can be
used as an authoritative override on top of a bulk-generated set. Both `inline:` and
`source:` may be used together on the same set, or either alone.

## Conventions

- **Addresses are decimal JSON numbers.** The YAML source writes them in hex
  (`0xFFD2`) for human readability; MapCompiler converts every address/size/offset field
  to a plain integer before serializing.
- **Optional keys are omitted, not null**, when absent in the source (e.g. a region with
  no `comment`, an occupant with no `image`).
- The JSON is pretty-printed (`Gson#setPrettyPrinting`) so the compiled artifact is
  human-inspectable for debugging, even though nothing reads it by hand at runtime.
