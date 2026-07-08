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
  "regions": [ { "name", "start", "end", "kind", "type"?, "comment"?,
                 "readable"?, "writable"?, "executable"? } ],
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
  "banking"?: { "initial_state", "context_register",
                "state":      [ { "name", "bits" } ],
                "mechanisms": [ { "strategy", "params": { ... }, "sets": [...] } ],
                "states"?:    [ { "value", "<windowName>": "<occupantName>", ... } ] },
  "rom_images": { "<imageName>": { "size", "occupant" } },
  "symbols": [ { "set", "default": <bool>, "region"?,
                 "entries": [ { "addr", "name", "kind", "comment"? } ] } ]
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
MapCompiler at build time (grammar: integers, state-field names, `last`/`second_last`/
`offset`, `+ - *`, parentheses — see `docs/SCHEMA.md`) but is passed through as a
string; the bank engine evaluates it at analysis time. A computed window may carry a
window-level `on_write` (typically `"mechanism"`: stores into the range are bank-switch
events, not memory writes). The YAML `size:` alternative to `end:` is resolved at
compile time — the map always carries `end`.

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
when their `when` matches the current bank state.

### `banking`

Omitted entirely for descriptors without a `banking:` section (schema v2 makes it
optional — a bankless board like NES NROM has none). When present:

- `initial_state` — the packed initial bank-state value. The YAML may express it as a
  per-field map (`{ LORAM: 1, HIRAM: 1, CHAREN: 1 }`); MapCompiler packs it (first
  `state` field = bit 0, each subsequent field the bits above).
- `context_register` — the Ghidra *language* context register name (which some
  processor modules expose for the disassembler/decompiler's own use), as opposed to
  `mechanisms` below, which is analyzer configuration.
- `state[]` — the ordered bank-state field tuple (`{ "name": "LORAM", "bits": 1 }`,
  ...): the sub-fields of the context register. Replaces schema v1's flat `state_bits`
  name list; a 1-bit-per-field tuple is equivalent to the old form, and multi-bit
  fields (NES bank registers) are why the change was made.
- `mechanisms[]` — how a bank-aware static analyzer (e.g. `C64BankingAnalyzer`)
  recognizes and interprets writes that change the banking state. A list (schema v1 had
  a single optional `mechanism`) because boards can have several — MMC3 has a
  select-data register pair *and* a mode bit in the same physical register. Each entry:
  `strategy` (which analyzer strategy class interprets it: `register-write`,
  `memory-latch`, `select-data`, `serial-shift`, `io-port`, `mode-register` — only
  `register-write` is implemented today), `params` (strategy-specific, passed through
  from the YAML with numbers normalized to decimal ints and map keys stringified), and
  `sets` (which `state` fields this mechanism feeds, validated at compile time). For
  C64's register-write, `params.address`/`params.mask` mean: the state changes when the
  CPU writes to `address` (1, i.e. `$01`); the new state is the written byte ANDed with
  `mask` (7 — bits 0-2 are LORAM/HIRAM/CHAREN; bits 3-5 are cassette-port lines).
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
input or `known_sha1` matching), each naming the window `occupant` it corresponds to.

### `symbols`

**Inline entries only, for now.** Each entry in the descriptor's `symbols:` list becomes
one output set carrying `set`, `default` (converted from the YAML `on`/`off` string to a
JSON boolean), an optional `region`, and `entries[]`. Only the descriptor's `inline:` list
(if present) is compiled into `entries[]` — sets that instead reference a `source:` file
(bulk symbol data generated from an external reference, not yet implemented) get an empty
`entries: []` while still carrying their `set`/`default`/`region` metadata. When the
`source:`-based generation pipeline lands, those sets will gain populated `entries[]` too;
the schema does not need to change.

## Conventions

- **Addresses are decimal JSON numbers.** The YAML source writes them in hex
  (`0xFFD2`) for human readability; MapCompiler converts every address/size/offset field
  to a plain integer before serializing.
- **Optional keys are omitted, not null**, when absent in the source (e.g. a region with
  no `comment`, an occupant with no `image`).
- The JSON is pretty-printed (`Gson#setPrettyPrinting`) so the compiled artifact is
  human-inspectable for debugging, even though nothing reads it by hand at runtime.
