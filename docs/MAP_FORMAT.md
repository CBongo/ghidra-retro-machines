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
  "regions": [ { "name", "start", "end", "kind", "type"?, "comment"? } ],
  "windows": [ { "name", "start", "end",
                 "occupants": [ { "name", "kind", "image"?, "on_write"?,
                    "subregions"?: [ { "name", "start", "end"?, "size"?, "repeat_to"?,
                                       "kind"?, "type"?, "comment"? } ] } ] } ],
  "banking": { "initial_state", "context_register", "state_bits": [...],
               "states": [ { "value", "<windowName>": "<occupantName>", ... } ] },
  "rom_images": { "<imageName>": { "size", "occupant" } },
  "symbols": [ { "set", "default": <bool>, "region"?,
                 "entries": [ { "addr", "name", "kind", "comment"? } ] } ]
}
```

### `system`

Pass-through of the descriptor's `system.id` / `system.name` / `system.cpu.language`.
This is the Ghidra language ID (e.g. `"6510:LE:16:default"`) the loader should target.

### `regions`

Direct translation of `memory.regions[]` — the always-visible (non-banked) parts of the
address space. `type`, when present, names a struct/enum defined in the companion `.gdt`
archive (e.g. `R6510`); `comment` is documentation only.

### `windows`

Direct translation of `memory.windows[]` — banked address ranges whose occupant depends
on the current banking state. Each occupant may carry:

- `image`: names a `rom_images` slot (ROM occupants).
- `on_write`: the occupant name that writes are redirected to while this occupant is
  mapped for reads (read/write asymmetry — see `docs/SCHEMA.md`). The loader is
  responsible for interpreting this; MapCompiler only passes it through unchanged.
- `subregions`: for `io`-kind occupants that are themselves subdivided (chip registers,
  etc). Each subregion carries `start` plus either `end` or `size`, an optional
  `repeat_to` (register-mirroring end address — also passed through for the loader to
  interpret, not expanded here), and an optional `type`/`kind`/`comment`.

### `banking`

Direct translation of the descriptor's `banking:` section: `initial_state`,
`context_register` (the Ghidra language context register name), the ordered `state_bits`
list, and `states[]` — one row per reachable banking-register value, each row being
`value` plus one key per window name (`LOROM`/`CHARIO`/`HIROM` for C64) mapping to the
occupant name active in that window for that state.

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
