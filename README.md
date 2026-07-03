# ghidra-retro-machines

**Give Ghidra the whole machine, not just the file.**

A Ghidra extension providing descriptor-driven system architecture loaders for retro
computers and consoles. Instead of loading a bare binary into an empty address space,
the loader sets up the complete machine around it: RAM/ROM regions, banked memory
windows, IO chip register structs, system ROM slots, and symbol sets — all driven by a
per-machine YAML descriptor with zero hard-coded system knowledge in Java.

**Status: early design.** The descriptor schema and the C64 machine definition exist;
the loader does not yet. See the [roadmap](#roadmap).

## Why

Existing retro loaders for Ghidra stop at "copy bytes to an address." Nobody models the
part that actually makes bare-metal reverse engineering painful: overlapping banked
memory, hardware register annotation, and system-ROM knowledge. The survey that led to
this project ([docs/SURVEY.md](docs/SURVEY.md)) found the same manual setup procedure
being re-executed by hand across the community — this extension automates it.

- **[docs/SCHEMA.md](docs/SCHEMA.md)** — the descriptor schema design
- **[machines/c64.yaml](machines/c64.yaml)** — the Commodore 64, the first machine:
  full memory map, the 8 PLA bank states driven by `$01`, read/write asymmetry
  (RAM-under-ROM write-through), VIC-II/SID/CIA register structs, KERNAL symbols,
  copyright-safe ROM slots

## Design highlights

- **Mechanism + initial state**: bank switching is decomposed into a named, parameterized
  mechanism strategy (C64: "write to `$01`"; NES: the mapper) plus pure-data initial
  state — mirroring how emulators encode the same knowledge.
- **`on_write` occupant property**: read/write asymmetry (C64 writes under ROM reach the
  RAM beneath; NES writes into PRG-ROM ranges *are* mapper events) is first-class.
- **Copyright-safe ROM slots**: system ROMs are never shipped; empty slots still get
  entry-point functions and symbols, so `JSR $FFD2` resolves to `CHROUT` without KERNAL
  bytes present.
- **Emulators as oracle**: hardware facts are cross-checked against accuracy-focused
  emulators (VICE, Mesen2) — validated design, not transcribed folklore.

## Roadmap

1. YAML → `.gdt` data-type archive build pipeline (the archives are usable in stock
   Ghidra, no extension required)
2. C64 PRG loader proof-of-concept: banked windows as overlay spaces, bank-state context
   register, IO annotation
3. Bundled 6510 processor language (bank context register lives there)
4. Flow-tracked bank-state analysis; upstream proposal for context-aware address
   resolution in Ghidra core
5. More machines: NES (mapper mechanisms), SNES, PS1
6. Generalized string detection (PETSCII, screen codes, per-game tile tables)

## Building

Requires a [Ghidra](https://ghidra-sre.org/) installation (12.x) and a matching Gradle
(see `application.gradle.version` in the install's `Ghidra/application.properties`):

```
gradle -PGHIDRA_INSTALL_DIR=<path-to-ghidra> buildExtension
```

The distributable zip lands in `dist/`. Note: a `GHIDRA_INSTALL_DIR` *environment
variable* takes precedence over the `-P` property (standard Ghidra skeleton behavior) —
if both exist, the env var silently wins.

## Relationship to game-music-extraction

This project was incubated in (and serves the reverse-engineering mission of)
[game-music-extraction](https://github.com/CBongo/game-music-extraction), which extracts
and converts video game music toward playable sheet music. The machines targeted here
are the machines whose music drivers that project reverses.

## License

[Apache 2.0](LICENSE)
