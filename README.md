# ghidra-retro-machines

**Give Ghidra the whole machine, not just the file.**

A Ghidra extension providing descriptor-driven system architecture loaders for retro
computers and consoles. Instead of loading a bare binary into an empty address space,
the loader sets up the complete machine around it: RAM/ROM regions, banked memory
windows, IO chip register structs, system ROM slots, and symbol sets — all driven by a
per-machine YAML descriptor with zero hard-coded system knowledge in Java.

**Status: working pipeline, two machines.** Descriptor schema v2 (state tuples,
mechanism strategies, physical spaces, computed windows), a C64 PRG loader with
bank-state analysis, and an iNES loader with a data-driven board registry (NROM
baseline) all work end-to-end. See the [roadmap](#roadmap).

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
- **[machines/nes.yaml](machines/nes.yaml)** — NES NROM, the second machine: physical
  PRG space with computed windows (`PRG[last]` handles NROM-128 mirroring and NROM-256
  with one expression), PPU/APU register structs, board registry keyed by iNES mapper
  number ([machines/sketches/](machines/sketches/) holds the UxROM/MMC3 schema
  validation sketches that the banked-mapper milestones will graduate)

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

1. ~~YAML → `.gdt` data-type archive build pipeline~~ (done — the archives are usable in
   stock Ghidra, no extension required)
2. ~~C64 PRG loader proof-of-concept: banked windows as overlay spaces, flow-tracked
   bank-state analysis, IO annotation~~ (done; upstream proposal posted as ghidra
   discussion #9349)
3. ~~Descriptor schema v2 + iNES loader with board registry, NROM end-to-end~~ (done)
4. Bundled 6510 processor language (bank context register lives there)
5. Machine-independent bank analyzer + strategy library; NES banked mappers
   (UxROM tier, then MMC1/MMC3) — see [docs/vision-board-banking.md](docs/vision-board-banking.md)
6. More machines: GB, SNES, PS1
7. Generalized string detection (PETSCII, screen codes, per-game tile tables)

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
