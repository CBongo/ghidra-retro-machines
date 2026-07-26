# ghidra-retro-machines

**Give Ghidra the whole machine, not just the file.**

A Ghidra extension providing descriptor-driven system architecture loaders for retro
computers and consoles. Instead of loading a bare binary into an empty address space,
the loader sets up the complete machine around it: RAM/ROM regions, banked memory
windows, IO chip register structs, system ROM slots, and symbol sets — all driven by a
per-machine YAML descriptor with zero hard-coded system knowledge in Java.

**Status: working pipeline, two machines, eight NES boards plus C64.** Descriptor
schema v2 (state tuples, mechanism strategies, physical spaces, computed windows,
mode-dependent layouts), a C64 PRG loader with bank-state analysis (now including
BASIC detokenization), and an iNES loader with a data-driven board registry all work
end-to-end. The machine-independent bank engine tracks banking on the NES discrete
mappers (NROM/UxROM/CNROM/AxROM/GxROM/BNROM), the register-file board Bandai FCG/LZ93D50
(mappers 16/157/159, address-decoded memory-latch) and, as of the M3 milestone, the protocol
mappers MMC1 (serial-shift) and MMC3 (select-data + mode-swapped layouts): on Mega Man
(UNROM) it resolves ~1,500 cross-bank JSR/JMP references into per-bank overlay spaces
and pulls ~7,400 instructions of banked code into analysis. Real-ROM acceptance on
MMC1/MMC3 commercial titles (Metroid, Zelda, SMB3, Crystalis) and an overlay-scale
measurement are the two items still open before M3 closes — see the
[banking design vision](docs/vision-board-banking.md) roadmap. See the
[roadmap](#roadmap) below for the rest.

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
  copyright-safe ROM slots; loads with the bundled
  [6510 language](data/languages/6510.slaspec) that models the on-die `$00`/`$01` port
  as registers
- **[machines/nes-nrom.yaml](machines/nes-nrom.yaml)** — NES NROM, the second machine: physical
  PRG space with computed windows (`PRG[last]` handles NROM-128 mirroring and NROM-256
  with one expression), PPU/APU register structs, board registry keyed by iNES mapper
  number
- **machines/nes-{uxrom,cnrom,axrom,gxrom,bnrom}.yaml** — the discrete-mapper boards:
  `memory-latch` mechanism (store anywhere in the ROM range latches the bank, optional
  bus-conflict AND, field extraction via shift/mask), switchable windows realized as
  home-bank-in-base plus one overlay per alternate bank
- **machines/nes-mmc1.yaml** / **machines/nes-mmc3.yaml** — the M3 protocol-mapper
  boards: `serial-shift` (MMC1's 5-write bit-serial commit protocol) and `select-data`
  with a co-emitted mode bit (MMC3's even/odd bank-select/bank-data pair), both with
  mode-dependent window layouts (`memory.layouts[]`) and function-level bank-state
  requirement warnings ([machines/sketches/](machines/sketches/) keeps the original
  schema-validation sketches as historical examples, superseded as hardware models by
  the shipping descriptors above — see each sketch's header comment)

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
4. ~~Bundled 6510 processor language: models the on-die $00/$01 I/O port as the
   PORTDDR/PORT registers so bank-switch stores are register dataflow. System-neutral
   (the port bits' banking meaning is board wiring, not CPU architecture, so no C64
   naming or bank-context register in the language); the C64 loader resolves it at
   import with a stock-6502 safety fallback~~ (done)
5. ~~Machine-independent bank analyzer + strategy library (`register-write`,
   `memory-latch`); NES discrete mappers with per-bank overlays, bank-switch-helper
   call propagation, cross-bank flow retargeting~~ (done — UxROM tier)
6. ~~MMC1/MMC3 protocol strategies (`serial-shift`, `select-data`), mode-dependent
   layouts, function-level bank-state warnings~~ (done — see
   [docs/vision-board-banking.md](docs/vision-board-banking.md) §9 M3; overlay-scale
   measurement and real-ROM acceptance still open)
7. ~~PETSCII display-string mapping + C64 BASIC detokenizing analyzer~~ (done — see
   [docs/petscii.md](docs/petscii.md) and [docs/basic-analyzer.md](docs/basic-analyzer.md))
8. More machines: GB, SNES, PS1
9. Generalized string detection beyond PETSCII (screen codes, per-game tile tables)

## Building

Requires a [Ghidra](https://ghidra-sre.org/) installation (12.x) and a matching Gradle
(see `application.gradle.version` in the install's `Ghidra/application.properties`):

The recommended setup names the install *root* once, in your machine-local
`~/.gradle/gradle.properties` (never in the repo — this keeps developer drive letters out
of every committed file):

```properties
# ~/.gradle/gradle.properties — the directory that holds ghidra_<ver>_PUBLIC.
# Absolute, WITH a trailing separator: on Windows a bare drive letter is drive-relative
# ("D:" means the current directory on D:), which resolves to "D:ghidra_<ver>_PUBLIC".
# Use a forward slash. A .properties file treats "\" as an escape character, so a
# trailing backslash is read as a line-continuation and silently leaves you with "D:".
ghidraInstallRoot=D:/
```

The build then composes that root with `ghidraTargetVersion` from `gradle.properties`, so
plain `gradle buildExtension` works and **retargeting to a new Ghidra is one line in
`gradle.properties`** — nothing outside the repo needs touching:

```
gradle buildExtension
```

The distributable zip lands in `dist/`.

### Overriding the install dir

Resolution order keeps the stock Ghidra skeleton's precedence unchanged, with
`ghidraInstallRoot` appended as a further fallback:

```
GHIDRA_INSTALL_DIR (env)  →  -PGHIDRA_INSTALL_DIR  →  ghidraInstallRoot
```

```
gradle -PGHIDRA_INSTALL_DIR=<path-to-ghidra> buildExtension
```

Note the upstream quirk this preserves: a `GHIDRA_INSTALL_DIR` *environment variable*
takes precedence over the `-P` property, so if both exist the env var silently wins.

Consequently `ghidraInstallRoot` is skipped entirely whenever `GHIDRA_INSTALL_DIR` is
defined. To fall through to it for a single invocation without touching your environment,
blank the variable on the command line:

```bash
GHIDRA_INSTALL_DIR= gradle buildExtension
```

That assigns the empty string rather than unsetting the variable, and works because the
resolution check is a Groovy truthiness test — `""` is falsy, so it falls through.
(`env -u GHIDRA_INSTALL_DIR gradle …` is the equivalent that genuinely unsets.)

This is the remedy for the one failure mode `ghidraInstallRoot` exists to avoid: an
environment variable is snapshotted when a shell — or a long-running agent session — starts,
so one that outlives a Ghidra retarget cannot be corrected in place, and the version guard
below will fail every build until the session restarts. `ghidraInstallRoot` is instead
re-read from disk on every invocation and composes with whatever `ghidraTargetVersion`
currently says. If you'd rather not think about it, leave `GHIDRA_INSTALL_DIR` unset
permanently.

Whatever the source, `build.gradle` compares the resolved install's own
`application.version` against `ghidraTargetVersion` and fails the build on any mismatch,
so a wrong install can never be used silently.

## Relationship to game-music-extraction

This project was incubated in (and serves the reverse-engineering mission of)
[game-music-extraction](https://github.com/CBongo/game-music-extraction), which extracts
and converts video game music toward playable sheet music. The machines targeted here
are the machines whose music drivers that project reverses.

## License

[Apache 2.0](LICENSE)
