# ghidra-retro-machines

**Give Ghidra the whole machine, not just the file.**

A Ghidra extension providing descriptor-driven system architecture loaders for retro
computers and consoles. Instead of loading a bare binary into an empty address space,
the loader sets up the complete machine around it: RAM/ROM regions, banked memory
windows, IO chip register structs, system ROM slots, and symbol sets — all driven by a
per-machine YAML descriptor with zero hard-coded system knowledge in Java.

**Status: working pipeline, three home-computer descriptors (C64, C128, PET 4032) and one
NES descriptor family spanning nine boards.** Descriptor schema v2 (state tuples, mechanism
strategies, physical spaces, computed windows, mode-dependent layouts), PRG loaders with
bank-state analysis (including BASIC detokenization for C64/PET/C128), and an iNES loader
with a data-driven board registry all work end-to-end. The machine-independent bank engine
tracks banking on the NES discrete mappers (NROM/UxROM/CNROM/AxROM/GxROM/BNROM), the
register-file board Bandai FCG/LZ93D50 (mappers 16/157/159, address-decoded memory-latch)
and, as of the M3 milestone, the protocol mappers MMC1 (serial-shift) and MMC3 (select-data
+ mode-swapped layouts): on Mega Man (UNROM) it resolves ~1,500 cross-bank JSR/JMP
references into per-bank overlay spaces and pulls ~7,400 instructions of banked code into
analysis. The overlay-scale measurement is done, and an initial real-ROM acceptance pass
against MMC1/MMC3 commercial titles has been recorded — see the
[banking design vision](docs/vision-board-banking.md) §9 M3 for current per-board results
and what remains open. See the [roadmap](#roadmap) below for the rest.

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
- **[machines/pet4032.yaml](machines/pet4032.yaml)** — the Commodore PET 4032 (32K,
  40-column, 12-inch CRTC): BASIC 4.0 workspace/token tables, 6520 PIA/6522 VIA/6545 CRTC
  register structs, fixed ROM slots; no banked memory
- **[machines/c128.yaml](machines/c128.yaml)** — the Commodore 128 in native mode
  (documented `CR=$00`/BASIC bank 15 power-up view): BASIC 7.0 with two-byte prefix
  tokens, MMU register struct, VIC-IIe/VDC/SID/CIA register structs; runs on the same
  6510 language as the C64 (the 8502 is 6510/6502-compatible)
- **[machines/nes-nrom.yaml](machines/nes-nrom.yaml)** — NES NROM: physical
  PRG space with computed windows (`PRG[last]` handles NROM-128 mirroring and NROM-256
  with one expression), PPU/APU register structs, board registry keyed by iNES mapper
  number
- **machines/nes-{uxrom,cnrom,axrom,gxrom,bnrom}.yaml** — the discrete-mapper boards:
  `memory-latch` mechanism (store anywhere in the ROM range latches the bank, optional
  bus-conflict AND, field extraction via shift/mask), switchable windows realized as
  home-bank-in-base plus one overlay per alternate bank
- **[machines/nes-bandai-fcg.yaml](machines/nes-bandai-fcg.yaml)** — the Bandai
  FCG/LZ93D50 register-file board (iNES mappers 16/157/159): address-decoded
  memory-latch, no serial-shift/select-data protocol
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
- **A real 6510 language**: Ghidra ships no 6510, so the extension bundles one
  (`6510:LE:16:default`). It models the on-die I/O port at `$00`/`$01` as registers, so the
  C64 bank-switch idiom `LDA $01 / AND #$F8 / ORA #$05 / STA $01` becomes ordinary register
  dataflow that the bank analyzer can follow. The port is named anonymously and carries no
  banking meaning — what its bits *do* is board wiring, so that lives in the machine
  descriptor.
- **Undocumented opcodes, opt-in**: sibling `6510:LE:16:undoc` and `6502:LE:16:undoc`
  variants decode the undocumented (commonly "illegal") NMOS opcodes — `SLO`, `LAX`, `SAX`,
  `DCP` and the rest — that demos, packers and music drivers use as load-bearing
  instructions. Deliberately not the default: once all 256 opcode bytes decode, speculative
  disassembly runs *through* data tables instead of stopping at an invalid byte, which costs
  more than it gains on anything that doesn't use them. Pick the variant in the import
  dialog's language list, or pass `-processor 6510:LE:16:undoc` headlessly.
- **A vendored SPC700 language, decode-only so far**: `SPC700:LE:16:retro` bundles the
  SPCdra project's SLEIGH decode table for the SNES sound co-processor. Disassembly
  (mnemonics, operands, instruction length) is sound; the p-code semantics carried over
  from upstream are known-incorrect and are being rewritten (bead grm-c9d.3) — don't trust
  decompiler output for this language yet.

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
   measurement is done, real-ROM acceptance has an initial pass recorded but is not yet
   closed against the full title list)
7. ~~PETSCII display-string mapping + C64 BASIC detokenizing analyzer~~ (done — see
   [docs/petscii.md](docs/petscii.md) and [docs/basic-analyzer.md](docs/basic-analyzer.md))
8. ~~PET 4032 and C128 native-mode descriptors + PRG loaders, BASIC 4/7 token-dialect
   detokenizing (including C128's two-byte prefix tokens)~~ (done)
9. More machines: GB, SNES, PS1
10. Generalized string detection beyond PETSCII (screen codes, per-game tile tables)

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

[Apache 2.0](LICENSE). Third-party material bundled here is recorded in
[NOTICE](NOTICE) — currently the undocumented-opcode SLEIGH semantics in
`data/languages/6510_illegal.sinc`, vendored from
[anarkiwi/deity-informant](https://github.com/anarkiwi/deity-informant) (also Apache 2.0)
and kept byte-identical to upstream so re-syncs stay a clean diff; and the SPC700 decode
table in `data/languages/spc700core.sinc`/`spc700ops.sinc`, vendored from
[qwertymodo/SPCdra](https://github.com/qwertymodo/SPCdra) (also Apache 2.0) as a fork
point rather than a sync target, since the p-code semantics built on top of it diverge
permanently once bead grm-c9d.3 rewrites them.

Note that project, and [grue74/ghidra-c64helpers](https://github.com/grue74/ghidra-c64helpers),
each also publish a language with the id `6510:LE:16:default`. Ghidra requires language ids
to be unique, so installing two of them at once will conflict; that is the only situation in
which it matters. Likewise, SPCdra itself publishes `spc700:LE:16:default`; this extension's
SPC700 language deliberately uses the id `SPC700:LE:16:retro` instead, so both can be
installed side by side without conflict.
