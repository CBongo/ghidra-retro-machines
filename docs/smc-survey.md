# Self-Modifying Code Recovery: Emulator & Debugger Survey (grm-1.7.4)

Survey of Ghidra 12.1 machinery for recovering self-modified code — ROM→RAM copies,
decrypt-on-the-fly, cross-processor uploads — resolving the grm-1.7 epic's design
tension: which patterns get **static modeling**, which get **emulation-assisted
recovery**, and which stay **documented manual workflow**. Source evidence from
D:/git/ghidra @ `e6ee047c5a` (master, 12.1-era) unless noted.

## 1. The three candidate machineries

Per the epic (and user direction), the Debugger is evaluated as a first-class recovery
path alongside headless emulation, in two distinct flavors:

| | A. Headless p-code emulation | B. Debugger, pure-emulation target | C. Debugger + external emulator (TraceRmi) |
|---|---|---|---|
| Driver | Analyzer/script code | Human in GUI | Human + connector |
| Fidelity | p-code semantics only; IO by policy | same as A | real hardware (VICE/Mesen accuracy) |
| Output | bytes written straight into Program | Trace snapshots; *Copy Into Program* (GUI) | Trace snapshots from live machine |
| Automatable | fully | no (service + copy action are GUI plugins) | partially (connector scripting) |
| Exists today | yes, fully supported | yes, shipped | **no retro connector exists** — would be new work |

## 2. Path A: headless p-code emulation — the supported, automatable path

**API status.** `EmulatorHelper` and the classic `ghidra.app.emulator` stack are
`@Deprecated(since = "12.1", forRemoval = true)` with explicit direction to
`PcodeEmulator` (`EmulatorHelper.java:52-54`). `PcodeEmulator`'s class doc calls it
"suitable for unit testing and scripting" and directs integrations to the composable
`PcodeEmulationCallbacks` rather than subclassing (`PcodeEmulator.java:29,42-52`).
So: **all new work targets `ghidra.pcode.emu.PcodeEmulator`**; anything written
against `EmulatorHelper` is dead on arrival.

**Program binding.** `EmulatorUtilities` (Framework/Emulation, "utilities for working
with *plain* emulators (not trace- or debugger-bound) and programs in scripts")
provides the whole harness floor: `loadProgram(machine, program[, blockSize])`
copies program bytes into emulator state, `chooseStackRange*` handles stack setup,
`initializeRegisters(thread, program, pc)` seeds context (`EmulatorUtilities.java:78,
103,118,248`).

**Run control.** No built-in fuel counter, but stepping is script-driven
(`thread.stepInstruction()` in a loop = trivial fuel/wall-clock bounds), plus:
- `PcodeMachine.addBreakpoint(address, sleighCondition)` — p-code-inject-based, does
  not modify the emulated image (`PcodeMachine.java:284-296`);
- `PcodeMachine.inject(address, sleighSource)` — replace/stub code at an address
  (`:254`), the sanctioned way to skip or fake routines (e.g. KERNAL calls);
- `setSuspended(true)` from a cancel listener (`:207`; the in-tree example wires it
  to the script monitor).

**Fault policy (the IO-register question).** Two layers, exactly what retro code needs:
- `PcodeEmulationCallbacks.readUninitialized(...)` fires when uninitialized state is
  read and may initialize it and continue (`PcodeEmulationCallbacks.java:385,442`) —
  this is the "unmapped IO read returns 0 (or a descriptor-supplied value)" hook.
- Default behavior without a callback: data reads of uninitialized memory warn and
  return zeros; instruction *decode* into uninitialized memory raises
  `DecodePcodeExecutionException` (`BytesPcodeExecutorStateSpace.java:212-249`) — a
  clean natural stop condition when a decryptor jumps somewhere we failed to produce.
- `beforeLoad`/`beforeStore` (`:200,:228`) additionally intercept *mapped* addresses,
  so IO regions that exist as blocks (our loaders create them) can get modeled reads.

**Write capture.** `dataWritten` callbacks (`:297-357`) deliver every store with
address and size — an exact dirty-set accumulator. Recovery = run bounded, collect
dirty set, read those ranges from emulator state, write into the Program. No
diffing, no trace database required.

**SMC correctness.** The interpreted emulator is self-modifying-code-safe *by
construction*: `SleighInstructionDecoder.parseNewBlock` pseudo-disassembles **one
instruction at a time from live emulator state**
(`SleighInstructionDecoder.java:98-104`, with an explicit source comment about
self-modifying code), and the one-block cache is dropped on any branch outside it
(`:81-89,117-126`). Caveat: `JitPcodeEmulator` compiles multi-instruction passages —
do **not** use the JIT emulator for SMC workloads without verifying its
invalidation-on-write story; the interpreted default is both correct and plenty fast
for KB-scale 8-bit loops.

**Write-back.** Plain `Memory` API inside a transaction: `setBytes` for in-place
patching, `createInitializedBlock(..., overlay=true)` for a "DECRYPTED_xxxx"
alternate view, and — load-bearing for run-from-elsewhere —
`Memory.createByteMappedBlock(name, start, mappedAddress, length, scheme, overlay)`
(`Memory.java:363`): a block whose bytes are *mapped 1:1 from another region*, i.e.
first-class dual-home representation where the RAM copy and its ROM master are the
same bytes with provenance for free.

**In-tree precedent.** `EmuX86DeobfuscateExampleScript` /
`EmuX86GccDeobfuscateHookExampleScript` (Features/Base/ghidra_scripts) are exactly
our shape: construct `PcodeEmulator`, `EmulatorUtilities.loadProgram`, breakpoints
around the deobfuscation routine, run, read recovered data out of emulator state,
annotate the program. The GhidraClass Debugger course module B2-Emulation documents
the same machinery. Emulation-assisted deobfuscation is a *documented, supported,
example-shipped* Ghidra workflow — not an exotic hack.

## 3. Path B: Debugger with pure-emulation target

`ProgramEmulationUtils.loadExecutable(snapshot, program)` / the emulation service
materialize a Trace from a Program with no live target; the GUI "Emulate" action,
time-travel snapshots, Dynamic Listing, and **Copy Into Program**
(`DebuggerCopyActionsPlugin`, `gui/copying`) complete a zero-code manual recovery
workflow: emulate past the copier/decryptor, watch memory change, copy the result
into the static program.

Headless, the picture is worse: traces *can* be created and populated from scripts
(`PopulateDemoTrace.java`), but the emulation service and the copy action are GUI
plugins; a headless trace round-trip buys nothing over Path A's direct
state-read → `Memory.setBytes`, at the cost of the whole Trace schema. **Verdict:
Path B is the interactive/manual tier** — document it as the escape hatch for cases
our automation doesn't recognize (grm-fy0 end-user docs should include a worked
example), and skip Trace plumbing entirely in automated recovery.

## 4. Path C: Debugger + real emulator over TraceRmi

In-tree TraceRmi agents: gdb, lldb, dbgeng, drgn, x64dbg, jpda — **no retro
emulators**. The `ghidratrace` Python client (Debugger-rmi-trace/src/main/py) is the
sanctioned kit for writing one; VICE's binary-monitor protocol is a plausible peer.
No community VICE/Mesen bridge exists today (web-checked 2026-07-12).

Why Path C still matters: fidelity. C64 protections derive EOR keys from CIA
timers/raster state; NES code depends on PPU timing. Naive p-code emulation answers
IO reads with policy values, not hardware behavior — recovered bytes would be
*wrong*, silently. The honest source for hardware-entangled cases is an accuracy
emulator (project principle: emulators are the oracle).

But there is a much cheaper 80% version: **VICE snapshot import**. VICE `.vsf`
snapshots contain the full C64 RAM image (`C64MEM` module) in a documented format —
a loader/script that imports a snapshot's RAM as (or into) a Program gets
"memory image after the decryptor ran under real hardware semantics" with zero
protocol work. Same shape as `.spc` files on the SNES side (below). **Verdict:
snapshot import = cheap standalone bead, high leverage; live TraceRmi connector =
real project, only if interactive live-state work proves valuable later.**

## 5. Decisions per use case (the epic's design tension, resolved)

**grm-1.7.1 run-from-elsewhere — STATIC. GO now, no emulation dependency.**
One-to-one copies are a data-relocation problem: descriptor-hinted (CHRGET → $73 as
the canonical fixture) at load time; detected copy loops (`LDA abs,X/STA abs,X`
bounds — the existing StoredValueScanner idiom machinery) as the analyzer tier.
Representation: `createByteMappedBlock` 1:1 against the ROM source for true
dual-home code (bytes stay shared; both listings live), falling back to an
initialized copy when the copy is transformed. Non-1:1 copiers (relocating,
patching): detect and WARN, don't mis-map; emulation can generalize this later but
is not needed for the common case.

**grm-1.7.2 decrypt-on-the-fly — EMULATION-ASSISTED (Path A). GO as the harness
pilot; P4 stands.** Tier 1: static recognizer for the constant-EOR loop (cheap,
covers the simple protections). Tier 2: bounded emulation of the recognized
decryptor entry — dirty-set capture, decrypted bytes into a `DECRYPTED_xxxx` overlay
(encrypted original stays navigable; provenance bookmark links them). Tier 3
(hardware-derived keys, chained/rolling schemes that touch CIA/raster): WARN +
manual workflow — Debugger pure-emulation (Path B) or VICE snapshot import (Path C
lite). This bead pilots the shared harness (§6).

**grm-1.7.3 SPC700 upload — HYBRID, STATIC-FIRST. GO with one new prerequisite.**
- **Language sourcing (prerequisite, was wrongly assumed):** stock Ghidra ships **no
  SPC700 sleigh** (`Ghidra/Processors/` has 6502/Z80/68000/…, no SPC700). Community
  option: SPCdra (qwertymodo) — SPC700 sleigh + `.spc` loader + HW register symbols.
  Evaluate license/quality for bundling vs. depending vs. writing our own (ISA is
  small and 6502-adjacent).
- **Fastest value is static:** the SPC ecosystem already ships full 64K sound-RAM
  images (`.spc` music rips *are* snapshots — GME's dumpspc.pl lineage consumes
  them). An `.spc`-image-to-Program path (reuse SPCdra's loader if suitable) delivers
  the disassembly target for AKAO driver RE immediately.
- **ROM-side extraction, static tier:** parse boot-time IPL uploads directly — the
  $2140-43 handshake carries documented address+length+data records; finding the
  record pointers in ROM is a static parse, no emulation.
- **Generic tier (after harness):** emulate the 65816 uploader with a
  port-write consumer modeling the IPL handshake state machine on the APU side —
  one consumer handles *every* game's uploader instead of per-game recognizers, and
  the same pattern covers C64→1541 drive-code upload later.
- **Deliverable shape:** **one** SPC700-language Program (a single 64K sound-RAM
  image) per game, alongside the SNES ROM (65816) Program — *not* one Program per
  uploaded image. A typical game runs the IPL **multiple times** to populate different
  regions of the *same* SPC700 RAM (e.g. one upload transfers the SPC700 driver code,
  another the static instrument/sample data, another filter/echo settings). The
  recovery model is therefore **accumulate all IPL transfers into the one SPC700 RAM
  image** at their respective target addresses — the same shape as loading a `.spc`
  snapshot, which *is* that fully-populated 64K image. Each upload site in the ROM gets
  a bookmark cross-linking to the target range it wrote in the SPC700 Program. Ghidra's
  one-language-per-Program constraint still means SPC700 lives in its own Program
  (separate from the 65816 ROM), but there is exactly **one** such Program per game,
  built up from N uploads, not N Programs.

## 6. Cross-cutting: one shared recovery harness

Two of three use cases (plus banking's future emulator integration, vision doc §7.1)
want the same bounded-emulation core. Build it once, extension-side:

**`EmulationRecovery`** (working name): given entry address + stop conditions
(breakpoint set / exit-range / dirty-watch / instruction fuel / wall-clock) + an IO
policy sourced from the board descriptor (IO regions → `readUninitialized` +
`beforeLoad` behavior), run `PcodeEmulator` over the current Program image, and
return {dirty address set, recovered bytes, stop reason, provenance log}. Callers
decide materialization (patch / overlay / byte-mapped block / new Program). This
uses the same `PcodeEmulationCallbacks` layer the banking vision already selected
for L4 emulator integration — one callback stack serves both features.

## 7. Risks and gotchas

1. **JIT emulator vs SMC** — use the interpreted `PcodeEmulator` only (§2).
2. **Uninitialized RAM defaults**: zeros are not real C64/NES power-on contents;
   decryptors keying off uninitialized RAM will diverge — surface "read of
   never-written RAM" in the provenance log, treat results as suspect.
3. **Hardware-entangled inputs** (timers, raster, controller): policy values produce
   silently wrong bytes; detect IO reads in the provenance log and downgrade
   confidence / recommend snapshot import.
4. **Banked windows as emulation source**: `EmulatorUtilities.loadProgram` copies
   *blocks*, including overlays — the harness must load the *correct bank's* bytes
   for switchable windows (consult banking state; shared infrastructure cuts both
   ways).
5. **KERNAL/BIOS calls out of the bounded region**: `inject()` stubs or include the
   ROM blocks in the image (our loaders already map them) — prefer the latter.
6. **Performance**: interpreted emulation of KB-scale 8-bit loops is negligible;
   no JIT needed.

## 8. Go/no-go summary

| Bead | Approach | Verdict |
|---|---|---|
| grm-1.7.1 run-from-elsewhere | Static (descriptor hint → idiom detection; byte-mapped blocks) | **GO**, independent of emulation |
| grm-1.7.2 decrypt-on-the-fly | Emulation-assisted (Path A harness pilot) + static tier + manual fallback | **GO**, P4 priority stands |
| grm-1.7.3 SPC700 upload | Static-first (.spc images, IPL record parse) → emulated-uploader generic tier | **GO**, new prerequisite: SPC700 language sourcing |
| Shared harness | `EmulationRecovery` on `PcodeEmulator` + callbacks | **GO**, new bead; blocks 1.7.2 tier-2 and 1.7.3 generic tier |
| Debugger (pure emu) | Manual workflow documentation (grm-fy0) | **GO** (docs only) |
| VICE snapshot import | Standalone loader/script bead | **GO**, small, high leverage |
| TraceRmi retro connector | Live VICE/Mesen bridge via ghidratrace | **NO-GO for now** — revisit on demonstrated need |

## References

- Deprecation: `Ghidra/Framework/Emulation/.../app/emulator/EmulatorHelper.java:52-54`
- Emulator core: `.../pcode/emu/PcodeEmulator.java`, `EmulatorUtilities.java`,
  `PcodeMachine.java`, `PcodeEmulationCallbacks.java`,
  `.../pcode/exec/BytesPcodeExecutorStateSpace.java`, `.../pcode/emu/SleighInstructionDecoder.java`
- Examples: `Ghidra/Features/Base/ghidra_scripts/EmuX86DeobfuscateExampleScript.java`,
  `EmuX86GccDeobfuscateHookExampleScript.java`;
  [GhidraClass Debugger B2-Emulation](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Debugger/B2-Emulation.md)
- Debugger: `.../debug/service/emulation/ProgramEmulationUtils.java`,
  `.../debug/gui/copying/DebuggerCopyActionsPlugin.java`,
  `Ghidra/Debug/Debugger-rmi-trace/src/main/py/src/ghidratrace/`
- Ecosystem: [SPCdra — SPC700 sleigh + .spc loader](https://github.com/qwertymodo/SPCdra);
  [VICE snapshot format](https://vice-emu.sourceforge.io/vice_9.html);
  [c64_ghidra scripts](https://github.com/c64cryptoboy/c64_ghidra);
  [C64LoaderWV](https://github.com/zeroKilo/C64LoaderWV)
- Related: `docs/vision-board-banking.md` §7.1 (emulator plug-points shared with banking L4)
