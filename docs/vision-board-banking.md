# Design Vision: Machine-Independent, Data-Driven Board-Level Banking

Status: draft v1 (2026-07-07). Companion to [rfc-banked-memory.md](rfc-banked-memory.md)
(the upstream pitch, posted as ghidra discussion
[#9349](https://github.com/NationalSecurityAgency/ghidra/discussions/9349)). The RFC argues
for one narrow core capability — a bank-state-aware address-resolution step. This document
is the full-stack architecture that capability serves: what Ghidra could look like if
board-level banking were a first-class, data-driven feature across *every* system that has
it, and the roadmap that gets there with the C64 and the popular NES mappers as stepping
stones.

## 1. The problem, stated once

On most 8/16-bit systems, what a CPU address *means* depends on runtime state held in a
latch that is usually not part of the CPU: cartridge mappers (NES MMC1/3/5, the discrete
*xROMs, GB MBCs, SMS Sega mapper), motherboard latches (C64 PLA, Spectrum 128 port $7FFD,
Apple II softswitches, MSX slot registers), or spare port pins driving a '374 (8051-style
embedded, countless arcade boards). Ghidra's model — one occupant per address, with
overlays as a manual escape hatch — cannot represent this, and the extension ecosystem
proves the cost. GhidraNes materializes one overlay block per (bank × candidate window),
ships an analyzer stub that returns `false` from everything (`GhidraNesAnalyzer.java:30-73`),
and its README documents the actual workflow: the *user* re-targets every cross-bank
`JMP/JSR` by hand and manually sets fallthrough after every bank-switch store
(`README.md:66-94`). GhidraBoy never reads the cartridge-type byte at $0147; MBC types
exist only as a header-annotation enum (`RomUtils.java:27-36`, `DataTypes.java:71-93`).
Every extension re-solves (or declines to solve) the same problem, because the platform
gives it nowhere to stand.

## 2. The four-layer model

All banking, on every system surveyed, decomposes into four layers. The split matters
because each layer has a different natural home, and conflating them is the root design
error to avoid (lesson: the 6510's port register is on-die, but the PLA that gives its
bits meaning is board-specific — the 6510T in the 1551 drive has the identical port wired
to drive-control signals).

| Layer | What it is | Natural home | Machine-dependence |
|---|---|---|---|
| **L1 Mechanism register** | The storage the program writes to change banks | Sleigh language — *only* when architecturally on-die (6510 port, 8051 SFRs) | Per-CPU, optional assist |
| **L2 Write detection + value recovery** | Recognizing bank-switch writes and recovering the written value | Analyzer + strategy library | Per-*mechanism class*, not per-machine |
| **L3 Interpretation** | Mapping mechanism state → (window → occupant) | Pure data: the board descriptor | Per-board, zero code |
| **L4 Application** | Making decode, references, decompilation, and emulation honor the bank state | Core (context register + resolution hook); overlays are the interim ceiling | Machine-independent |

The key empirical observations behind the split:

- What makes L2 cheap is **static identifiability of mechanism writes**, not on-die-ness.
  `STA $01` (fixed zero-page address), `OUT ($FE),A` (immediate port number), and
  `STA $8000` (write into a ROM range) are all statically recognizable; MMC1's serial
  protocol is not — it needs a small state machine over an instruction sequence.
- L3 is *always* board data, even when L1 exists. There is no system where the
  interpretation belongs in the processor language.
- L4 is *identical* for every system once L2/L3 hand it a resolved bank state. This is
  the layer the RFC asks core to own.

## 3. The target experience (think big)

What "first-class" means, described as a user session:

1. **Import.** User drags `crystalis.nes` into Ghidra. The iNES loader reads the header,
   sees mapper 4, and offers *Board: NES-TLROM (MMC3)* next to the Language field — a
   board descriptor chosen from a data registry the same way languages are chosen, with
   the same override affordance. No per-bank combo boxes.
2. **Memory.** The PRG ROM lands **once**, in a physical `PRG` space (256 KiB, its file
   layout). CPU space has two switchable 8 KiB windows and two fixed ones; the fixed
   windows are resolved immediately ($E000 = last bank, per descriptor). No bank × window
   block explosion.
3. **Analysis.** A machine-independent bank analyzer, configured entirely by the
   descriptor, finds MMC3 bank-select/bank-data write pairs, recovers values (constant,
   masked-RMW, or table-driven via dataflow), and stamps the recovered bank state into a
   context register over the flow that follows — with per-bit partial knowledge where
   recovery is incomplete.
4. **Everything downstream just works.** Disassembly of `JSR $A000` resolves to the
   function in PRG bank 23 because that is the R7 value in force at the call site; the
   decompiler shows `submap_load()` not `FUN_a000`; clicking the reference navigates to
   the physical location. Where the state is unknown, the reference is explicitly
   ambiguous (a *set* of candidates), not silently wrong.
5. **The listing shows bank state** the way it shows register values today: a margin
   column, and a "bank view" selector so the user can ask "show me $A000 as bank 23
   sees it."
6. **Emulation honors the board.** Running the entry point in the p-code emulator routes
   loads/stores through the same descriptor: writes to $8000/$8001 update the modeled
   mapper, subsequent fetches read the newly-mapped bank. Static model and dynamic oracle
   are the same data. (This also gives us the validation loop we already use emulators
   for — VICE/Mesen as behavioral truth.)
7. **The tool discovers what today's loaders ask for.** GhidraNes makes the user guess
   each bank's base window from a combo box at import (`BankAddressOption.java:13-80`)
   because nothing downstream can recover from a wrong guess. With bank-switch detection
   in place, that question answers itself: the analyzer observes which window each
   recovered bank value is mapped into and which window's addresses the bank's own code
   references (internal absolute refs, vector targets), and *assigns placements by
   following the flows*. Import-time options become overrides for the rare ambiguous
   case, not required upfront knowledge.
8. **Adding a new board is writing YAML.** No Java, unless the board introduces a
   genuinely new *mechanism class* (strategy), which is rare — the strategy vocabulary
   below covers every system in the survey with six entries.

## 4. Design principles

1. **Priority rule** (project-wide): use existing Ghidra infrastructure/API first; if
   none fits, do it the way existing Ghidra code does it (TMode, PIC bank bits,
   SegmentedAddressSpace are the precedents); roll our own only where demonstrably
   insufficient — and record why, as upstream-citable evidence.
2. **Data-driven to the bone.** Everything per-board is descriptor data (L3, plus L2
   strategy *configuration*). Code is reserved for the per-mechanism-class strategies
   (L2, a small closed library) and the machine-independent engine (L4).
3. **Mirror emulator architecture.** Accuracy emulators already factor this exactly the
   same way: a mapper *class* (strategy) parameterized by board data, routing a
   (state, address, access) triple to backing storage. Divergence from how VICE/Mesen
   model the same hardware is a design smell. (Emulators are the oracle, never the code
   quarry — GPL.)
4. **Degrade honestly.** Unknown bank state must produce explicit ambiguity (candidate
   sets, WARNING bookmarks, partial-knowledge annotations), never a silently wrong
   reference. Per-bit partial knowledge (RegisterValue's value+mask model) is the
   representation throughout.
5. **Physical-space backing, windowed views.** Banked content exists once, in a physical
   address space matching the ROM file; CPU windows are *mappings into it*, enumerated
   (C64: 8 PLA states) or computed (NES: `bank × 0x2000 + offset`). Overlay blocks per
   bank are the interim implementation of this idea, not the idea itself — GhidraNes's
   bank × window explosion is what happens when views are materialized as storage.
6. **Analysis over interrogation.** Never ask the user at import for what flow analysis
   can infer afterward. Bank-to-window placement, fixed-window identification, and
   cross-bank linkage are all *derivable* once mechanism writes are detected — the only
   reason existing tools front-load these as user guesses is that they have no analyzer
   to derive them. Options exist as overrides, defaults come from the descriptor, and
   the analyzer refines placements as evidence accumulates.

## 5. Board descriptor schema v2

Schema v1 (see [SCHEMA.md](SCHEMA.md), `machines/c64.yaml`) already carries regions,
windows/occupants, a mechanism, and an enumerated state table. Three generalizations make
it machine-independent; C64 remains expressible unchanged in spirit.

### 5.1 Bank state is a named tuple, not one register

```yaml
banking:
  state:                      # the abstract bank-state tuple (context register fields)
    - { name: LORAM,  bits: 1 }
    - { name: HIRAM,  bits: 1 }
    - { name: CHAREN, bits: 1 }
```

NES MMC3 needs `{ prg_mode: 1, R6: 6, R7: 6 }`; MMC1 needs
`{ prg_mode: 2, prg_bank: 5 }`. The tuple maps onto one Ghidra context register with
per-field sub-registers — `RegisterValue`'s value+mask storage gives per-bit partial
knowledge for free, and merges at flow joins use its existing combine semantics.

### 5.2 Mechanisms are a list of strategy instances

```yaml
banking:
  mechanisms:
    - strategy: register-write          # C64: STA $01 (and friends)
      params: { address: 0x0001, mask: 0x07 }
      sets: [LORAM, HIRAM, CHAREN]      # which state fields this mechanism feeds
```

The **strategy vocabulary** (the entire L2 code surface — each is a parameterized class,
discoverable via ClassSearcher like analyzers):

| Strategy | Behavior | Systems |
|---|---|---|
| `register-write` | Store to fixed address; value (masked) is the state | C64 $01, Spectrum $7FFD*, Apple II softswitch pokes |
| `memory-latch` | Store anywhere in a range; written value (or a field of it) is the state; optional bus-conflict rule (value AND ROM byte) | UxROM, AxROM, CNROM, GxROM, BNROM, GB MBC coarse regs, SMS $FFFC-$FFFF |
| `select-data` | Two addresses: one selects a target state field, the other writes it | MMC3 ($8000/$8001), MMC5 in part, VRC parts |
| `serial-shift` | N sequential writes deliver value bit-at-a-time; a reset condition aborts | MMC1 |
| `io-port` | `OUT` to an immediate or register-held port number | Z80 systems: Spectrum*, MSX slot register, arcade Z80 boards |
| `mode-register` | Register whose value selects among *window layouts* (not just occupants) | MMC1 control, MMC3 $8000 bit 6, MMC5 $5100 |

(*Spectrum's $7FFD is an io-port on Z80 but the pattern-shape is register-write; the
strategy is chosen by mechanism shape, not by system.)

Each strategy owns: recognizing candidate writes (static pattern and/or dataflow),
recovering the written value (delegating to shared dataflow machinery — constant, masked
RMW algebra, table lookup), and emitting *state-field updates* with per-bit confidence.
Protocol strategies (`serial-shift`, `select-data`) additionally carry a small
instruction-sequence state machine.

### 5.3 Occupants can be computed, windows can be mode-dependent

Enumerated (C64, unchanged):

```yaml
windows:
  - name: LOROM
    start: 0xA000
    end: 0xBFFF
    occupants:
      - { name: RAM_A000, kind: ram }
      - { name: BASIC, kind: rom, image: basic, on_write: RAM_A000 }
banking:
  states:                # truth table keyed by state tuple
    - { LORAM: 1, HIRAM: 1, LOROM: BASIC, ... }
```

Computed (NES UxROM):

```yaml
physical:
  - { name: PRG, image: prg_rom }        # the ROM file, laid out once
windows:
  - name: PRG_LO                          # switchable
    start: 0x8000
    end: 0xBFFF
    maps: PRG[bank * 0x4000]              # occupant = expression over state fields
  - name: PRG_HI                          # fixed
    start: 0xC000
    end: 0xFFFF
    maps: PRG[last]                       # last bank in the image
```

Mode-dependent (MMC3 sketch — `layouts` selected by a mode field):

```yaml
layouts:
  - when: { prg_mode: 0 }
    windows:
      - { name: W8000, start: 0x8000, size: 0x2000, maps: PRG[R6 * 0x2000] }
      - { name: WA000, start: 0xA000, size: 0x2000, maps: PRG[R7 * 0x2000] }
      - { name: WC000, start: 0xC000, size: 0x2000, maps: PRG[second_last] }
      - { name: WE000, start: 0xE000, size: 0x2000, maps: PRG[last] }
  - when: { prg_mode: 1 }                # $8000 and $C000 swap roles
    windows:
      - { name: W8000, start: 0x8000, size: 0x2000, maps: PRG[second_last] }
      - { name: WC000, start: 0xC000, size: 0x2000, maps: PRG[R6 * 0x2000] }
      # ...
```

The expression language stays deliberately tiny: state fields, integer arithmetic,
`last`/`second_last` (the window-relative offset is added implicitly by the contiguous
block mapping, not written in the expression). If a board needs more, that is a signal to
add a strategy or a schema feature, not to grow a Turing tarpit.

### 5.4 Everything else generalizes unchanged

Kinds and permission defaults, `on_write` read/write asymmetry, ROM image slots
(copyright-safe, never shipped), symbol sets, and type definitions all carry over from
schema v1. Non-CPU spaces (NES PPU/CHR, which GhidraNes wrongly parks in CPU space at
$0000) become additional physical spaces with their own windows — same machinery, and
explicitly out of the critical path for code-RE milestones.

## 6. Layer-by-layer architecture

### L1 — CPU assist (optional, per-CPU)

Where the mechanism register is architecturally on-die, model it as a real register in
the language so its value rides ordinary dataflow: the bundled 6510 language gets a
**system-neutral** `PORT` register (routed from $00/$01 accesses; no bank-bit names —
those are board data). This is the ARM `ISAModeSwitch` pattern verbatim
(`ARM.sinc:208-211`). Per-system bit naming, if desired, is a pspec alias
(`ARMt.pspec`: `<register name="TB" alias="ISAModeSwitch"/>`). CPUs without an on-die
mechanism skip L1 entirely; L2 dataflow carries the load alone.

### L2 — The bank analyzer and strategy library

One machine-independent analyzer (working title `BoardBankAnalyzer`), configured wholly
by the descriptor:

1. Instantiate the configured strategies; scan instructions for candidate mechanism
   writes (each strategy knows its shapes).
2. Recover written values via shared dataflow: SymbolicPropogator where whole-value
   tracking suffices (it does, once L1 registers exist); the masked-RMW backward-scan
   algebra (already built and verified in `C64BankingAnalyzer`) where it does not;
   protocol state machines for `serial-shift`/`select-data`.
3. Maintain per-instruction bank state as a **partial-knowledge tuple** (today:
   `PortState(knownMask, bits)` — to be replaced by `RegisterValue`, which it
   reimplements), propagated over the CFG with agree-bit merges, call-clobber rules,
   and descriptor `initial_state` defaults for unknown bits.
4. Hand resolved states to L4: stamp the context register over ranges
   (`ProgramContext.setValue`), annotate switch sites (comments, per-bit provenance),
   bookmark genuinely-unknown states.

Function-level extensions (later milestones): record each function's *required* entry
bank state and *effect* on bank state; propagate over the call graph; flag callers that
violate requirements. This is where banked RE stops being per-instruction and starts
being architectural.

**Bank-placement inference** (the "no upfront guessing" principle made concrete): for
boards where a bank could legally occupy more than one window (MMC1's 16 KiB banks fit
$8000 or $C000; GhidraNes punts this to a per-bank import combo box), L2 derives the
placement instead of asking. Evidence sources, in strength order: (a) recovered switch
values — a bank number written to a mechanism that maps window W *is* an observation
"bank N appears at W"; (b) self-reference consistency — code inside a bank that takes
absolute references into window W's range votes for W (and against alternatives whose
ranges its references miss); (c) fixed-window anchors — reset/IRQ vectors and the
descriptor's `last`/`second_last` rules pin the fixed banks, giving inference a known
starting frame. Placements start as descriptor defaults, upgrade to inferred with
provenance recorded, and remain user-overridable.

### L3 — Interpretation

A pure function `resolve(state_tuple, window) → occupant/physical-offset`, evaluated
from the descriptor (truth table lookup or expression evaluation). No code per board.
The same function drives static analysis, the emulator hook, and the UI's bank-view
selector — one source of truth, which is precisely what emulator mapper classes got
right.

### L4 — Application

Two generations:

- **Interim (overlay generation).** What M0 ships for C64: alternates as overlay blocks,
  the analyzer patching references post-hoc into the right space. Ceiling documented in
  the RFC: base-space operands never resolve into overlays without patching; block count
  explodes with bank count (tolerable ≤ ~16 banks × few windows; MMC3's 64 × 2 hurts;
  MMC5 is impractical).
- **First-class (core hook).** The RFC ask: all operand/flow address resolution funnels
  through `SleighInstructionPrototype.getHandleAddr`, where context is in scope but
  unused; insert `resolve(context, address, access_type)` with access_type ∈
  {READ, WRITE, EXECUTE}. Backed by physical spaces + windows instead of overlays, the
  block explosion disappears and read/write/execute asymmetry (`on_write`, ROM
  write-through) is expressed exactly once.

## 7. What first-class requires from Ghidra core

*(Grounding for this section: direct source survey of D:/git/ghidra; the
disassembler/reference chokepoints are covered in the RFC and not repeated.)*

- **Context storage & flow** already suffice for carrying bank state: context registers
  with sub-fields, per-bit partial values (`RegisterValue`), range-stamped values with
  space-wide defaults (`ProgramContext`), and disassembler context flow with `noflow`
  semantics. This is the load-bearing good news: L4's *state channel* exists today; what
  is missing is only the *resolution step* that consumes it.
- **Decompiler**: the decompiler obtains bytes and symbols through per-query callbacks;
  bank-aware resolution must be applied where those callbacks translate program
  addresses, so that a call through a switchable window decompiles to the right callee.
  (Detailed plug-points: §7.1 below.)
- **Emulator**: p-code emulation exposes memory-access interception suitable for routing
  loads/stores/fetches through the L3 resolver, with strategy writes updating modeled
  state. (Detailed plug-points: §7.1 below.)
- **Importer**: loaders already contribute custom options and consult opinion services
  for language choice; a *board* choice is the same shape (registry of descriptors,
  header-driven default, user override).
- **Prior art in-tree** for "same address, state-dependent meaning": TMode/ISA modes,
  PIC bank bits, `SegmentedAddressSpace` (the *inverse* mapping — many CPU addresses to
  one physical — but proof that non-linear address spaces are integrable), and overlay
  spaces themselves.

### 7.1 Core plug-point details

Direct-source findings (D:/git/ghidra, 12.x tree), one insertion point per subsystem:

**Decompiler.** The decompiler is out-of-process; during decompilation it calls back
into `DecompileCallback` with `(spacename, offset)` queries. The load-bearing callbacks
are `getBytes` (`DecompileCallback.java:162` — raw `Memory.getBytes`, no context
indirection), `getPcode`/`getInstruction` (`:214`, `:365`), and
`getMappedSymbols → lookupSymbol` (`:654`, `:1072`). A bank-aware step is an
**address-translation shim** applied to every incoming query address before it reaches
memory/listing/symbol lookups. Crucially, the bank context is already reachable there:
`pseudoDisassemble` today pulls the entry context-register value via
`ProgramContext.getRegisterValue(baseContextRegister, funcEntry)` (`:396-404`) — the
same read serves a bank field.

**Emulator.** Two current hook layers (legacy `MemoryAccessFilter` is deprecated as of
12.1). Op-level: `PcodeEmulationCallbacks.beforeLoad`/`beforeStore`
(`PcodeEmulationCallbacks.java:200`, `:228`) fire on every LOAD/STORE with thread,
space, and offset in hand — the composable place to consult modeled bank state and
rewrite the effective location (the class docs explicitly prefer callback composition,
`:34-37`). State-level: subclassing `BytesPcodeExecutorStateSpace.read/write`
(`BytesPcodeExecutorStateSpace.java:212`, `:75`) via
`AbstractBytesPcodeExecutorStatePiece.newSpace` (`:117`) is more faithful — banking in
the state survives *every* access path including instruction fetch. Strategy writes
update the modeled mapper; fetches read the newly mapped bank; per-thread bank state is
representable through `ThreadPcodeExecutorState`.

**Context storage and flow.** Everything the state channel needs exists:
`ProgramContext.setRegisterValue(start, end, value)` (`ProgramContext.java:99`) with
range-mapped persistence, program-wide defaults (`setDefaultDisassemblyContext`,
`:235`), and per-bit partial values throughout. Sleigh's `noflow` attribute splits
context fields into flowing and pinned-per-range varieties
(`AbstractProgramContext.java:54-109`) — a bank selector wants the *flowing* variety
(TMode-style) so "this region runs in bank N" carries along control flow. One
documented limitation to design around: at flow joins, `DisassemblerContextImpl.
mergeToFutureFlowState` (`:172-188`) does **not** reconcile differing incoming context —
first writer wins and conflicts go to a collision list. Our analyzer's agree-bit merge
(per-bit intersection) is strictly richer; expect the analyzer to pre-chew joins rather
than relying on disassembler-time merging.

**Address-space prior art.** `SegmentedAddressSpace` (instantiated from the pspec by
`SleighLanguage.java:970-973`) proves non-linear spaces integrate with references,
listing, and decompiler — but it solves the *inverse* problem: many CPU addresses to
one flat offset via a pure function (`getFlatOffset`, `:71-76`), no runtime-state
input, and `Address` carries the disambiguator (the segment) inside itself. Banking is
one CPU address to many physical bytes, disambiguated by state *outside* the address.
Verdict: segmentation is the pattern for a custom space's integration surface, and
simultaneously the proof that a new mechanism (context input to resolution) is
genuinely missing — Ghidra's historical answer to overloaded addresses has always been
"add another static space" (Harvard code/data spaces, 8051 SFR/bit spaces), never
"resolve one space by runtime state."

**Importer.** A board choice is a loader `Option`
(`Loader.getDefaultOptions`, `Loader.java:176`; headless via `-loader...` args) —
decoupled from `LoadSpec`'s language/compiler pair, so no core contract changes.
Precedent for bundled data shaping memory layout at import: the ELF extension mechanism
(`ElfExtension`/`ElfLoadAdapter` via ClassSearcher) and per-processor pspec
`<default_memory_blocks>` — a board-descriptor registry is the same pattern with a
richer data file.

## 8. Machine-independence validation

The design is only machine-independent if every surveyed system maps onto it without new
concepts. The test table:

| System / mapper | L1 assist | L2 strategy | L3 mapping | Notes |
|---|---|---|---|---|
| C64 PLA | 6510 `PORT` | register-write | truth table (8 states) | M0 shipped (overlay gen) |
| NES NROM | — | — (no banking) | fixed | loader baseline |
| NES UxROM/BNROM/AxROM/GxROM/CNROM | — | memory-latch (+bus-conflict) | computed, fixed-last | discrete tier |
| NES MMC1 | — | serial-shift + mode-register | mode-dependent layouts | protocol tier |
| NES MMC3 | — | select-data + mode-register | mode-dependent layouts | protocol tier |
| NES MMC5 | — | mode-register + select-data | 4 PRG modes, RAM/ROM select | boss fight; needs SRAM banking |
| GB MBC1/3/5 | — | memory-latch (banked regs in ROM ranges) | computed + fixed bank 0 | 2nd-console proof |
| SMS Sega mapper | — | memory-latch ($FFFC-$FFFF) | computed | |
| Spectrum 128 | — | io-port ($7FFD) | small truth table + computed RAM page | Z80 `OUT` |
| Apple II softswitches | — | register-write (R/W-sensitive addresses) | truth table | access-*type*-triggered switches stress the access_type parameter |
| MSX | — | io-port (slot reg) + memory-latch (mapper) | two-level (slot, then mapper) | hardest composition test |
| 8051 + '374 latch | port SFRs (already registers) | register-write (SFR) | computed | embedded validation |
| Arcade Z80 latches | — | io-port / memory-latch | per-board data | long tail = pure YAML |

Two entries stress-test the schema on purpose: Apple II (switches triggered by *reading*
particular addresses — access-type-sensitive mechanisms) and MSX (two-level slot-then-
mapper composition). Neither breaks the four layers; both would break a design that
hard-wired "write to latch, value is bank".

## 9. Roadmap

Milestones are sequenced so each proves one layer on real binaries before the next
depends on it. C64 (done) proved the pipeline shape; NES proves machine-independence,
because its mappers span the whole strategy vocabulary.

- **M0 — C64 pipeline (shipped).** PRG loader, home-in-base overlay layout, Phase 0
  bank analyzer with per-bit masked-RMW tracking, RFC posted upstream (#9349).
  *Proved: L2 dataflow, L3-as-data, overlay-generation L4, and the ceiling that
  motivates the core hook.*
- **M1 — Schema v2 + NES baseline.** Descriptor schema v2 (state tuples, mechanisms
  list, physical spaces, computed occupants, layouts); regenerate C64 from v2
  byte-identically; iNES loader with board registry; NROM end-to-end (vectors, MMIO
  types/symbols — no banking). *Proves: the schema generalizes; the loader stack is
  system-neutral.*
- **M2 — Strategy library + discrete mappers.** Extract `BoardBankAnalyzer` +
  `register-write` strategy from `C64BankingAnalyzer` (C64 must regress zero); add
  `memory-latch` (with bus-conflict rule); ship UxROM/AxROM/CNROM/GxROM/BNROM.
  Acceptance: cross-bank `JSR`/`JMP` auto-resolve on real UNROM titles (Mega Man,
  Castlevania, Contra, DuckTales — which are also GME music-RE targets: `nes/megaman`,
  `nes/bionic`). *Proves: machine-independence of L2/L4 engine.*
- **M3 — Protocol strategies + placement inference.** `serial-shift` (MMC1) and
  `select-data` + `mode-register` (MMC3), including mode-dependent layouts;
  bank-placement inference (MMC1's 16 KiB banks assigned to $8000/$C000 by following
  flows, not import options — retiring the GhidraNes-style per-bank guess entirely);
  function-level bank-state requirements and call-graph propagation (shipped as
  `BoardBankAnalyzer#annotateBankRequirementViolations`, bead `grm-6a7.2`: per-function
  `requiresOnEntry`/`modifiedMask`/`exitState` derived AFTER the Phase-1/2 dataflow
  fixpoint by a bottom-up chaotic-iteration walk of the direct call graph, used only to
  raise a WARNING bookmark at a direct call site whose caller-local in-state is missing
  bits the callee's dispatch needs — read-only; nothing feeds back into the fixpoint.
  Known-ness only, not value-level requirements; indirect calls are not propagated
  through. Back-propagation/narrowing Phase-1 state from these summaries — a mutual-
  fixpoint/termination-risk problem — is explicitly deferred past M3). Acceptance on
  major MMC1/MMC3 libraries (Metroid, Zelda / SMB3, Crystalis). *Proves: stateful
  mechanisms fit the strategy interface; inference beats interrogation; overlay ceiling
  is now measurably painful (64 × 2 blocks) — evidence for the core ask.*
- **M4 — Scale + second console.** MMC5 (PRG modes, RAM/ROM select, SRAM banking); GB
  MBC1/5 via descriptors with near-zero new code — the machine-independence demo;
  performance and UX hardening (bank margin/comments at minimum).
- **M5 — Core integration (gated on #9349 signal).** Physical-space windows + the
  `resolve(context, address, access_type)` hook implemented in the Ghidra fork; migrate
  L4 off overlay generation; decompiler + emulator plumbing; upstream PRs per Path A.
  M2-M4's real-game evidence is the PR's justification package.

Parallel track (independent of milestones): grm-bk6 (system-neutral 6510 language with
`PORT`) and grm-wkk (TMode-style analyzer refactor) upgrade C64's L1/L2 and de-risk the
strategy extraction in M2.

## 10. Open questions and risks

1. **Upstream appetite** (the A-vs-C fork in the road) — mitigated by engage-first: the
   RFC is posted; M2-M4 build the evidence package either way, and everything through M4
   lives extension-side regardless.
2. **Ambiguous-state references** — candidate *sets* need UI/DB representation; interim
   answer is primary-candidate + bookmark, which loses information. Core design question
   for M5.
3. **Self-modifying/RAM-resident code under banking** (common in C64 loaders, MMC5
   games) — out of scope for static resolution; the emulator integration is the honest
   answer there.
4. **CHR/PPU-side banking** — same machinery, separate physical space; deliberately
   deferred until code-RE milestones land (GME's music-extraction interest is data
   tables + code, not graphics).
5. **Descriptor expression creep** — the mini-language must stay enumerable +
   arithmetic; anything richer becomes a strategy. Guard in review.

## 11. Relationship to GME

Bank-aware NES disassembly directly serves GME's music extraction (`nes/megaman`,
`nes/bionic`, `nes/smb`, `nes/zelda` notes all fight bank-swapped sequence data by
hand today). The M2 acceptance titles are chosen to pay rent twice: they validate the
banking engine *and* unblock music-driver RE that currently requires manual bank
arithmetic in Perl.
