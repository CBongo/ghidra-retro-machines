# RFC: Context-aware address resolution for banked memory (extending overlays)

> **STATUS: POSTED** as
> [NationalSecurityAgency/ghidra discussion #9349](https://github.com/NationalSecurityAgency/ghidra/discussions/9349)
> (2026-07-05). This file is the source of record for the proposal text; substantive
> revisions should be mirrored to the discussion. All file/line citations are against the
> Ghidra 12.1.2 source. Tracked as bead `gib.2` / `rrh` in the GME tracker; motivating
> loader + Phase 0 analyzer live in this repo (CBongo/ghidra-retro-machines).

## Summary

Many widely-RE'd systems have **banked memory**: several physical memories share one CPU
address range, with a runtime register selecting which one responds (C64 `$01` processor
port, NES mappers, SNES LoROM/HiROM, banked Z80 machines, 8051 code banks, PIC data
banks). Ghidra's best available model today is overlay address spaces, and they fall short
in one specific, code-locatable way: **operand address resolution never consults bank
state**. This RFC proposes a minimal extension — reuse the existing flow-tracked Sleigh
context-register machinery (the mechanism behind ARM's `TMode`) and add **one hook** so
that resolving an operand to an `Address` can depend on `(context, address, access_type)`
instead of being fully static. No new subsystem; the two inputs the hook needs are already
computed adjacent to the resolution site.

## The problem, as reported by users

These independent reports are all the same missing capability:

- **Discussion #6651** (HD6305Y2 banked ROM): author attempted the natural workaround — a
  context register tracking the bank — and found jumps still resolve to the wrong bank.
  No resolution.
- **Discussion #5913** (C166 banked registers): decompiler confusion, no clean solution.
- **Issue #7052** (8051 code bank switching): open feature request, dormant.
- **Issue #2546** (6502 with 385K banked ROM): the 64K address-space cap forces separate
  imports, and references cannot cross separately-imported files.
- **Issue #1332** (MIPS overlays): the pain is not 6502-specific.
- **Issue #864** (6502 language default blocks vs. C64 PRG): adjacent friction in the same
  ecosystem.

The only overlay-related change merged in recent memory (PR #1376 / issue #1375) was a
spurious-warning bugfix — overlays receive maintenance, but no capability growth.

## Why overlays are the ceiling today (the code-level cause)

Every operand and flow address funnels through a single primitive:

`ghidra/app/plugin/processors/sleigh/SleighInstructionPrototype.java`,
`getHandleAddr(FixedHandle hand, AddressSpace curSpace)` (line 1565):

```java
Address newaddr = hand.space.getTruncatedAddress(hand.offset_offset, false);

// if we are in an address space, translate it
if (curSpace.isOverlaySpace()) {
    newaddr = curSpace.getOverlayAddress(newaddr);
}
return newaddr;
```

`hand.space` is the RAM space baked into the operand's `ConstTpl` by the Sleigh spec —
fully static. The only dynamic input is `curSpace`, the space *the instruction itself
lives in*, and `OverlayAddressSpace.getOverlayAddress` (line 153) only re-homes an address
into **that same overlay**. Two consequences:

1. **A base-space instruction can never resolve an operand into an overlay.** `JSR $FFD2`
   in main RAM resolves to base `$FFD2` even if the meaningful target (a banked ROM's
   entry) lives at `KERNAL::ffd2`. Labels in overlays are simply never consulted. This is
   exactly the failure the author of #6651 hit.
2. **An instruction in overlay A can never resolve into overlay B** over the same range —
   `getOverlayAddress` requires the source space to be A's own base.

There is no notion of *runtime bank state* anywhere in this path. Downstream, the
references materialized by `CodeManager.addReferencesForInstruction`
(`ghidra/program/database/code/CodeManager.java:2604`) inherit the wrong target, and the
decompiler follows the references.

## Key observation: the needed inputs are already at the call site

The proposal is small because Ghidra has already built almost all of it:

- **Bank state can already be modeled and flow-tracked.** Sleigh context registers,
  propagated along control flow by `DisassemblerContextImpl`/`ProgramContext` and
  persisted per address range, are the exact mechanism behind ARM interworking: the
  `TMode` context field (`Ghidra/Processors/ARM/data/languages/ARM.sinc:88-91`) steers
  which instructions *decode*, is set along flow via `globalset`, and is user-overridable
  through the existing Set Register Values UX. A `bank` context register is the same
  machinery — the only difference is *what should consume it*.
- **The context value is in scope at the resolution site.**
  `SleighInstructionPrototype.getAddress(int opIndex, InstructionContext context)` (line
  788) already holds the `SleighParserContext` (obtained at line 796), whose packed
  context bits encode the bank register's value at that instruction. It just isn't passed
  into `getHandleAddr`.
- **The access type is computed at the same layer.**
  `RefTypeFactory.getDefaultMemoryRefType`
  (`ghidra/program/model/symbol/RefTypeFactory.java:398`), driven from
  `CodeManager.getOperandMemoryReferenceType` (line 2775), already distinguishes
  READ/WRITE/READ_WRITE per operand from the instruction's p-code input/result objects.
- **Cross-space references are already legal at the storage layer.**
  `ReferenceDBManager.addMemoryReference` (line 422) checks only that both endpoints are
  memory addresses — a base-space instruction may already hold a reference into an overlay
  if something creates it. No storage change is needed.

## Proposal

Three pieces, ordered by how much is genuinely new:

### 1. A bank context register (existing machinery, zero core change)

The processor spec (or a language extension shipped by a loader) declares a context
register, e.g. `c64bank = (0,2)`, exactly like `TMode`. Loaders set its initial value;
analyzers and users adjust it along flow with the mechanisms that already exist
(`globalset`, `ProgramContext`, Set Register Values).

### 2. A declarative bank map (new data, no new engine)

A per-program mapping — supplied by the loader or language — from
`(banked address range, context value) → memory block`. For the C64:

| range | `c64bank` | read target | write target |
|---|---|---|---|
| `$A000-$BFFF` | 7 | `BASIC` (ROM) | `RAM_A000` |
| `$A000-$BFFF` | 5 | `RAM_A000` | `RAM_A000` |
| `$E000-$FFFF` | 7 | `KERNAL` (ROM) | `RAM_E000` |
| `$D000-$DFFF` | 3 | `CHARGEN` (ROM) | `RAM_D000` |
| … | | | |

Note the **read/write asymmetry** columns: this is hardware truth, not a modeling luxury.
On the C64 the CPU write line always reaches the RAM under ROM — `LDA $A000` and
`STA $A000` in the *same* bank state legitimately target *different* memories
(read BASIC ROM / write the RAM beneath). The NES has the same shape: reads of
`$8000-$FFFF` hit PRG-ROM while writes to the same addresses are mapper-register
commands. This is why the hook signature below takes the access type — per-context
overlay selection alone cannot represent it.

### 3. The one new core hook (the actual ask)

Thread the already-available `InstructionContext`/`SleighParserContext` and the intended
`RefType` into `getHandleAddr` (or a new overload), and let the space selection consult
the bank map:

```
resolve(context, address, access_type) -> memory block / overlay space
    where access_type ∈ { READ, WRITE, EXECUTE }
```

falling back to today's behavior when no bank map covers the address. Everything
downstream — reference creation, flow following (`gatherFlows`, line 657), the
decompiler's use of references — inherits correct targets with no further change.

This mirrors, precisely, what `TMode` already does for *decode*, applied to *address
resolution*: same context machinery, same flow tracking, same user-override story, one
new consumer.

### Is EXECUTE a real third mode, or just READ?

On the systems in scope, the banking hardware sees only *address + R/W line*: the C64 PLA
and NES mappers cannot distinguish an opcode fetch from a data read (the 6502's SYNC pin
is not routed to them). Fetch is electrically a read, so **the bank map defaults EXECUTE
to the READ mapping and needs no third column** in the common case.

The hook signature still carries EXECUTE as a distinct value, for three low-cost reasons:

1. **It is free.** Flow targets and data operands already arrive at the resolution layer
   distinguished (`gatherFlows` vs. `RefTypeFactory.getDefaultMemoryRefType`); collapsing
   them would be added work, not saved work.
2. **Fetch-sensitive hardware exists.** The Z80 exposes an opcode-fetch signal (M1) and
   shipping designs key on it — Sega's MC-8123 and Capcom's Kabuki decrypt opcodes
   differently from data reads *at the same address*. Those are encryption rather than
   banking, but they establish that an optional per-window execute override is worth
   keeping representable without burdening the common case.
3. **Policy may legitimately differ by mode.** Following flow into a bank on
   low-confidence context poisons analysis with wrongly-decoded bytes; a low-confidence
   data reference is merely an imprecise xref. Keeping the mode visible lets an
   implementation demand higher context confidence for EXECUTE resolution than for READ.

**Analyzer compatibility** (branch-into-non-executable heuristics): the existing checks
compose cleanly because they run *after* resolution selects the block —
`Disassembler.getInitializedMemory(program, restrictToExecuteMemory)`
(`ghidra/program/disassemble/Disassembler.java:309`) filters on
`block.isInitialized() && block.isExecute()` (line 411) for whatever block the target
lands in. Today a `JMP $D000` on the C64 is permission-checked against the single static
block at that address regardless of bank state; with context-aware resolution the same
jump checks the *bank-selected* block — executable overlay RAM in an all-RAM bank state
(rightly unflagged), the non-executable I/O block in the I/O state (rightly flagged: that
jump really does target chip registers), and character-generator ROM in a CHARGEN state
(glyph bitmap data, which a machine descriptor sensibly marks non-executable — also
rightly flagged). Unmapped or unknown context falls back to today's resolution, so
analyzers see the status quo. The heuristics get more accurate targets, and finer-grained
ones, with no analyzer changes.

## Prior art in-tree (the mechanism half-exists)

- **`TMode`** — context register steering decode, flow-tracked, user-overridable. The UX
  and propagation model to copy.
- **`InjectPayloadSegment`**
  (`ghidra/program/model/lang/InjectPayloadSegment.java`) — the Sleigh `<segmentop>`
  mechanism, where a *register value* (segment selector) already participates in
  computing an effective address.
- **`SegmentedAddressSpace`**
  (`ghidra/program/model/address/SegmentedAddressSpace.java`) — a built-in address space
  whose addressing is a function of a segment value; bank-like addressing already exists
  in the address model.
- **`VarnodeContext`** (`ghidra/program/util/VarnodeContext.java`) — the symbolic
  propagation engine already tracks register→space associations along flow (see its
  overlay-awareness remarks around line 237).

## Motivating case: the C64 PRG loader in this repo

Our descriptor-driven C64 loader (working, headless-verified) had to adopt a
**home-in-base** layout to be usable at all: the bank state at load time (`$37` → BASIC,
I/O, KERNAL visible) is materialized as *base-space* blocks so that KERNAL API labels
(`CHROUT@$FFD2` etc.) and I/O chip structs land where base-space references actually
resolve; only the *alternate* occupants (`RAM_A000`, `RAM_D000`, `CHARGEN`, `RAM_E000`)
become overlays. This makes the default bank configuration fully cross-referenced today —
and it is the best that can be done without the hook.

What it cannot represent:

- Any reference **into** a swapped-in bank (e.g. code that flips `LORAM` off and then
  reads data at `$A000` from the RAM beneath BASIC) — resolution still lands on the
  base-space home block.
- Code **executing from** banked RAM (`RAM_E000` under KERNAL — a common trick for IRQ
  handlers with ROM banked out): its operand references resolve inside its own overlay
  only, never across.
- The read/write asymmetry at all: `STA $A000` with BASIC banked in *should* reference
  `RAM_A000::a000`, but there is exactly one resolvable target per address today.

Interim mitigation (no core change, and cited here as evidence of demand rather than a
solution): a bank-aware analyzer that watches the mechanism's bank-select writes (trivial
on C64 — stores to `$01`; complex on NES — mapper-class-specific patterns like MMC1's
serial writes) and explicitly `addMemoryReference()`s into the right overlay. Legal today
(see storage-layer note above), but it recreates flow tracking by hand and leaves decode,
data flow, and the decompiler unaware.

## Phasing

Each phase adds one dimension to resolution:

- **Phase 0 — today, no core change (implemented):** loaders use home-in-base + overlay
  alternates; a bank-aware analyzer flow-tracks the bank register and hand-creates
  cross-space references — including write-under-ROM retargeting — where the default
  resolution is wrong (both working in CBongo/ghidra-retro-machines). Proves demand,
  documents pain, and demonstrates every capability of the proposal except the part that
  requires the core hook: making *default* resolution, flow following, and the decompiler
  bank-aware instead of patching references after the fact.
- **Phase 1 — bank-aware resolution (the core ask): "which bank is switched in?"**
  Context register + bank map + the resolution hook, consulting `(context, address)`
  only: **one target per address per bank state** — the occupant the bank-state table
  names. A load, a store, and a jump to the same address in the same bank state all
  resolve to that one occupant. This alone fixes the reported pain class (#6651
  cross-bank calls, #2546 cross-bank xrefs), and the map needs nothing beyond the
  per-state occupant table. We propose the hook *signature* carry `access_type` from day
  one, with Phase 1 implementations treating all modes identically — so Phase 2 changes
  data and semantics, never API.
- **Phase 2 — access-mode fidelity: "within one bank state, can a read and a write
  diverge?"** The bank map gains the separate read/write target columns shown above, and
  the hook honors them: `STA $A000` with BASIC banked in now resolves to the RAM beneath
  (write-under-ROM) while `LDA $A000` stays on the ROM; NES PRG-ROM reads vs.
  mapper-register writes likewise. Purely additive over Phase 1.

Motive for the split: Phase 1 is the smallest reviewable change carrying most of the
value; Phase 2's read-target ≠ write-target divergence is the conceptually novel part
and benefits from landing on a proven Phase 1.

## M3 status update (2026-07-12)

Phase 0 (the overlay-side workaround this RFC argues is a ceiling, not a fix) has now
been proven across the whole strategy vocabulary the vision doc's mapper survey
targets, not just C64's `register-write` case: `memory-latch` (discrete NES mappers),
`select-data` (MMC3), and `serial-shift` (MMC1) all flow-track their own protocol
state and hand-patch cross-bank references the same way, including boards whose window
*arrangement* itself is mode-dependent (`memory.layouts[]`) and boards where multiple
mechanisms/targets share one physical register. None of this needed a core change —
which is itself further evidence the ceiling is real: the overlay-side engine now
covers every mechanism shape in scope for M3 and still cannot make *default*
resolution, flow following, or the decompiler bank-aware, because that is exactly the
part Phase 0 cannot reach by construction.

The *quantitative* evidence this RFC's "Motivating case" section was missing — overlay
block-count/navigability pain at commercial-ROM scale — is now collected (`grm-6a7.3`,
real ROMs, CI-excluded per convention; full data in
[`mmc3-overlay-scale.md`](mmc3-overlay-scale.md)). Measured on Ghidra 12.1.2: loading a
real MMC3 cartridge creates a deterministic **`3N − 1` overlay address spaces** for N
in-range 8 KiB PRG banks, at load time, before any analysis — **191 overlay spaces** for a
512 KiB game (Mega Man 4, 64 banks), a **~27× blow-up** over the UxROM baseline (**7**).
Two corrections fell out of the measurement, neither touching a claim above: (a) *Super
Mario Bros. 3* is 256 KiB PRG / 32 banks / 95 overlays, not the 512 KiB / 64-bank case
earlier prose assumed (that conflated PRG with total ROM incl. CHR) — the true 64-bank
title is Mega Man 4; (b) the cost is **not** compute — full auto-analysis of the
191-overlay program runs in ~1 s (import+analysis wall-clock is flat from baseline to worst
case), so the ceiling is representational and navigational, not performance. Sharper still:
static resolution *into* those overlays is idiom-dependent and often near-zero (Crystalis,
a 256 KiB MMC3 title, resolved **0** cross-bank references into its 95 overlay spaces and
raised 12 unresolved-state warnings) — the `3N − 1` spaces are paid for regardless, while
the banked code they hold stays disconnected from the call graph. That gap is exactly what
Phase 1's bank-aware *default* resolution closes.

## Questions for maintainers

1. Is there internal effort in this direction? (~~PIC18 banking issue #9052 was closed
   "Internal effort — we already have a fix in progress";~~ looks like the PIC case was a
   specific bug that might not relate to this case; still, we would much rather align than
   duplicate.)
   <!-- 2026-07-05: qualifier added after review — #9052's underlying issue (#9051) was
        fixed with a simple sleigh update, so it likely doesn't indicate internal work on
        generalized bank switching. Mirrored from the live discussion text. -->
2. Is the `getHandleAddr` seam the right place, or is there a preferred layer (e.g.
   `CodeManager.addReferencesForInstruction`, or an `AddressSpace`-level abstraction like
   a context-parameterized `OverlayAddressSpace`)?
3. Where should the bank map live — `.pspec`, a loader-populated program property, or a
   new first-class program object? (We currently compile it from a YAML machine
   descriptor into loader-consumed data, so any of these is reachable for us.)
4. On the Phase 1/2 split: are you comfortable with the hook signature including
   `access_type` from day one (Phase 1 ignoring it) to avoid API churn when Phase 2's
   per-mode targets land — or would you rather the parameter appear only when something
   consumes it?

## Alternatives considered

- **One program per bank state:** loses cross-bank xrefs entirely (this is the #2546
  pain), multiplies analysis effort, and diverges as soon as any shared range is edited.
- **Widened flat address space with bank-offset addressing** (the 8051-style trick):
  works for pure code banking with assembler cooperation, but does not model shared
  ranges, RAM-under-ROM, or runtime-computed bank state, and breaks pointer arithmetic
  fidelity.
- **Status quo (pure overlays):** the documented ceiling this RFC starts from.
