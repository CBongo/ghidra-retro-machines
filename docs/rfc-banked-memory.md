# RFC: Context-aware address resolution for banked memory (extending overlays)

> **STATUS: INTERNAL DRAFT — not yet posted.** Target venue: GitHub Discussion on
> NationalSecurityAgency/ghidra. All file/line citations are against the Ghidra 12.1.2
> source. Tracked as bead `gib.2` / `rrh` in the GME tracker; motivating loader lives in
> this repo (CBongo/ghidra-retro-machines).

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
```

falling back to today's behavior when no bank map covers the address. Everything
downstream — reference creation, flow following (`gatherFlows`, line 657), the
decompiler's use of references — inherits correct targets with no further change.

This mirrors, precisely, what `TMode` already does for *decode*, applied to *address
resolution*: same context machinery, same flow tracking, same user-override story, one
new consumer.

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

- **Phase 0 (no core change, exists/underway):** loaders use home-in-base + overlay
  alternates; bank-aware analyzers hand-create cross-space references. Proves demand,
  documents pain.
- **Phase 1 (this RFC's core ask):** bank context register + declarative bank map +
  context-aware resolution hook for READ/EXECUTE targets.
- **Phase 2:** access-type-aware selection (the read/write asymmetry columns), completing
  the model for write-under-ROM and mapper-register writes.

## Questions for maintainers

1. Is there internal effort in this direction? (PIC18 banking issue #9052 was closed
   "Internal effort — we already have a fix in progress"; we would much rather align than
   duplicate.)
2. Is the `getHandleAddr` seam the right place, or is there a preferred layer (e.g.
   `CodeManager.addReferencesForInstruction`, or an `AddressSpace`-level abstraction like
   a context-parameterized `OverlayAddressSpace`)?
3. Where should the bank map live — `.pspec`, a loader-populated program property, or a
   new first-class program object? (We currently compile it from a YAML machine
   descriptor into loader-consumed data, so any of these is reachable for us.)
4. Would you want the phases split as above, or READ-only resolution first with
   asymmetry folded in from the start?

## Alternatives considered

- **One program per bank state:** loses cross-bank xrefs entirely (this is the #2546
  pain), multiplies analysis effort, and diverges as soon as any shared range is edited.
- **Widened flat address space with bank-offset addressing** (the 8051-style trick):
  works for pure code banking with assembler cooperation, but does not model shared
  ranges, RAM-under-ROM, or runtime-computed bank state, and breaks pointer arithmetic
  fidelity.
- **Status quo (pure overlays):** the documented ceiling this RFC starts from.
