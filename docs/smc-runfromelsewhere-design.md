# Run-From-Elsewhere Recovery: Implementation Design (grm-1.7.1)

Design for grm-1.7.1 (SMC use case 1: code copied from ROM/loaded image to RAM and
executed there). Turns the survey verdict (`docs/smc-survey.md` §5, "run-from-elsewhere
— STATIC, GO now, no emulation dependency") into buildable structure. All API/schema
facts validated against the extension and the 12.1.2 install; citations are `file:line`.

Companion to `docs/smc-decrypt-design.md` (grm-1.7.2, decrypt-on-the-fly), whose
recognizer machinery this reuses.

## 1. The problem and the two tiers

Code is copied verbatim from a source region (ROM, or another part of the loaded image)
into RAM and run there: C64 BASIC copies CHRGET to zero page `$0073`; NES games copy hot
loops / NMI stubs to RAM; C64 games copy loaders under ROM shadows. Statically, the RAM
destination is empty (uninitialized) at analysis time, so the copied code is invisible.

Unlike decrypt-on-the-fly, this is **not** a transform — a 1:1 copy is a *data-relocation*
problem, solvable statically with no emulation:

- **Tier A — descriptor-hinted** (load time). A machine fact ("region X is copied to
  address Y at boot") declared in the board descriptor; the loader materializes the
  destination. CHRGET→`$73` is the canonical case.
- **Tier B — analyzer-detected** (analysis time). Recognize the copy *loop*
  (`LDA src,X` / `STA dst,X` / `DEX` / `BPL`, no transform between load and store) and
  materialize the destination — the same recognizer shape as `C64DecryptLoopAnalyzer`
  minus the EOR step.

## 2. Representation: dual-home via `createByteMappedBlock`

> **No longer the default (2026-07-25, grm-chu).** The byte-mapped block described below is the
> representation for **transformed** copies and for destinations that **cannot be carved**
> (already initialized, spanning two blocks, or sitting in an overlay space). The default for a
> **verbatim copy into uninitialized RAM** is now an in-place carve plus an initialized snapshot
> in the base address space, so a real `JSR $0073` resolves to the materialized code with no
> bridging. See [`smc-inplace-vs-overlay.md`](smc-inplace-vs-overlay.md) for the verdict (no
> Ghidra core change needed), the three strategies weighed, and the placement policy — Gate 0
> plus preconditions 1-4 — that chooses between the two.

The key mechanic (new to this repo — no existing use, confirmed). A **byte-mapped block**
maps its bytes 1:1 (or by ratio) onto another region; `Memory.java:49-51`:
"byte read/write operations are **passed-through** the mapped region." So a byte-mapped
block at the RAM destination, mapped to the source, is *true dual-home code*: the RAM copy
and its ROM/source master are the **same bytes**, both listings live, provenance for free.

- **API**: `Memory.createByteMappedBlock(name, start, mappedAddress, length, overlay)` —
  the 1:1 default overload (`Memory.java:397`). Use this **directly**, not the
  `MemoryBlockUtils` wrapper (`MemoryBlockUtils.java:170`), which does not expose a
  `ByteMappingScheme`; 1:1 is all we need.
- **Live pass-through**: reads return the source region's *current* bytes. So the block
  only shows real bytes when the **source block is initialized** at those offsets;
  otherwise reads surface `??` exactly as a direct uninitialized read would
  (`Memory.getBytes` throws `MemoryAccessException` for uninitialized locations).

### When 1:1 mapping is wrong

A copier that **transforms** (relocates addresses, patches bytes) does not produce
identical bytes, so a 1:1 byte-mapped block would misrepresent it. Two fallbacks:

- **Transformed-but-recoverable** (e.g. constant relocation applied statically): a plain
  *initialized copy* block populated with the computed bytes (like the decrypt overlay),
  not a byte map.
- **Non-1:1 / runtime-dependent** (relocating loaders, patch-during-copy): **detect and
  WARN**, do not mis-map. Emulation (grm-edg) can generalize this later; it is not needed
  for the common verbatim case.

## 3. The ROM prerequisite (grm-mbm) — decisive for Tier A

**Today the C64 BASIC/KERNAL/CHARGEN ROM blocks are uninitialized.** `c64.yaml`'s
`rom_images:` slots and per-occupant `image:` keys are documented
(`docs/SCHEMA.md:80`, `c64.yaml:155-171`: "Copyright-safe slots: never shipped… User
fills via loader option") but **not consumed by any Java** — `C64PrgLoader.createWindowOccupant`
(`C64PrgLoader.java:360-386`) unconditionally calls `createUninitializedBlock` for ROM
occupants. ZEROPAGE (`c64.yaml:28-31`, owns `$0073`) is likewise uninitialized.

Consequence: **a byte-mapped block `$0073 → KERNAL $E3A2` maps onto uninitialized source
bytes and shows `??` until the user supplies a real KERNAL ROM.** Populating the ROMs is
**grm-mbm** (optional user-supplied ROM files → initialized ROM blocks). The dual-home
CHRGET view only "lights up" once grm-mbm lands.

**ROM files located (2026-07-13):** `H:/emulators/c64/basic.c64` and
`H:/emulators/c64/kernel.c64` (both 8192 bytes — genuine BASIC/KERNAL dumps; the KERNAL
was confirmed by locating the CHRGET signature at the expected offset, see §4). A CHARGEN
dump likely lives under the sibling VICE dirs. These are the user-supplied inputs grm-mbm
consumes.

Two ways to proceed given this:
1. **grm-mbm first**, then Tier A CHRGET is fully real (dual-home with live ROM bytes).
2. **Best-effort now**: create the byte-mapped block unconditionally (it matches hardware
   truth and auto-populates when ROM bytes arrive); a test can assert the block exists
   with the correct mapping + provenance even while its bytes read `??`.

## 4. Descriptor schema: `copied_from`

A boot-copy hint attached to the **destination** region, reusing the existing occupant
name-resolution that `on_write` already uses (`docs/SCHEMA.md` mapping table). A RAM
region may host several independent ROM-sourced copies, so it is a list:

```yaml
- name: ZEROPAGE
  start: 0x0002
  end: 0x00FF
  kind: ram
  copied_from:                       # NEW: optional boot-copy hints
    - name: CHRGET
      start: 0x0073                  # destination sub-range
      end: 0x008A                    # 0x18 bytes
      source: KERNAL                 # source occupant/region name (resolved like on_write)
      source_addr: 0xE3A2            # absolute source address in that block
      disassemble: true              # optional (default false)
      create_function: true          # optional (default false)
      # entry: 0x0075                # optional mid-range entry, for a headered payload
      comment: "CHRGET fetch routine, copied to zero page at KERNAL init"
```

As implemented (grm-1.7.1.2) `MapCompiler` normalizes every address key to a JSON integer and
**fails the build** on an unknown `source`, `end < start`, a range escaping its owning region,
or an `entry` outside the range; `DescriptorCopyHintAnalyzer` applies the result. See
`docs/SCHEMA.md` ("Boot copies") and `docs/MAP_FORMAT.md` (`regions`) for the frozen wording.

The loader resolves `source: KERNAL` to the KERNAL block, then — per the descriptor
principle "descriptor declares facts, loader decides representation" (`SCHEMA.md`
principle 5) — chooses: byte-mapped block if the source is initialized, best-effort
byte-mapped (or skip) if not.

**CHRGET constants VERIFIED (2026-07-13)** against `H:/emulators/c64/kernel.c64`: the
CHRGET/CHRGOT routine (`E6 7A D0 02 E6 7B AD …`) sits at file offset `$03A2` → source
**`$E3A2` in the KERNAL ROM** (`$E000-$FFFF`), *not* the BASIC ROM as the folklore had it.
Destination `$0073-$008A` = `0x18` (24) bytes, matching the routine length. So the hint is
`source: KERNAL, source_addr: 0xE3A2`.

## 5. Cross-space bridging (both tiers)

The value is navigability: a `JSR $0073` at a call site should reach the CHRGET code.

- **Provenance**: NOTE bookmark + PRE/EOL comments cross-linking destination ↔ source
  (mirror `C64DecryptLoopAnalyzer`'s materialize).
- **References**: where a call/jump targets the destination, ensure it resolves to the
  dual-home block; where useful, a back-reference from the destination to the source
  master.
- **Disassembly**: disassemble the destination once it has bytes (byte-mapped from an
  initialized source, or an initialized copy) — same `DisassembleCommand`/`CreateFunctionCmd`
  idiom `C64DecryptLoopAnalyzer` now uses.

## 6. Tier B recognizer (analyzer-detected copy loops)

Structurally `C64DecryptLoopAnalyzer` **minus the transform**: `LDA src,X` immediately
followed by `STA dst,X` (different bases, same index), an index step, and a conditional
back-branch; `src`/`dst`/`len` resolved by the same operand helpers (`indexedBase`
handles the Scalar-not-Address base). Because `src != dst` (relocation, not in-place) this
is cleanly distinct from the decrypt loop (`src == dst`). Confidence: apply when the
source range is initialized and the destination is later executed (a `JMP`/`JSR` into it);
else candidate/WARN. This tier is **testable now with a self-contained PRG fixture**
(source bytes live in the loaded PRG, hence initialized) — no ROM dependency.

> **The evidence gate is strict, and that was settled by real ROMs (2026-07-25, grm-1.7.6).**
> The first increment softened the rule above: it materialized *every* recognized copy and
> withheld only *disassembly* when no jump into the range was found, on the theory that placing
> bytes is always safe and CHRGET-shaped deferred calls would otherwise be missed. Widening the
> recognizer past the C64 disproved it. This loop shape is simply how 6502 code moves **data**,
> so on real NES cartridges the permissive rule snapshotted ordinary runtime buffers — Ironsword
> materialized a block over the **stack page**, Mega Man three short blocks in work RAM, SMB3 one
> at `$0715` — each fragmenting the RAM block and marking a buffer that changes every frame as
> "initialized" from one meaningless sample. A data copy's destination holds nothing fixed, so
> there is nothing honest to put there. The recognizer now materializes **only** with a
> jump into the range, and otherwise leaves a NOTE bookmark recording what it saw.
>
> What makes the strict rule affordable is that the deferred-call case it was protecting now has
> its own front-end: CHRGET is a §4 `copied_from` directive, where the board's author *states*
> that the payload is code, and a human who spots a missed copy has the manual transfer script
> (grm-1.7.1.1). Evidence-free materialization was the auto recognizer covering for front-ends
> that did not exist yet.

## 7. Recommended sequencing

1. **grm-mbm (ROM loading)** — unblocks the canonical Tier-A CHRGET dual-home and is
   broadly useful (ROM routines become disassemblable). Do first if Tier A is the goal.
2. **Tier A `copied_from` schema + loader** — descriptor hint → `createByteMappedBlock`;
   CHRGET as the fixture (real bytes once grm-mbm lands, best-effort before).
3. **Tier B copy-loop recognizer** — reuse `C64DecryptLoopAnalyzer` machinery; testable
   immediately with a PRG-internal copy fixture, independent of ROM.

Tiers A and B share the materialization (byte-mapped dual-home + provenance + disassembly),
exactly as the decrypt tiers shared theirs.

## 8. Open questions

1. ~~Verify CHRGET constants~~ **DONE (2026-07-13)**: dest `$0073-$008A` (`0x18`), source
   **KERNAL `$E3A2`** (verified against `H:/emulators/c64/kernel.c64`; folklore's "BASIC"
   was wrong — it is KERNAL).
2. ~~Best-effort vs gated Tier A~~ **ANSWERED (2026-07-25, grm-chu)** — and the earlier
   recommendation (best-effort materialization against an uninitialized source) is
   **reversed**. Tier A now **gates on a readable source**: if the source bytes are not in
   `getAllInitializedAddressSet()`, the boot-copy hint (§4) is **ignored** — log note only, no
   block of any kind, and explicitly **no overlay fallback**. Self-healing is recovered by
   re-running instead of by live mapping: the materializer is idempotent and the analyzer
   declares `supportsOneTimeAnalysis`, so a later-supplied ROM materializes the copy on a
   re-run. That makes an analyzer/command front-end a requirement for Tier A rather than
   loader-time-only work, or the "ROM added later" path is unreachable. Rationale and the full
   placement policy: `docs/smc-inplace-vs-overlay.md` §5-6.
3. **Banked sources**: the survey flags that a copy source may live in a banked window;
   the mapped block must reference the correct bank's bytes. Defer until a banked-source
   case appears.

## 9. Deliverable status

- [x] Mechanic (`createByteMappedBlock` semantics, 1:1 dual-home, fallbacks) — §2
- [x] Placement decision (in-place carve vs overlay, and when each applies) — grm-chu,
      `docs/smc-inplace-vs-overlay.md`
- [x] ROM prerequisite identified (grm-mbm) + proceed-options — §3
- [x] `copied_from` descriptor schema — §4
- [x] Tier-B recognizer plan (reuses grm-1.7.2 machinery) — §6
- [x] Sequencing recommendation — §7
- [x] Implementation — grm-mbm (ROM loading), grm-1.7.1 (Tier-B recognizer, now
      `CopyLoopAnalyzer`), grm-chu (in-place placement), grm-1.7.1.1 (the `RunFromElsewhere`
      facade), and grm-1.7.1.2 (Tier-A: the `copied_from` schema key in `MapCompiler`, the C64
      CHRGET hint in `machines/c64.yaml`, and `DescriptorCopyHintAnalyzer` applying it under the
      ROM gate)
