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

Consequence: **a byte-mapped block `$0073 → BASIC $E3A2` maps onto uninitialized source
bytes and shows `??` until the user supplies a real BASIC ROM.** Populating the ROMs is
**grm-mbm** (optional user-supplied ROM files → initialized ROM blocks). The dual-home
CHRGET view only "lights up" once grm-mbm lands.

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
      source: BASIC                  # source occupant/region name (resolved like on_write)
      source_addr: 0xE3A2            # absolute source address in that block
      comment: "CHRGET fetch routine, copied to zero page at BASIC init"
```

The loader resolves `source: BASIC` to the BASIC block, then — per the descriptor
principle "descriptor declares facts, loader decides representation" (`SCHEMA.md`
principle 5) — chooses: byte-mapped block if the source is initialized, best-effort
byte-mapped (or skip) if not. **CHRGET addresses ($0073-$008A, source $E3A2) are
well-known folklore but not yet verified in this repo — confirm against a real BASIC ROM
disassembly before baking them in.**

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

1. **Verify CHRGET constants** ($0073-$008A / $E3A2) against a real BASIC ROM before use.
2. **Best-effort vs gated Tier A**: create the CHRGET byte-mapped block before grm-mbm
   (shows `??`, self-heals) or gate it on an initialized source? (Recommend best-effort +
   a log note, matching hardware truth.)
3. **Banked sources**: the survey flags that a copy source may live in a banked window;
   the mapped block must reference the correct bank's bytes. Defer until a banked-source
   case appears.

## 9. Deliverable status

- [x] Mechanic (`createByteMappedBlock` semantics, 1:1 dual-home, fallbacks) — §2
- [x] ROM prerequisite identified (grm-mbm) + proceed-options — §3
- [x] `copied_from` descriptor schema — §4
- [x] Tier-B recognizer plan (reuses grm-1.7.2 machinery) — §6
- [x] Sequencing recommendation — §7
- [ ] Implementation (blocked on sequencing decision: grm-mbm-first vs Tier-B-first)
