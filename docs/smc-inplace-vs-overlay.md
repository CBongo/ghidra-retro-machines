# In-Place Carve vs Overlay for Materialized Copies (grm-chu)

Investigation verdict for grm-chu ("in-place block initialization vs overlay for
run-from-elsewhere copies — may require Ghidra core changes / upstream discussion"). It decides
how a materialized ROM→RAM copy is represented in the program, and closes the core-change
question the bead was opened on.

**No code is written by this note** — it is the placement decision that grm-1.7.1's materializer
implements. All Ghidra API facts were validated against the `Ghidra_12.1.2_build` source
checkout, which was this project's `ghidraTargetVersion` when the note was
written (the project has since retargeted; see `gradle.properties` for the current value, and
re-check any citation before relying on its line numbers); citations are `file:line`.

**Verdict, up front: no Ghidra core change is needed, there is no upstream ask, and this must
not be folded into `docs/rfc-banked-memory.md` (Ghidra discussion #9349).** The chosen
representation for a verbatim copy into uninitialized RAM is an **in-place carve plus an
initialized snapshot** in the base address space; the byte-mapped overlay of
`docs/smc-runfromelsewhere-design.md` §2 is retained as the fallback for everything else.

Companion to `docs/smc-runfromelsewhere-design.md` (grm-1.7.1), whose §2 this narrows, and to
`docs/smc-decrypt-design.md` (grm-1.7.2), whose overlay choice this deliberately leaves intact.

## 1. The problem and its concrete cost

grm-1.7.1 (commit `abb41da`) recognizes ROM→RAM copy loops and materializes the destination as a
**byte-mapped overlay** (`COPY_xxxx`, living in its own address space), because the destination
(`$0073` for CHRGET, `$C000` in the `copyloop` fixture) already sits inside a loader-created
*uninitialized* block, where a second non-overlay block would collide.

That is a workaround, not the truth: those RAM bytes genuinely *become* the copied code. The
concrete cost, as the bead states it — a real call site `JSR $0073` resolves to `base:$0073`,
**not** to the overlay copy. References never point at the materialized code, navigation breaks,
and the "a call or jump enters the destination" code-evidence signal is unreliable for
deferred-call cases like CHRGET, whose callers appear arbitrarily far from the copy loop. Today
only the single entering jump found within six instructions of the loop is hand-bridged
(`C64CopyLoopAnalyzer.bridgeJump`, `:237-266`); every other call site is on its own.

## 2. Verdict: no core change, and not an RFC #9349 item

The bead flagged that in-place initialization of a sub-range "may require Ghidra core changes."
It does not. Five findings, verified against the pinned checkout:

1. **`Memory.split` has no initialized-ness check** — `MemoryMapDB.java:989-1035` rejects only
   bit-mapped, non-1:1 byte-mapped, `OTHER`-overlay, and split-at-block-start.
   `UninitializedSubMemoryBlock.split` is implemented (`:73-85`). Splitting uninitialized RAM is
   fully supported.
2. **`convertToInitialized` is whole-block only** (`Memory.java:498-510`,
   `MemoryMapDB.java:1112-1147`). There is *no* sub-range variant — not public, not
   package-private. Mixed init/uninit sub-blocks inside one block are storable but semantically
   broken, and the core says so verbatim at `MemoryMapDB.java:437-438` ("seems like mixing is a
   bad idea"); `getInitializedAddressSet()` is built at whole-block granularity
   (`MemoryMapDB.java:235-240`).
3. **The blessed pattern is split → split → convertToInitialized → setBytes → rename the
   `.split` blocks**, and there is an in-tree analyzer precedent doing exactly this against a
   large uninitialized block: `GolangSymbolAnalyzer.java:712-728` isolates the 4-byte
   `runtime.writeBarrier` flag. This repo's own loader already carves uninitialized regions the
   same way at load time (`AbstractCbmPrgLoader.createCarvedTarget`, `:706-744`, producing
   `RAM_MAIN_0800` / `RAM_MAIN_0816`) — in-place materialization is that idiom moved to analysis
   time.
4. **`join` can never put the block back** — it refuses blocks of differing initialized-ness
   (`MemoryMapDB.java:1082-1085`). Fragmentation is permanent, matching what the loader already
   produces.
5. Ghidra's own closest analogue, the Debugger's *Copy Into Program*, is **not** a better
   precedent: it calls `convertToInitialized` on the **entire** containing block or falls back to
   an overlay (`DebuggerCopyIntoProgramDialog.java:784-796`). Our carve is strictly more
   surgical.

Every step is reachable through the public `Memory` API, with both an upstream analyzer
precedent (finding 3) and a precedent in this repo's own loader. So there is nothing to ask
upstream for. It also does not belong in `docs/rfc-banked-memory.md`, whose subject is the one
genuine core gap — "operand address resolution never consults bank state"
(`docs/rfc-banked-memory.md:15-17`). Attaching a representation choice we can already implement
to an open core-hook proposal would only dilute that ask.

## 3. The three strategies weighed

### 3.1 Strategy A — byte-mapped overlay (status quo; retained as fallback)

`createByteMappedBlock(name, start, mappedAddress, length, /*overlay=*/true)` in a fresh overlay
space, mapped 1:1 onto the source.

- **Pro:** true dual-home byte identity. Read/write passes through to the source region
  (`docs/smc-runfromelsewhere-design.md:40-42`), so there is exactly one master copy of the
  bytes and no snapshot to go stale.
- **Pro:** self-healing. A block created while the source is still uninitialized lights up on its
  own once real bytes arrive (the grm-mbm ROM-loading case, `docs/smc-runfromelsewhere-design.md`
  §3).
- **Pro:** universally applicable — the destination may be initialized, span blocks, or already
  live in an overlay space; none of it matters.
- **Pro:** provenance for free via the block's mapped range; nothing in the base space is
  touched.
- **Con:** the bead's whole complaint. References from the base space resolve to `base:dst`, not
  into the overlay, so the materialized code is off the call graph except for the one jump
  `bridgeJump` (`C64CopyLoopAnalyzer.bridgeJump:237-266`) can reach.
- **Con:** the copy is not independently patchable — a write to the copy writes through to the
  ROM master (`docs/smc-runfromelsewhere-design.md:40-42`).
- **Con:** the block reports `isInitialized() == false` (`ByteMappedSubMemoryBlock.java:53-55`),
  the same second-class-citizen problem strategy C loses on below. It is only as initialized as
  its source: `MemoryMapDB.addBlockAddresses` (`:221-234`) contributes just the intersection of
  the mapped source range with the already-initialized set.

### 3.2 Strategy B — carve plus initialized snapshot (CHOSEN)

`split` ×2 to isolate exactly `[dst, dst+len)` inside the existing uninitialized block, then
`convertToInitialized(block, 0)`, then `setBytes(dst, source bytes)`.

- **Pro:** real bytes at `base:dst`. `JSR $0073` resolves natively to the materialized code with
  no bridging at all, which is precisely what grm-chu asked for.
- **Pro:** the block reports `isInitialized() == true`, so consumers that gate on initialized-ness
  see the copy as real memory.
- **Pro:** the copy is independently patchable without writing through to the ROM master.
- **Pro:** nothing is deleted. `split` (`MemoryMapDB.java:989-1035`) and `convertToInitialized`
  (`MemoryMapDB.java:1112-1147`) rebuild byte storage only; neither calls `deleteAddressRange`,
  so symbols, comments and references already in the range survive the operation — contrast
  `removeBlock`, which does call it (`MemoryMapDB.java:1887`).
- **Pro:** precedent on both sides — `GolangSymbolAnalyzer.java:712-728` upstream, and this
  repo's `AbstractCbmPrgLoader.createCarvedTarget` (`:706-744`) at load time.
- **Con:** it is a snapshot, not a live view. Bytes that appear at the source *after*
  materialization do not propagate; re-running the analyzer is the remedy (§6).
- **Con:** fragmentation is permanent — `join` refuses blocks of differing initialized-ness
  (`MemoryMapDB.java:1082-1085`). This matches what the loader already produces, so it is a cost
  the program layout already carries.
- **Con:** it needs a readable source at materialization time (§6) and a destination that
  satisfies all four preconditions (§5); otherwise strategy A still has to exist.

### 3.3 Strategy C — non-overlay byte-mapped block in base space (rejected)

Carve the range free, then place a byte-mapped block at `base:dst` with `overlay=false`, mapped
1:1 onto the source — dual-home bytes *and* base-space addresses.

**This is legal.** `createByteMappedBlock(..., overlay=false)` gates only on `checkRange`
(`MemoryMapDB.java:1952`); there is no rule against a mapped block in the default space. And it
would have kept strategy A's two best properties — dual-home byte identity and self-healing when
ROM bytes arrive later — while fixing the reference-resolution failure that motivated the bead.
This was a genuinely close call, and it loses on two specific verifiable properties rather than
on principle:

- Freeing the range requires `removeBlock`, which **does** call `deleteAddressRange`
  (`MemoryMapDB.java:1887`). Symbols, comments, references and code units in the destination
  range are destroyed and would have to be reconstructed. Strategy B's `split` +
  `convertToInitialized` path destroys nothing.
- The resulting block reports `isInitialized() == false`. A mapped block that reads through to
  real ROM bytes but denies being initialized is a second-class citizen to every consumer that
  tests initialized-ness — including `getInitializedAddressSet()`, which is whole-block granular
  (`MemoryMapDB.java:235-240`).

Losing self-healing (B's snapshot con) is the price paid, and §6 mitigates it: the materializer
is idempotent and re-runnable, so "source bytes arrived later" is recoverable by re-running the
analyzer rather than by relying on a live mapping.

### 3.4 Side by side

| Property | A: overlay | B: carve + snapshot | C: base-space byte map |
|---|---|---|---|
| `JSR dst` from base space reaches the copy | no | **yes** | yes |
| Live dual-home (source edits propagate) | yes | no — snapshot | yes |
| Block reports `isInitialized()` | false | **true** | false |
| Destroys symbols/comments/refs in the range | no | no | **yes** (`:1887`) |
| Copy independently patchable | no | **yes** | no |
| Works for initialized / multi-block / overlay destinations | **yes** | no | no |
| Leaves the block map unfragmented | yes | no (`:1082-1085`) | no |

## 4. The `Transform.IDENTITY` fence and the carve == write invariant

`convertToInitialized` fills a range with a **synthetic byte**. That is only ever acceptable when
the destination's prior content carries **no information**. That is true for a run-from-elsewhere
destination — undefined RAM before the copy runs — and **false in the general SMC case**. A
decrypt-in-place (`src == dst`) has real, meaningful *encrypted* bytes at the destination;
initializing over them would destroy the pre-decryption view that `docs/smc-decrypt-design.md`
deliberately preserves so a static reading of the decryptor stub still sees what the CPU saw
(`docs/smc-decrypt-design.md:172-175`).

`TransferTransform` (a top-level enum, `retromachines.TransferTransform` — not a type nested in
`TransferSpec`) already anticipates `CONSTANT_XOR` / `ROLLING_XOR` being unified onto this
materializer, so the fence must be **structural, not incidental**:

- **In-place requires `TransferTransform.IDENTITY`.** Anything transformed keeps the overlay
  representation, unconditionally. (Precondition 3 of §5 — destination must be uninitialized —
  happens to block the decrypt case too, but relying on that is an accident waiting to be
  refactored away.)
- **Carve range == write range, always.** Carve exactly `[dst, dst+len)` and immediately
  `setBytes` all `len` bytes, so no synthetic fill byte survives the operation. Never carve wider
  than what can be filled: `docs/smc-survey.md:196-198` is explicit that zeros are not real
  C64/NES power-on contents, and a zero-filled block that *reports* initialized is a worse lie
  than an uninitialized one. Assert this invariant in the materializer — do not leave it
  documented here only.

## 5. Placement policy

Evaluated entirely **before any mutation** — every check is cheap and total, so there is no
partial-carve recovery path to write.

**Gate 0 — materialize at all?** The whole source range must read back: the materializer simply
attempts `Memory.getBytes(src, new byte[len])` and treats a short read or `MemoryAccessException`
as failure, which is equivalent to an `getAllInitializedAddressSet()` containment test but total
and allocation-free. On failure: **skip**, provenance only (§6). This applies to every placement,
overlay included.

**Gate 0.5 — is the destination even where it looks? (amended 2026-07-27, grm-bqs.)** On a banked
machine the base-space block at a destination is only the window's **home** occupant. A C64 copy
targeting `$E000` finds `KERNAL`, which with no ROM dump supplied is uninitialized and therefore
satisfies preconditions 1-4 below — so the original policy carved it, shredding a ROM image into
`KERNAL / COPY_e000 / KERNAL_E008` and labelling a RAM copy as ROM.

The descriptor cannot settle this on its own, and it is worth being precise about why, because the
plausible fix is wrong. Which occupant a write reaches is **bank-state-dependent**: within the C64
`CHARIO` window a store to `$D000` reaches the VIC registers when I/O is banked in and `RAM_D000`
when it is not, and reads differ again — the schema has no `on_read` key at all, because a read
simply goes to whichever occupant is live. A static `windows[].occupants[].on_write` walk can only
answer the cases where every occupant happens to agree, and would have to refuse `CHARIO` outright.

It does not need to. `BoardBankAnalyzer.retargetReferences:1440-1451` already resolves **every**
store against the bank state live at that instruction and re-homes its write reference into the
occupant the write reaches. So the resolution belongs in the front-end, which has the storing
instruction in hand: `CopyLoopAnalyzer` reads that answer off the `STA` it is already anchored on
(`LoopIdioms.overlayWriteTarget`) and hands the materializer a destination already homed in the
right space, marked `TransferTarget.RESOLVED_SPACE`. Precise rather than merely safe: `$D000` gets
the *right* answer per bank state instead of a refusal.

Matched across the whole destination range, not at `dst` alone — an indexed store's references are
written by the constant reference analyzer at whatever index values it resolved, so `STA $E000,X`
over an 8-byte loop yields references to `$E006`/`$E007` and never to `$E000` itself (grm-phv).

Front-ends with **no instruction to resolve through** — a descriptor `copied_from` directive, the
manual command — get a blanket rule instead, precondition 5 below. A declarative front-end that
wants a banked destination should name the occupant explicitly; the vocabulary already exists
(`RunFromElsewhereTransfer` accepts space-qualified addresses such as `src:W8000_M3_B1:a500`).

**Then in-place** iff *all* of the following hold, otherwise **overlay** (today's behavior,
unchanged):

| # | Precondition | Why |
|---|---|---|
| 1 | `spec.transform() == TransferTransform.IDENTITY` | The §4 fence: never synthesize bytes over meaningful content. |
| 2 | `[dst, dst+len)` lies wholly within **one** block | Multi-block carve is out of scope for v1. |
| 3 | That block is **uninitialized** | Never overwrite loaded file bytes — the pre-copy image stays navigable. |
| 4 | Block is `MemoryBlockType.DEFAULT`, not mapped, and **not in an overlay space unless Gate 0.5 put it there** | Splittable per `MemoryMapDB.split`; base space is the point (refs resolve there) — except for the one overlay we were *aimed* at rather than *fell back* into. |
| 5 | Block is **writable and non-volatile** | Only plain RAM is ever carved: a ROM occupant is not writable and an I/O occupant is volatile, both derived from the descriptor's `kind` by `DescriptorSupport.perms`/`markVolatileIfIo`. This is what protects the front-ends Gate 0.5 cannot help. |

A carve that Gate 0.5 redirected is reported as `TransferPlacement.IN_PLACE_BANKED`, not
`IN_PLACE`: the bytes are where the CPU runs them from *in that bank state*, which is as native as
a banked machine gets, but a base-space `JSR $E000` still names the home occupant — so it takes the
same entering-jump bridge `OVERLAY` takes. Honest scope: only that one jump is bridged. Other call
sites into `$E000` still resolve per live bank state, which is correct — with KERNAL banked in, a
`JSR $E000` really does hit KERNAL.

## 6. Unreadable source: produce nothing, do not fall back

A snapshot needs readable source bytes. An unreadable source is **not** a placement fallback —
Gate 0 failing means nothing is materialized at all, in any representation:

- For the **auto recognizer** (grm-1.7.1) this is rare but real: a copy loop reading `$E000`
  with no KERNAL ROM supplied. Skip materialization, but still emit provenance at the copy loop
  so the analyst sees "recognized, not materialized — supply a ROM", using the
  `BookmarkType.WARNING` shape the analyzer already uses for unbounded loops
  (`C64CopyLoopAnalyzer:152-157`).
- For the **Tier-A `copied_from` descriptor directive** (grm-1.7.1.2) the directive is simply
  **ignored**: no KERNAL ROM means no CHRGET copy is produced, log note only.

If ROM bytes appear in the program later, the directive can kick in then: the materializer is
idempotent (`getBlock(name) != null` guard) and the analyzer declares `supportsOneTimeAnalysis`,
so a re-run materializes it. **Consequence to record against grm-1.7.1.2:** Tier A therefore
needs an analyzer or command front-end, not loader-time-only work — a directive consumed only at
load time makes the "ROM added later" path unreachable.

This **supersedes** `docs/smc-runfromelsewhere-design.md` §8 open question 2, which recommended
best-effort materialization against an uninitialized source. The answer is now: gate on a
readable source, ignore the directive otherwise.

## 7. Consequences for other beads

- **grm-r6f** (reference-precedence retargeting: redirect refs from base to a copied overlay)
  **narrows**: in-place copies resolve natively in the base space and need no retargeting at all,
  so the bead applies only to the overlay-fallback path of §3.1 and to banking. Qualified by
  grm-bqs: a Gate 0.5 *redirected* carve lives in an overlay and does **not** resolve natively, so
  it still needs the entering-jump bridge.
- **grm-bqs** (banked destinations) **amends §5**, adding Gate 0.5 and precondition 5. Its wider
  lesson is a reuse boundary: the placement decision consumes `BoardBankAnalyzer`'s resolved write
  reference rather than re-deriving an answer from the descriptor, because only the analyzer has
  the bank state the answer depends on.
- **grm-1.7.1.2** (Tier-A `copied_from` descriptor directive) **inherits the ROM-gated placement
  rule** of §5 and §6 — materialize in place when the source ROM is readable, ignore the
  directive when it is not, and provide an analyzer/command front-end so a later-supplied ROM can
  still trigger it.
- **grm-1.7.2** (decrypt-on-the-fly) is **unaffected**: precondition 1 keeps every transformed
  copy on the overlay representation `docs/smc-decrypt-design.md` §5 already specifies.

## 8. Deliverable status

Every box below shipped as scoped. The §5 policy has since been **amended once**; the amendment is
listed with its own bead rather than folded into the original items, so this stays a record of what
shipped and when, not of what the note originally imagined.

- [x] Verdict: no Ghidra core change, no upstream ask, not an RFC #9349 item — §2
- [x] Five API findings with citations against `Ghidra_12.1.2_build` — §2
- [x] Three strategies weighed, including the rejected base-space byte map — §3
- [x] `TransferTransform.IDENTITY` fence + carve == write invariant — §4
- [x] Placement policy (Gate 0 + preconditions 1-4) — §5
- [x] Unreadable-source rule (skip, do not fall back) — §6
- [x] Implementation (`TransferMaterializer` carve path + placement decision matrix, with
      `C64CopyLoopAnalyzer` reduced to recognition) — landed with grm-chu
- [x] Tier-A analyzer/command front-end so the "ROM added later" path is reachable — grm-1.7.1.2
      (`DescriptorCopyHintAnalyzer`, a one-shot-capable `BYTE_ANALYZER`)
- [x] **Amended 2026-07-27, grm-bqs**: banked destinations — Gate 0.5 (resolve through the store's
      own re-homed write reference) plus precondition 5 (carve only plain RAM), and the
      `IN_PLACE_BANKED` placement — §5. Regression fixtures `copybanked`/`copybankedrom`, whose
      goldens are deliberately byte-identical.
