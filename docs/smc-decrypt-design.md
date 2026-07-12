# Decrypt-on-the-Fly Recovery: Implementation Design (grm-1.7.2)

Concrete implementation design for grm-1.7.2 (SMC use case 2: code stored encrypted /
EORed in place, decrypted at runtime, then executed). Turns the survey verdict
(`docs/smc-survey.md` §5, par.140-147) into buildable structure: recognizer heuristics,
the decrypted-bytes materialization + provenance model, and the interface contract
against the shared emulation harness (`grm-edg`).

**No code is written by this note — it is the design gate before implementation.** All
code references validated against the extension @ current `main`; citations are
`file:line`.

## 1. Scope and tier structure (from the survey)

Three tiers, in ascending cost and descending automatability. This bead is the **pilot
for the shared `grm-edg` harness**, so the design pins the tier-1↔tier-2 seam (§4)
before either side is built.

| Tier | Handles | Approach | Dependency |
|---|---|---|---|
| **1** | constant-key EOR loop (`EOR #imm`, or EOR against a fixed in-image byte) | static recognizer → decrypt inline → overlay | none — **unblocked** |
| **2** | rolling/chained key, computed key, multi-pass — any decryptor that is self-contained and touches no hardware | recognize entry → **bounded emulation** (`grm-edg`) → dirty-set → overlay | `grm-edg` |
| **3** | hardware-derived keys (CIA timer / raster / SID), or unrecognized shapes | WARN + provenance bookmark; point at manual workflow | docs only |

Tier 3's "manual workflow" is Path B (Debugger pure-emulation, *Copy Into Program*) or
Path C-lite (VICE `.vsf` snapshot import) — both are separate beads
(`docs/smc-survey.md` §3-4); tier 3 here is only the **detect-and-refer** behavior.

## 2. The recognizer target: what a decrypt loop looks like

The canonical constant-EOR in-place decryptor on 6502 is an indexed read-modify-write
loop:

```
      LDX #len-1            ; or LDY; or count up to #len
loop: LDA table,X          ; indexed load from the encrypted range   (absolute,X / zp,X)
      EOR #$5A             ; constant key  (tier 1)   — or EOR key,X (rolling, tier 2)
      STA table,X          ; store back to the SAME range            (absolute,X / zp,X)
      DEX                  ; or INX
      BPL loop             ; or BNE / CPX+BNE
      JMP table            ; …then execution enters the now-decrypted range
```

Recognition is a **shape match on a short basic block that is the target of a
back-branch**, not dataflow. The load-bearing invariants that make it a decrypt loop and
not an arbitrary table transform:

1. an indexed **load** and an indexed **store** using the **same index register** and
   the **same base address** (read range == write range → *in-place*);
2. a **transform** between them on the accumulator (`EOR` is the tier-1 marker; the
   presence of any A-transform generalizes to tier 2);
3. an **index step** (`INX`/`DEX`/`INY`/`DEY`) and a **conditional back-branch** to the
   block head, bounding the range;
4. the decrypted range is subsequently **branched into** (a `JMP`/`JSR` into
   `[base, base+len)`), which is what makes it *code* recovery rather than a data
   codec — and the confidence signal that we should disassemble the result.

### Why this is new code, not a `StoredValueScanner` extension

`StoredValueScanner` (`src/main/java/retromachines/StoredValueScanner.java`) is the
closest existing idiom but **cannot** do this, for two structural reasons:

- It models each store's source as an affine mask `(x & aAcc) | oAcc` over `AND`/`ORA`
  immediates (`resolveStoredValue`, :98); **`EOR` is in `A_MODIFIERS` (:79) purely as a
  scan-*stopping* opaque modifier** — XOR is not representable in that affine form
  without a third accumulator. It literally cannot fold an EOR into a value.
- It is **single-store and straight-line**: it walks backward within one basic block and
  bails at any control-flow join or non-fallthrough predecessor. A decrypt loop is
  indexed and iterated by construction — the exact opposite shape.

So tier 1 is a **new loop recognizer** that *borrows the scanner's idioms* — small
closures over mnemonic sets, the operand helpers (`isImmediate` :315,
`immediateOperandValue` :326, `plainAbsoluteTarget` :341), and block-walking via
`Instruction.getFlows()`/`getFallThrough()` — but does not call into it. Because
`StoredValueScanner` is package-private (`final class`, :61), any code reusing those
helpers **must live in the `retromachines` package** anyway.

## 3. Tier 1 recognizer: analyzer shape and heuristics

**Class**: `C64DecryptLoopAnalyzer` (working name) in `retromachines`, modeled on
`C64BasicAnalyzer` (`src/main/java/retromachines/C64BasicAnalyzer.java`) — the
single-pass annotate-and-bookmark template, **not** the heavy dataflow-fixpoint
`BoardBankAnalyzer`.

- `extends AbstractAnalyzer`, `super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER)`.
  Instruction (not byte) analyzer: recognition needs decoded instructions. Runs **after**
  Ghidra's disassembly reaches the decryptor stub but the analyzer must tolerate the
  encrypted range being un-/mis-disassembled (that is the whole point).
- `setPriority(...)`: after `REFERENCE_ANALYSIS` (mirror `BoardBankAnalyzer.java:161`), so
  branches/flows exist to find the back-edge and the jump-into-range.
- `canAnalyze`: gate on `program.getExecutableFormat().equals(C64PrgLoader.NAME)`
  (mirror `C64BasicAnalyzer.java:100-104`). Auto-discovered by Ghidra `ClassSearcher` —
  **no registration file** (confirmed: `Module.manifest` empty, no `META-INF/services`).
- `setSupportsOneTimeAnalysis()` — this is exactly a run-on-demand recovery pass.

**`added()` algorithm** (over the analyzed `AddressSetView`):

1. Find candidate loop heads: instructions that are the destination of a **backward**
   conditional branch whose body is ≤ ~8 instructions (self-contained loop).
2. Within the body, match invariants (1)-(3) from §2 using the operand helpers: one
   `LDA base,idx`, one `STA base',idx'` with `base==base'` and `idx==idx'`, an
   `EOR`/transform in between, an index step matching the branch sense.
3. Resolve the **range**: `base` from `plainAbsoluteTarget`-style operand read; `len`
   from the loop bound (`LDX #imm` init + step/branch sense). If the bound is not a
   static immediate → not tier 1; emit a tier-2/3 candidate (§4) and stop.
4. Resolve the **key**: `immediateOperandValue` of the `EOR` → tier-1 constant.
   `EOR base2,X` (rolling) → **not tier 1**, hand to tier 2.
5. Emit a **RecognizedDecryptor** record (§4). Tier 1 additionally *executes the
   transform itself* (it is a pure byte XOR over a known range with a known constant —
   no emulator needed) and materializes (§5).

**Confidence gating** (a decrypt loop is a strong shape, but guard against false hits):
require invariant (4) — a later `JMP`/`JSR` into `[base, base+len)` — for **auto-apply**;
without it, recognize but only **bookmark a candidate** (WARN) and do not rewrite bytes.
This keeps a generic table-transform loop (e.g. a checksum or screen fill) from being
silently "decrypted."

## 4. The tier-1 ↔ tier-2 seam: `RecognizedDecryptor`

This is the load-bearing design decision the pilot exists to get right: **tier 1's output
type is exactly tier 2's (harness) input type**, so the two tiers share one recognizer
front-end and differ only in the recovery engine behind it.

```
RecognizedDecryptor {
  Address  entry;            // loop head (tier 2) / first body insn (tier 1)
  AddressRange target;       // [base, base+len) — the range that gets rewritten
  KeyModel key;              // CONSTANT(byte) | ROLLING(addr) | COMPUTED | UNKNOWN
  StopHint stop;             // exit address / dirty-watch on `target` / fuel bound
  Confidence confidence;     // AUTO (jump-into-range seen) | CANDIDATE (not)
  Address  jumpInto;         // the branch that enters `target`, if found (nullable)
}
```

- `KeyModel.CONSTANT` → tier 1 decrypts inline (§3.5), no harness.
- `ROLLING`/`COMPUTED`/`UNKNOWN` with `confidence==AUTO` → tier 2: pass `entry`, a
  dirty-watch `StopHint` on `target`, and the descriptor IO policy (§6) to `grm-edg`.
- `UNKNOWN`/hardware-touching → tier 3: WARN bookmark + refer to manual workflow.

Both tiers converge on the **same materialization** (§5) given `{target, recovered
bytes, provenance}` — whether the bytes came from an inline XOR or from the emulator's
dirty-set read.

## 5. Materialization and provenance model

The survey mandates: **encrypted original stays navigable; decrypted view is an
overlay; a provenance bookmark links them** (`smc-survey.md` par.143-147). Two of the
three mechanics here are **new to this codebase** (flagged by the code survey) and are
the implementation risk to retire first.

### 5.1 The `DECRYPTED_xxxx` overlay block (new-ish)

Create an **overlay** memory block over `target` named `DECRYPTED_<hexstart>` and write
the recovered bytes into it:

- `MemoryBlockUtils.createInitializedBlock(program, /*overlay=*/true, name, start,
  bytes, ..., log)` — the exact call loaders already use
  (`NesRomLoader.java:576-589`, `C64PrgLoader.java:336-354`), but **invoked from an
  analyzer's `added()` rather than a `Loader`** — no existing precedent for that timing
  in this repo; first thing to prototype. `MemoryBlockUtils` is not documented to forbid
  it, but it is unproven here.
- Naming: follow the deterministic `OverlayNaming` convention style
  (`DescriptorSupport.java:797`) — a parseable `DECRYPTED_<start>` so a later pass (or
  the banktest dump) can round-trip block ↔ source range. The overlay's `AddressSpace`
  name **is** the block name once `isOverlay=true`.
- Writing bytes: `program.getMemory().setBytes(...)` into the new block — **no
  `setBytes` call exists anywhere in `src/main/java` today** (reads use `getBytes`); this
  is genuinely new and the second thing to prototype. (An initialized block seeded from a
  `byte[]` may avoid a separate `setBytes` entirely — prefer that if the API allows
  seeding at creation.)

Overlay (not in-place patch) is chosen deliberately: the encrypted bytes remain at their
home addresses in the base space, so a static reading of the *stub* still sees what the
CPU saw before decryption, while disassembly of the *payload* proceeds in the overlay.
(`createByteMappedBlock` is **not** used here — that is the run-from-elsewhere/dual-home
tool for grm-1.7.1; a decrypt transforms bytes, so a mapped 1:1 block is wrong.)

### 5.2 Provenance (established mechanic)

- A **NOTE bookmark** at `entry` and at `target.start`:
  `program.getBookmarkManager().setBookmark(addr, BookmarkType.NOTE, CATEGORY, msg)` —
  the exact pattern at `C64BasicAnalyzer.java:203-206`. `CATEGORY =
  "C64DecryptLoopAnalyzer"`. Message records: source range, key model/value, tier used
  (static vs emulated), and — critically — any harness **suspect flags** (uninitialized-
  RAM or IO reads, §6/§7).
- A **PRE comment** on the overlay block start and an **EOL comment** at the decryptor
  `entry` cross-linking the two addresses (comment API already used,
  `C64BasicAnalyzer.java`).
- WARN bookmark instead of NOTE when `confidence==CANDIDATE` or the harness flagged the
  result suspect — never silently present low-confidence bytes as ground truth.

## 6. Tier 2 and the `grm-edg` interface contract

Tier 2 does **not** decrypt; it hands a `RecognizedDecryptor` to the harness and
materializes what comes back. The contract this bead pins for `grm-edg`:

```
EmulationRecovery.recover(
    Program program,
    Address entry,
    StopConditions stop,          // exit-range | dirty-watch(target) | fuel | wallclock
    IoPolicy io                   // sourced from the board descriptor (below)
) -> RecoveryResult {
    AddressSetView dirty;         // every address written  (dataWritten callbacks)
    byte[] recovered;             // dirty bytes read back from emulator state
    StopReason reason;            // NORMAL | FUEL | DECODE_FAULT | CANCELLED
    ProvenanceLog log;            // IO-read sites, uninitialized-RAM reads, warnings
}
```

- Engine: interpreted `ghidra.pcode.emu.PcodeEmulator` (SMC-safe by construction;
  **never** `JitPcodeEmulator`), `EmulatorUtilities.loadProgram`, script-driven
  `stepInstruction` fuel loop — all per `smc-survey.md` §2.
- **IO policy is descriptor-sourced, not hardcoded.** The harness reads the compiled
  `machines/<id>.map` IO occupant and its `subregions[]` — the same structure
  `DescriptorSupport.createIoSubregions` (`DescriptorSupport.java:206`) consumes, authored
  in `machines/c64.yaml:68-112` (VIC `$D000`, SID `$D400`, CIA1 `$DC00`, CIA2 `$DD00`,
  IO1/IO2). A read into any typed IO subregion → `PcodeEmulationCallbacks.readUninitialized`
  / `beforeLoad` returns a policy value **and records the site in `ProvenanceLog`**. This
  is the mechanism that lets tier 2 *detect* it has strayed into tier-3 territory: an IO
  read during decryption means the key may be hardware-derived → downgrade confidence to
  suspect (§7).
- `target` from the `RecognizedDecryptor` becomes a `dirty-watch` stop condition: run
  until the whole range is written (+ a fuel cap). `DecodePcodeExecutionException` (decode
  into uninitialized memory) is a clean natural stop if the decryptor jumps somewhere we
  failed to produce (`smc-survey.md` §2, par.53-55).

Since `grm-edg` is a separate open bead, tier 2 is **specified here but built there**;
this note's job is to guarantee the `RecognizedDecryptor`/`RecoveryResult` shapes line up
so tier 1 (now) and tier 2 (later) share the recognizer and the materializer.

## 7. Risks (decrypt-specific; general harness risks in survey §7)

1. **False-positive decrypt** — a checksum/fill loop matches shape (1)-(3) but not (4).
   Mitigation: require jump-into-range for auto-apply; else CANDIDATE bookmark only (§3).
2. **Uninitialized RAM as key input** — power-on RAM isn't zero on a real C64; a
   decryptor keying off it diverges silently. Harness must log "read of never-written
   RAM" → suspect (survey §7.2).
3. **Hardware-derived keys** (CIA timer/raster) — the tier-2→tier-3 boundary; detected
   *only* by the IO-read provenance (§6). Without descriptor IO regions the harness can't
   tell, which is why IO policy is descriptor-sourced, not optional.
4. **Analyzer-time overlay creation + `setBytes`** — both unproven in this repo (§5);
   prototype these two mechanics in isolation before wiring the recognizer, since the
   whole feature is dead if a post-import analyzer can't create/populate an overlay.
5. **Re-run idempotence** — a second analyzer pass must detect an existing
   `DECRYPTED_<start>` block and skip, not stack overlays (cf. `BoardBankAnalyzer`'s
   rerun-fingerprint cache, `BoardBankAnalyzer.java:196-325`).

## 8. Testing plan (banktest regression)

Follow the `mkbasictest.py` → `checkC64Basictest()` → `expected/*.dump` template
(`tools/banktest/`, survey of harness confirms the exact steps):

1. **`mksmctest.py`** (or extend `mkbanktest.py`): hand-assemble a `.prg` with a
   constant-EOR loop over a small encrypted code block that, decrypted, is a recognizable
   routine (e.g. a `JMP` chain), followed by a `JMP` into the range (invariant 4).
2. **`checkSmctest()`** in `VerifyBankTest.java`: assert the `DECRYPTED_<start>` overlay
   block exists, its bytes match the known-plaintext, the provenance NOTE bookmark is
   present, and the payload disassembles. Reuse `criterion(id, bool, detail)`
   (`VerifyBankTest.java:915`).
3. Extend `dump()` (`VerifyBankTest.java:104-164`) so the new block name + bookmark
   category appear in the normalized golden dump.
4. Register `run_one smctest <fixture> C64PrgLoader` in `run-banktest.sh` (~:130-142);
   `build-and-test.sh bless` once, `check` thereafter.

A **tier-1-only** fixture (constant key, no emulation) is fully testable now and is the
acceptance gate for the static tier independent of `grm-edg`.

## 9. Open questions (resolve before/while implementing)

1. **Overlay vs in-place patch default** — this note recommends overlay always (keeps
   encrypted stub navigable). Confirm no downstream analyzer needs the *decrypted* bytes
   at their *home* addresses (if so, a mapped/patched variant is a follow-up).
2. **Recognizer generality vs C64-first** — design types are machine-neutral, but the
   first analyzer gates on `C64PrgLoader`. Is a 6502-generic base worth it now, or after
   a second machine wants it? (Recommend C64-first; extract later.)
3. **Where `RecognizedDecryptor` lives** — shared type between this analyzer and
   `grm-edg`; put it in `retromachines` alongside the harness types so both beads compile
   against one definition.

## 10. Deliverable status

- [x] Tier-1 recognizer heuristics (loop shape, invariants, confidence gating) — §2-3
- [x] Materialization + provenance model (`DECRYPTED_xxxx` overlay, bookmarks) — §5
- [x] `grm-edg` interface contract (`RecognizedDecryptor` / `RecoveryResult`, IO policy) — §4,§6
- [x] Testing plan — §8
- [ ] Implementation (tier 1 static: unblocked; tier 2: needs `grm-edg`)
