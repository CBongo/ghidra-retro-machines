# Where the bank comes from: a catalogue of bank-source idioms

A bank switch is only useful to the analyzer if it can say **which bank** was switched in. Most
of the warnings and notes in a real-ROM golden come down to one question: *where did the value
written to the mechanism come from, and how did the program get it there?* Real games answer that
in a small number of recurring shapes. This document names them, so that a bead, a warning and a
design can all point to the same thing.

It is a catalogue of **idioms in game code**, not of our classes. Where an idiom maps to an
existing mechanism, the mapping is given, but the idiom is defined by what the 6502 code does.

The classes and their letters come from the deferred-request recon (`grm-5tl.20.2`, 2026-11-08):
two passes over 936 unique NES PRG images, about 25 titles read by hand. The letters are stable
and beads use them; add new classes at the end and never re-letter.

## The classes at a glance

| Class | Idiom | The cell holds | Analyzer today | Examples |
|---|---|---|---|---|
| **A** | Argument cell: the bank is stored to RAM (or a register) right before the switch call | the bank about to be committed | Resolved from the caller's store (`HelperArgumentRecovery`, `LocalStoreForwarding`); `BankMirrors.Kind.INPUT` | ff1 `$57`, megaman3 `$f5`, Rygar (bank in X), Fighting Simulator `$58` |
| **B** | Current-bank shadow: the switch also stores the bank to RAM, and a later reload re-commits it | the live bank (or a saved copy) | `RESTORED_BANK` notes (`grm-yflf`, `grm-rd6h`), PHA/PLA and save-slot pairing (`grm-mej.3`, `grm-zsxz`); `WRITE_THROUGH` / `SAVE_SLOT`; per-game `banking.shadow_commits` | tmnt `$21`, cv2 `$1c`, zelda2 `$0769`, Ikari `$70`, Ninja Gaiden `$5c` |
| **C** | Busy / re-entrancy flag around the switch | not a bank | Should stay silent; a flag misread as a bank source is a bug | cv2 `$1b`, Metal Gear 2 `$24`, megaman3 `$f6`/`$f7` |
| **D** | **Deferred request**: the bank is written to a request cell at sites that do not switch; a later pass (main loop or NMI) commits it | a bank that will be live later | Not handled; epic `grm-5tl.20` | Metroid `$24` (call-time), Tecmo Bowl `$1d` (NMI, data) |
| **E** | Deferred **CHR** request, committed in NMI | a CHR bank | Out of scope (graphics) | Tecmo Bowl `$2c`, `$cc` |
| **F** | Bank-ID read-back: the program reads the live bank from a byte inside the mapped bank that holds that bank's own number | — (ROM byte, not RAM) | `banking.bank_identifying_offsets` and content derivation; `BankMirrors.Kind.ROM_IDENTIFYING` | dodge `$BFF9`, tmnt3 `$A000`, Tecmo Bowl `$bff8`, Gretzky `$8000`, TMNT `cec0 LDA $8000` |

The four `BankMirrors.Kind` values (`src/main/java/retromachines/BankMirrors.java`) are the
analyzer's own vocabulary for the RAM and ROM cells involved. The consuming rule is the important
part: only `WRITE_THROUGH` and `ROM_IDENTIFYING` cells may be answered from tracked bank state,
because they hold the **live** bank. `INPUT` and `SAVE_SLOT` hold a bank that is deliberately not
the live one, and resolving them from tracked state would ship a confidently wrong bank. Class D
cells are the same in that respect: they hold the bank that *will* be live.

## A. Argument cell (synchronous)

```
LDA #$03        ; or LDA table,X / LDY cell / ...
STA $57         ; the argument cell (or keep it in A/X/Y)
JSR switch      ; the helper reads $57 (or the register) and commits it
```

**Recognize it by** adjacency: the write to the cell, and the call to the switch, are in the
same straight line. The cell is read inside the helper, or by the caller just before the call.

**Analyzer.** The helper is modelled as taking an argument; `HelperArgumentRecovery` finds the
inbound register or cell, and the call site resolves the bank from the caller's store. Notes:
"bank value is this helper's ARGUMENT" at the helper, a bank comment at the call site. Variants
handled:

- the argument spilled to a RAM cell inside the helper and reloaded across a call the callee
  provably does not write (`grm-hsv.9`, dodge `$69`, `FUN_fe96`);
- a cell filled by `PLA / STA` inside the helper (dodge `FUN_ff08` via `$0103`);
- an index-register argument renamed through `TAY`/`TAX` (`grm-ld68`, contra `c0d3`).

**Open.** An argument passed in Y and moved into A through a scratch cell at helper entry
(`TYA / STA $00 / ... ORA $00`, Metroid `c4ef`) reports "takes NO INBOUND ARGUMENT" today
(`grm-hsv.15`). A bank carried in an object record (Rygar `$032e,X & 7`) or a per-handler bank
table (Rygar `$c193,Y`) is honest-unknown unless the index is known.

## B. Current-bank shadow, and restore by reload

```
switch:  STA $21        ; shadow = bank being committed (write-through)
         STA $8000      ; mechanism
...
restore: LDA $21        ; or LDA saved_copy / PLA
         JSR switch     ; re-commit the bank that was live earlier
```

**Recognize it by** the write to the cell being part of the switch itself (the same basic block
as the mechanism write), and later loads of the cell feeding the mechanism again. A saved copy
(`LDA $70 / STA $71`, Ikari) or a stack save (`LDA $BFF9 / PHA ... PLA`, dodge) is the same
idiom one step removed.

**Analyzer.** A reload that re-commits the live bank is a `RESTORED_BANK` **note**, not a
warning: the value is correct by construction even though it is not a known number. The proof
needs the save and the restore to pair (`CrossBlockStackPairing` for the stack, including joins
over shared-return-call tails since `grm-hsv.13`; `SaveSlotForwarding` for RAM save slots,
crossing calls only when the callee closure provably never writes the slot). A game whose helper
re-derives the bank from a shadow with no argument can be stated per game with
`banking.shadow_commits` (`docs/SCHEMA.md`).

**Sub-variants seen.**

- *Single-writer home bank:* the shadow has one writer and one value (California Raisins `$da`,
  always 6).
- *Shadow synced without a switch:* code running in bank N stores N to the shadow with no
  mechanism write (Ninja Gaiden bank 4 storing `#4`), or a restore copies a saved shadow back
  (`$7f` → `$5c`). These are **not** requests (class D), even though no switch follows them.
- *Re-commit from RAM latches written with constants:* cv2 `c140`–`c182` re-commit Control/CHR
  from `$0100`–`$0102`, whose every writer stores a constant. Left as warnings (`grm-hsv.9`, note
  on `grm-hum`): resolving them needs a value-set fact about the cell, not a pairing proof.
- *Fixed bits in a shadow:* Metroid re-commits `($25 & $FE) | bit` and `($28 & $18) | Y`; the
  preserved bits are constant program-wide but no local proof exists (`grm-hsv.14`).

## C. Busy or re-entrancy flag

```
LDA #1 / STA $1b    ; "switch in progress"
...serial writes...
LDA #0 / STA $1b
; NMI: LDA $1b / BNE retry_later
```

**Recognize it by** constant 0/1 (or bit) stores bracketing the mechanism writes, and reads that
only branch, never feed the mechanism. Usually exists because an MMC1 serial sequence cannot be
interrupted by another switch.

**Analyzer.** Nothing to resolve. The only risk is misclassifying the flag as a class D request
cell (both are written at sites with no switch), so a detector must require that the cell feeds
the mechanism value.

## D. Deferred request (the live bank as game state)

```
; requester (no switch here)       ; fulfiller, later (main loop or NMI)
LDA area_table,Y                   LDY $24
STA $24        ; request cell      BEQ none
RTS                                LDA #0 / STA $24   ; pending clear
                                   DEY / STY $23      ; applied bank
                                   ...commit Y...
```

**Recognize it by** a cell that is the commit's bank source whose other writers have **no
switch on their path to the next return**. A pending clear inside the commit and an applied-bank
cell are strong supporting evidence but not required. Guards learned from the corpus:

1. a writer that stores the bank it is executing in, or loads its own bank-ID byte (class F), is
   a shadow sync (class B), not a request;
2. the commit must read the cell at the helper's entry, not through the helper's own store;
3. a cell can be dual-use (Tecmo Bowl `$1d` is a bank when the pending flag `$1a` is positive and
   a byte count otherwise), so filter by the mode guard or by the valid bank range.

**Two variants seen.**

- *Call-time (Metroid).* `$24` = bank+1, written by constants, `INY`, and table `ca30` indexed
  by area. `c4de`→`c4e8` commits it and records `$23`. About 45 calls from the fixed bank then run
  in whichever area bank is live; the candidate set is {0..5} (`grm-5tl.20.1`).
- *NMI, data (Tecmo Bowl).* `$1d` is the bank of the VRAM-update list; the NMI commits it at
  `c0d3`, reads the list through `($1b),Y`, and restores the interrupted bank from `$0c` (saved
  from the bank-ID byte `$bff8`). No calls depend on it; only data reads do.

**Analyzer.** Not handled; the warnings are honest ("takes NO INBOUND ARGUMENT", "genuinely
undeterminable value"). Plan in epic `grm-5tl.20`: a per-game candidate-set hint, then inference
from the request cell's writers, then emission of references into every candidate bank (one
reference plus a note where the target's code is identical across them, and pruning of banks
where the target is not plausible code).

**Frequency.** Rare: two titles in 936 PRG images. Most "the bank comes from RAM" cells are
class A or B.

## E. Deferred CHR request

The same idiom as D, but the committed register selects CHR (graphics) banks, typically in NMI
right after the PPU register writes (Tecmo Bowl: `$2c` at `c1ea`, and `$cc` with bit 7 as the
pending flag at `c087`). It never affects which code runs. Out of scope while graphics analysis
is; recorded so that a detector for D can exclude it by the register it commits to.

## F. Bank-ID read-back from ROM

```
LDA $BFF9     ; this bank's own number, stored in every bank at the same offset
PHA           ; save it
...switch, call, ...
PLA
JSR switch    ; restore
```

**Recognize it by** a load from a fixed offset in the switchable window whose byte equals (or
encodes) the bank number in every realized bank. Games use it instead of a RAM shadow: dodge
`$BFF9`, Tecmo Bowl `$bff8`, Wayne Gretzky `$8000` (each bank's first byte), TMNT `cec0 LDA $8000`
("which bank am I in?").

**Analyzer.** Derived from image content (`BankMirrors.romIdentifyingOffsets`, encodings in
`IdentifyingEncoding`, e.g. River City Ransom's `bank >> 1` on odd banks only, `grm-km4f`) or stated
per game with `banking.bank_identifying_offsets`. A read of the offset resolves from tracked state,
and a save/restore through it is a `RESTORED_BANK` note. Fixed banks that hold a different byte
there can be exempted (`grm-hsv.8`).

## Related: interrupts that switch and do not restore

Not a bank-source class, but it changes what "the live bank" means. Rygar's NMI (`c0f6`)
switches to bank 6 then bank 3 and **never restores** the interrupted bank, so its main-thread
code re-switches before every banked access. A static analyzer that assumes an interrupt leaves
the bank unchanged would carry a stale bank across any point where the NMI can fire. Most games
either save and restore around the NMI (Tecmo Bowl's `$0c`) or never switch in it.

## Classifying a new site

1. Does the value written to the mechanism come from a RAM cell or a ROM read? If it is an
   immediate or a register loaded from an immediate, it is a plain resolved switch.
2. ROM read at a fixed window offset whose byte tracks the bank → **F**.
3. RAM cell: find every writer of the cell (`tools/recon/cellxref.py --writers`).
   - Every writer is next to a switch call and stores the value about to be committed → **A**.
   - The cell is written as part of the switch, and reloads re-commit it → **B**.
   - Writers store 0/1 around the switch and readers only branch → **C**.
   - Some writers have no switch on their path and the cell is the commit's bank source,
     after the guards under D → **D** (or **E** if the commit is to a CHR register).
4. Record the class on the bead, with the decisive addresses.

Tools: `tools/recon/reqscan.py` (corpus scan for candidate helpers and cells), `reqrank.py`
(rankings over its output), `cellxref.py` (readers, writers, call sites in one ROM),
`bankdiff.py` (is a banked call target the same code in every candidate bank), and
`tools/banktest/dis6502.py` for a plain disassembly. The scanners are heuristics: they cannot see
NMI-vs-main-loop placement or indirect jumps, and they guess helper entries, so every class needs
a hand read to confirm.
