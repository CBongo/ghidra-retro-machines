# Real-ROM bless history

The append-only archive of the real-ROM tier's re-bless log. Each entry records why
`tools/banktest/realrom/expected/*.dump` goldens moved: which rows, which count or sample
lines, which bead or commit caused it, and what the owner ruled.

**This file is history, not status.** The current state of the tier (last verified result, known
failing or bistable rows, the toolchain banner a run must show) lives in the
`realrom-current-fails` bd memory (`bd recall realrom-current-fails`), which is deliberately kept
short and current-only. Anything that stops being current there, and every dated `LATEST` entry,
is moved here, newest first, under a new dated section at the top.

Entries are copied verbatim from the memory and are plain text, not Markdown: identifiers with
underscores or asterisks may render oddly. Each was true when written, and later entries
supersede earlier ones. A bead id or commit hash in an entry is the authoritative record of
that change.

## 2026-10-16 -- wizwarr re-blessed (grm-v60, far-call trampoline placement)

New FarCallTrampolineAnalyzer resolves ff83 JMP ($001b) per call site: low byte from the
caller's Y, high byte $80 from the write-once init store at 895a (owner ruling: general
write-once rule, accepted only when the target lands on a JMP/JSR abs entry in the destination
bank), bank from A via the bc02/bc05/bc08 BIT-skip entries. 58 call sites -> 24 vector slots in
PRG_ALL_B1..B3, 0 declined. wizwarr: instrs.inOverlay 0 -> 3964, refs.intoOverlay.retargeted
0 -> 24, intraOverlay 0 -> 915, bankComments 59 -> 61 (8c76/8ca0 bank 3 via FUN_0300), warnings
3 -> 7 (ff76/ff7f "becomes unknown" now also in the B1/B2 overlay copies of the trampoline),
symbols 23 -> 75. Removed sample lines are sampling only: the symbol sample now truncates
(25 of 63), and the COPY_0300/033d notes are reworded because new bank-3 code calls into them.
check nes: the other 34 rows byte-identical; build-and-test.sh check SUITE OK.

## 2026-10-16 -- megaman/megaman3 and 21 other rows retargeted to GoodNES [!] (grm-cssm, grm-n2pa)

Hash-line-only except drmario (overdump's phantom W8000_M0_B2/4/6 overlays gone, blocks 8 -> 5),
kicarus (prgsha256: old pin had one corrupt byte) and megaman (relocation only, counts
identical). See tools/banktest/realrom/README.md "Which dump each NES row pins".

## 2026-10-16 -- bionic re-blessed (grm-dos9.14)

Two changes, both owner-ruled 2026-10-16. (1) HelperDiscovery.findCallEdgeWrappers accepts a
body-closing plain JMP as a relay, so FUN_dcbe (STA $65 / JMP dcaa, entering FUN_dca8's chain
mid-body) is a call-edge wrapper: c2e2 (LDA #$0B / JSR d7cc -> thunk -> dcbe) now resolves
prg_bank=11, verified against the bytes. (2) A helper-body site whose scan stops at a join of
helper entries, every one judged at its own call sites, is the new ENTRY_SUPPLIED stop (a NOTE,
census-exempt): dcaa/dcba warnings -> notes, and bionic's prg_mode lock forms (3, first at c04b,
shifter reset at ffe1 outvoted). bionic warnings 2 -> 0, notes 3 -> 5, bankComments 5 -> 6,
refs.intoOverlay.retargeted 1 -> 2. check nes: the other 34 rows byte-identical;
build-and-test.sh check SUITE OK after nesmmc1test's M11 shadow-helper control moved from
"stays a warning" to "entry-supplied note" (its c252/c262 are a transcription of dcaa/dcba).

## 2026-10-15 -- cv3 re-blessed (grm-dos9.11)

BankDataflowEngine.joinArms now admits a join predecessor in another function's body (the
4-arg closedWorldPredecessors, as grm-mej.21's cross-block search already did). cv3's e2dc
STA $5116 is a store tail shared by the e2d6 (LDA #$87 / BNE e2dc) and e2da (LDA #$9e)
entries; Ghidra gives the tail to FUN_e2da only, so the BNE edge looked cross-function and the
site warned "genuinely undeterminable". It now forks on bank_5116 = 7 | 30 (bit 7 is MMC5's ROM
select). cv3 warnings 15 -> 14, bankComments 171 -> 172, nothing else moved. check nes: the
other 34 rows byte-identical (run with the GoodNES USA dir passed positionally, so no SKIPs);
build-and-test.sh check SUITE OK.

## 2026-10-15 -- deadly_towers re-blessed (grm-pwuh, 53597e2)

deadly_towers was carried as "BATCH-DEPENDENT: fails every batched run, solo passes" from
grm-x4y1.6 until this fix. That label was wrong. The row failed SOLO too, most runs (solo FAIL,
FAIL, PASS; with DeterminismProbe 1 pass in 11); the harness's one solo diagnostic rerun had
simply passed. The real cause was its BNROM trampolines (fc27/fc3c/fc51 in every bank), which
switch banks and THEN read their jump table. Ghidra read each copy's table from its own bank, the
B2 copy got 59 garbage targets, and their decodes raced real flow, so the fc3f helper model (fd42
bank 3 vs 0) varied run to run.

The fix reads such tables from the switched-in bank (BankContext + CrossBankTable in
JumpTableBoundAnalyzer, pinned by references), keeps only the valid prefix, and requires the
switched-in bank's own copy to read an overlapping table. Re-blessed from a dump that was
byte-identical across 4 solo runs and the batched run:
- every sample.bankcomment line is unchanged from the old golden;
- symbols 636 -> 350 (garbage switch/case labels gone);
- intraOverlay 1660 -> 1915 and instrs.inOverlay 4517 -> 4734 (the real cross-bank targets);
- warnings 1 -> 2, the new one being ad41, real code flowing into RAM.
No other row moved on check nes. Follow-ups: grm-ktne (the 'via fcfa' RESET attributions),
grm-1qi7 (other BankContext consumers), grm-u7cy (one solo rerun cannot tell "batch-dependent"
from "flaky").

## Retired status records, 2026-08-22 to 2026-10-13 (moved 2026-10-15, grm-x4y1.1)

These are summaries (not verbatim) of status text that used to live in the
`realrom-current-fails`, `realrom-flap-hashes` and `realrom-12-1-3-toolchain-fails` bd
memories. All of it is obsolete: as of 2026-10-14 (grm-x4y1.3, cd59001) `check all` is
all-PASS and byte-identical across five consecutive runs at batch sizes 1/5/10/20/45, and no row
is failing or bistable. `realrom-current-fails` now holds current state only; the two other
memories were retired. Kept here so the reasoning behind each past state is not lost.

**Steady state before the fixes (2026-09-20 to 2026-09-26, patched decompiler).** `check nes` was
`pass=30 fail=3` of 33 (floor `fail=2`, dodge and ff1, after grm-hvc1 re-blessed rcproam on
2026-09-21), and a run could legitimately report anywhere from `fail=2` to `fail=6` depending on
which bistable rows landed on which pole. Rows involved: `dodge` was a STALE GOLDEN (grm-q1bi:
grm-pdd6's NO_DEPOSIT removals, warnings 40->29 / bankComments 29->25) mixed with jitter; `ff1`
bistable with coupled states 1847/7382 <-> 1880/7426(7444) and a third 1849/7400 (grm-4nr,
grm-g73); `dragonpower` warnings 5<->6 at 8ee4 and symbols 152<->168 at a546; `shenlong` symbols
97<->113; `lwings` bankComments 37<->40 via the three caseD_f8 sites (ede6, ee2e, ee8d), the only
one whose jitter moved `sample.bankcomment` lines, and ALSO a stale golden hidden behind that
bistability (grm-k5m, ea90ba9, reworded three CopyLoopAnalyzer sample.note lines on 2026-09-20 and
the golden was not refreshed until grm-rap8 on 2026-09-26); `rcproam` bistable, re-blessed under
grm-hvc1; `megaman` found nondeterministic on 2026-09-26 (grm-4wqd: refs.intoOverlay 1705<->1698,
one bankcomment a9ac<->a9ab, on both sides of an `ab-test.sh --repeat 2` including unmodified
HEAD 0e891a0). The 12.1.4 retarget run (grm-rap8, 2026-09-26) was `pass=42 fail=5 skip=0` of 47:
megaman, dragonpower, dodge, ff1, lwings. The rule then was "read WHICH rows, the count alone is
not the test; a ninth candidate or a non-matching signature is real".

**Patched-decompiler blesses (2026-09-20 to 2026-09-25).** After the owner's 2026-09-20 ruling
(grm-qp5x.3), megaman (1705/7428/156, warnings 31, notes 11) and wizwarr (warnings 5, notes 15)
were blessed green on the GP-6936-patched `decompile.exe` (sha256 1afff91d...); grm-rd6h
(099df21, 2026-09-25) re-blessed megaman (warnings 30 / notes 12, d571 a RESTORED_BANK note),
wizwarr (warnings 3 / notes 17) and ironsword (warnings 5 / notes 5, 040a). Also 2026-09-20
(grm-qp5x.4): rcransom blessed at refs 1221 / instrs.inOverlay 5722; the old 6434 was STOCK
walking the 9352 jump table for 128 entries (grm-b3m guard defeat) on one configuration only;
the decompiler crashes on FUN_9314 on every build (grm-gz42), so a return to 6434 would be the
over-read reappearing. The candidate cache keys on the binary's hash, the staleness stamp's
line 4 names the build, and `grm_decompiler_build_name` in `tools/banktest/lib/common.sh` is the
hash table (a rebuild gives a new hash; MinGW is not reproducible). Stock 12.1.4 is ea42e06d...,
kept as `decompile.exe.stock-12.1.4`.

**The 12.1.3 stock-toolchain failures (`realrom-12-1-3-toolchain-fails`, 2026-08-22, grm-9wl6).**
A controlled A/B (source byte-identical, only `ghidraTargetVersion` flipped, cache removed per
side, repeated runs) showed megaman and wizwarr failing on stock 12.1.3 and matching their
goldens on 12.1.2: megaman refs 1704 -> ~1744, bankComments 156 -> 160/161/162 (unstable against
itself, so unblessable); wizwarr warnings 4 -> 7 (extra lines at 81b3, ffa1 and 8631). Ruling
then: the goldens were right, the 12.1.3 output wrong, neither row blessable; owner decision
2026-08-22 was to leave both failing and documented (grm-qp5x). Root cause was found 2026-09-04
(grm-qp5x.1): the single commit 6dd07f90ff, GP-6936 "wrapped memory ranges", rewrites a 2-byte
access at stack offset -1 of the 16-bit 6502 stack into a JOIN varnode; the local patch of
2026-09-20 removed the failures (see `ghidra-12-1-3-native-regression-gp6936`). Oddity noted at
the time: the three 12.1.2 control runs all landed on 1703, the minority pole of grm-g73's 8/2
split (~0.8% by chance); moot once megaman's jitter was fixed. The reusable method is the
one-line toolchain toggle above plus `git log <tagA>..<tagB> -- <subtree>`.

**Flap hashes (`realrom-flap-hashes`, 2026-10-09, grm-hp9s).** A table of full sha256 dump
hashes for the two known GxROM flaps, used to clear `ab-test.sh` diffs without repeat runs:
dragonpower (a546 jump-table race, symbols 152 <-> 168) 3e767dda...8430 / 6ed95cf4...d (the
golden) seen on 7c78302 and 3402b79, reused to clear grm-ze06.3; shenlong (symbols 97 <-> 113)
0a1f002b...b4c / e070b8d7...a96 (the golden) on 3402b79, reused to clear grm-ze06.2. Other
flapping rows (ff1, megaman, lwings, dodge, rcproam) were never hashed (grm-du7y).

**How it ended (2026-10-13, current facts moved to the memory).** grm-kon2
(JumpTableOverrideRelocatorAnalyzer writes the override for a switch the bound analyzer could only
pin by references) fixed the timing-dependent dragonpower/shenlong symbol flap and the symbol
lines of ten rows; grm-uioc made the analysis thread pin off by default (pinned, unpinned, 4- and
2-thread runs all byte-identical; the pin had been tmnt's canary, refs.intoOverlay 44, instrs 103);
grm-x51h and grm-if81 fixed the remaining dead-fall-through/pointer-data races. `check nes` was
all-PASS and byte-identical from then. The 2026-10-14 re-measurement (grm-x4y1.3) found `check
all` all-PASS, so every hash in the flap table above is obsolete. tetris and shenlong were then
dropped from the tier (grm-x4y1.7, 2026-10-14) as duplicates of drmario and dragonpower, and their
goldens deleted. Full per-change detail for the blesses is in the verbatim sections below.

## LATEST entries 2026-09-26 to 2026-10-13, verbatim

Moved here from `realrom-current-fails` on 2026-10-15 (grm-x4y1.1). Their `Expected floor` and
flap sentences are obsolete; see the section above.

LATEST 2026-10-13 (grm-x51h: DecidedBranchAnalyzer.deadCodeStart also keeps a dead fall-through that defined POINTER DATA references. Cause: InlineJumpTableDispatchAnalyzer lays JumpEngine table entries as pointers (DATA refs) and only SCHEDULES functions at the targets; DecidedBranch (BLOCK_ANALYSIS) runs on the freshly disassembled targets before those functions exist, so chain entries that linear disassembly reached as fall-throughs (tmnt b78a.. via b579 JSR $C702, table b57c incl. $B5A2) were cleared with only a pointer pointing at them. The table recognizer was never the problem.) Re-blessed 7 rows, COUNT lines only, every count UP (refs.intoOverlay/intraOverlay/instrs.inOverlay; no bankComment/warning/note/sample line changed): tmnt instrs 14930->15099 (= pre-kdgv), zelda 12868->12957, cv3 19345->19416, contra 2785->2798, tmnt3 4489->4514, lwings 7445->7473, smb2 6522->6524. blmaster (kdgv's ebf4 palette target) unchanged. check nes before bless: 27 pass + exactly these 7. Synthetic SUITE OK. Expected floor: fail=0.

LATEST 2026-10-13 (grm-uioc): THE ANALYSIS THREAD PIN IS OFF BY DEFAULT. The runners and serve.sh now use Ghidra's default pool; GRM_THREAD_PIN=1 re-pins (-Dcpu.core.override=1) as a DIAGNOSTIC, and it is keyed in both candidate caches. Basis: after grm-kon2, check nes 34/34 byte-identical across pinned, unpinned 12-thread x2, 4-thread and 2-thread runs; synthetic gate SUITE OK unpinned; goldens unchanged (they were already unpinned-correct). A row that moves with thread count is now an ORDER RACE TO FIX (cf. grm-4nr, grm-eyn, grm-v60.1, grm-kon2), not a reason to restore the pin. Old "pinned" mentions in older entries below are history. Expected floor still fail=0.

LATEST 2026-10-13 (grm-kon2: JumpTableOverrideRelocatorAnalyzer also writes the override for a switch JumpTableBoundAnalyzer could only PIN BY REFERENCES (no real function contained it on any pass that reached it), by re-running the bound analyzer's decompile-and-bound (boundFunctions) when a function containing it is created. Before, whether such a switch got its override (and its switch/case_N labels) depended on whether its function body existed by the bound analyzer's 2nd pass -- timing, not thread count: dragonpower a546 152<->168, shenlong 97<->113. Bound EOL comment no longer repeats per pass.) Re-blessed 10 rows, SYMBOL lines only (counts UP, every new line a USER_DEFINED override switch/case label; no ref/instr/bankComment/warning/note changed anywhere): cv3 147->181, dodge 136->239, ff1 108->143, lwings 18->95, megaman 122->216, rcproam 37->109, rcransom 31->49, smb3 18->31, tmnt 103->110 (new override is jmp_8f34; the grm-rsxe KNOWN_CODE pin at 9474 is untouched), ultimaav 18->23. dragonpower 168 / shenlong 113 now match their existing goldens every run. check nes on the final build: pinned and two unpinned runs gave 34/34 BYTE-IDENTICAL dumps (first time pinned==unpinned holds on every row; grm-uioc). Expected floor: fail=0. THE SHENLONG/DRAGONPOWER SYMBOL FLAP NAMED BELOW IS FIXED -- a recurrence is a regression.

LATEST 2026-10-13 (grm-kdgv: DecidedBranchAnalyzer -- a conditional branch StoredValueScanner.knownBranchOutcome decides TAKEN gets a fall-through override of none, and code reached ONLY from that dead fall-through is cleared (ClearFlowAndRepairCmd; kept if any FLOW ref, entry point, function or user label at the fall-through). Owner ruling: clearing is right even when the cleared bytes are live at runtime -- the multi-entry 'LDA #n / BNE common' chains (tmnt b786.. via word table $B5A2, kicarus a217/a21e/a225) were decoded only by the impossible fall-through; reaching them is grm-x51h. HelperArgumentRecovery.prologueOutcome now steps along a decided branch over the cleared gap, keeping ultimaav f35f's 'NO INBOUND ARGUMENT' wording): re-blessed 12 rows, COUNT/sample-ref lines only, every count DOWN -- contra cv3 ff1 kicarus lwings megaman3 rcransom smb2 smb3 tmnt tmnt3 zelda (cv3 instrs.inOverlay 19831->19345, tmnt 15099->14930, zelda 12958->12868; kicarus a237 JMP $a22c becomes a call-return ref, Ghidra's shared-return handling once a22c lost its fall-from). No bank comment, warning or note changed on any row. Synthetic: nesforktest/nesforkhometest IDENTITY only -- their fixtures were wrong (LDA $10 / LDX #imm / BEQ: LDX set Z, so one 'runtime' arm was dead); generator now does LDX first. check nes on the final build: 20 pass + those 12 (intended, blessed) + dragonpower 152 / shenlong 97 flap; 3 consecutive runs gave byte-identical dumps for the 12. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST, 2026-09-26 (grm-rap8, 12.1.4 RETARGET): 'realrom-test.sh check all' on D:/ghidra_12.1.4_PUBLIC with the patched binary carried over (12.1.4 changed no decompiler source; stock 12.1.4 is ea42e06d..., kept as decompile.exe.stock-12.1.4): pass=42 fail=5 skip=0 of 47 -- megaman (1698/7413/157, the known 1698 state), dragonpower (warnings 6->5 at 8ee4), dodge (stale, 40->29 / 29->25), ff1 (1849/7400 -- a THIRD ff1 state, also seen on 12.1.3 in an earlier run, so jitter), lwings. All SNES rows and nes-curated otherwise green. LWINGS WAS ALSO A STALE GOLDEN, hidden behind its bistability: grm-k5m (ea90ba9, 2026-09-20) reworded three CopyLoopAnalyzer sample.note lines ('...and the payload does not decode as a subroutine...') and the golden (blessed 2026-09-03) was never refreshed, so lwings failed EVERY run since. Re-blessed 2026-09-26 in grm-rap8 (wording-only diff, bankComments-40 state). From now on an lwings failure should be count lines only (37<->40).

## Entries 2026-10-03 to 2026-10-13

Moved here from `realrom-current-fails` on 2026-10-13.

LATEST 2026-10-13 (grm-if81: OverlayRefProvenance, a user-property record of the overlay refs retargetReferences CREATED per instruction; a later round retracts recorded refs it no longer places, restores a base ref when that leaves the operand with none, and the end-of-round sweep retracts records of untracked instructions; confirming another pass's ref never adopts it): re-blessed REF COUNTS ONLY on 3 rows -- tmnt3 refs.intoOverlay 1102->1101, rcransom 2515->2507, zelda2 440->432 (zelda2: the base-space copy of routine 8ff8..9039 loses 8 stale W8000_M3_B6 refs at 8ffa 9001 900b 9012 9018 901e 9028 9032, intra-window so base refs were never retired; deterministic across two runs). No instr/comment/warning/block count moved on any row. Synthetic: nesintrawintest loses 2 stale PRG_LO_B1 refs (new criterion W5), nesskiptest loses c009 -> PRG_LO_B2::8010. check nes on this build: 29 pass + the 3 above (intended, blessed) + dragonpower 152 / shenlong 97 symbol flap. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-13 (grm-mej.25 follow-up 7637e00: the slot writer census propagates X/Y FORWARD through the callee closure, seeded at the crossed call, merged at joins, kept across a nested call only if calleePreserves; replaces 1d809f6's top-level-only entry stop): re-blessed cv3 (warnings 16->15, bankComments 170->171: ebdd WARNING -> partly known bank comment via FUN_e2e6, bank_5115 bits 0,3,5,6 = 0). check nes on this build: 33 pass + cv3 (intended, blessed); no flap drew. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-13 (grm-mej.25 1d809f6: slot writer census carries X/Y proven at the crossed call into the callee closure via a RegisterEnv entry stop, state-free fallback when the closure re-enters its entry; grm-mej.26 df3961c: end-of-round sweep retracts this analyzer's WARNING/NOTE bookmarks at addresses the round did not bookmark): no real-ROM row moved -- no warning or note COUNT changed on any row, so no real-ROM site carried a stale bookmark; cv3 byte-identical (ebdd/ebd5 still warn, cause unestablished, see grm-mej.19). Synthetic nesmmc3mirrortest loses its stale 'BOOKMARK Warning e2dc' (golden edited to that one line). check nes on the mej.26 build: 32 pass + shenlong 97 / dragonpower 152 (shenlong PASS on --only rerun, dragonpower 152 again); on the mej.25 build: 33 pass + dragonpower 152. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-13 (grm-mej.24: StoredValueScanner.entersUnknownBank treats a target inside a realized OVERLAY block as a KNOWN bank, so the save-slot writer census / save-helper test walk far calls retargeted into overlays; base-space banked targets entered from another block still abandon): no real-ROM row moved (cv3 byte-identical -- its e725/e7ec arms genuinely nest the save helper, so e681 stays a warning under the every-arm rule). Synthetic nesmmc3mirrortest re-blessed, ONE line: e2dc 'bank ? [WARNING: analyzer limit]' -> r7=3 via FUN_e3fc (slot $59 carried over JSR $A000 -> WA000_B2::a000); its Warning BOOKMARK survives from round 1 and is stale (grm-mej.26). check nes on this build: 33 pass + shenlong 97 flap (PASS on --only rerun). Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-12 (grm-mej.22 + grm-mej.23, 3f983b0: save-slot proof walks cross-function JMPs into a shared tail; a DIRTY-census call into a SAVE HELPER (straight line entry -> one plain STA slot, clean after) ends the path, resolved per call under stateAt(call), adopted only when every arm is RESTORED_BANK on one cell): no row moved, nothing re-blessed (cv3 byte-identical -- its far calls are overlay targets, entersUnknownBank still DIRTY, grm-mej.24). check nes on this build: 33 pass + dragonpower 152 flap. The flap drew 152 on 3 consecutive runs of this build (full run, --only rerun, first A/B), so a plain rerun is NOT a reliable discriminator; ab-test.sh --dirty --all --only dragonpower --repeat 4 HEAD showed this build producing HEAD's exact 168 dump hash too (movement=NO). Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-12 (grm-5dgx, windows that ignore low bank bits -- MMC1 modes 0/1 W8000 prg_bank>>1, MMC5 mode 0 W8000 >>2, modes 1/2 W8000 >>1, mode 1 WC000 >>1 -- realize ONE overlay per image, the canonical field value v & decodedMask (DescriptorExpressions.decodedMask, shared by loader + analyzer); bankUniverse re-expands to every valid field value; residence pins only decoded bits; window resolution judges known on decoded bits): re-blessed 16 rows BLOCK LINES ONLY -- bionic blmaster cv2 cv3 dodge drmario ff1 kicarus megaman2 rcproam rtk2 tetris tmnt ultimaav zelda zelda2 (cv3 blocks.total 105->89, 16 W8000_M2 blocks; rtk2 329->257); no ref/instr/comment/warning count moved on any row. Synthetic: 11 fixtures lose twin BLOCK lines, nesmmc5test retargets W8000_M0_B7 -> B4. check nes on the final build: 34/34 pass. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-12 (grm-mej.21, X1 cross-block PHA/PLA search: (a) a JUMP into the join from ANOTHER function is walked like any edge (closedWorldPredecessors 4-arg, crossBlock only; joinArms/save-slot keep the strict rule) -- Ghidra cannot give two routines a shared epilogue, bodies may not overlap; (b) different pushes per arm no longer abandon: StoredValueScanner.pairedArms resumes from each PHA under stateAt and adopts only when EVERY arm is RESTORED_BANK on the SAME cell (ReadBack.arms/reads(); membership must be PROVEN at each read)): re-blessed cv3 (warnings 17->16, notes 13->14: e63e RESTORED via $8000 read at e61e or e631, joined at FUN_e62f's e63d PLA). check nes on this build: 32 pass + cv3 (intended, blessed) + dragonpower 152 flap (PASS on --only rerun). Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-12 (grm-d59c + grm-mej.20. d59c: JumpTableBound.planarGap -- planar split lo/hi pointer tables arrive as ONE merged size-1 load table of caseCount+gap bytes; bounded to the gap (2<=gap<caseCount) + lowest-target over both halves, analyzer proves every kept target == lo[i]|hi[i]<<8 from the image. mej.20: BankCommentProvenance.removeSegment matched segments by splitting on "; ", which every partial bank comment contains, so partial comments were NEVER refreshed/retracted after round 1 (now boundary-matched); BankMirrors write-through walk crosses a CALL entry into a helper's middle only while it has loaded no cell below it (cv3 $21 / ultimaav $5e yes, dbz_datach $59 argument cell no)): re-blessed dodge (8251 64->26; warnings 24->21), rcransom (W8000_M0_B10::82b3 64->27; instrs.inOverlay 11603->11804), megaman2 (92e4 255->15 + switch/case labels; 11 bank comments lose stale mirroring bits), cv3 (warnings 21->17, notes 11->13: e141/e24a RESTORED via $21; e722 bank_5115 bits 2,4 unknown; e2dc stale comment retracted), ultimaav (f1f1/f522 RESTORED via $5e), tmnt3 (3 comments lose stale r7.2). check nes on the combined build: 33 pass + dragonpower 152 symbol flap. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-11 (grm-xwnc + grm-dos9.10. xwnc: SerialShift/SelectData writesInRange gained MemoryLatch's operand tier + physical-space compare -- a store in a banked overlay copy gets a DATA (not WRITE) ref into its OWN overlay, so overlay copies of MMC1/MMC3 helpers were never classified; HelperDiscovery.sameBodyBytes deleted. dos9.10: SwitchOutcome.deposit judges RESOLVED on the site's own deposit bits, classifyGap gates on the stop, BoardBankAnalyzer.directShownState renders a non-RESOLVED direct site as a gap, so echoed prg_mode no longer turns a helper-argument/undeterminable site into an 'assumed' comment): re-blessed zelda (bfbc echo comments -> HELPER_ARGUMENT notes, overlay helper copies bf98/bfa8 noted, 725d now resolves prg_bank=5 via FUN_W8000_M3_B5__bf98; bankComments 93->92, notes 36->40), megaman3 (+9 bank comments in W8000_M0_B22: self-mapping r6=22,r7=23/24 sites + calls via FUN_W8000_M0_B22__803a), dodge (+bd98 helper-argument note on bank-1 helper copy; +82eb WARNING on MISDISASSEMBLED data 'STX $8F8E' next to 'STA #$aa' -- grm-nh4g's hazard, now visible in overlays too). Synthetic nesmmc1test re-blessed (overlay c200/c210 notes, c06c warning names FUN_WC000_M2_B7__c200). check nes on this build: 29 pass + those 3 (intended, blessed) + shenlong 97 / dragonpower 152 flap (shenlong passed on rerun; dragonpower went PASS,PASS,FAIL over three reruns). Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-11 (grm-dos9.5, BankDataflowEngine.mapsElsewhere: a base-space byte gets no state when that state FULLY pins its window to a realized, non-home overlay backed by a different file byte -- base holds home bytes only, so they never run under it; same-window flows exempt (duplicated routines), no realized overlay (gmap-suppressed modes, drmario/tetris) or same image byte keeps it; pass 1 now carries BankResolution): re-blessed 11 rows -- blmaster contra cv3 lwings megaman megaman2 rcransom smb3 tmnt tmnt3 ultimaav -- refs.intoOverlay.retargeted falls on each (megaman2 230->71, ultimaav 119->12); A/B probe vs HEAD: 640 of 645 lost refs are base home-bank bytes referencing their OWN window's overlay with byte-DIFFERENT source bytes (phantoms), the other 5 are tmnt3 fixed-bank refs under its mode-1 lock; megaman2/ultimaav lose 182/42 overlay instrs disassembled at phantom branch targets; cv3 +114, tmnt3 +149 instrs. Synthetic nesmodetest/nesmmc5test lose their phantom BRK->c010/e020 refs. check nes on the final build: 34/34 pass (flap did not draw). Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-11 (grm-mej.18, ALIAS identifying encoding + content scan of the LOCKED layout mode's windows: cv3's MMC5 mode-2 $8000 holds $80|bank, which re-selects the same 16K image through bank_5115's 7-bit field; BankMirrors.romIdentifyingOffsets admits it only from agreement identity cannot explain, so MMC2-shaped 'identity but the top bank' stays refused per grm-km4f): re-blessed cv3 (warnings 31->21, notes 1->11: e5bc e5e9 e7d9 e7e9 e9b0 ff3d ff87 ffa7 ffb7 ffc7 are RESTORED notes, membership PROVEN by tracked state, no cv3.yaml hint). Synthetic nesmmc3idtest gains bank_id_9ff0 (mode-0 lock scans W8000; same $1FF0 byte through R6; ID8 updated). check nes on this build: 31 pass + cv3 (intended, blessed) + dragonpower 152 / shenlong 97 flap (both PASS on an immediate --only rerun). Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-11 (grm-dos9.2, call sites into a multi-entry helper cross every join on their straight-line fall-through entry path unless the call can re-enter it -- RegisterEnv.entryPathJoins / HelperArgumentRecovery.entryPathJoins): re-blessed cv3 (warnings 61->31, bankComments 144->169, instrs.inOverlay 19539->19717; every FUN_e2da caller -> bank_5116=30, 22 FUN_e2e0 callers resolve). A first cut without the re-entry rule moved smb3 (FUN_ffad) and smb2 (FUN_ff73) to a false 'select=5' known through a select LOOP's head; on the final build both are byte-identical. check nes on this build: 32 pass + cv3 (intended, blessed) + dragonpower 152 flap. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-11 (grm-dos9.8, MMC1 RMW shifter reset recognized when its target is in the SAME 16K-aligned region as the instruction, not only inside its own bytes -- SerialShiftBankSwitchStrategy.rmwOriginalByte): re-blessed 6 rows, each one RESET-path RMW going WARNING -> prg_mode=3 reset bank comment: cv2 ffd2 + tmnt ffda (INC $FFFF, IRQ vector hi byte), dodge ffe8 (INC $FFF1=$EA), ultimaav ffda (INC $FFFB=$F1), drmario + tetris ff16 (INC $FF00=$D8). Downstream comments gain known prg_mode; drmario/tetris now lock prg_mode 0, cv2/tmnt lock 3 (cv2 +4, tmnt +1 'assumed to stay 3' notes). check nes on this build: 27 pass + those 6 (intended, blessed) + dragonpower 152 flap. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-11 (grm-dos9.9, owner ruling: explicit mode sets outvote implicit ones -- an MMC1 shifter reset (SwitchOutcome.implicitDeposit; a call is implicit when every site of its helper is) votes in the prg_mode lock census only when nothing sets the field explicitly): rcproam now locks prg_mode 0 (resets ff85/ffea outvoted); re-blessed rcproam (notes 10->11: f8ce JMP $ff89 tail call 'assumed to stay 0'). blmaster/kicarus/zelda log their outvoted resets, goldens unchanged. drmario/tetris still blocked by the unrecognized ff16 INC $FF00 reset (grm-dos9.8). check nes on this build: 32 pass + rcproam (intended, blessed) + dragonpower 152 flap. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-11 (grm-dos9.7, the prg_mode lock census skips NO_DEPOSIT and HELPER_ARGUMENT direct sites, so MMC1 rows can lock; blmaster's fixed_after_init hint removed as redundant): locks now also form on blmaster 3, kicarus 3, zelda 3. Re-blessed zelda (instrs.inOverlay 11428->12958, refs.intoOverlay 2567->2889, bankComments 93, notes 36; bfbc HELPER_ARGUMENT note became an 'assumed' comment -> grm-dos9.10). blmaster byte-identical WITHOUT its hint. Analyzer log now says why no lock formed ('prg_mode not locked: ...'). check nes on this build: 32 pass + zelda (intended, blessed) + dragonpower 152 flap. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-11 (grm-dos9.3, bank comments echo the layout-mode field when the dataflow knows it -- helper calls via CallSwitch.stateAfter, direct switches via BankAnnotationAdapter.withLayoutMode, only alongside the site's own knowledge so no WARNING flips): WORDING-ONLY re-bless of cv3 and rtk2 (MMC5: '[known: prg_mode.0=..,prg_mode.1=..,bank_511x...]'), plus synthetic nesmodetest/nesmmc5test/nesmmc5wraptest. No count moved on any row. nesmodetest F4:c002/F4:8042 criteria updated -- the old '8042 prg_mode=0? assumed' was WRONG (the overlay runs mode 1). check nes on this build: 30 pass + cv3/rtk2 (intended) + shenlong 97 / dragonpower 152 flaps. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-11 (grm-dos9.6, layout-mode LOCK: prg_mode locked when every reset-reached write agrees; async + fallback seeds get it; unresolved later writes keep it (NOTE 'assumed to stay N'), only a KNOWN contradiction rejects + WARNs; 'Detected PRG mode' program property): locks form on cv3 (2), smb2 (0), megaman3 (0), tmnt3 (1); none rejected. Re-blessed smb2 (warnings 6->5, bankComments 36, notes 29), megaman3 (warnings 3, bankComments 10, notes 3), tmnt3 (notes 2) + synthetic nesmodetest/nesmmc5test (more grm-dos9.5 phantom BRK->c010 refs, fallback seeds now carry the locked mode). NOTE: smb2 ff7e / megaman3 ff4e lost their 'undeterminable' WARNING to the partial-knowledge rule (prg_mode now known in-state). check nes on this build: 30 pass + those 3 (intended) + dragonpower 152 flap. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-11 (grm-dos9.4, BankDataflowEngine seeds only real entries up front; unreached function entries get the power-on seed as a FALLBACK, never competing with caller-propagated state): re-blessed 19 rows -- bionic blmaster contra cv3 dodge ff1 kicarus lifeforce lwings megaman megaman2 rcransom smb2 smb3 tmnt tmnt3 ultimaav zelda zelda2 -- plus synthetic nesmodetest/nesmmc3mirrortest/nesmmc3idtest/nesmmc5test. Headline moves: blmaster instrs.inOverlay 0->566 (W8000_M3_B5 now reached), rcransom 6404->11587, tmnt3 3425->4365, megaman2 5310->5492; contra/smb3/zelda2 lose 57/11/1 instrs while retargeted refs rise. MMC1/MMC3 comments go from partly assumed to fully known (caller mirroring/r6/r7 now survive into callees). KNOWN WRONG, blessed with a note: nesmodetest phantom BRK->c010 COMPUTED_JUMP refs (grm-dos9.5). Confirmation check nes on this build: 33 pass + shenlong 97 flap; all 19 re-blessed rows reproduced byte-identical. Expected floor: fail=0 plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-10 (grm-dos9.1, machines/games/cv3.yaml: initial_state prg_mode 2 + fixed_after_init [prg_mode]): re-blessed cv3 (blocks.total 329->105 -- mode 2 stated, other modes' overlays suppressed; instrs.inOverlay 835->19360, refs.intoOverlay 211->5117, bankComments 114->144 all prg_mode=2, warnings 21->61: the new ones are on newly reached code, mostly multi-entry shared-tail helpers e2d6/e2da and e2e0/e2e6 -> grm-dos9.2). check nes on this build: fail=2 = shenlong 97 + dragonpower 152, the known symbol flap only; all other 32 PASS. Expected floor unchanged: fail=0 plus that flap.

LATEST 2026-10-10 (grm-cqwn, SplitDispatchTableAnalyzer inline form: LDA tbl,r/STA P/LDA tbl+1,r/STA P+1 falling straight into JMP (P) that the decompiler declined): re-blessed wizwarr (bankComments 59, notes 23, symbols 23 -- the long-held 14/15 state is GONE, every grm-fxtp line back via the b198 19-entry NMI state table), megaman (instrs.inOverlay 7722, refs.intoOverlay 1719, notes 13: B5 a285 and e716 tables), rcransom (instrs.inOverlay 6404, refs.intoOverlay 1381: B12 9343 25-entry table). check nes on this build before bless: fail=3 = exactly those three; all other 31 PASS (shenlong/dragonpower flap did not draw). Expected floor is now fail=0, plus the shenlong 97 / dragonpower 152 symbol flap.

LATEST 2026-10-07 (grm-mej.8, a partly known live-mirror read-back keeps RESTORED_BANK + its ReadBack instead of collapsing to RESOLVED): re-blessed rcransom (warnings 22->20, notes 6->8: cd57 and ef85 FUN_fed1 restores are now RESTORED notes, membership PROVEN by tracked state). check nes on this build: fail=3 = rcransom (intended, now blessed) + wizwarr (held, bankComments 14/notes 15) + shenlong 97 (the known flap; memory-latch, unreachable by this change). Expected floor unchanged: fail=1 wizwarr, plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-05 (grm-fekc c2c03d0, per-site recovery for select-data helpers with mixed STY/STA registers + foldDeposits order/threading fixes): re-blessed tmnt3 (refs.intoOverlay 834 / intraOverlay 811 / retargeted 23 / instrs.inOverlay 3425 / bankComments 119 / warnings 56), rcransom (bankComments 72: f21d's wrong select=7 via FUN_ff29 removed), megaman3 (c0b8 wording only), and synthetic nesmmc3mirrortest. check nes on this build: fail=2 = wizwarr (held, bankComments 14/notes 15) + shenlong 97 (pre-existing flap: drew 97 in 6/6 runs on this build, but ab-test --dirty vs HEAD showed HEAD producing the IDENTICAL 97 dump on 1 of 2 repeats, and shenlong is memory-latch, which the change cannot reach). Expected floor: fail=1 wizwarr, plus the shenlong/dragonpower symbol flap.

LATEST 2026-10-04 (grm-t223, switch-window bound stops at the next table's base): contra BLESSED at refs.intoOverlay 716 / intraOverlay 703 / instrs.inOverlay 2798 / bankComments 22 / warnings 4 / symbols 26 -- 849f = 7 entries (owner read), case_0..case_6. NOTE the earlier 'contra 277' held signature was STALE: the grm-qa5z/rsxe/jmsm series (A/B c275e53 vs 90ad3d2) had already moved contra 277 -> 720 refs (Konami inline dispatcher, the same reach tmnt/cv3 were re-blessed for: fixed-bank JSR FUN_c139 bank comments c199..c235); grm-t223 itself only drops 849f's 4 phantom cases (720 -> 716, A/B vs HEAD). check nes on this build: fail=3 = contra (intended, now blessed) + wizwarr (held, bankComments 14/notes 15) + shenlong 97 (the known flap). Expected floor is now fail=1: wizwarr.

LATEST 2026-10-04 (grm-qa5z 4675c39, grm-rsxe 1753c6d, grm-jmsm 90ad3d2): re-blessed tmnt (refs.intoOverlay 3794 / instrs.inOverlay 14972 / bankComments 105 / warnings 10 / notes 7 / symbols 103 -- c702 inline dispatcher now recognized, bank 5 tables 940a=45 and 9477=23), cv3 (bankComments 12 -> 114, same Konami c702 dispatcher), dodge (B3 810d table 6 -> 7 entries, 80f2). tmnt byte-identical across 3 runs on the rsxe build. Expected check nes floor is now fail=2: contra (277/warnings 4), wizwarr (bankComments 14/notes 15). FLAP BACK, PRE-EXISTING: shenlong 113<->97 and dragonpower 168<->152 symbols each drew the low state 1 in 4 runs on CLEAN HEAD c275e53 (measured in a separate worktree), and again on this build -- not caused by this series; the 2026-10-03 "fixed" claim below is superseded. Treat a lone shenlong 97 or dragonpower 152 as this flap, anything else on those rows as real.

LATEST 2026-10-04 (owner reads of grm-akiv held rows): tmnt BLESSED at refs.intoOverlay 0 / instrs 0 / bankComments 8 (owner: 8fb8 = 6 entries; lost bank-6 code is real but reached only via c702 inline table -> grm-qa5z). contra stays HELD (owner: 849f = 7 entries, window bound gives 11 by over-reading 86cd -> grm-t223; do not bless at 11). Same build also shipped grm-46ch (megaman2 re-blessed: c78d note, 91c4/91d7/931b/932e prg_bank=13) and grm-rr5p (no real-ROM movement). Expected check nes floor is now fail=2: contra (277/warnings 4), wizwarr (bankComments 14/notes 15).

LATEST 2026-10-04 (grm-9z9t + grm-txzf): WORDING-ONLY re-bless of 14 rows -- cv3, db3, dbz2, dbz_datach, dbz_saiyan, dragonpower, ironsword, lifeforce, lwings, megaman, megaman3, rtk2, shenlong, tmnt3 -- plus contra's 3 wording lines hand-carried into its still-held golden. Unresolved helper calls that never sought an argument are no longer worded 'whose bank argument could not be recovered': memory-latch helpers now say 'latched value is re-derived inside the helper', null-argReg helpers say 'models with no argument register' (BankDataflowEngine.ArgumentSought). No warning COUNTS moved. grm-txzf's clobber-proof change moved no row. Floor unchanged: fail=3 = contra (277/warnings 4), tmnt (0/0 bankComments 8), wizwarr (bankComments 14/notes 15). WATCH: dragonpower drew its 152-symbol state ONCE in three full runs on this build (168 on the other two and on a fresh --only rerun) -- grm-aemp's note said that flap was fixed, so it is back, rarely; unrelated to this wording change (bless taken from a 168 run).

LATEST 2026-10-04 (grm-lb54, clobber-proof latch: a branch AFTER the argument is lost for good no longer voids the 'no inbound argument' proof): re-blessed rcransom (f1d0 FUN_ff07) and ultimaav (f35f FUN_f34b, MMC1 LDA #$0E then branch-always BNE over an alt entry) -- ONE wording line each, warning->warning, no count moves. check nes on this build: fail=5 = those two (intended, now blessed) + contra/tmnt/wizwarr at their held signatures (contra 277/warnings 4, tmnt 0/0 bankComments 8, wizwarr bankComments 14/notes 15). ff1 and dodge PASS on this build (blessed after grm-aemp, e.g. 3c48cf6 grm-q1bi). So the expected floor is now fail=3: contra/tmnt/wizwarr.

LATEST 2026-10-03 (grm-aemp: JumpTableBound pins a switch the listing has not disassembled yet; MosConstantReference walks fall-through-only body islands): check nes on this build is DETERMINISTIC -- 34/34 rows byte-identical across THREE pinned runs AND one unpinned run (pinned == unpinned). New baseline fail=5 = contra/ff1/tmnt/wizwarr (held, unchanged signatures: contra 277/warnings 4, ff1 1798/7350, tmnt 0/0 bankComments 8, wizwarr bankComments 14/notes 15) + dodge (grm-q1bi, held for owner read, NEW deterministic state refs.intoOverlay 2556 / intraOverlay 2531 / instrs.inOverlay 11447 / symbols 135 -- +295 instrs are the 8445 table's case code at 8451.. and a00a..a236, previously referenced but never disassembled). dragonpower now PASSES at its 168 golden deterministically (the 152 state is gone; its old "flap" was a timing race on the a546 table, not thread count). smb3 re-blessed refs 2568 (b460 LDA $b34d,Y base ref). The dodge 2480<->2477 and dragonpower 152<->168 flaps are FIXED -- if either reappears it is a regression. Prior paragraphs' fail=6 baseline and the 'dodge jitters 2477/2480' and 'dragonpower 152 flap' notes are superseded.

HISTORY, all superseded: pass=27 fail=6 on stock 12.1.3 measured 2026-09-03 (megaman/wizwarr attributed to GP-6936 + five bistable); pass=29 fail=4 at 2267e94; pass=30 fail=3 at 072323e; smb3 green again since 2026-09-02 (grm-pnxm). The 2026-08-22 ruling to leave megaman/wizwarr red until upstream moves is superseded by the 2026-09-20 patched-install ruling.

## Entries 2026-09-27 to 2026-10-02

Archived on 2026-10-12 to the `realrom-bless-history-2026-09` bd memory, which was retired when its contents were moved here on 2026-10-13.

LATEST 2026-10-02 (grm-rnf0, e06ab49, cross-window inline jump-table targets resolved through the JSR's bank state): re-blessed zelda (instrs.inOverlay 5966->11395, refs.intoOverlay 1364->2561, intraOverlay 2485, bankComments 89->91 with f218/f22e prg_bank=4; enemy dispatch tables fbb4 106 and fd82 95 now resolve into W8000_M3_B4) and tmnt3 (warning 8443 -> 85e4, counts equal; ab-test --dirty --repeat 2 shows it deterministic, 8443 had been reached only via fa00 targets decoded in the wrong bank). check nes: fail=6 baseline = contra/dragonpower/dodge/ff1/tmnt/wizwarr at the signatures below (contra 277/warnings 4, dragonpower 152, dodge 2480, ff1 1798/7350, tmnt 0/0 bankComments 8, wizwarr bankComments 14/notes 15), byte-identical across two runs of this build. zelda2 must stay GREEN: a first draft lost its 814b comment and FUN_bf9d notes by not disassembling home-resolved targets -- if zelda2 moves on an inline-table change, check that case first.

LATEST 2026-10-02 (grm-ujj5, bank_wrap: image on nes-mmc3.yaml): re-blessed tmnt3. refs.intoOverlay 0->410, instrs.inOverlay 0->1405, bankComments 37->49, warnings 43->37. R7=58 at 915e..91f1 now reads 'wraps to 26', R6=47 at 8776 'wraps to 15', and the calls into WA000_B26 (a1a1/a001/a15d) resolve. check nes: fail=6 baseline. contra/ff1/tmnt/wizwarr/dragonpower are byte-identical to the grm-3er5 run; dodge drew its other refs state (2477 vs 2480), and dodge is MMC1, so the change cannot reach it.

LATEST 2026-10-02 (grm-3er5, SplitDispatchTableAnalyzer): re-blessed rcproam, which differs ONLY in the 818a primary label (case_5 primary again; it was case_1). Deterministic on three runs with this build: the newly reachable NMI object handlers change label order. No counts move, because rcproam's code is in the non-overlay W8000 block, which the dump does not count. Payoff verified with ReachProbe: bd15 is FUN_bd15 and contains bd2e/bd39/bd4f. check nes: fail=6 baseline (contra/ff1/tmnt/wizwarr/dodge/dragonpower), all BYTE-IDENTICAL to the grm-2m07 run.

LATEST 2026-10-02 (grm-2m07, neighbour-table jump-table bound): re-blessed dbz2 (symbols 51: cb97 bounded 44 -> 15 at cbfd's dd65 table; 15 case labels + switch). It was the ONLY cut across check nes. check nes on this build: fail=6 = the held contra/ff1/tmnt/wizwarr + dodge + dragonpower 152, all six BYTE-IDENTICAL to clean HEAD. The inCode guard is load-bearing: without it, dbz2 and dbz_saiyan picked up zero-page/PPU case labels from a far neighbour. shenlong 113->97 flapped once in that unguarded run.

LATEST 2026-10-02 (grm-1od4, a92b1ed, CopyLoop zero-page size floor): re-blessed smb (blocks.total 5, RAM 0000-07ff whole, notes 6; cf45/efa4 declined as 'zero-page copy under 8 bytes'). check nes on this build: fail=6 baseline = contra/ff1/tmnt/wizwarr held + dodge + dragonpower 152 flap, plus smb (intended). Decode-only route still admits wizwarr x3 and ironsword x1.

LATEST 2026-09-29 (grm-j2kl, InlineJumpTableDispatchAnalyzer: JSR-inline jump tables / SMB JumpEngine): re-blessed zelda (instrs.inOverlay 5966, refs 1364, bankComments 89), smb3 (11694 / 2567 / 160), smb2 (6525 / 1588, notes 25), lwings (7471 / 1674, bankComments 48, warnings 10), smb (blocks.total 8: two COPY_ blocks are grm-1od4 CopyLoop false positives, blessed as-is), zelda2 (bankComments 10, notes 44), db3 (warnings 8, notes 9), tmnt3 (bankComments 37, warnings 43). check nes on this build: fail=6 = the held contra/ff1/tmnt/wizwarr + dodge (grm-q1bi) + dragonpower 152/168 flap, all byte-identical to their states under grm-yjiq. Cross-window table targets (zelda e6a3, smb3 a054) are declined by the tail trim, not placed -- grm-rnf0.

LATEST 2026-09-29 (grm-yjiq, overlapping byte-table jump-table bound): re-blessed rcproam (bankComments 12, symbols 37: ff89 is FUN_ff89 again, 9ad4 bounded 128 -> 11 via the new valid-target rule, 9b05 handler now carries 9b07/9b0f comments). ALSO MOVES dodge, CORRECTLY but unblessed (grm-q1bi): W8000_M3_B3::8445 bounded 8 -> 4 (symbols 136 -> 141, refs.intoOverlay -2; hand-verified from the ROM, index = LDA $d0/AND #$c0/LSR x5). That check nes: fail=8 = rcproam (intended, now blessed) + dodge + the held contra/ff1/tmnt/wizwarr + dragonpower/shenlong 152/97 flap; ab-test --dirty vs HEAD showed contra, dragonpower, shenlong, ff1, tmnt, wizwarr BYTE-IDENTICAL. dodge refs.intoOverlay itself also jitters (2477 vs 2480 on the same build).

LATEST 2026-09-28 (grm-fxtp, below-table cut in the lowest-target bound): re-blessed lwings (bankComments 36: dc61/dc7a/dc93 were reached only via over-read dcaf entries; real code behind the ff1e stub dispatch, grm-h0oa), dbz2 (symbols 35) and rcproam (818a primary label case_5). EXPECTED FAILING, held for owner read: wizwarr (bankComments 14, notes 15), ff1 (1798/7350 on this build), plus grm-akiv's contra and tmnt, and dodge (grm-q1bi). dragonpower 152<->168 flap as before.

LATEST 2026-09-28 (grm-78b, 2f1ebc1, BranchAlwaysPairAnalyzer): re-blessed blmaster (e68e/f25a bank comments fully known; FUN_f1ca ends at f23a) and megaman3 (ref 810a -> 81ae now UNCONDITIONAL_CALL: 81ae became a function entry). That check nes: fail=7 = contra, ff1, tmnt (grm-akiv, held for owner) + dodge (grm-q1bi) + blmaster, megaman3 (intended, now blessed) + shenlong symbols 113->97 (dragonpower's 168<->152 flap, seen on its twin; shenlong's golden is 113). ff1 seen at 1882/7531 as well as 1849/7487 on this build.

LATEST 2026-09-28 (grm-akiv, switch-window jump-table bound for tables AFTER their code): re-blessed megaman (bankComments 120, warnings 27, symbols 122 -- e000/e121/e44e = 18/19/10, the 8d1f phantoms gone; its 144<->145 / caseD_dc<->caseD_a4 flap now reads 120<->121-ish, unmeasured) and lwings (warnings 9; helper c34c is FUN_c34c, no longer caseD_f8, so the documented 37<->40 caseD_f8 flap may be gone -- pinned==unpinned on one run each). EXPECTED FAILING on this build, HELD for owner read (docs/human-research-todo.md section 1): contra (refs 277, warnings 4), ff1 (1849/7487 -- a new state; still bistable), tmnt (refs.intoOverlay 0, instrs.inOverlay 0, bankComments 8). Plus dodge (grm-q1bi, unchanged by grm-akiv) and dragonpower's rare 152 flap. tmnt is NO LONGER a usable pin canary on this build: its 44/103 came from phantom entries of the 8f34 table; owner ruled 2026-09-28 no replacement canary for now.

LATEST 2026-09-27 (grm-v60.1, 1f09986): re-blessed dragonpower (warnings 3, notes 1, symbols 168) and shenlong (warnings 5, notes 1, symbols 113). RESET far-call now resolved, so the main program is reachable. dragonpower is 168 in 7/8 runs, 152 in 1 (grm-aemp). check nes on this build: pass=29 fail=5 = dragonpower+shenlong (intended, now blessed), dodge (stale, grm-q1bi; 2470 pinned in A/B, 2473 seen in the full run), ff1 (1898/7538 <-> 1865/7494 flap), lwings (40 <-> 37).
LATEST 2026-09-27 (grm-eyn.1, 921a5dc): re-blessed db3 (notes 8, symbols 135 -- three fixed-bank switch tables, each ending at its entry 0) and ultimaav (refs 228, retargeted 14, bankComments 8: the lost de2f comment was reached only via over-read 97d7 entry 63 = ddd0, mid-instruction; owner confirmed 97d7 = 4 entries). rcransom was blessed earlier (18ffa10). Of the grm-eyn movements only dodge (grm-q1bi) remains unblessed; lwings/ff1/megaman flaps as below.
LATEST 2026-09-27 (grm-ld68, c2d1135): re-blessed contra (warnings 6, notes 1: c0d3 RESTORED via Y) and lifeforce (warnings 3, notes 1: e7fa) -- the Y-channel identity-table rule restores the notes grm-oj20 removed, now attributed to the register the helper consumes. That run: check nes pass=26 fail=8 = contra+lifeforce (intended) + rcransom (grm-eyn bound movement, owner-confirmed CORRECT 2026-09-27 on grm-eyn -- blessable, bless still pending) + db3, ultimaav (same grm-eyn run, unread) + lwings 40<->37, ff1 1865/7494, dodge (known).

LATEST 2026-09-27 (grm-oj20, a0d5409): re-blessed contra (warnings 7, notes 0: c0d3 back to a warning) and lifeforce (warnings 4, notes 0: e7fa back to a warning) -- their X1 RESTORED notes were built from A while the helper consumes Y (PLA/TAY/JSR). grm-ld68 is expected to restore both via the Y channel. dbz_saiyan c4da (PLA/JSR, no TAY) correctly unchanged. That run: check nes pass=25 fail=9 = contra+lifeforce (intended) + megaman (jitter 144<->145) + db3, dodge, ff1, lwings, rcransom, ultimaav (known).

ALSO 2026-09-27 (grm-mej.3 X1, cross-block PHA/PLA pairing): re-blessed contra (warnings 6, notes 1: c0d3 RESTORED), dbz_saiyan (warnings 1, notes 6: c4da), lifeforce (warnings 3, notes 1: e7fa), megaman2 (warnings 5, notes 37: cb60). lwings flapped 40->37 at caseD_f8 even PINNED on the combined build, so it is still bistable.

LATEST, 2026-09-27 (grm-eyn, extension-side JumpTableBoundAnalyzer): the lowest-target jump-table bound now ships IN THE EXTENSION (no decompiler patch needed; install still carries the GP-6936 binary). Re-blessed on it: megaman (1698/7666/144; a734 -> 8 entries; the 12 8d1f phantom comments gone), rcproam (warnings 1, notes 10, symbols 25), dragonpower + shenlong (warnings 2, symbols 77 -- override switch/case labels), ff1 (1898/7538). STILL FAILING, deliberately unblessed pending an owner listing read (docs/human-research-todo.md section 1): rcransom (1151/5450, bab3 76->4, 85c9 86->10), db3 (notes 9->8), ultimaav (refs 228, bankComments 8), dodge (stale per grm-q1bi, now also 2470/11116 from the bound). DETERMINISM on this build: 32/34 rows byte-identical run to run; ff1 still flaps (1865/7494 <-> 1898/7538) and megaman flaps bankComments 144 <-> 145 with the helper label caseD_dc <-> caseD_a4 (a label-naming race). dragonpower/lwings/dodge/rcproam were stable across both pinned runs. THREAD PIN: kept; unpinned is now run-to-run stable too, but pinned vs unpinned differ deterministically on dodge (2470 vs 2473) and lwings (40 vs 37) -- grm-nems. The cache key now includes the pin (GRM_THREAD_PIN), so a measurement run can never serve a bless.
