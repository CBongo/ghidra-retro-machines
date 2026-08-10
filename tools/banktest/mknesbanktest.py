#!/usr/bin/env python3
"""Hand-assembles the NES banking-analyzer regression ROMs (bead grm-5tl.17,
extended by grm-5tl.13.3 and grm-aqf).

Usage: mknesbanktest.py <output-dir>

Writes nesbanktest.nes, nesbanktest2.nes, and nesmodetest.nes (each: 16-byte iNES
header + 4 x 16 KiB PRG banks, no CHR) into <output-dir>. No dependencies beyond
Python 3.

The first two target the shipped UxROM board descriptor (machines/nes-uxrom.yaml,
iNES mapper 2): a switchable 16 KiB window at $8000-$BFFF (computed window PRG_LO,
home bank = 0, memory-latch mechanism with bus_conflict) and a fixed 16 KiB window at
$C000-$FFFF (PRG_HI = PRG[last]) holding RESET/NMI/IRQ code and the vector table.
This exercises NesRomLoader's computed-window "home-in-base" overlay placement
(PRG_LO_B1/_B2/_B3 FileBytes-backed overlay blocks) and
NesBankingAnalyzer/BoardBankAnalyzer reference retargeting through
MemoryLatchBankSwitchStrategy's bus-conflict path. The third targets the SYNTHETIC
mode-dependent-layout test board (machines/nes-modetest.yaml, iNES mapper 100) --
see its section below.

nesbanktest.nes bank layout (16 KiB each, PRG image is 4 banks = 64 KiB):
  bank 0 (home, mapped at $8000-$BFFF by default): marker byte 0x00 at $8000, filler.
  bank 1: marker byte 0x01 at $8000, filler (never selected; just distinguishable).
  bank 2: marker byte 0x02 at $8000; RTS routine at $8005 -- the JSR target once bank 2
          is selected (non-home -- exercises PRG_LO_B2 overlay retargeting).
  bank 3 (also the fixed PRG_HI window, PRG[last]): RESET/NMI/IRQ code, the
          bus-conflict-matching byte at $FFF0, and the vector table at $FFFA-$FFFF.

Because bank 3's file offset (3 * 0x4000 = 0xC000) equals PRG_HI's CPU base
($C000), a CPU address in the fixed bank equals its offset within the bank -- code
below is written directly at its CPU address for readability.

RESET ($C000):
  C000  A9 02        LDA #$02        ; select bank 2 (non-home; PRG_LO home is bank 0)
  C002  8D F0 FF     STA $FFF0       ; mapper-latch write (memory-latch, bus_conflict);
                      target is a fixed (bank-invariant) ROM byte this script sets to
                      0x02 so the bus-conflict AND is a no-op on the intended value
  C005  20 05 80     JSR $8005       ; call into bank 2's RTS routine -- the JSR operand
                      resolves through PRG_LO in state bank=2, non-home -> retargeted to
                      the PRG_LO_B2 overlay space
  C008  4C 08 C0     JMP $C008       ; infinite loop (nothing left to do)
  C00B  40           RTI             ; NMI/IRQ handler

nesbanktest2.nes: a 3-deep overlay-bank JSR chain (bead grm-5tl.13.3) whose deepest
reference is only resolvable once the banking analyzer has converged over >= 3 full
rounds. RESET selects bank 2 and calls its routine at PRG_LO_B2::8005; that routine
calls back into the fixed bank at $C010 ("trampoline1"), which selects bank 1 and
calls PRG_LO_B1::8010; that routine calls back into the fixed bank at $C020
("trampoline2"), which selects bank 3 and calls PRG_LO_B3::8030 (the deepest target).

Why this needs >= 3 rounds: trampoline1 ($C010) is not reachable from RESET's initial
flow at all -- it only becomes visible once round 1 retargets JSR $8005 into
PRG_LO_B2 and DisassembleCommand flow-follows through bank 2's JSR $C010, which
disassembles trampoline1's instructions for the first time. The analyzer's dataflow
(mergeAndEnqueue skips addresses that aren't disassembled yet) can therefore only
*analyze* trampoline1 in round 2, which is what resolves its JSR $8010 into
PRG_LO_B1 and in turn newly disassembles trampoline2 ($C020) via bank 1's JSR $C020.
Round 3 is required to analyze trampoline2 and resolve its JSR $8030 into
PRG_LO_B3::8030 -- the deepest REF. That REF's existence is therefore direct proof
that at least 3 full analyzer rounds ran; this fixture guards the fingerprint-skip
logic (bead grm-5tl.13.3) against ever short-circuiting a round that still had
pending work.

RESET ($C000):
  C000  A9 02        LDA #$02        ; select bank 2
  C002  8D E2 FF     STA $FFE2       ; latch bank 2 (bus-conflict byte at $FFE2 = 0x02)
  C005  20 05 80     JSR $8005       ; round 1: retargets to PRG_LO_B2::8005
  C008  4C 08 C0     JMP $C008       ; infinite loop
  C00B  40           RTI             ; NMI/IRQ handler
  C010  A9 01        LDA #$01        ; trampoline1 -- only reachable via bank 2's routine
  C012  8D E1 FF     STA $FFE1       ; latch bank 1
  C015  20 10 80     JSR $8010       ; round 2: retargets to PRG_LO_B1::8010
  C018  A9 02        LDA #$02
  C01A  8D E2 FF     STA $FFE2       ; restore caller's bank 2
  C01D  60           RTS
  C020  A9 03        LDA #$03        ; trampoline2 -- only reachable via bank 1's routine
  C022  8D E3 FF     STA $FFE3       ; latch bank 3
  C025  20 30 80     JSR $8030       ; round 3: retargets to PRG_LO_B3::8030 (deepest)
  C028  A9 01        LDA #$01
  C02A  8D E1 FF     STA $FFE1       ; restore caller's bank 1
  C02D  60           RTS
  C030  60           RTS             ; bank-3 routine; PRG_LO_B3 window offset $8030
                      maps to the same file byte as PRG_HI $C030 (dual-mapped, never
                      referenced as PRG_HI $C030)
  FFE0-FFE3           bank-number table (00 01 02 03), bus-conflict-safe latch targets

nesmodetest.nes (bead grm-aqf): mode-dependent-layout fixture for the SYNTHETIC
machines/nes-modetest.yaml board (iNES mapper 100, NESdev-reserved for test use). The
board has two memory.layouts[] keyed off a 1-bit prg_mode field (latched by stores to
$6000-$6FFF, mask 0x01) and a 2-bit bank field (latched by stores to $5000-$5FFF,
mask 0x03) -- two independent memory-latch mechanisms setting disjoint state fields:
  prg_mode 0 (home): W8000 = PRG[bank * 0x4000] (switchable), WC000 = PRG[last] (fixed)
  prg_mode 1:        W8000 = PRG[last] (fixed),  WC000 = PRG[bank * 0x4000] (switchable)
The loader realizes the home layout's home instances in base space (W8000 = bank 0,
WC000 = PRG[last]) and everything else as mode-qualified overlays: W8000_M0_B1/_B2/_B3
(home layout, non-home banks), W8000_M1 (mode-1 fixed instance), and
WC000_M1_B0/_B1/_B2/_B3 (mode-1 switchable instances). BoardBankAnalyzer (bead grm-qvi)
retargets references into the _M* overlays the same way it does the plain _B* ones,
via a two-level mode -> window -> bank lookup; nesmodetest is wired into
run-banktest.sh / VerifyBankTest's checkNesModetest() goldens.

PRG is 4 x 16 KiB; WC000's home mapping is PRG[last] = file 0xC000-0xFFFF, so a CPU
address $C000+x in the home mode equals PRG file offset 0xC000+x (code below is
written at its CPU address, as in the fixtures above). Note W8000_M1 maps the SAME
last bank, so CPU $8000+x in mode 1 also equals PRG file offset 0xC000+x.

RESET ($C000, executes with the reset seed prg_mode=0/bank=0):
  C000  A9 01        LDA #$01
  C002  8D 00 50     STA $5000       ; bank latch -> 1 (mode still 0, known from seed)
  C005  20 00 80     JSR $8000       ; mode0/bank1 -> analyzer target W8000_M0_B1::8000
  C008  A9 01        LDA #$01
  C00A  8D 00 60     STA $6000       ; mode latch -> 1 (bank=1 must SURVIVE: separate
                      mechanisms position disjoint state fields)
  C00D  4C 40 80     JMP $8040       ; mode1 -> W8000 fixed(last) -> W8000_M1::8040
  C010  40           RTI             ; NMI/IRQ handler

Mode-1 phase at PRG 0xC040 (= W8000_M1::8040). It executes in the $8000 window
deliberately: with prg_mode=1 in effect, WC000 is the switchable window, so code
lingering at $C0xx -- even an idle-loop JMP -- would be retargeted into a WC000_M1_B*
overlay; hopping to the fixed $8000 window sidesteps that.
  8040  A9 02        LDA #$02
  8042  8D 00 50     STA $5000       ; bank -> 2 INSIDE a mode-qualified overlay
                      (prg_mode=1 must be preserved by the bank mechanism)
  8045  20 30 C0     JSR $C030       ; mode1/bank2 -> analyzer target WC000_M1_B2::C030
  8048  4C 48 80     JMP $8048       ; self idle (overlay-internal ref, not retargeted)

Routine targets:
  PRG 0x4000 (bank 1 offset 0 = W8000_M0_B1::8000): 60 RTS (replaces the bank marker)
  PRG 0x8030 (bank 2 offset 0x30 = WC000_M1_B2::C030): 60 RTS
Vectors: NMI/IRQ -> $C010 (RTI), RESET -> $C000.

nesmmc3test.nes (bead grm-6a7.1): exercises machines/nes-mmc3.yaml (iNES mapper 4) and
SelectDataBankSwitchStrategy end to end. PRG is 8 x 8 KiB banks (64 KiB): bank 7 = PRG[last]
(fixed WE000, home), bank 6 = PRG[second_last] (WC000's home in prg_mode 0, unused
directly by this fixture), bank 1 = r7's initial value (WA000's home bank -- deliberately
non-zero, see nes-mmc3.yaml's initial_state comment), bank 0 = r6's initial value (W8000's
home bank in prg_mode 0). RESET runs entirely inside the fixed WE000 window ($E000-$FFFF,
home -- file offset equals CPU address here, as in the fixtures above) so none of the
straight-line control flow itself ever crosses a window whose mapping the code is about to
change (the trap nesmodetest's module doc calls out avoiding).

RESET ($E000, executes with the reset seed select=0/prg_mode=0/r6=0/r7=1):
  E000  A9 06        LDA #$06        ; select R6 (bits 0-2 = 6, bit 6 = 0 -> mode stays 0)
  E002  8D 00 80     STA $8000       ; select write (even) -- select=6, prg_mode=0 known
  E005  A9 02        LDA #$02        ; bank value 2
  E007  8D 01 80     STA $8001       ; data write (odd) -- select=6 known -> r6=2
  E00A  20 00 80     JSR $8000       ; F1: mode0/r6=2 -> W8000_M0_B2::8000
  E00D  A9 00        LDA #$00        ; select R0 (a CHR register, untracked)
  E00F  8D 00 80     STA $8000       ; select=0, prg_mode=0 (unchanged) known
  E012  A9 AA        LDA #$AA        ; arbitrary CHR data byte
  E014  8D 01 80     STA $8001       ; select=0 (CHR, untracked) -> r6/r7 UNTOUCHED
                      (SelectDataBankSwitchStrategy's no-poison contract, grm-6a7.1)
  E017  20 00 80     JSR $8000       ; F2: r6=2 SURVIVED the CHR write -> still W8000_M0_B2
  E01A  A9 07        LDA #$07        ; select R7
  E01C  8D 00 80     STA $8000       ; select=7, prg_mode=0 known
  E01F  A9 03        LDA #$03        ; bank value 3
  E021  8D 01 80     STA $8001       ; select=7 known -> r7=3
  E024  20 00 A0     JSR $A000       ; F3: r7=3, WA000 invariant-hoisted (no _M qualifier;
                      home bank is r7's initial value 1, so bank 3 is non-home) ->
                      WA000_B3::A000
  E027  A9 46        LDA #$46        ; $46 = 0100_0110: bit 6 set (mode->1), bits 0-2 = 6
  E029  8D 00 80     STA $8000       ; select=6, prg_mode=1 known -- mode flip co-emitted
                      from the SAME byte as the select index (no separate mode mechanism)
  E02C  20 00 C0     JSR $C000       ; F4: post-mode-flip -- WC000 is now switchable on r6
                      (r6=2, still known -- survived every write above) -> WC000_M1_B2::C000
                      (dual-mapped with W8000_M0_B2::8000 -- both are bank 2's PRG content)
  E02F  4C 2F E0     JMP $E02F       ; idle loop, in the fixed home WE000 window (safe)
  E032  40           RTI             ; NMI/IRQ handler

Routine targets (all RTS):
  PRG 0x4000 (bank 2 offset 0 = W8000_M0_B2::8000 AND WC000_M1_B2::C000, dual-mapped)
  PRG 0x6000 (bank 3 offset 0 = WA000_B3::A000)
Vectors: RESET -> $E000, NMI/IRQ -> $E032.

nesmmc3test2.nes (bead grm-6a7.2, extended by grm-snu): function-level bank-state
requires-on-entry/call-site-violation fixture, same board (machines/nes-mmc3.yaml).
Deliberately does NOT touch nesmmc3test.nes (kept byte-for-byte to avoid golden churn on
an unrelated bead). Exercises a bare DATA-write-only helper H -- STA $8001 with no
accompanying select write of its own, the shape a real MMC3 driver commonly uses when
several data writes share one earlier select (current findHelpers/HelperModel behavior
for this shape: H is classified a helper with constState=null, argReg='A' (from H's own
STA $8001), effectMask/lsb the select-data mechanism's full field width, switchSite = H's
STA $8001). Call-site recovery routes through
SelectDataBankSwitchStrategy#depositHelperArgument's OWN override (bead grm-snu): the
recovered data byte is routed to whichever target register the CALLER's own tracked
select value picks at the call site -- select=6/7 (R6/R7) deposit only that one target
field, an untracked select (CHR 0-5) is a verified no-op (no comment, no warning), and an
unknown select honestly poisons every configured target field (R6+R7) without touching
select/prg_mode, which a data write can never reach. Four callers JSR the SAME H:

RESET ($E000, seed select=0/prg_mode=0/r6=0/r7=1):
  E000  20 00 E1     JSR $E100       ; CallerA
  E003  20 20 E1     JSR $E120       ; CallerB
  E006  20 60 E1     JSR $E160       ; CallerC
  E009  20 80 E1     JSR $E180       ; CallerD
  E00C  4C 0C E0     JMP $E00C       ; idle loop
  E00F  40           RTI             ; NMI/IRQ handler

CallerA ($E100) -- establishes select=6 (R6) itself before calling H:
  E100  A9 06        LDA #$06        ; select R6
  E102  8D 00 80     STA $8000       ; select=6, prg_mode=0 known
  E105  A9 02        LDA #$02        ; data byte = 2
  E107  20 40 E1     JSR $E140       ; call H -- select known here -> requiresOnEntry(H)
                      satisfied -> NO WARNING at E107; routed deposit: r6=2, select=6 and
                      prg_mode=0 UNTOUCHED (fully known, no '?') -- bead grm-snu
  E10A  60           RTS

CallerB ($E120) -- select genuinely unknown at its call to H:
  E120  AD 00 E2     LDA $E200       ; opaque absolute load -- select-data's
                      hooks.resolveLoad always returns null (write-only registers), so
                      this leaves A wholly unknown
  E123  8D 00 80     STA $8000       ; select (and co-emitted prg_mode) -> UNKNOWN
  E126  A9 03        LDA #$03        ; data byte = 3 (itself known -- irrelevant; H's
                      dispatch needs SELECT known, not the data byte)
  E128  20 40 E1     JSR $E140       ; call H -- select unknown here -> requiresOnEntry(H)
                      VIOLATED -> WARNING bookmark at E128; routed deposit honestly
                      poisons r6+r7 ONLY (the call could have hit either), leaving
                      select/prg_mode as they already were (still unknown here, but never
                      claimed by this call) -- bead grm-snu
  E12B  60           RTS

CallerC ($E160) -- establishes select=0 (an untracked CHR register) before calling H:
  E160  A9 00        LDA #$00        ; select R0 (CHR, untracked)
  E162  8D 00 80     STA $8000       ; select=0, prg_mode=0 known
  E165  A9 04        LDA #$04        ; data byte = 4 (irrelevant -- CHR target is
                      untracked, so this call is a verified no-op)
  E167  20 40 E1     JSR $E140       ; call H -- select known (CHR) -> requiresOnEntry(H)
                      satisfied (select IS known) -> NO WARNING at E167; ownedMask=0 ->
                      also NO bank-> comment at E167 (verified no-op, not merely unknown)
                      -- bead grm-snu
  E16A  60           RTS

CallerD ($E180) -- establishes select=7 (R7) before calling H:
  E180  A9 07        LDA #$07        ; select R7
  E182  8D 00 80     STA $8000       ; select=7, prg_mode=0 known
  E185  A9 04        LDA #$04        ; data byte = 4
  E187  20 40 E1     JSR $E140       ; call H -- select known here -> requiresOnEntry(H)
                      satisfied -> NO WARNING at E187; routed deposit: r7=4, select=7 and
                      prg_mode=0 UNTOUCHED (fully known, no '?') -- bead grm-snu
  E18A  60           RTS

H ($E140) -- the bare data-write helper:
  E140  8D 01 80     STA $8001       ; data write; A = whatever the caller loaded
  E143  60           RTS

Because the engine's Phase-1 dataflow merges state at every function entry across ALL
its callers (context-insensitive), H's OWN internal in-state at its STA $8001 is the
agree-bit merge of every caller's state reaching it -- select/prg_mode come out unknown
there regardless of caller (CallerB's poison dominates the merge). That is exactly what
makes H's own requiresOnEntry come out non-empty (select+prg_mode: the switch's own
effect ends up not knowing bits its in-state didn't know either -- see
BoardBankAnalyzer#annotateBankRequirementViolations's javadoc). The per-call-site
violation check, though, is NOT context-insensitive: it re-examines each CALLER's own
locally-tracked in-state at its own JSR address (each caller's JSR instruction is a
different address with independently-tracked flow), which is where the per-caller
distinction -- and, per bead grm-snu, the per-caller ROUTING -- actually comes from.

CallerE/CallerF/H2 and CallerG/H3 (bead grm-67g): the INBOUND ARGUMENT CELL shape,
where the caller passes H2's data byte through a RAM shadow ($0720) instead of a
register, and the helper's own register-select write ($0721/$8000) sits between the
caller's store and the helper's read of it. This is smb3's FUN_ffc2 transcribed byte
for byte (see BoardBankAnalyzer#inboundArgumentCell's worked example) -- the shape
grm-67g's fix (bead 8cc0517) added the machinery for, but that machinery had no
synthetic regression coverage of its own: the real-ROM tier smb3 exercises it through
is not part of build-and-test.sh (grm-mu7's first guard silently destroyed three real
ROMs while all 45 synthetic goldens stayed green -- see this module doc's own account
above; a real-ROM-only regression check is exactly the kind of gap that leaves open).
Three scenarios. CallerE/F/G each establish select+prg_mode THEMSELVES (LDA #$47 /
STA $8000, the same fixture idiom CallerA/C/D use above) before their JSR: select-data's
routed deposit needs a KNOWN select at the call site to know which register the $8001
data write targets, and select is write-only register state that does not survive as
"inherited" from an unrelated earlier caller the way a RAM cell does -- relying on that
would silently poison the deposit (select UNKNOWN -> no "bank ->" comment at all) rather
than testing the inbound-argument-cell shape these scenarios exist for.

  H2 ($E210): LDA #$47 / STA $0721 / STA $8000 / LDA $0720 / STA $8001 / RTS -- the
              bare two-write helper. STA $0721 is a decoy cell one byte off the real
              one; the helper's OWN select write is constant ($47 -> select=7,
              prg_mode=1), and the DATA byte comes from whatever the caller left at
              $0720, which the helper itself never writes.
  CallerE ($E220): LDA #$47 / STA $8000 / LDA #$05 / STA $0720 / LDA #$03 / JSR H2 --
              the positive case: after establishing select itself, it stores $05 (5)
              to $0720 immediately before the call, so inboundArgumentCell's caller-side
              forward scan (StoredValueScanner#callerCellValue) attributes $05 cleanly.
              Right before the JSR it loads A with $03 -- a DECOY distinct from the
              cell's value, so a recovered r7=3 would prove the strategy is (wrongly)
              register-sourcing the bank from A while r7=5 proves it is genuinely
              cell-sourced. Expect select=7, prg_mode=1, r7=5 (never r7=3), fully
              known, no warning at the JSR $E210 (E22C).

              EVERY BANK NUMBER IN THIS TRIO MUST BE IN RANGE (0-7), and that is a
              correctness requirement rather than tidiness. This fixture ships 8 PRG
              banks, and BoardBankAnalyzer refuses to annotate a recovered bank with no
              corresponding image slice -- it emits a "value-RECOVERY bug" warning and
              leaves the site bare (bead grm-hum, docs/vision-board-banking.md section 10
              item 10). smb3's real numbers are 27 and 26; transcribing them here made
              the positive case fail with a fully CORRECT recovery, and worse, made the
              negative controls pass without testing anything, since an out-of-range
              wrong answer is suppressed on its way out whatever produced it.
  CallerF ($E240): LDA #$47 / STA $8000 / LDA #$05 / STA $0720 / JSR Harmless / JSR H2 --
              the control: an intervening call between the store and the JSR to H2. A
              JSR may write anywhere, so the caller-side scan (which declines at any
              call it cannot see through -- see StoredValueScanner#forwardedStoreValue)
              cannot attribute the store across it. Expect a WARNING at the JSR $E210
              (E24D), not a value (no r7=5 claim).
  H3 ($E260) / CallerG ($E280): LDA #$47 / STA $0720 / STA $8000 / LDA $0720 /
              STA $8001 / RTS -- the self-written-cell shape: H3 writes the SAME cell
              it later reads back, so the byte at $0720 when H3's LDA runs is H3's own
              $47, not whatever CallerG (LDA #$47 / STA $8000 / LDA #$05 / STA $0720 /
              JSR H3) put there. inboundArgumentCell's `written` set exists precisely to
              catch this ($0720 is both read and written inside the helper) and decline
              the cell. Expect select=7, prg_mode=1, r7=7, fully known, no warning at the
              JSR $E260 (E28A) -- and specifically NOT r7=5. H3 really does put $47 into
              $8001, so r7 = $47 & $3F = 7 is the TRUTH here and valueSuppliedInsideHelper
              recovers it correctly by forwarding H3's own store to its own load.
              CallerG's $05 is a DEAD store; attributing it would ship r7=5, a confident
              wrong bank taken from a caller whose byte the helper threw away -- and 5 is
              a REAL bank in this image, so that wrong answer would be annotated rather
              than caught by the range guard. CallerE vs. CallerG is the A/B pair --
              identical caller bytes, 5 where the cell is inbound and 7 where it is not.
              Note this is a DIFFERENT defect from the one that shipped: smb3's r7=7 was
              wrong because it was read at the $8000 SELECT site rather than the $8001
              bank site, which suppliesHelperValueAtFirstSite fixed in increment 1.
              Reading a helper's own value is not the error; reading it from the wrong
              site was.

Vectors: RESET -> $E000, NMI/IRQ -> $E018 (the RESET flow's idle loop and RTI moved
from $E00C/$E00F to $E015/$E018 to make room for the three new dispatch calls). H3
moved from $E250 to $E260 and CallerG from $E260 to $E280 because CallerF now runs
through $E250 (it needs three extra bytes for its own select-establishing LDA/STA).
"""

import sys
import os

PRG_BANK_SIZE = 0x4000
PRG_BANKS = 4
PRG_SIZE = PRG_BANK_SIZE * PRG_BANKS
MAPPER = 2          # UxROM (nesbanktest / nesbanktest2)
MAPPER_MODETEST = 100  # synthetic nes-modetest board (NESdev-reserved test mapper)
MAPPER_MMC3 = 4        # MMC3 (nesmmc3test)
MAPPER_SERIALTEST = 222  # synthetic nes-serialtest board; see machines/nes-serialtest.yaml's
                          # module doc for why 222 (not 100/101/102/248) was chosen
MAPPER_MMC1 = 1        # real MMC1 board (nesmmc1test); see machines/nes-mmc1.yaml
MAPPER_BANDAI = 16     # Bandai FCG/LZ93D50 board (nesbandaitest); see machines/nes-bandai-fcg.yaml

MMC3_BANK_SIZE = 0x2000
MMC3_BANKS = 8
MMC3_PRG_SIZE = MMC3_BANK_SIZE * MMC3_BANKS

# nesserialtest.nes: 8 x 16 KiB PRG banks (128 KiB, Metroid-class shape per bead grm-hsv.1).
SERIAL_BANKS = 8
SERIAL_PRG_SIZE = PRG_BANK_SIZE * SERIAL_BANKS

# nesmmc1test.nes: 8 x 16 KiB PRG banks (128 KiB, Metroid-shaped per bead grm-hsv.2).
MMC1_BANKS = 8
MMC1_PRG_SIZE = PRG_BANK_SIZE * MMC1_BANKS


def _bank3_putter(prg):
    # Bank 3 == the fixed PRG_HI window; file offset == CPU address (see module doc).
    bank3_base = 3 * PRG_BANK_SIZE
    assert bank3_base == 0xC000

    def put(cpu_addr, data):
        off = bank3_base + (cpu_addr - 0xC000)
        prg[off:off + len(data)] = bytes(data)

    return put


def make_prg():
    prg = bytearray([0x00] * PRG_SIZE)

    # Bank markers at the first byte of each bank (offset $8000 once mapped in).
    for bank in range(PRG_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank

    # Bank 2's JSR target routine at CPU $8005 -> file offset 2*0x4000 + 5.
    bank2_rts_off = 2 * PRG_BANK_SIZE + 0x0005
    prg[bank2_rts_off] = 0x60  # RTS

    put = _bank3_putter(prg)

    put(0xC000, [0xA9, 0x02])              # LDA #$02
    put(0xC002, [0x8D, 0xF0, 0xFF])         # STA $FFF0
    put(0xC005, [0x20, 0x05, 0x80])         # JSR $8005
    put(0xC008, [0x4C, 0x08, 0xC0])         # JMP $C008 (self loop)
    put(0xC00B, [0x40])                     # RTI

    # Bus-conflict target byte: must equal the value latched (0x02) so
    # MemoryLatchBankSwitchStrategy's bus-conflict AND is a faithful no-op.
    put(0xFFF0, [0x02])

    # Vector table.
    put(0xFFFA, [0x0B, 0xC0])  # NMI   -> $C00B (RTI)
    put(0xFFFC, [0x00, 0xC0])  # RESET -> $C000
    put(0xFFFE, [0x0B, 0xC0])  # IRQ   -> $C00B (RTI)

    return bytes(prg)


def make_prg_bandai():
    """MemoryLatchBankSwitchStrategy address-decode fixture for the Bandai FCG/LZ93D50
    board (bead grm-9ty, machines/nes-bandai-fcg.yaml, iNES mapper 16). Same 4-bank /
    64 KiB shape as nesbanktest.nes (bank 3 == the fixed PRG_HI window, file offset ==
    CPU address), but the mechanism is a register-file latch: writes anywhere in
    $8000-$FFFF hit one of 14 registers selected by the address's low nibble, and only
    nibble $8 is the PRG bank. Unlike UxROM there is NO bus conflict (FCG has a dedicated
    latch), so the recovered bank is just the driven immediate.

    The fixture's whole point is to prove the addr_mask/addr_match decode: RESET selects
    PRG bank 2 via STA $8008 (register $8), then deliberately writes a CHR register
    (STA $8000, decoy value 1) and an IRQ register (STA $800A, decoy value 3) -- both in
    the latch range, both with values that, if the decode were absent (a plain whole-range
    memory-latch), would clobber prg_bank to 1 then 3. The following JSR $8005 must still
    retarget into bank 2's overlay (PRG_LO_B2::8005); if either decoy had latched, it would
    resolve elsewhere. So the single `COMMENT ... prg_bank=2` and the one REF into _B2 are
    together direct proof the sibling registers are non-latches.

    RESET ($C000, in the fixed PRG_HI/bank-3 window):
      C000  A9 02      LDA #$02        ; PRG bank 2
      C002  8D 08 80   STA $8008       ; register $8 -> prg_bank=2 (the real select)
      C005  A9 01      LDA #$01        ; decoy value 1
      C007  8D 00 80   STA $8000       ; register $0 (CHR) -- must NOT move prg_bank
      C00A  A9 03      LDA #$03        ; decoy value 3
      C00C  8D 0A 80   STA $800A       ; register $A (IRQ enable) -- must NOT move prg_bank
      C00F  20 05 80   JSR $8005       ; -> PRG_LO_B2::8005 (proves prg_bank survived as 2)
      C012  4C 12 C0   JMP $C012       ; self loop
      C015  40         RTI             ; NMI/IRQ handler
    """
    prg = bytearray([0x00] * PRG_SIZE)

    # Bank markers at the first byte of each bank (offset $8000 once mapped in).
    for bank in range(PRG_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank

    # Bank 2's JSR target routine at CPU $8005 -> file offset 2*0x4000 + 5.
    prg[2 * PRG_BANK_SIZE + 0x0005] = 0x60  # RTS

    put = _bank3_putter(prg)

    put(0xC000, [0xA9, 0x02])              # LDA #$02
    put(0xC002, [0x8D, 0x08, 0x80])         # STA $8008  (register $8: PRG bank)
    put(0xC005, [0xA9, 0x01])              # LDA #$01
    put(0xC007, [0x8D, 0x00, 0x80])         # STA $8000  (register $0: CHR -- decoy)
    put(0xC00A, [0xA9, 0x03])              # LDA #$03
    put(0xC00C, [0x8D, 0x0A, 0x80])         # STA $800A  (register $A: IRQ -- decoy)
    put(0xC00F, [0x20, 0x05, 0x80])         # JSR $8005
    put(0xC012, [0x4C, 0x12, 0xC0])         # JMP $C012 (self loop)
    put(0xC015, [0x40])                     # RTI

    # Vector table.
    put(0xFFFA, [0x15, 0xC0])  # NMI   -> $C015 (RTI)
    put(0xFFFC, [0x00, 0xC0])  # RESET -> $C000
    put(0xFFFE, [0x15, 0xC0])  # IRQ   -> $C015 (RTI)

    return bytes(prg)


def make_prg2():
    """The 3-deep overlay-bank JSR chain fixture (bead grm-5tl.13.3); see module doc."""
    prg = bytearray([0x00] * PRG_SIZE)

    prg[0 * PRG_BANK_SIZE] = 0x00  # bank 0 marker
    prg[1 * PRG_BANK_SIZE] = 0x01  # bank 1 marker
    prg[2 * PRG_BANK_SIZE] = 0x02  # bank 2 marker

    # Bank 1's routine at CPU $8010 -> file offset 1*0x4000 + 0x10.
    b1 = 1 * PRG_BANK_SIZE
    prg[b1 + 0x0010:b1 + 0x0013] = bytes([0x20, 0x20, 0xC0])  # JSR $C020
    prg[b1 + 0x0013] = 0x60                                    # RTS

    # Bank 2's routine at CPU $8005 -> file offset 2*0x4000 + 5.
    b2 = 2 * PRG_BANK_SIZE
    prg[b2 + 0x0005:b2 + 0x0008] = bytes([0x20, 0x10, 0xC0])  # JSR $C010
    prg[b2 + 0x0008] = 0x60                                    # RTS

    put = _bank3_putter(prg)

    put(0xC000, [0xA9, 0x02])              # LDA #$02
    put(0xC002, [0x8D, 0xE2, 0xFF])         # STA $FFE2 (latch bank 2)
    put(0xC005, [0x20, 0x05, 0x80])         # JSR $8005 (round 1 -> PRG_LO_B2::8005)
    put(0xC008, [0x4C, 0x08, 0xC0])         # JMP $C008 (self loop)
    put(0xC00B, [0x40])                     # RTI

    put(0xC010, [0xA9, 0x01])              # LDA #$01 (trampoline1)
    put(0xC012, [0x8D, 0xE1, 0xFF])         # STA $FFE1 (latch bank 1)
    put(0xC015, [0x20, 0x10, 0x80])         # JSR $8010 (round 2 -> PRG_LO_B1::8010)
    put(0xC018, [0xA9, 0x02])              # LDA #$02
    put(0xC01A, [0x8D, 0xE2, 0xFF])         # STA $FFE2 (restore bank 2)
    put(0xC01D, [0x60])                     # RTS

    put(0xC020, [0xA9, 0x03])              # LDA #$03 (trampoline2)
    put(0xC022, [0x8D, 0xE3, 0xFF])         # STA $FFE3 (latch bank 3)
    put(0xC025, [0x20, 0x30, 0x80])         # JSR $8030 (round 3 -> PRG_LO_B3::8030)
    put(0xC028, [0xA9, 0x01])              # LDA #$01
    put(0xC02A, [0x8D, 0xE1, 0xFF])         # STA $FFE1 (restore bank 1)
    put(0xC02D, [0x60])                     # RTS

    put(0xC030, [0x60])                     # RTS (bank-3 routine; dual-mapped with PRG_HI)

    # UxROM bank-number table: bus-conflict-safe latch targets (byte at address N == N-FFE0).
    put(0xFFE0, [0x00, 0x01, 0x02, 0x03])

    # Vector table.
    put(0xFFFA, [0x0B, 0xC0])  # NMI   -> $C00B (RTI)
    put(0xFFFC, [0x00, 0xC0])  # RESET -> $C000
    put(0xFFFE, [0x0B, 0xC0])  # IRQ   -> $C00B (RTI)

    return bytes(prg)


def make_prg_uxhelper():
    """Bank-switch helper ARGUMENT recovery fixture (bead grm-hum). Same 4-bank / 64 KiB
    UxROM shape as nesbanktest.nes (bank 3 == the fixed PRG_HI window, file offset == CPU
    address), carrying the two real-cartridge idioms that grm-3x1 made visible but could
    not recover a value from. Both are transcribed from ROMs whose SHA-256s are pinned in
    tools/banktest/realrom/manifest.tsv; the addresses here are the fixture's, the SHAPES
    are the cartridges'.

    IDIOM 1 -- "argument in Y", from Contra (U) $C13F. The canonical bus-conflict-safe
    UxROM switch: index a table of bank numbers with the argument register, then store the
    byte you just read back to the address you read it from, so the CPU-driven value and
    the ROM byte agree and the board's missing bus isolation cannot corrupt the latch.

      SelectBank ($C140):
        C140  B9 D0 FF   LDA $FFD0,Y      ; bank argument arrives in Y, NOT in A
        C143  99 D0 FF   STA $FFD0,Y      ; mechanism write
        C146  60         RTS

    Before grm-hum the engine recorded this helper's argument register as A -- taken from
    the STA -- and then scanned each call site for an LDA #imm that has nothing to do with
    the bank. Recovering it requires evaluating the helper's own switch site under the call
    site's register environment (the argument is in Y) AND resolving an indexed load whose
    index is a known constant (the table read).

    IDIOM 2 -- "two switches, the last one wins", from Mega Man (U) FUN_d846. A helper
    whose FIRST switch is a plain immediate and whose SECOND is a refless indexed store
    fed by a ROM table read. Before grm-3x1 only the first was visible, so the engine
    confidently reported the wrong bank for every call site; grm-3x1 made the second
    visible, which correctly demoted the whole helper to "unrecoverable" -- and grm-hum
    resolves it to the bank that actually survives the RTS.

      TwoSwitch ($C120):
        C120  A9 03      LDA #$03
        C122  8D D3 FF   STA $FFD3        ; switch #1 -> bank 3
        C125  A9 00      LDA #$00
        C127  0A         ASL A            ; A = 0 (constant across the shift)
        C128  AA         TAX              ; X = 0
        C129  BD 1E D8   LDA $D81E,X      ; index table -> 0x01
        C12C  A8         TAY              ; Y = 1
        C12D  99 D0 FF   STA $FFD0,Y      ; switch #2 -> bank 1  (refless, indexed)
        C130  60         RTS              ; the board is left in bank 1, NOT bank 3

    RESET ($C000) exercises both, and deliberately keeps one honest gap so a future change
    that "fixes" the remaining warnings by guessing fails loudly:

      C000  A0 02      LDY #$02
      C002  20 40 C1   JSR $C140     ; recoverable  -> bank 2
      C005  20 05 80   JSR $8005     ; -> PRG_LO_B2::8005 (the recovery is load-bearing)
      C008  A4 10      LDY $10       ; zero-page RAM -- genuinely not statically knowable
      C00A  20 40 C1   JSR $C140     ; MUST NOT resolve
      C00D  20 20 C1   JSR $C120     ; -> bank 1, regardless of the poison left by $C00A
      C010  20 10 80   JSR $8010     ; -> PRG_LO_B1::8010 (proves switch #2 beat switch #1)
      C013  A9 09      LDA #$09
      C015  8D D9 FF   STA $FFD9     ; bank 9 on a 4-bank image -- impossible, must warn
      C018  4C 18 C0   JMP $C018     ; self loop
      C01B  40         RTI           ; NMI/IRQ handler

    Note $FFD9 holds 0x09 so the bus-conflict AND is a faithful no-op there: the
    impossible-bank guard must fire on a value the hardware really would have latched,
    not on one the AND had already reduced to something legal.
    """
    prg = bytearray([0x00] * PRG_SIZE)

    # Bank markers at the first byte of each bank (offset $8000 once mapped in). This is
    # also, incidentally, the "bank-identifying byte" idiom Contra uses at $8000 -- see
    # bead A in grm-hum's plan; nothing in this fixture reads it yet.
    for bank in range(PRG_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank

    # Bank 1's routine at CPU $8010, bank 2's at CPU $8005 and $8020 -- the retarget targets.
    prg[1 * PRG_BANK_SIZE + 0x0010] = 0x60  # RTS
    prg[2 * PRG_BANK_SIZE + 0x0005] = 0x60  # RTS
    prg[2 * PRG_BANK_SIZE + 0x0020] = 0x60  # RTS (tail-call test's target)

    put = _bank3_putter(prg)

    # --- RESET ---
    put(0xC000, [0xA0, 0x02])              # LDY #$02
    put(0xC002, [0x20, 0x40, 0xC1])         # JSR $C140   (recoverable -> bank 2)
    put(0xC005, [0x20, 0x05, 0x80])         # JSR $8005   (-> PRG_LO_B2::8005)
    put(0xC008, [0xA4, 0x10])              # LDY $10     (RAM -- unrecoverable on purpose)
    put(0xC00A, [0x20, 0x40, 0xC1])         # JSR $C140   (must NOT resolve)
    put(0xC00D, [0x20, 0x20, 0xC1])         # JSR $C120   (-> bank 1)
    put(0xC010, [0x20, 0x10, 0x80])         # JSR $8010   (-> PRG_LO_B1::8010)
    put(0xC013, [0x20, 0x70, 0xC1])         # JSR $C170   (makes SetBank2 a real function)
    put(0xC016, [0x20, 0x60, 0xC1])         # JSR $C160   (tail-call helper -> bank 2, NOT 3)
    put(0xC019, [0x20, 0x20, 0x80])         # JSR $8020   (-> PRG_LO_B2::8020)
    put(0xC01C, [0xA9, 0x09])              # LDA #$09
    put(0xC01E, [0x8D, 0xD9, 0xFF])         # STA $FFD9   (impossible bank 9 of 4)
    put(0xC021, [0x4C, 0x21, 0xC0])         # JMP $C021   (self loop)
    put(0xC024, [0x40])                     # RTI

    # --- TailSwitch ($C160) / SetBank2 ($C170): the MEGA MAN FUN_d846 -> FUN_c3b3 shape ---
    # TailSwitch's own highest-address switch says bank 3, but it does not RETURN -- it tail
    # jumps to SetBank2, which latches bank 2 and returns to TailSwitch's caller. So the bank
    # live after JSR $C160 is 2. Summarizing a helper by the last switch in its OWN body gets
    # this wrong, which is exactly what Mega Man's FUN_d846/FUN_d131/FUN_c55d do to $C3B3.
    # SetBank2 is JSR'd directly from RESET as well, so Ghidra makes it a separate function
    # and the JMP is a genuine inter-function tail call rather than an intra-function jump
    # that would fold the two bodies together and hide the whole problem.
    put(0xC160, [0xA9, 0x03])              # LDA #$03
    put(0xC162, [0x8D, 0xD3, 0xFF])         # STA $FFD3   (switch -> bank 3)
    put(0xC165, [0x4C, 0x70, 0xC1])         # JMP $C170   (TAIL CALL -- control leaves here)
    put(0xC170, [0xA9, 0x02])              # LDA #$02
    put(0xC172, [0x8D, 0xD2, 0xFF])         # STA $FFD2   (switch -> bank 2)
    put(0xC175, [0x60])                     # RTS

    # --- TwoSwitch ($C120): Mega Man FUN_d846 idiom ---
    put(0xC120, [0xA9, 0x03])              # LDA #$03
    put(0xC122, [0x8D, 0xD3, 0xFF])         # STA $FFD3   (switch #1 -> bank 3)
    put(0xC125, [0xA9, 0x00])              # LDA #$00
    put(0xC127, [0x0A])                     # ASL A
    put(0xC128, [0xAA])                     # TAX         (X = 0)
    put(0xC129, [0xBD, 0x1E, 0xD8])         # LDA $D81E,X (-> 0x01)
    put(0xC12C, [0xA8])                     # TAY         (Y = 1)
    put(0xC12D, [0x99, 0xD0, 0xFF])         # STA $FFD0,Y (switch #2 -> bank 1)
    put(0xC130, [0x60])                     # RTS

    # --- SelectBank ($C140): Contra $C13F idiom ---
    put(0xC140, [0xB9, 0xD0, 0xFF])         # LDA $FFD0,Y
    put(0xC143, [0x99, 0xD0, 0xFF])         # STA $FFD0,Y
    put(0xC146, [0x60])                     # RTS

    # Index table read by TwoSwitch with a statically known X=0. Sited well away from the
    # bank table so a scan that confuses the two cannot accidentally pass.
    put(0xD81E, [0x01])

    # UxROM bank-number table: bus-conflict-safe latch targets, byte at $FFD0+N == N.
    put(0xFFD0, [0x00, 0x01, 0x02, 0x03])
    # Impossible-bank probe target: 0x09 so the bus-conflict AND does not launder it.
    put(0xFFD9, [0x09])

    # Vector table.
    put(0xFFFA, [0x1B, 0xC0])  # NMI   -> $C01B (RTI)
    put(0xFFFC, [0x00, 0xC0])  # RESET -> $C000
    put(0xFFFE, [0x1B, 0xC0])  # IRQ   -> $C01B (RTI)

    return bytes(prg)


def make_prg_mode():
    """The mode-dependent-layout fixture for nes-modetest (bead grm-aqf); see module doc."""
    prg = bytearray([0x00] * PRG_SIZE)

    # Bank markers at the first byte of each bank, matching the other fixtures' convention.
    # Bank 1's marker is immediately replaced by its RTS routine, and bank 3's by RESET's
    # first opcode -- both intentional (see the module doc's nesmodetest section).
    for bank in range(PRG_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank

    # Bank 1 offset 0 (= W8000_M0_B1::8000, the mode-0/bank-1 JSR target): RTS.
    prg[1 * PRG_BANK_SIZE + 0x0000] = 0x60  # RTS

    # Bank 2 offset 0x30 (= WC000_M1_B2::C030, the mode-1/bank-2 JSR target): RTS.
    prg[2 * PRG_BANK_SIZE + 0x0030] = 0x60  # RTS

    # Bank 3 = PRG[last]: the home-mode WC000 window (CPU $C000+) AND the mode-1 W8000
    # window (CPU $8000+). put() addresses it by its home-mode CPU address.
    put = _bank3_putter(prg)

    # RESET phase (home mode prg_mode=0, bank seeded 0).
    put(0xC000, [0xA9, 0x01])               # LDA #$01
    put(0xC002, [0x8D, 0x00, 0x50])         # STA $5000 (bank latch -> 1)
    put(0xC005, [0x20, 0x00, 0x80])         # JSR $8000 (mode0/bank1 -> W8000_M0_B1::8000)
    put(0xC008, [0xA9, 0x01])               # LDA #$01
    put(0xC00A, [0x8D, 0x00, 0x60])         # STA $6000 (mode latch -> 1; bank=1 survives)
    put(0xC00D, [0x4C, 0x40, 0x80])         # JMP $8040 (mode1 -> W8000_M1::8040)
    put(0xC010, [0x40])                     # RTI (NMI/IRQ handler)

    # Mode-1 phase; written at PRG 0xC040 == W8000_M1's CPU $8040 (dual-mapped -- the
    # code deliberately runs in the fixed $8000 window; see module doc).
    put(0xC040, [0xA9, 0x02])               # 8040: LDA #$02
    put(0xC042, [0x8D, 0x00, 0x50])         # 8042: STA $5000 (bank -> 2 inside overlay)
    put(0xC045, [0x20, 0x30, 0xC0])         # 8045: JSR $C030 (mode1/bank2 -> WC000_M1_B2::C030)
    put(0xC048, [0x4C, 0x48, 0x80])         # 8048: JMP $8048 (self idle)

    # Vector table.
    put(0xFFFA, [0x10, 0xC0])  # NMI   -> $C010 (RTI)
    put(0xFFFC, [0x00, 0xC0])  # RESET -> $C000
    put(0xFFFE, [0x10, 0xC0])  # IRQ   -> $C010 (RTI)

    return bytes(prg)


def make_prg_mmc3():
    """The SelectDataBankSwitchStrategy end-to-end fixture (bead grm-6a7.1); see module doc."""
    prg = bytearray([0x00] * MMC3_PRG_SIZE)

    # Bank markers at the first byte of each bank (harmless -- not referenced directly,
    # matches the other fixtures' convention of leaving a visible trace per bank).
    for bank in range(MMC3_BANKS):
        prg[bank * MMC3_BANK_SIZE] = bank

    # Bank 2 offset 0 (dual-mapped: W8000_M0_B2::8000 AND WC000_M1_B2::C000): RTS.
    prg[2 * MMC3_BANK_SIZE] = 0x60
    # Bank 3 offset 0 (WA000_B3::A000): RTS.
    prg[3 * MMC3_BANK_SIZE] = 0x60

    # Bank 7 == PRG[last] == the fixed WE000 window; file offset == CPU address (WE000's
    # CPU base $E000 equals its file offset 7 * 0x2000 = 0xE000).
    bank7_base = 7 * MMC3_BANK_SIZE
    assert bank7_base == 0xE000

    def put(cpu_addr, data):
        off = bank7_base + (cpu_addr - 0xE000)
        prg[off:off + len(data)] = bytes(data)

    put(0xE000, [0xA9, 0x06])              # LDA #$06 (select R6)
    put(0xE002, [0x8D, 0x00, 0x80])        # STA $8000 (select=6, prg_mode=0)
    put(0xE005, [0xA9, 0x02])              # LDA #$02
    put(0xE007, [0x8D, 0x01, 0x80])        # STA $8001 (data -> r6=2)
    put(0xE00A, [0x20, 0x00, 0x80])        # JSR $8000 (F1 -> W8000_M0_B2::8000)
    put(0xE00D, [0xA9, 0x00])              # LDA #$00 (select R0, CHR -- untracked)
    put(0xE00F, [0x8D, 0x00, 0x80])        # STA $8000 (select=0, prg_mode=0)
    put(0xE012, [0xA9, 0xAA])              # LDA #$AA (arbitrary CHR data byte)
    put(0xE014, [0x8D, 0x01, 0x80])        # STA $8001 (CHR data -- r6/r7 untouched)
    put(0xE017, [0x20, 0x00, 0x80])        # JSR $8000 (F2 -- r6=2 survived -> W8000_M0_B2::8000)
    put(0xE01A, [0xA9, 0x07])              # LDA #$07 (select R7)
    put(0xE01C, [0x8D, 0x00, 0x80])        # STA $8000 (select=7, prg_mode=0)
    put(0xE01F, [0xA9, 0x03])              # LDA #$03
    put(0xE021, [0x8D, 0x01, 0x80])        # STA $8001 (data -> r7=3)
    put(0xE024, [0x20, 0x00, 0xA0])        # JSR $A000 (F3 -> WA000_B3::A000, hoisted, no _M)
    put(0xE027, [0xA9, 0x46])              # LDA #$46 (select=6, mode bit set)
    put(0xE029, [0x8D, 0x00, 0x80])        # STA $8000 (select=6, prg_mode=1 -- mode flip)
    put(0xE02C, [0x20, 0x00, 0xC0])        # JSR $C000 (F4 -> WC000_M1_B2::C000)
    put(0xE02F, [0x4C, 0x2F, 0xE0])        # JMP $E02F (idle loop, fixed home window)
    put(0xE032, [0x40])                     # RTI (NMI/IRQ handler)

    # Vector table.
    put(0xFFFA, [0x32, 0xE0])  # NMI   -> $E032 (RTI)
    put(0xFFFC, [0x00, 0xE0])  # RESET -> $E000
    put(0xFFFE, [0x32, 0xE0])  # IRQ   -> $E032 (RTI)

    return bytes(prg)


def make_prg_mmc3_2():
    """The requires-on-entry / function-summary fixture (bead grm-6a7.2, design D, M3
    scope) for SelectDataBankSwitchStrategy, extended by bead grm-snu to exercise the
    state-routed depositHelperArgument override. See module doc's nesmmc3test2 section: a
    bare DATA-write-only helper (select assumed already established by its caller) is
    called from callers with select known-and-tracked (R6/R7, routed deposit), known-and-
    untracked (CHR, verified no-op), and genuinely unknown (violation -> WARNING bookmark
    at the JSR, honest poison of R6+R7 only).
    """
    prg = bytearray([0x00] * MMC3_PRG_SIZE)

    for bank in range(MMC3_BANKS):
        prg[bank * MMC3_BANK_SIZE] = bank

    # Bank 7 == PRG[last] == the fixed WE000 window; file offset == CPU address, as in
    # make_prg_mmc3() above.
    bank7_base = 7 * MMC3_BANK_SIZE
    assert bank7_base == 0xE000

    def put(cpu_addr, data):
        off = bank7_base + (cpu_addr - 0xE000)
        prg[off:off + len(data)] = bytes(data)

    # RESET ($E000): call CallerA (no violation, routes to r6), CallerB (violation,
    # poisons r6+r7), CallerC (no violation, verified no-op via untracked CHR select),
    # CallerD (no violation, routes to r7), then the grm-67g inbound-argument-cell
    # trio (CallerE positive, CallerF intervening-call control, CallerG self-written-
    # cell control), then idle. The idle loop and NMI/IRQ RTI moved from $E00C/$E00F
    # to $E015/$E018 to make room for the three new dispatch calls.
    put(0xE000, [0x20, 0x00, 0xE1])        # JSR $E100 (CallerA)
    put(0xE003, [0x20, 0x20, 0xE1])        # JSR $E120 (CallerB)
    put(0xE006, [0x20, 0x60, 0xE1])        # JSR $E160 (CallerC)
    put(0xE009, [0x20, 0x80, 0xE1])        # JSR $E180 (CallerD)
    put(0xE00C, [0x20, 0x20, 0xE2])        # JSR $E220 (CallerE)
    put(0xE00F, [0x20, 0x40, 0xE2])        # JSR $E240 (CallerF)
    put(0xE012, [0x20, 0x80, 0xE2])        # JSR $E280 (CallerG -- moved from $E260)
    put(0xE015, [0x4C, 0x15, 0xE0])        # JMP $E015 (idle loop)
    put(0xE018, [0x40])                     # RTI (NMI/IRQ handler)

    # CallerA ($E100): establishes select=6 itself before calling the data-only helper
    # -- requiresOnEntry(H) is satisfied here, so no WARNING at CallerA's JSR. bead
    # grm-snu: the routed deposit lands data byte 2 in r6 alone, leaving select=6 and
    # prg_mode=0 untouched (fully known).
    put(0xE100, [0xA9, 0x06])              # LDA #$06 (select R6)
    put(0xE102, [0x8D, 0x00, 0x80])        # STA $8000 (select=6, prg_mode=0 known)
    put(0xE105, [0xA9, 0x02])              # LDA #$02 (data byte)
    put(0xE107, [0x20, 0x40, 0xE1])        # JSR $E140 (H) -- select known, no violation;
                                             # routed deposit -> r6=2
    put(0xE10A, [0x60])                     # RTS

    # CallerB ($E120): poisons select via an unresolvable load (plain LDA of an address
    # select-data's hooks.resolveLoad never resolves -- the registers are write-only)
    # immediately before writing $8000, so select is genuinely unknown at its JSR --
    # requiresOnEntry(H) is NOT satisfied here -> WARNING at CallerB's JSR. bead grm-snu:
    # the routed deposit honestly poisons r6+r7 ONLY (never select/prg_mode, which a data
    # write can't reach), rather than the pre-fix DEFAULT deposit that fabricated a known
    # select value out of the data byte.
    put(0xE120, [0xAD, 0x00, 0xE2])        # LDA $E200 (unresolvable -- opaque load)
    put(0xE123, [0x8D, 0x00, 0x80])        # STA $8000 (select -> unknown)
    put(0xE126, [0xA9, 0x03])              # LDA #$03 (data byte -- itself known, doesn't
                                             # matter: H's dispatch needs SELECT, not data)
    put(0xE128, [0x20, 0x40, 0xE1])        # JSR $E140 (H) -- select unknown -> violation
    put(0xE12B, [0x60])                     # RTS

    # CallerC ($E160) -- bead grm-snu: establishes select=0 (R0, an untracked CHR
    # register) before calling H. select IS known here, so requiresOnEntry(H) is
    # satisfied (no WARNING) -- but the routed deposit's ownedMask is 0 (verified no-op),
    # so the call site also gets NO bank-> comment, and r6/r7's prior knowledge survives
    # the call untouched.
    put(0xE160, [0xA9, 0x00])              # LDA #$00 (select R0, CHR -- untracked)
    put(0xE162, [0x8D, 0x00, 0x80])        # STA $8000 (select=0, prg_mode=0 known)
    put(0xE165, [0xA9, 0x04])              # LDA #$04 (data byte -- irrelevant, CHR target)
    put(0xE167, [0x20, 0x40, 0xE1])        # JSR $E140 (H) -- select known (CHR) ->
                                             # verified no-op: no comment, no warning
    put(0xE16A, [0x60])                     # RTS

    # CallerD ($E180) -- bead grm-snu: establishes select=7 (R7) before calling H. Mirrors
    # CallerA but routes to the OTHER tracked target, proving the routing genuinely reads
    # the tracked select value rather than being hardcoded to R6.
    put(0xE180, [0xA9, 0x07])              # LDA #$07 (select R7)
    put(0xE182, [0x8D, 0x00, 0x80])        # STA $8000 (select=7, prg_mode=0 known)
    put(0xE185, [0xA9, 0x04])              # LDA #$04 (data byte)
    put(0xE187, [0x20, 0x40, 0xE1])        # JSR $E140 (H) -- select known, no violation;
                                             # routed deposit -> r7=4
    put(0xE18A, [0x60])                     # RTS

    # H ($E140): the bare data-write helper -- select is assumed already set by the
    # caller (real MMC3 code commonly amortizes one select write across several data
    # writes). Call-site recovery routes through SelectDataBankSwitchStrategy's own
    # depositHelperArgument override (bead grm-snu) rather than the interface DEFAULT.
    put(0xE140, [0x8D, 0x01, 0x80])        # STA $8001 (data write; A = caller's argument)
    put(0xE143, [0x60])                     # RTS

    # Arbitrary byte CallerB's unresolvable load reads (value itself is irrelevant --
    # the point is that value recovery cannot pin it down at all).
    put(0xE200, [0x00])

    # ------------------------------------------------------------------
    # grm-67g: inbound-argument-cell trio (H2/CallerE/CallerF, H3/CallerG).
    #
    # Each of CallerE/F/G now establishes select+prg_mode ITSELF (LDA #$47 / STA $8000,
    # matching CallerA/C/D's idiom above) before its JSR. Select-data's routed deposit
    # (SelectDataBankSwitchStrategy#depositHelperArgument) needs a KNOWN select to know
    # which register the $8001 data write targets; select is write-only register state
    # that does not survive as "inherited" across a JSR the way a RAM cell does, so
    # relying on state left behind by an earlier, unrelated caller silently poisons the
    # deposit (select UNKNOWN -> no "bank ->" comment at all, criteria G5/CallerB's
    # documented behaviour) rather than warning about it. H2/H3 still additionally
    # perform their OWN $8000 write; the shape under test -- one helper doing both
    # mechanism writes (select+prg_mode via its own constant, bank via an inbound RAM
    # cell) -- is unchanged.
    # ------------------------------------------------------------------

    # H2 ($E210): smb3's FUN_ffc2 transcribed byte for byte -- a two-write helper whose
    # register-select write ($8000) is CONSTANT ($47 -> select=7, prg_mode=1) and whose
    # data write ($8001) is fed from RAM shadow $0720, a cell H2 itself never writes.
    # STA $0721 is the decoy: one byte off the real cell, present so
    # BoardBankAnalyzer#inboundArgumentCell has something to rule out via its `written`
    # set before it settles on $0720.
    put(0xE210, [0xA9, 0x47])              # LDA #$47 (select=7, prg_mode=1 -- constant)
    put(0xE212, [0x8D, 0x21, 0x07])        # STA $0721 (decoy cell, NOT the argument cell)
    put(0xE215, [0x8D, 0x00, 0x80])        # STA $8000 (select=7, prg_mode=1 known)
    put(0xE218, [0xAD, 0x20, 0x07])        # LDA $0720 (the argument cell -- caller-supplied)
    put(0xE21B, [0x8D, 0x01, 0x80])        # STA $8001 (data write -> r7 = whatever $0720 held)
    put(0xE21E, [0x60])                     # RTS

    # CallerE ($E220): the positive case -- establishes select=7/prg_mode=1 itself (its
    # own $47 -> $8000, the fixture idiom) so H2's routed deposit has a known select to
    # target, then stores $05 to $0720 immediately before the JSR so the caller-side
    # forward scan (StoredValueScanner#callerCellValue) attributes it cleanly. Right
    # before the JSR it loads A with $03 -- a DECOY distinct from the cell's value,
    # present so a recovered r7=3 would prove the strategy is (wrongly) register-
    # sourcing the bank from A, while r7=5 proves it is genuinely cell-sourced. Both
    # values are IN RANGE (this image ships 8 PRG banks): an out-of-range bank is
    # suppressed on its way out with a value-recovery warning, which would make this
    # criterion fail on a CORRECT recovery and make the controls below pass vacuously.
    # Expect select=7, prg_mode=1, r7=5 (never r7=3), fully known, no warning at the
    # JSR $E210 (E22C).
    put(0xE220, [0xA9, 0x47])              # LDA #$47 (select=7, prg_mode=1 -- fixture idiom)
    put(0xE222, [0x8D, 0x00, 0x80])        # STA $8000 (select=7, prg_mode=1 known)
    put(0xE225, [0xA9, 0x05])              # LDA #$05 (5 -- the real bank, IN RANGE)
    put(0xE227, [0x8D, 0x20, 0x07])        # STA $0720 (the argument cell)
    put(0xE22A, [0xA9, 0x03])              # LDA #$03 (3 -- DECOY in A, also in range;
                                             # would (wrongly) give r7=3)
    put(0xE22C, [0x20, 0x10, 0xE2])        # JSR $E210 (H2) -> select=7/prg_mode=1/r7=5
    put(0xE22F, [0x60])                     # RTS

    # Harmless ($E230): an arbitrary intervening subroutine CallerF calls between its
    # store to $0720 and its call to H2 -- content doesn't matter, only that it is a CALL
    # (a JSR may write anywhere, so the caller-side scan must decline across it).
    put(0xE230, [0x60])                     # RTS

    # CallerF ($E240): the intervening-call control -- establishes select=7/prg_mode=1
    # itself (same idiom as CallerE), then is otherwise identical to CallerE except a JSR
    # to Harmless sits between the store and the JSR to H2. That breaks
    # forwardedStoreValue's straight-line/no-call requirement, so the $0720 store cannot
    # be attributed across the call. Expect a WARNING at the JSR $E210 (E24D), not a value
    # (no r7=5 claim).
    put(0xE240, [0xA9, 0x47])              # LDA #$47 (select=7, prg_mode=1 -- fixture idiom)
    put(0xE242, [0x8D, 0x00, 0x80])        # STA $8000 (select=7, prg_mode=1 known)
    put(0xE245, [0xA9, 0x05])              # LDA #$05 (5)
    put(0xE247, [0x8D, 0x20, 0x07])        # STA $0720 (the argument cell)
    put(0xE24A, [0x20, 0x30, 0xE2])        # JSR $E230 (Harmless) -- breaks the forward scan
    put(0xE24D, [0x20, 0x10, 0xE2])        # JSR $E210 (H2) -> select=7/prg_mode=1 known,
                                             # r7 UNKNOWN -- WARNING, no "bank ->" for r7
    put(0xE250, [0x60])                     # RTS

    # H3 ($E260) -- moved from $E250 because CallerF now runs through $E250: the
    # self-written-cell control -- same shape as H2, EXCEPT the decoy write lands on
    # $0720 itself (not $0721), so H3 both writes and reads the same cell.
    # inboundArgumentCell's `written` set exists precisely to catch this and decline the
    # cell, so the CALLER's byte is never attributed. What remains is H3's own $47, which
    # valueSuppliedInsideHelper then recovers correctly -- and r7 = 0x47 & 0x3F = 7 is the
    # TRUTH here, because H3 really does write $47 to $8001. The wrong answer to guard
    # against is r7=5, the caller's dead byte -- and 5 is a real bank here, so that wrong
    # answer would be annotated rather than suppressed by the out-of-range guard.
    put(0xE260, [0xA9, 0x47])              # LDA #$47 (select=7, prg_mode=1 -- constant)
    put(0xE262, [0x8D, 0x20, 0x07])        # STA $0720 (SELF-writes the cell it reads below)
    put(0xE265, [0x8D, 0x00, 0x80])        # STA $8000 (select=7, prg_mode=1 known)
    put(0xE268, [0xAD, 0x20, 0x07])        # LDA $0720 (reads back H3's OWN $47, not the
                                             # caller's byte)
    put(0xE26B, [0x8D, 0x01, 0x80])        # STA $8001 (data write -- r7=7 is correct here;
                                             # r7=5 would be the caller's dead byte)
    put(0xE26E, [0x60])                     # RTS

    # CallerG ($E280) -- moved from $E260: establishes select=7/prg_mode=1 itself (same
    # idiom as CallerE/F), then mirrors CallerE's store shape (same $05) so the only
    # variable between this scenario and CallerE's is H3 vs. H2 -- which is what makes
    # the difference in outcome attributable to the self-written cell rather than to the
    # caller. CallerG's own $0720 write is dead: H3 overwrites it before reading it back.
    # 5 is a REAL bank here, so a wrong attribution would be ANNOTATED rather than caught
    # by the out-of-range guard -- which is what makes this a control and not a formality.
    # Expect r7=7 (H3's own byte), and specifically NOT r7=5, at the JSR $E260 (E28A).
    put(0xE280, [0xA9, 0x47])              # LDA #$47 (select=7, prg_mode=1 -- fixture idiom)
    put(0xE282, [0x8D, 0x00, 0x80])        # STA $8000 (select=7, prg_mode=1 known)
    put(0xE285, [0xA9, 0x05])              # LDA #$05 (5, but H3 never sees it)
    put(0xE287, [0x8D, 0x20, 0x07])        # STA $0720 (dead store -- H3 overwrites this)
    put(0xE28A, [0x20, 0x60, 0xE2])        # JSR $E260 (H3) -> r7=7, never r7=5
    put(0xE28D, [0x60])                     # RTS

    # Vector table.
    put(0xFFFA, [0x18, 0xE0])  # NMI   -> $E018 (RTI)
    put(0xFFFC, [0x00, 0xE0])  # RESET -> $E000
    put(0xFFFE, [0x18, 0xE0])  # IRQ   -> $E018 (RTI)

    return bytes(prg)


class _Asm:
    """Tiny sequential 6502 assembler over a bytearray, used only by
    make_prg_serial() (bead grm-hsv.1): tracks its own CPU address so instruction
    offsets don't have to be hand-counted the way the other fixtures above do --
    this fixture has too many same-shaped chain instructions for that to stay
    readable/correct by hand. put(addr, data) below (module-level helper reused
    by the older fixtures) is the same idea; this class just automates the
    CPU-address bookkeeping for a long straight-line stream."""

    def __init__(self, prg, base_cpu, base_file):
        self.prg = prg
        self.base_cpu = base_cpu
        self.base_file = base_file
        self.cpu = base_cpu

    def label(self):
        return self.cpu

    def _emit(self, data):
        off = self.base_file + (self.cpu - self.base_cpu)
        self.prg[off:off + len(data)] = bytes(data)
        self.cpu += len(data)

    def lda_imm(self, v):
        self._emit([0xA9, v & 0xFF])

    def lda_zp(self, addr):
        self._emit([0xA5, addr & 0xFF])

    def sta_zp(self, addr):
        self._emit([0x85, addr & 0xFF])

    def ldx_imm(self, v):
        self._emit([0xA2, v & 0xFF])

    def ldy_imm(self, v):
        self._emit([0xA0, v & 0xFF])

    def dey(self):
        self._emit([0x88])

    def bne(self, target):
        rel = target - (self.cpu + 2)
        assert -128 <= rel <= 127, "BNE target out of range"
        self._emit([0xD0, rel & 0xFF])

    def sta_abs(self, addr):
        self._emit([0x8D, addr & 0xFF, (addr >> 8) & 0xFF])

    def lsr_a(self):
        self._emit([0x4A])

    def inc_abs(self, addr):
        self._emit([0xEE, addr & 0xFF, (addr >> 8) & 0xFF])

    def jsr(self, addr):
        self._emit([0x20, addr & 0xFF, (addr >> 8) & 0xFF])

    def jmp(self, addr):
        self._emit([0x4C, addr & 0xFF, (addr >> 8) & 0xFF])

    def lda_absx(self, addr):
        self._emit([0xBD, addr & 0xFF, (addr >> 8) & 0xFF])

    def pha(self):
        self._emit([0x48])

    def pla(self):
        self._emit([0x68])

    def rti(self):
        self._emit([0x40])

    def rts(self):
        self._emit([0x60])

    def chain5(self, addr):
        """Emits the fully-unrolled STA/LSR commit chain (5 stores, 4 shifts --
        see machines/nes-serialtest.yaml / SerialShiftBankSwitchStrategy) to
        `addr`; returns the 5 STA instructions' addresses (index 4 = the commit,
        write 5)."""
        addrs = []
        for i in range(5):
            addrs.append(self.label())
            self.sta_abs(addr)
            if i < 4:
                self.lsr_a()
        return addrs


def make_prg_serial():
    """SerialShiftBankSwitchStrategy end-to-end fixture (bead grm-hsv.1) for the
    SYNTHETIC machines/nes-serialtest.yaml board (iNES mapper 222). banking.state is
    mirroring(2)+prg_mode(2)+prg_bank(5), one serial-shift mechanism over the whole
    $8000-$FFFF register range, targets {0: mirroring+prg_mode (Control), 3: prg_bank},
    reset -> prg_mode=3. RESET runs entirely inside the fixed WC000 window (prg_mode
    stays 3/fix-last throughout -- W8000 switches on prg_bank, WC000 = PRG[last] =
    bank 7 = home, so file offset equals CPU address there, as in the other fixtures).

    Eight scenarios, run back-to-back (bead grm-hsv.1's F-* criteria, plus grm-4kc's):
      F-reset:        LDA #$80 / STA $8000 -- bit-7 reset; prg_mode=3 known (idempotent
                       re-assertion of the seeded initial state).
      F-unrolled:     LDA #$05 then the 5x STA/LSR chain to $E000 (canonical PRG target
                       address) -- commits prg_bank=5; JSR $8000 retargets into the
                       bank-5 overlay (W8000_M3_B5, since W8000 is mode-varying and
                       prg_mode=3 is this board's home mode).
      F-noncanonical: LDA #$06 then the chain to $FFF9 -- SAME target (PRG, bits 14:13
                       of $FFF9 == bits 14:13 of $E000) via a non-canonical in-window
                       address (FF1's exact trick) -- commits prg_bank=6; JSR $8000
                       retargets into W8000_M3_B6.
      F-chr-discard:  LDA #$AA then a chain to $A000 (CHR0, target 1 -- no `targets`
                       entry) between the two PRG operations above and the next JSR --
                       recognized, discarded; the following JSR $8000 still retargets to
                       W8000_M3_B6, proving prg_bank survived.
      F-loop:         the counted-loop idiom (the SECONDARY recognizer -- the wiki-
                       canonical form no surveyed commercial game uses): LDA #$03 /
                       LDY #$05 / loop: STA $E000 / LSR A / DEY / BNE loop -- the commit
                       (prg_bank=3) attaches to the BNE itself (computeSwitch matches the
                       branch; no engine hook -- see SerialShiftBankSwitchStrategy's
                       javadoc), the in-loop STA is suppressed (echo, no poison), and the
                       JSR $8000 after the loop retargets into W8000_M3_B3.
      F-unresolvable: LDX #$00 / LDA $C200,X (opaque, indexed) feeding a chain to $E000
                       -- write 1's own bit 7 can't be resolved (the scanner doesn't
                       model LDA<indexed>) -> honest poison/WARNING at write 1; write 5's
                       target is still known (address-derived) but its VALUE degrades to
                       unknown -- no false "bank ->" claim anywhere in the chain.
      F-partial-bit7: LDX #$01 / LDA $C200,X feeding a single, non-chained STA $8000 --
                       bit 7 unresolvable -> poison/WARNING, and critically NOT
                       misclassified as a confident reset (no false prg_mode=3 claim).
      F-rmw-reset:    INC <its own address> -- the self-modifying reset idiom (bionic's
                       RESET, $FFE1: EE E1 FF  INC $FFE1). A read-modify-write into the
                       register range used to poison unconditionally, because
                       storeRegister() knows only STA/STX/STY; but the byte it reads is
                       its own $EE opcode -- knowable by SELF-REFERENCE, with no
                       memory-map reasoning, since whichever bank is mapped the byte read
                       is the one the CPU just fetched as this opcode. Bit 7 set -> reset
                       -> prg_mode=3. Placed immediately after F-partial-bit7 so it
                       restores prg_mode from UNKNOWN rather than re-asserting a known 3.

    Vectors: RESET -> the chain above; NMI/IRQ -> a lone RTI right after the idle loop.
    """
    prg = bytearray([0x00] * SERIAL_PRG_SIZE)

    for bank in range(SERIAL_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank  # bank marker, matching the other fixtures

    # JSR $8000 targets: banks 3 (F-loop), 5, and 6, each an RTS at their window-local
    # offset 0 (replacing the marker byte, as in nesmodetest/nesmmc3test).
    prg[3 * PRG_BANK_SIZE] = 0x60
    prg[5 * PRG_BANK_SIZE] = 0x60
    prg[6 * PRG_BANK_SIZE] = 0x60

    # Bank 7 == PRG[last] == the fixed WC000 window (prg_mode=3, this board's home mode);
    # file offset equals CPU address there (bank7_base == 0xC000... no: WC000 is 16 KiB
    # at CPU $C000, and bank 7's FILE offset is 7*0x4000 = 0x1C000, so CPU $C000+x maps to
    # file 0x1C000+x -- the asm helper's base_file/base_cpu pair encodes that translation).
    bank7_base = 7 * PRG_BANK_SIZE

    def put7(cpu_addr, data):
        off = bank7_base + (cpu_addr - 0xC000)
        prg[off:off + len(data)] = bytes(data)

    asm = _Asm(prg, 0xC000, bank7_base)

    labels = {}
    labels['reset'] = asm.label()
    asm.lda_imm(0x80)
    labels['f_reset'] = asm.label()
    asm.sta_abs(0x8000)                      # F-reset: bit-7 set -> prg_mode=3 known

    asm.lda_imm(0x05)
    unrolled = asm.chain5(0xE000)            # F-unrolled: canonical PRG target
    labels['f_unrolled_write1'] = unrolled[0]
    labels['f_unrolled_commit'] = unrolled[4]
    labels['f_unrolled_jsr'] = asm.label()
    asm.jsr(0x8000)

    asm.lda_imm(0x06)
    noncanon = asm.chain5(0xFFF9)            # F-noncanonical: same target, odd address
    labels['f_noncanonical_commit'] = noncanon[4]
    labels['f_noncanonical_jsr'] = asm.label()
    asm.jsr(0x8000)

    asm.lda_imm(0xAA)
    chrdiscard = asm.chain5(0xA000)          # F-chr-discard: CHR0, recognized/discarded
    labels['f_chr_discard_commit'] = chrdiscard[4]
    labels['f_chr_discard_jsr'] = asm.label()
    asm.jsr(0x8000)

    # F-loop: the counted-loop idiom (secondary recognizer; see module doc).
    asm.lda_imm(0x03)                        # seed: prg_bank 3
    labels['f_loop_counter'] = asm.label()
    asm.ldy_imm(0x05)                        # trip count 5
    labels['f_loop_head'] = asm.label()
    asm.sta_abs(0xE000)                      # in-loop STA (suppressed: echo, no poison)
    asm.lsr_a()
    asm.dey()
    labels['f_loop_bne'] = asm.label()
    asm.bne(labels['f_loop_head'])           # the commit site (prg_bank=3)
    labels['f_loop_jsr'] = asm.label()
    asm.jsr(0x8000)                          # -> W8000_M3_B3::8000

    asm.ldx_imm(0x00)
    labels['f_unresolvable_load'] = asm.label()
    asm.lda_absx(0xC200)                     # opaque indexed load -- unresolvable seed
    unresolvable = asm.chain5(0xE000)        # F-unresolvable
    labels['f_unresolvable_write1'] = unresolvable[0]
    labels['f_unresolvable_commit'] = unresolvable[4]

    asm.ldx_imm(0x01)
    labels['f_partial_load'] = asm.label()
    asm.lda_absx(0xC200)                     # opaque indexed load, reused table
    labels['f_partial_write'] = asm.label()
    asm.sta_abs(0x8000)                      # F-partial-bit7: isolated, not chained

    # F-rmw-reset (bead grm-4kc): the self-modifying reset idiom, transcribed in shape from
    # Bionic Commando's RESET ($FFE1: EE E1 FF  INC $FFE1). Deliberately placed HERE, directly
    # after F-partial-bit7 -- that scenario poisons all three fields, so this reset is visibly
    # restoring prg_mode from UNKNOWN to a known 3 rather than idempotently re-asserting a
    # value that was already known, which is what it would be anywhere else in this fixture.
    labels['f_rmw_reset'] = asm.label()
    asm.inc_abs(labels['f_rmw_reset'])       # INC <itself>: reads its own $EE opcode -> $EF

    labels['idle'] = asm.label()
    asm.jmp(labels['idle'])                  # idle loop, in the fixed home WC000 window
    labels['rti'] = asm.label()
    asm.rti()                                # NMI/IRQ handler

    # Unrelated data table backing the two "unresolvable" indexed loads above.
    put7(0xC200, [0x11, 0x22])

    # Vector table.
    put7(0xFFFA, [labels['rti'] & 0xFF, (labels['rti'] >> 8) & 0xFF])
    put7(0xFFFC, [labels['reset'] & 0xFF, (labels['reset'] >> 8) & 0xFF])
    put7(0xFFFE, [labels['rti'] & 0xFF, (labels['rti'] >> 8) & 0xFF])

    return bytes(prg), labels


def make_prg_mmc1():
    """SerialShiftBankSwitchStrategy end-to-end fixture for the REAL machines/nes-mmc1.yaml
    board (bead grm-hsv.2, iNES mapper 1). Metroid-shaped (128 KiB, 8 x 16 KiB banks; see
    scratchpad's mmc1-idioms.md ground-truth survey of Zelda1/FF1/Metroid), and -- unlike
    nesserialtest.nes's chain5()-inline-in-caller shapes -- built around a genuine JSR'd
    SWITCH HELPER subroutine (the dominant real-world idiom every surveyed game uses: a
    fully unrolled 5x STA/LSR chain reached via JSR, never inlined at the call site), so
    this fixture is what actually exercises BoardBankAnalyzer.findHelpers/
    recoverCallArgument for SerialShiftBankSwitchStrategy -- nesserialtest never did,
    since every one of its chains lived directly in the caller.

    banking.state is mirroring(2)+prg_mode(2)+prg_bank(5), matching nes-serialtest.yaml
    exactly; nes-mmc1.yaml's one difference is byte-accurate 32K-mode (prg_mode 0/1)
    addressing via the new `>>` maps: operator (bead grm-hsv.2) -- not exercised by this
    fixture, which stays in prg_mode 3 (fix-last, home) and prg_mode 2 (fix-first) only,
    the two modes real MMC1 games actually run PRG switches in.

    RESET runs entirely inside the fixed-last WC000 window (prg_mode=3, the reset-dance
    convention/this board's home mode) until the deliberate mode-2 transition near the
    end. PRG is 8 x 16 KiB banks; bank 7 == PRG[last] == WC000's home content, so CPU
    $C000+x equals file offset (bank 7 base)+x throughout -- the asm objects below encode
    that translation the same way nesserialtest's did.

    Six separate code regions (six `_Asm` instances sharing one `prg` buffer):
      main   @ $C000: RESET flow -- reset dance, two helper-mediated PRG switches with a
             CHR chain sandwiched between them, the three relay/mid-body call sites, the
             prg_mode->2 transition, and the unresolvable-value call site.
      helper @ $C200: SwitchBank -- the shared 5x STA/LSR chain to $E000 (canonical PRG
             target address, register bits 14:13 of $E000 == target 3), ending RTS. Every
             PRG switch in `main` reaches this ONE subroutine via JSR, Zelda1/FF1/Metroid-
             style (LDA #imm / JSR SwitchBank) -- this is what makes findHelpers see a
             call site rather than an inline chain.
      shadow @ $C250: the grm-nju two-convention helper -- `LDA $65` then the same chain.
      saver  @ $C2A0: the grm-mu7 save/restore helper -- `PHA / LDA #$01 / STA $0103 / PLA`
             then the same chain. Castlevania 2's FUN_c187 byte for byte: the prologue
             clobbers the argument register and then puts it back, so the argument DOES
             reach the chain and the call must resolve. It is the shadow helper's opposite
             number, and the pair is what forces the guard to distinguish a clobber that
             loses the argument from one that does not.
      relay  @ $C280: two 3-byte jump-table slots, one per grm-nju idiom (see below).
      target @ $C300: a lone RTS -- the JSR target that must retarget into the mode-2
             layout's switchable WC000 overlay after the transition (see below).

    THE grm-nju IDIOMS (call sites 5-7, transcribed in shape from Bionic Commando, whose
    every bank switch routes through a jump table and which resolved ZERO bank values
    before this). A call's flow target is not always where control lands:

      $C280  JMP $C200   -- targets a function ENTRY, so Ghidra types it thunk_FUN_c200.
                            The thunk is a different Function than the helper, so a
                            helper map keyed on Function missed it.
      $C283  JMP $C250   -- likewise a thunk, to the shadow helper's own entry.
      $C286  JMP $C252   -- targets MID-BODY, so Ghidra cannot type it a thunk and leaves
                            it an ordinary one-instruction function. It is not the helper
                            and contains no switch site, so the map missed it too.

    Both misses were SILENT: calledHelper returned null and runDataflow folded the call as
    a no-op on bank state -- neither an annotation nor a warning. The shadow helper exists
    to make $C252 genuinely mid-body: its $C250 prologue reloads the bank from RAM, so the
    function has two argument conventions (entering at $C250 ignores A; entering at $C252
    takes the bank in A), and only the second is the one the relay uses.

      LDA #$03 / JSR $C280  -- call site 5: resolves prg_bank=3 through the thunk form.
      JSR $8000             -- -> W8000_M3_B3::8000, proving the reference retarget too.
      JSR $C283             -- call site 6: the shadow helper's OWN entry, where the bank
                               comes from $65 and A is stale. Must DECLINE with a warning:
                               reaching a helper is not the same as knowing its argument.
                               Recovering this one needs cross-function store forwarding
                               and belongs to grm-mej.3, not here.
      LDA #$04 / JSR $C286  -- call site 7: resolves prg_bank=4 through the mid-body form.
      JSR $8000             -- -> W8000_M3_B4::8000.
      LDA #$06 / JSR $C283  -- call site 8 (bead grm-mu7): the shadow helper's own entry
                               a second time, now with a KNOWN bank in A. Must decline
                               too -- the prologue clobbers A before the chain reads it,
                               so the caller's value is not the helper's argument no
                               matter how well the scan resolved it. Site 6's twin, and
                               the only one of the two that can tell the prologue check
                               apart from "the scan found nothing".

    RESET ($C000, seed prg_mode=3/prg_bank=0/mirroring=0):
      LDA #$80 / STA $8000             -- reset dance: bit-7 write, prg_mode forced 3
                                           (home, idempotent re-assertion of the seed).
      LDA #$02 / JSR SwitchBank        -- call site 1 (helper argReg='A'): commits
                                           prg_bank=2 via the shared helper.
      JSR $8000                        -- retargets to W8000_M3_B2::8000 (mode3 is home;
                                           bank 2 is non-home -> _M3_B2 overlay).
      LDA #$AA + a 5x STA/LSR chain to $A000 (CHR0, target 1, no `targets` entry -- same
                                           no-poison contract nesserialtest's F-chr-discard
                                           exercises): recognized, discarded; prg_bank must
                                           SURVIVE, proven by the next switch below.
      LDA #$05 / JSR SwitchBank        -- call site 2 (SAME helper, different immediate):
                                           commits prg_bank=5.
      JSR $8000                        -- retargets to W8000_M3_B5::8000 (bank 5 also
                                           non-home for W8000 -> _M3_B5 overlay). If
                                           prg_bank had been clobbered by the CHR chain,
                                           this would retarget somewhere else or fail --
                                           this JSR is therefore also indirect proof the
                                           CHR write stayed a no-op on prg_bank.
      LDA #$07 / JSR SwitchBank        -- call site 3 (SAME helper, third immediate,
                                           deliberately == `last`): commits prg_bank=7 --
                                           see the mode-2 design note below for why 7. NOT
                                           followed by a JSR $8000 (unlike sites 1/2): bank
                                           7 IS the fixed-last bank WC000's home window
                                           already shows, i.e. this fixture's own running
                                           code -- a JSR $8000 here would dual-map into
                                           RESET itself rather than a clean routine, which
                                           is not the retargeting shape this call site is
                                           for (it exists purely to stage prg_bank=7 ahead
                                           of the mode flip).
      LDA #$08 + a 5x STA/LSR chain to $8000 (Control, target 0): commits mirroring=0,
                                           prg_mode=2 (fix-first) -- the mode transition.
      JSR $C300                        -- retargets to WC000_M2_B7::C300 (see design note).
      LDX #$00 / LDA $C400,X / JSR SwitchBank -- call site 4: an opaque indexed load (the
                                           scanner does not model indexed addressing, same
                                           as nesserialtest's F-unresolvable) feeds the SAME
                                           helper's argReg='A'. recoverCallArgument's
                                           backward scan for A fails to resolve -> honest
                                           WARNING bookmark, no false "bank ->" claim --
                                           the Metroid-mailbox analog for the *call-site*
                                           value-recovery path specifically (nesserialtest's
                                           F-unresolvable exercised the same failure mode
                                           for an inline chain's own seed, not a helper
                                           call's recovered argument).
      JMP $<self>                      -- idle loop.
      RTI                              -- NMI/IRQ handler.

    Mode-2 transition design (the control-flow-discipline puzzle the bead's brief calls
    out): in prg_mode 3, $8000 switches and $C000 is fixed-last; in prg_mode 2, $8000 is
    fixed-first and $C000 switches -- there is no window fixed in BOTH modes, so code
    physically resident at $C0xx during the transition would normally get its own ground
    pulled out from under it. This fixture sidesteps that by making the SWITCHED WINDOW's
    content identical across the transition instead of avoiding the switched window: call
    site 3 above deliberately commits prg_bank=7, which is also `last` (the same physical
    bank WC000's fixed-last mapping already showed) -- so when the mode-2 chain flips
    prg_mode to 2, WC000 becomes switchable at the CURRENT prg_bank (7), which maps the
    exact same bytes it mapped as the fixed window a moment ago. Every instruction from
    RESET through the post-switch JSR $C300 physically sits in that one never-moving bank
    (which is also why call site 3 above is deliberately NOT followed by a JSR into the
    W8000 window the way sites 1/2 are -- bank 7 IS this running code, not a separate
    routine); the only thing that changes is which *symbolic* window name a reference
    into it resolves through (WC000 before the flip, WC000_M2_B7 after) -- exactly the
    same dual-mapped-bytes pattern nesmmc3test's W8000_M0_B2/WC000_M1_B2 already
    established for MMC3, now reproduced for a mode-dependent-layout mechanism whose
    windows don't share a common fixed anchor the way MMC3's WA000/WE000 do.
    """
    prg = bytearray([0x00] * MMC1_PRG_SIZE)

    for bank in range(MMC1_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank  # bank marker, matching the other fixtures

    # Bank 2/5's JSR targets (W8000_M3_B2::8000 / W8000_M3_B5::8000): RTS, replacing the
    # marker byte, as in nesserialtest/nesmmc3test. Bank 7 is deliberately NOT given a
    # separate RTS here -- it IS this fixture's running code (see the mode-2 design note).
    prg[2 * PRG_BANK_SIZE] = 0x60
    prg[5 * PRG_BANK_SIZE] = 0x60
    # Banks 3 and 4 likewise, for the two grm-nju relay call sites' follow-up JSR $8000.
    prg[3 * PRG_BANK_SIZE] = 0x60
    prg[4 * PRG_BANK_SIZE] = 0x60
    # Bank 1 likewise, for the grm-mu7 save/restore call site's follow-up JSR $8000.
    prg[1 * PRG_BANK_SIZE] = 0x60

    bank7_base = 7 * PRG_BANK_SIZE

    def put7(cpu_addr, data):
        off = bank7_base + (cpu_addr - 0xC000)
        prg[off:off + len(data)] = bytes(data)

    main = _Asm(prg, 0xC000, bank7_base)
    helper = _Asm(prg, 0xC200, bank7_base + 0x200)
    shadow = _Asm(prg, 0xC250, bank7_base + 0x250)
    relay = _Asm(prg, 0xC280, bank7_base + 0x280)
    saver = _Asm(prg, 0xC2A0, bank7_base + 0x2A0)
    target = _Asm(prg, 0xC300, bank7_base + 0x300)

    labels = {}

    # --- helper @ $C200: the shared SwitchBank subroutine (Zelda1/FF1/Metroid idiom) ---
    labels['switch_bank'] = helper.label()
    helper.chain5(0xE000)
    helper.rts()

    # --- shadow helper @ $C250: Bionic Commando's FUN_dca8 shape (bead grm-nju).
    # A prologue that reloads the bank from a RAM shadow, then the same 5x chain. The
    # consequence is that the function has TWO argument conventions: entering at $C250
    # takes the bank from $65 and ignores A entirely, while entering at $C252 -- the
    # chain's first write, which the game reaches by jumping straight there -- takes it
    # in A. Ghidra keeps $C252 mid-body, so a helper model keyed on the containing
    # function can only describe one of the two, and describes it at the wrong entry.
    labels['shadow_entry'] = shadow.label()
    shadow.lda_zp(0x65)
    labels['shadow_midbody'] = shadow.label()
    shadow.chain5(0xE000)
    shadow.rts()

    # --- saver helper @ $C2A0: Castlevania 2's FUN_c187 shape (bead grm-mu7, second
    # increment). A prologue that CLOBBERS the argument register and then puts it back:
    #
    #     PHA / LDA #$01 / STA $0103 / PLA / <the same 5x chain>
    #
    # The `LDA #$01` writes A before the chain's first store, so a guard that asks only
    # "does anything write argReg between entry and the first site" declines here -- and
    # that is exactly what the first version of grm-mu7's guard did, silently destroying
    # three real ROMs (kicarus -215 overlay instrs, dodge -10692, cv2 -2 bank comments)
    # while all 45 synthetic goldens stayed green, because not one of them saved and
    # restored. This helper exists so the SYNTHETIC gate covers the idiom: the real-ROM
    # tier is not part of build-and-test.sh, so it cannot be what protects this.
    labels['saver_entry'] = saver.label()
    saver.pha()
    saver.lda_imm(0x01)
    saver.sta_abs(0x0103)                    # the side effect the argument is saved across
    saver.pla()                              # ...and here it comes back
    saver.chain5(0xE000)
    saver.rts()

    # --- relay table @ $C280: the 3-byte jump-table slots real cartridges route bank
    # switches through (bionic's $D6BB/$D6E2/$D751). Ghidra types the two slots below
    # differently for reasons that have nothing to do with the game: the first targets a
    # function entry and becomes a thunk, the second targets mid-body and stays an
    # ordinary one-instruction function. Both were invisible to the old
    # getFunctionAt-based call-site lookup, and both must now resolve.
    # SLOT ORDER IS LOad-BEARING, and it is bionic's. Ghidra's thunk analysis creates a
    # function at each thunk's DESTINATION, so whichever of $C250/$C252 it reaches first
    # becomes a function entry -- and if that were $C252 there would be no mid-body entry
    # left to model. Bionic wins this race by address order ($D6BB->$DCA8 precedes
    # $D6E2->$DCAA), so the shadow-entry slot is placed below the mid-body slot here for
    # the same reason. VerifyBankTest asserts the resulting shape rather than assuming it.
    labels['relay_to_entry'] = relay.label()
    relay.jmp(labels['switch_bank'])
    labels['relay_to_shadow'] = relay.label()
    relay.jmp(labels['shadow_entry'])
    labels['relay_to_midbody'] = relay.label()
    relay.jmp(labels['shadow_midbody'])

    # --- target @ $C300: the post-mode-switch WC000_M2_B7 JSR target ---
    labels['mode2_target'] = target.label()
    target.rts()

    # --- main @ $C000: RESET flow ---
    labels['reset'] = main.label()
    main.lda_imm(0x80)
    labels['f_reset'] = main.label()
    main.sta_abs(0x8000)                     # reset dance: bit-7 set -> prg_mode=3 known

    labels['call1_imm'] = main.label()
    main.lda_imm(0x02)                       # bank 2
    labels['call1_jsr'] = main.label()
    main.jsr(labels['switch_bank'])          # call site 1 (argReg='A') -> prg_bank=2
    labels['call1_use_jsr'] = main.label()
    main.jsr(0x8000)                         # -> W8000_M3_B2::8000

    main.lda_imm(0xAA)
    chrchain = main.chain5(0xA000)           # CHR0 chain: recognized, discarded
    labels['chr_commit'] = chrchain[4]

    labels['call2_imm'] = main.label()
    main.lda_imm(0x05)                       # bank 5
    labels['call2_jsr'] = main.label()
    main.jsr(labels['switch_bank'])          # call site 2 (SAME helper) -> prg_bank=5
    labels['call2_use_jsr'] = main.label()
    main.jsr(0x8000)                         # -> W8000_M3_B5::8000

    # --- the three grm-nju call sites, all before the mode flip (prg_mode still 3, so
    # W8000 is the switchable window and the follow-up JSRs retarget through it). They
    # sit here rather than after the flip so the bank-7 staging immediately below still
    # runs last, leaving the mode-2 transition narrative exactly as it was. ---
    labels['relay_entry_imm'] = main.label()
    main.lda_imm(0x03)                       # bank 3, passed in A
    labels['relay_entry_jsr'] = main.label()
    main.jsr(labels['relay_to_entry'])       # call site 5: JSR -> relay -> SwitchBank
    labels['relay_entry_use_jsr'] = main.label()
    main.jsr(0x8000)                         # -> W8000_M3_B3::8000, proving the retarget

    # Call site 6: the shadow helper's OWN entry, reached through its own relay slot. The
    # bank comes from $65, not from A, and A here is whatever the JSR above left --
    # unknown. It must decline with an honest WARNING rather than attribute a stale
    # register. It is ALSO what gives the fixture its shape: this is the thunk whose
    # destination Ghidra turns into FUN_C250 with a body spanning $C252, which is what
    # leaves $C252 a mid-body address rather than a function of its own. It therefore
    # comes BEFORE the mid-body call site, as it does in bionic.
    labels['shadow_jsr'] = main.label()
    main.jsr(labels['relay_to_shadow'])      # -> prg_bank unknown (poisoned)

    labels['relay_mid_imm'] = main.label()
    main.lda_imm(0x04)                       # bank 4, passed in A
    labels['relay_mid_jsr'] = main.label()
    main.jsr(labels['relay_to_midbody'])     # call site 7: JSR -> relay -> $C252 mid-body
    labels['relay_mid_use_jsr'] = main.label()
    main.jsr(0x8000)                         # -> W8000_M3_B4::8000, proving the retarget

    # Call site 9 (bead grm-mu7, second increment): the SAVE/RESTORE helper. Its prologue
    # clobbers A and then restores it across the stack, so the argument really does reach
    # the chain and this MUST resolve -- it is call site 8's opposite number. Together the
    # two pin the distinction the guard has to draw: site 8 clobbers and never restores
    # (decline), site 9 clobbers and restores (resolve). A guard that only asks "was argReg
    # written" cannot tell them apart, and answers site 9 wrong.
    #
    # Placed BEFORE site 8 on purpose: site 8's honest poison has to be the last thing to
    # touch prg_bank before call site 3, or M14b's downstream-propagation check loses the
    # very unknown it asserts.
    labels['saver_imm'] = main.label()
    main.lda_imm(0x01)                       # bank 1, saved and restored by the helper
    labels['saver_jsr'] = main.label()
    main.jsr(labels['saver_entry'])          # call site 9 -> prg_bank=1, NOT declined
    labels['saver_use_jsr'] = main.label()
    main.jsr(0x8000)                         # -> W8000_M3_B1::8000, proving the retarget

    # Call site 8 (bead grm-mu7): the shadow helper's OWN entry AGAIN, but this time with
    # a KNOWN bank in A. It is call site 6's A/B twin and the only one of the pair that
    # can prove WHY the engine declines.
    #
    # Site 6 declines with A unknown, so its decline is equally explained by "the backward
    # scan found nothing" -- the same reason M9 already covers. This one leaves A fully
    # known, in range, and otherwise unused by the fixture, so the scan succeeds and the
    # ONLY remaining reason to decline is the prologue clobber itself: $C250's `LDA $65`
    # overwrites A before the chain that reads it. Before grm-mu7 nothing checked that,
    # and this call site reported a confident prg_bank=6 -- a WRONG bank, which this
    # engine rates strictly worse than no bank, since findHelpers necessarily takes
    # argReg='A' from the chain's STA and cannot see that the prologue got there first.
    #
    # Placed here, between site 7's follow-up JSR and the bank-7 staging below, so the
    # honest poison it deposits is immediately overwritten by call site 3's known
    # prg_bank=7 and cannot reach the mode-2 transition's narrative.
    #
    # One deliberate side effect of that placement: call site 3's JSR now runs with
    # prg_bank unknown on entry, so the bank-requirement scan flags it -- an extra WARNING
    # bookmark at $C044 that sits alongside its own fully-resolved prg_bank=7 annotation.
    # That is kept rather than designed around, because it proves the decline PROPAGATES
    # instead of merely suppressing a comment; VerifyBankTest's M14b pins it, and explains
    # both why it lands there and why the requirement itself is imprecise (grm-izu).
    labels['clobber_imm'] = main.label()
    main.lda_imm(0x06)                       # a KNOWN bank the helper must NOT believe
    labels['clobber_jsr'] = main.label()
    main.jsr(labels['relay_to_shadow'])      # -> prg_bank unknown (honest poison), NOT 6

    labels['call3_imm'] = main.label()
    main.lda_imm(0x07)                       # bank 7 (== last; see mode-2 design note)
    labels['call3_jsr'] = main.label()
    main.jsr(labels['switch_bank'])          # call site 3 (SAME helper) -> prg_bank=7
                                              # (no follow-up JSR $8000 -- see design note)

    main.lda_imm(0x08)                       # mirroring=0, prg_mode=2 (fix-first)
    modechain = main.chain5(0x8000)          # Control (target 0) chain
    labels['mode_commit'] = modechain[4]
    labels['mode2_jsr'] = main.label()
    main.jsr(labels['mode2_target'])         # -> WC000_M2_B7::C300 (post-switch)

    main.ldx_imm(0x00)
    labels['unresolvable_load'] = main.label()
    main.lda_absx(0xC400)                    # opaque indexed load -- unresolvable seed
    labels['unresolvable_jsr'] = main.label()
    main.jsr(labels['switch_bank'])          # call site 4 -> recoverCallArgument fails

    labels['idle'] = main.label()
    main.jmp(labels['idle'])                 # idle loop
    labels['rti'] = main.label()
    main.rti()                               # NMI/IRQ handler

    # Unrelated data table backing the unresolvable indexed load above.
    put7(0xC400, [0x33, 0x44])

    # Vector table.
    put7(0xFFFA, [labels['rti'] & 0xFF, (labels['rti'] >> 8) & 0xFF])
    put7(0xFFFC, [labels['reset'] & 0xFF, (labels['reset'] >> 8) & 0xFF])
    put7(0xFFFE, [labels['rti'] & 0xFF, (labels['rti'] >> 8) & 0xFF])

    return bytes(prg), labels


def make_prg_mmc1_override():
    """Placement-override + provenance fixture for machines/nes-mmc1.yaml (bead grm-hsv.3).

    Proves the two halves of the user bank-placement override the loader accepts as
    `-loader-placement W8000:5` (window:bank; colon separator, not '=' -- cmd.exe's
    analyzeHeadless.bat splits arg values on '=') and BoardBankAnalyzer applies:
      1. OVERRIDE FIRES where dataflow left the switchable bank unknown -- a JSR $8000
         after an *unresolvable* prg_bank commit retargets into W8000_M3_B5 (the pinned
         bank), tagged "[user override]", instead of the home-bank fallback.
      2. FLOW WINS over the override where dataflow DID recover the bank -- a later JSR
         $8000 after a KNOWN prg_bank=3 commit retargets into W8000_M3_B3 (not the pinned
         B5); the override is inert, no "[user override]" tag.

    All in prg_mode 3 (home). The reset dance makes the whole state known (prg_mode=3,
    prg_bank=0, mirroring=0 -- same as nesmmc1test's M1), so an *unresolvable* switch is
    needed to drive prg_bank genuinely unknown: an opaque indexed load (LDA $C400,X --
    recoverCallArgument/StoredValueScanner does not model indexed addressing) seeds the
    unrolled commit chain, exactly nesserialtest's F-unresolvable / nesmmc1test's call-4
    idiom, but here for an INLINE chain's own seed. Main runs entirely in the fixed-last
    WC000 window (bank 7 == PRG[last]); banks 3 and 5 hold a lone RTS at offset 0 so the
    two retargeted JSR targets disassemble.

    RESET ($C000, seed prg_mode=3/prg_bank=0/mirroring=0):
      C000 LDA #$80 / C002 STA $8000   -- reset dance: whole state known ([switch-value flow]).
      C005 LDX #$00
      C007 LDA $C400,X                 -- opaque indexed load: A unresolvable.
      C00A chain5($E000)               -- commits prg_bank UNKNOWN (commit STA5 @ C01A).
      C01D JSR $8000                   -- prg_bank unknown -> OVERRIDE -> W8000_M3_B5::8000.
      C020 LDA #$03
      C022 chain5($E000)               -- commits prg_bank=3 KNOWN (commit STA5 @ C032).
      C035 JSR $8000                   -- prg_bank=3 known -> FLOW WINS -> W8000_M3_B3::8000.
      C038 JMP $C038                   -- idle loop.
      C03B RTI                         -- NMI/IRQ handler.
    """
    prg = bytearray([0x00] * MMC1_PRG_SIZE)

    for bank in range(MMC1_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank  # bank marker, matching the other fixtures

    # Banks 3 and 5's JSR targets (W8000_M3_B3::8000 / W8000_M3_B5::8000): lone RTS,
    # replacing the marker byte, as in nesmmc1test's bank 2/5 targets.
    prg[3 * PRG_BANK_SIZE] = 0x60
    prg[5 * PRG_BANK_SIZE] = 0x60

    bank7_base = 7 * PRG_BANK_SIZE

    def put7(cpu_addr, data):
        off = bank7_base + (cpu_addr - 0xC000)
        prg[off:off + len(data)] = bytes(data)

    main = _Asm(prg, 0xC000, bank7_base)
    labels = {}

    labels['reset'] = main.label()
    main.lda_imm(0x80)
    labels['f_reset'] = main.label()
    main.sta_abs(0x8000)                     # reset dance: whole state known

    main.ldx_imm(0x00)
    labels['opaque_load'] = main.label()
    main.lda_absx(0xC400)                    # opaque indexed load -> A unresolvable
    uchain = main.chain5(0xE000)             # commits prg_bank UNKNOWN
    labels['unknown_commit'] = uchain[4]
    labels['override_jsr'] = main.label()
    main.jsr(0x8000)                         # prg_bank unknown -> override -> W8000_M3_B5

    main.lda_imm(0x03)                        # known seed
    fchain = main.chain5(0xE000)             # commits prg_bank=3 KNOWN
    labels['known_commit'] = fchain[4]
    labels['flow_jsr'] = main.label()
    main.jsr(0x8000)                         # prg_bank=3 known -> flow wins -> W8000_M3_B3

    labels['idle'] = main.label()
    main.jmp(labels['idle'])                 # idle loop
    labels['rti'] = main.label()
    main.rti()                               # NMI/IRQ handler

    # Unrelated data table backing the unresolvable indexed load above.
    put7(0xC400, [0x33, 0x44])

    # Vector table.
    put7(0xFFFA, [labels['rti'] & 0xFF, (labels['rti'] >> 8) & 0xFF])
    put7(0xFFFC, [labels['reset'] & 0xFF, (labels['reset'] >> 8) & 0xFF])
    put7(0xFFFE, [labels['rti'] & 0xFF, (labels['rti'] >> 8) & 0xFF])

    return bytes(prg), labels


def make_prg_wrapper():
    """Pass-through-wrapper fixture (bead grm-2dr, increment 1) for the REAL
    machines/nes-mmc1.yaml board (iNES mapper 1) -- same board descriptor as
    make_prg_mmc1(), left byte-identical by this fixture living entirely on its own.

    Exercises BoardBankAnalyzer's new pass-through-wrapper recognition: a function that
    (a) writes no mechanism itself, (b) is a straight run of plain fall-through
    instructions -- no branch, no jump, no JSR, not terminal -- and (c) whose LAST
    instruction falls through exactly into the ENTRY of a real bank-switch helper (or of
    another such wrapper), must now have calls landing on it resolve their bank argument,
    because the argument register survives across the wrapper body into the helper's
    prologue. Two real-ROM shapes motivate this: Castlevania 2's FUN_c183 (STA $1C) ->
    FUN_c185 (LDA $1C) -> FUN_c187 (the MMC1 chain), and TMNT's FUN_cea5 (STA $21) ->
    FUN_cea7 (the chain).

    `nesmmc1test`/`nesuxhelpertest` contain no fallthrough-wrapper shape at all, so a
    prior helper-prologue change (grm-mu7) regressed three real ROMs while all 45
    synthetic goldens stayed green -- this fixture exists to close that coverage gap
    without touching those two (make_prg_mmc1() stays untouched, keeping nesmmc1test.dump
    byte-identical).

    Five contiguous helper/wrapper REGIONS, each its own `_Asm` with an EXPLICIT base
    address chosen so a wrapper's last byte abuts its helper's first byte exactly (the
    whole point of the shape under test), plus `main` (the RESET flow):

      wrap1 @ $C100: single_wrapper (`STA $20`, 2 bytes, preserves A) falls straight into
             single_helper (chain5($E000) + RTS) at $C102 -- the simplest positive case.
      wrap2 @ $C140: outer_wrapper (`STA $21`) falls into inner_wrapper (`LDA $21`) falls
             into helper2 (chain5($E000) + RTS) -- the Castlevania 2 stacked shape, and
             the only real test of the fixpoint (a wrapper falling into ANOTHER wrapper).
      neg1  @ $C180: jsr_pred (`JSR harmless_target` then falls through) -> helper3 --
             negative control: a JSR in the body disqualifies it as a wrapper even though
             it still falls through into a real helper's entry. Pins the boundary the
             increment does NOT cover: blmaster's FUN_e61b reaches its helper via JSR, not
             fallthrough, and stays out of scope.
      harmless @ $C1F0: jsr_pred's harmless JSR target (a lone RTS).
      neg2  @ $C200: rts_pred (`LDA #imm` / `RTS`) is immediately adjacent to helper4 --
             contiguous in address, exactly like the positive cases -- but TERMINAL, so it
             never falls through. Negative control: adjacency alone must not be mistaken
             for the fallthrough shape.

    Every wrapper AND every helper is also reached by a direct JSR of its own (`main`'s
    call sites below), so each gets its own Ghidra Function -- the design depends on
    `getFunctionAt(wrapperEntry)`/`getFunctionAt(helperEntry)` being non-null.

    RESET ($C000, seed prg_mode=3/prg_bank=0/mirroring=0, same reset dance as
    make_prg_mmc1()):
      LDA #$80 / STA $8000             -- reset dance: prg_mode=3 known.

      LDA #$03 / JSR single_wrapper    -- W1: resolves prg_bank=3 through the wrapper.
      JSR $8000                        -- -> W8000_M3_B3::8000, proving the retarget.
      LDA #$06 / JSR single_wrapper    -- W2: SAME wrapper, distinct immediate ->
                                           prg_bank=6, distinguishable from W1.
      JSR $8000                        -- -> W8000_M3_B6::8000.

      LDA #$04 / JSR outer_wrapper     -- W3: the OUTER call of the stacked pair. Must
                                           resolve: `STA $21` then `LDA $21` is a
                                           same-cell save/restore, which the prologue
                                           guard (extended from grm-mu7's stack-based
                                           PHA/PLA case) already models -> prg_bank=4.
      JSR $8000                        -- -> W8000_M3_B4::8000.
      JSR inner_wrapper                -- W4: the INNER call, entering directly at
                                           `LDA $21` with no immediate beforehand. Must
                                           NOT resolve: from this entry point the body is
                                           just `LDA $21` -- an opaque read of an untracked
                                           zero-page shadow, the same category as
                                           nesmmc1test's `LDA $65` shadow helper. Honest
                                           WARNING, no "bank ->" claim.

      LDA #$07 / JSR jsr_pred          -- W6 (negative control 1): the JSR-bodied
                                           predecessor. Must NOT resolve at all -- not
                                           recognized as a wrapper, so the call is
                                           ordinary and untouched by this feature.
      LDA #$01 / JSR rts_pred          -- W7 (negative control 2): the RTS-terminal
                                           predecessor. Must NOT resolve -- terminal, so
                                           it never reaches helper4 by fallthrough despite
                                           sitting immediately next to it.

      LDA #$02 / JSR single_helper     -- fixture integrity: direct call to single_helper
                                           itself (bypassing the wrapper) -- ordinary
                                           helper call, must still resolve prg_bank=2, and
                                           forces single_helper to be its own Function.
      LDA #$05 / JSR helper2           -- likewise for helper2 -> prg_bank=5.
      LDA #$01 / JSR helper3           -- likewise for helper3 -> prg_bank=1 (helper3 is a
                                           genuine helper; only jsr_pred fails to forward
                                           into it).
      LDA #$07 / JSR helper4           -- likewise for helper4 -> prg_bank=7 (helper4 is a
                                           genuine helper; only rts_pred fails to forward
                                           into it).

      JMP $<self>                      -- idle loop.
      RTI                              -- NMI/IRQ handler.
    """
    prg = bytearray([0x00] * MMC1_PRG_SIZE)

    for bank in range(MMC1_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank  # bank marker, matching make_prg_mmc1()

    # JSR $8000 targets for the three RESOLVING wrapper call sites (W1/W2/W3): RTS,
    # replacing the marker byte, as in make_prg_mmc1(). Banks used only by the
    # fixture-integrity direct calls (2, 5, 1, 7) need no RTS -- nothing retargets
    # against them.
    prg[3 * PRG_BANK_SIZE] = 0x60  # W8000_M3_B3::8000 (single wrapper, call A)
    prg[6 * PRG_BANK_SIZE] = 0x60  # W8000_M3_B6::8000 (single wrapper, call B)
    prg[4 * PRG_BANK_SIZE] = 0x60  # W8000_M3_B4::8000 (stacked pair, outer call)

    bank7_base = 7 * PRG_BANK_SIZE

    def put7(cpu_addr, data):
        off = bank7_base + (cpu_addr - 0xC000)
        prg[off:off + len(data)] = bytes(data)

    labels = {}

    # --- wrap1 @ $C100: single forwarding wrapper, contiguous with its helper ---
    wrap1 = _Asm(prg, 0xC100, bank7_base + 0x100)
    labels['single_wrapper'] = wrap1.label()
    wrap1.sta_zp(0x20)                        # writes no mechanism; A survives untouched
    labels['single_helper'] = wrap1.label()   # falls straight through -- addresses abut
    wrap1.chain5(0xE000)
    wrap1.rts()

    # --- wrap2 @ $C140: stacked pair (Castlevania 2 shape), both contiguous ---
    wrap2 = _Asm(prg, 0xC140, bank7_base + 0x140)
    labels['outer_wrapper'] = wrap2.label()
    wrap2.sta_zp(0x21)                        # save A to $21
    labels['inner_wrapper'] = wrap2.label()   # abuts outer_wrapper exactly
    wrap2.lda_zp(0x21)                        # restore A from $21 (round-trips the value)
    labels['helper2'] = wrap2.label()         # abuts inner_wrapper exactly
    wrap2.chain5(0xE000)
    wrap2.rts()

    # --- harmless @ $C1F0: jsr_pred's harmless JSR target (built before neg1 so neg1 can
    # reference its label rather than a bare literal) ---
    harmless = _Asm(prg, 0xC1F0, bank7_base + 0x1F0)
    labels['harmless_target'] = harmless.label()
    harmless.rts()

    # --- neg1 @ $C180: negative control 1 -- a JSR in the body disqualifies it as a
    # wrapper even though it still falls through into a real helper's entry ---
    neg1 = _Asm(prg, 0xC180, bank7_base + 0x180)
    labels['jsr_pred'] = neg1.label()
    neg1.jsr(labels['harmless_target'])       # a JSR -- not a "plain fall-through" body
    labels['helper3'] = neg1.label()          # abuts jsr_pred exactly regardless
    neg1.chain5(0xE000)
    neg1.rts()

    # --- neg2 @ $C200: negative control 2 -- terminal (RTS), so despite sitting
    # immediately next to a real helper it never reaches it by fallthrough ---
    neg2 = _Asm(prg, 0xC200, bank7_base + 0x200)
    labels['rts_pred'] = neg2.label()
    neg2.lda_imm(0x09)                        # arbitrary; this function never forwards it
    labels['rts_pred_rts'] = neg2.label()
    neg2.rts()                                # terminal -- control flow stops here
    labels['helper4'] = neg2.label()          # adjacent in address, NOT in control flow
    neg2.chain5(0xE000)
    neg2.rts()

    # --- main @ $C000: RESET flow ---
    main = _Asm(prg, 0xC000, bank7_base)
    labels['reset'] = main.label()
    main.lda_imm(0x80)
    labels['f_reset'] = main.label()
    main.sta_abs(0x8000)                      # reset dance: prg_mode=3 known

    # W1: single wrapper, call A -- bank 3.
    labels['w1a_imm'] = main.label()
    main.lda_imm(0x03)
    labels['w1a_jsr'] = main.label()
    main.jsr(labels['single_wrapper'])
    labels['w1a_use_jsr'] = main.label()
    main.jsr(0x8000)                          # -> W8000_M3_B3::8000

    # W2: single wrapper, call B -- SAME wrapper, bank 6 (distinct immediate).
    labels['w1b_imm'] = main.label()
    main.lda_imm(0x06)
    labels['w1b_jsr'] = main.label()
    main.jsr(labels['single_wrapper'])
    labels['w1b_use_jsr'] = main.label()
    main.jsr(0x8000)                          # -> W8000_M3_B6::8000

    # W3: stacked pair, OUTER call -- bank 4; must resolve (same-cell save/restore).
    labels['w2_imm'] = main.label()
    main.lda_imm(0x04)
    labels['w2_jsr'] = main.label()
    main.jsr(labels['outer_wrapper'])
    labels['w2_use_jsr'] = main.label()
    main.jsr(0x8000)                          # -> W8000_M3_B4::8000

    # W4: stacked pair, INNER call -- no immediate; must NOT resolve (untracked shadow).
    labels['w3_jsr'] = main.label()
    main.jsr(labels['inner_wrapper'])

    # W6 (negative control 1): JSR-bodied predecessor; must NOT resolve at all.
    labels['w4_imm'] = main.label()
    main.lda_imm(0x07)
    labels['w4_jsr'] = main.label()
    main.jsr(labels['jsr_pred'])

    # W7 (negative control 2): RTS-terminal predecessor; must NOT resolve at all.
    labels['w5_imm'] = main.label()
    main.lda_imm(0x01)
    labels['w5_jsr'] = main.label()
    main.jsr(labels['rts_pred'])

    # Fixture integrity: direct JSRs to every helper's OWN entry (bypassing the
    # wrapper/negative-control predecessor above it), so each becomes its own Ghidra
    # Function and resolves normally as an ordinary helper call.
    labels['direct1_imm'] = main.label()
    main.lda_imm(0x02)
    labels['direct1_jsr'] = main.label()
    main.jsr(labels['single_helper'])
    labels['direct2_imm'] = main.label()
    main.lda_imm(0x05)
    labels['direct2_jsr'] = main.label()
    main.jsr(labels['helper2'])
    labels['direct3_imm'] = main.label()
    main.lda_imm(0x01)
    labels['direct3_jsr'] = main.label()
    main.jsr(labels['helper3'])
    labels['direct4_imm'] = main.label()
    main.lda_imm(0x07)
    labels['direct4_jsr'] = main.label()
    main.jsr(labels['helper4'])

    labels['idle'] = main.label()
    main.jmp(labels['idle'])                  # idle loop
    labels['rti'] = main.label()
    main.rti()                                # NMI/IRQ handler

    # Vector table.
    put7(0xFFFA, [labels['rti'] & 0xFF, (labels['rti'] >> 8) & 0xFF])
    put7(0xFFFC, [labels['reset'] & 0xFF, (labels['reset'] >> 8) & 0xFF])
    put7(0xFFFE, [labels['rti'] & 0xFF, (labels['rti'] >> 8) & 0xFF])

    return bytes(prg), labels


def make_prg_relay():
    """Call-edge-wrapper fixture (bead grm-2dr, increment 2) for the REAL
    machines/nes-mmc1.yaml board (iNES mapper 1).

    A SEPARATE ROM from neswrappertest.nes on purpose, for the same reason that one is
    separate from nesmmc1test.nes: `neswrappertest.dump` staying byte-identical is the
    proof that increment 2 did not disturb increment 1's pass-through recognition, and
    extending it would destroy exactly that signal.

    Exercises BoardBankAnalyzer.findCallEdgeWrappers: a function that (a) writes no
    mechanism itself, (b) reaches a real bank-switch helper by an interior JSR rather
    than by falling through into it, (c) makes exactly ONE such call, and (d) reaches
    that call unconditionally with the caller's argument register intact, must now have
    calls landing on IT resolve their bank argument. blmaster's FUN_e61b is the real-ROM
    shape: `STA $DB` on entry, A reloaded from that shadow, then `$e627 JSR $e63c` into
    the MMC1 chain -- twelve call sites, none of them recovered before this.

    ADMISSION NEEDS TWO GATES AND THE NEGATIVE CONTROLS BELOW PIN BOTH SEPARATELY,
    because neither subsumes the other. `branch_pred` is the important one: a branch does
    NOT make argumentSurvivesPrologue decline (a nonzero getFlows() only clears its
    straight-line state and the walk continues), so a prefix that branches around the
    relay but never touches A passes the VALUE gate and must be rejected by the
    STRUCTURAL one (isPassThroughInto over the prefix).

    Regions, each its own `_Asm` with an explicit base address. Unlike
    make_prg_wrapper()'s, these do NOT need to abut -- the relay is a JSR, so the helpers
    live in their own block:

      relay_wrapper @ $C100: `STA $22` / `LDA $22` / `JSR relay_helper` / `RTS` -- the
             blmaster shape and the only ADMITTED function here. The store/reload pair is
             load-bearing: it is what grm-mu7's argumentCells/argumentReloadSource model
             recognizes, and without it the `LDA` would read as a plain clobber.
      two_call_pred @ $C120: `JSR relay_helper` / `JSR helper_b` / `RTS` -- negative
             control: TWO known-helper calls, so the effect at its return is not either
             helper's. This is the rule that also keeps blmaster's FUN_eb98 out.
      nonhelper_pred @ $C140: `JSR harmless_target` / `RTS` -- negative control: calls
             something that is not a helper at all, so there is no relay to key on and
             the call stays ordinary.
      branch_pred @ $C160: `BNE +2` / `LDX #$00` / `JSR helper_branch` / `RTS` --
             negative control for the STRUCTURAL gate specifically. Nothing here writes
             A, so the value gate accepts the prefix; the branch must reject it anyway,
             because the relay is not reached unconditionally.
      clobber_pred @ $C180: `LDA #$01` / `JSR helper_clobber` / `RTS` -- negative control
             for the VALUE gate specifically: structurally a perfect pass-through into
             its relay, but it eats the caller's argument first, so the caller's byte is
             not this helper's argument.
      harmless @ $C1A0: nonhelper_pred's JSR target (a lone RTS).
      helpers @ $C200: relay_helper, helper_b, helper_branch, helper_clobber -- four
             ordinary MMC1 chain5($E000)+RTS helpers, one per region above so a rejected
             predecessor cannot be confused with a broken helper.

    RESET ($C000, same reset dance as make_prg_mmc1()):
      LDA #$80 / STA $8000             -- prg_mode=3 known.

      LDA #$03 / JSR relay_wrapper     -- R1: MUST resolve prg_bank=3 through the relay.
      JSR $8000                        -- -> W8000_M3_B3::8000, proving the retarget.
      LDA #$06 / JSR relay_wrapper     -- R2: SAME wrapper, distinct immediate ->
                                          prg_bank=6, so the recovery is per-call-site
                                          rather than a constant folded onto the wrapper.
      JSR $8000                        -- -> W8000_M3_B6::8000.

      LDA #$07 / JSR two_call_pred     -- R3: must NOT resolve (exactly-one rule).
      LDA #$07 / JSR nonhelper_pred    -- R4: must NOT resolve (no helper call at all).
      LDA #$05 / JSR branch_pred       -- R5: must NOT resolve (structural gate).
      LDA #$03 / JSR clobber_pred      -- R6: must NOT resolve (value gate).

      LDA #$02 / JSR relay_helper      -- fixture integrity: every helper is also called
      LDA #$05 / JSR helper_b             directly, so each gets its own Ghidra Function
      LDA #$01 / JSR helper_branch        and resolves normally. This is what proves the
      LDA #$04 / JSR helper_clobber       negative controls fail on their OWN shape
                                          rather than because their helper is broken.
      JMP $<self>                      -- idle loop.
      RTI                              -- NMI/IRQ handler.
    """
    prg = bytearray([0x00] * MMC1_PRG_SIZE)

    for bank in range(MMC1_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank  # bank marker, matching make_prg_mmc1()

    # JSR $8000 targets for the two RESOLVING call sites (R1/R2): RTS, replacing the
    # marker byte, as in make_prg_mmc1(). Banks reached only by the fixture-integrity
    # direct calls need no RTS -- nothing retargets against them.
    prg[3 * PRG_BANK_SIZE] = 0x60  # W8000_M3_B3::8000 (relay wrapper, call A)
    prg[6 * PRG_BANK_SIZE] = 0x60  # W8000_M3_B6::8000 (relay wrapper, call B)

    bank7_base = 7 * PRG_BANK_SIZE

    def put7(cpu_addr, data):
        off = bank7_base + (cpu_addr - 0xC000)
        prg[off:off + len(data)] = bytes(data)

    labels = {}

    # --- helpers @ $C200: four ordinary MMC1 helpers, built first so the predecessor
    # regions below can reference their labels rather than bare literals ---
    helpers = _Asm(prg, 0xC200, bank7_base + 0x200)
    labels['relay_helper'] = helpers.label()
    helpers.chain5(0xE000)
    helpers.rts()
    labels['helper_b'] = helpers.label()
    helpers.chain5(0xE000)
    helpers.rts()
    labels['helper_branch'] = helpers.label()
    helpers.chain5(0xE000)
    helpers.rts()
    labels['helper_clobber'] = helpers.label()
    helpers.chain5(0xE000)
    helpers.rts()

    # --- harmless @ $C1A0: nonhelper_pred's JSR target ---
    harmless = _Asm(prg, 0xC1A0, bank7_base + 0x1A0)
    labels['harmless_target'] = harmless.label()
    harmless.rts()

    # --- relay_wrapper @ $C100: THE POSITIVE CASE (blmaster FUN_e61b's shape) ---
    relay = _Asm(prg, 0xC100, bank7_base + 0x100)
    labels['relay_wrapper'] = relay.label()
    relay.sta_zp(0x22)                        # stash the caller's bank in the shadow
    relay.lda_zp(0x22)                        # reload it -- the save/restore pair
    labels['relay_wrapper_jsr'] = relay.label()
    relay.jsr(labels['relay_helper'])         # the relay call
    relay.rts()

    # --- two_call_pred @ $C120: negative control -- two known-helper calls ---
    neg_two = _Asm(prg, 0xC120, bank7_base + 0x120)
    labels['two_call_pred'] = neg_two.label()
    neg_two.jsr(labels['relay_helper'])
    neg_two.jsr(labels['helper_b'])
    neg_two.rts()

    # --- nonhelper_pred @ $C140: negative control -- the only call is to a non-helper ---
    neg_non = _Asm(prg, 0xC140, bank7_base + 0x140)
    labels['nonhelper_pred'] = neg_non.label()
    neg_non.jsr(labels['harmless_target'])
    neg_non.rts()

    # --- branch_pred @ $C160: negative control for the STRUCTURAL gate. Nothing writes
    # A, so the value gate accepts this prefix; the branch must reject it anyway ---
    neg_branch = _Asm(prg, 0xC160, bank7_base + 0x160)
    labels['branch_pred'] = neg_branch.label()
    neg_branch.bne(0xC164)                    # skips the LDX; either way reaches the JSR
    labels['branch_pred_ldx'] = neg_branch.label()
    neg_branch.ldx_imm(0x00)                  # deliberately does NOT touch A
    labels['branch_pred_jsr'] = neg_branch.label()
    neg_branch.jsr(labels['helper_branch'])
    neg_branch.rts()

    # --- clobber_pred @ $C180: negative control for the VALUE gate. Structurally a
    # perfect pass-through into its relay, but it eats the caller's argument first ---
    neg_clobber = _Asm(prg, 0xC180, bank7_base + 0x180)
    labels['clobber_pred'] = neg_clobber.label()
    neg_clobber.lda_imm(0x01)                 # supplies its own value, ignoring the caller
    labels['clobber_pred_jsr'] = neg_clobber.label()
    neg_clobber.jsr(labels['helper_clobber'])
    neg_clobber.rts()

    # --- main @ $C000: RESET flow ---
    main = _Asm(prg, 0xC000, bank7_base)
    labels['reset'] = main.label()
    main.lda_imm(0x80)
    labels['f_reset'] = main.label()
    main.sta_abs(0x8000)                      # reset dance: prg_mode=3 known

    # R1: the relay wrapper, call A -- bank 3. MUST resolve.
    labels['r1_imm'] = main.label()
    main.lda_imm(0x03)
    labels['r1_jsr'] = main.label()
    main.jsr(labels['relay_wrapper'])
    labels['r1_use_jsr'] = main.label()
    main.jsr(0x8000)                          # -> W8000_M3_B3::8000

    # R2: SAME wrapper, bank 6 -- proves per-call-site recovery, not a folded constant.
    labels['r2_imm'] = main.label()
    main.lda_imm(0x06)
    labels['r2_jsr'] = main.label()
    main.jsr(labels['relay_wrapper'])
    labels['r2_use_jsr'] = main.label()
    main.jsr(0x8000)                          # -> W8000_M3_B6::8000

    # R3-R6: the four negative controls; none may produce a "bank ->" claim.
    labels['r3_imm'] = main.label()
    main.lda_imm(0x07)
    labels['r3_jsr'] = main.label()
    main.jsr(labels['two_call_pred'])
    labels['r4_imm'] = main.label()
    main.lda_imm(0x07)
    labels['r4_jsr'] = main.label()
    main.jsr(labels['nonhelper_pred'])
    labels['r5_imm'] = main.label()
    main.lda_imm(0x05)
    labels['r5_jsr'] = main.label()
    main.jsr(labels['branch_pred'])
    labels['r6_imm'] = main.label()
    main.lda_imm(0x03)
    labels['r6_jsr'] = main.label()
    main.jsr(labels['clobber_pred'])

    # Fixture integrity: a direct JSR to every helper's own entry, so each becomes its
    # own Ghidra Function and resolves as an ordinary helper call. This is what makes the
    # negative controls above evidence about THEIR shape rather than about their helper.
    labels['direct1_imm'] = main.label()
    main.lda_imm(0x02)
    labels['direct1_jsr'] = main.label()
    main.jsr(labels['relay_helper'])
    labels['direct2_imm'] = main.label()
    main.lda_imm(0x05)
    labels['direct2_jsr'] = main.label()
    main.jsr(labels['helper_b'])
    labels['direct3_imm'] = main.label()
    main.lda_imm(0x01)
    labels['direct3_jsr'] = main.label()
    main.jsr(labels['helper_branch'])
    labels['direct4_imm'] = main.label()
    main.lda_imm(0x04)
    labels['direct4_jsr'] = main.label()
    main.jsr(labels['helper_clobber'])

    labels['idle'] = main.label()
    main.jmp(labels['idle'])                  # idle loop
    labels['rti'] = main.label()
    main.rti()                                # NMI/IRQ handler

    # Vector table.
    put7(0xFFFA, [labels['rti'] & 0xFF, (labels['rti'] >> 8) & 0xFF])
    put7(0xFFFC, [labels['reset'] & 0xFF, (labels['reset'] >> 8) & 0xFF])
    put7(0xFFFE, [labels['rti'] & 0xFF, (labels['rti'] >> 8) & 0xFF])

    return bytes(prg), labels


def make_ines_header(prg_banks, chr_banks, mapper):
    h = bytearray(16)
    h[0:4] = b"NES\x1a"
    h[4] = prg_banks
    h[5] = chr_banks
    h[6] = (mapper & 0x0F) << 4  # low mapper nibble, no trainer/mirroring flags
    h[7] = mapper & 0xF0         # high mapper nibble; NES 2.0 bits (h[7] & 0x0C) left 0
    # bytes 8-15 stay zero: plain iNES 1.0, no DiskDude tail
    return bytes(h)


def _write_rom(outdir, filename, prg, mapper=MAPPER, prg_banks=PRG_BANKS):
    header = make_ines_header(prg_banks, 0, mapper)
    rom = header + prg
    path = os.path.join(outdir, filename)
    with open(path, "wb") as f:
        f.write(rom)
    print("wrote %s (%d bytes)" % (path, len(rom)))


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mknesbanktest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    prg = make_prg()

    # Sanity-check the hand-computed addresses/encodings before writing. Bank 3's file
    # offset (3 * 0x4000 = 0xC000) equals PRG_HI's CPU base, so -- as in put() above --
    # a bank-3 byte's index into `prg` equals its CPU address directly.
    assert len(prg) == PRG_SIZE
    assert 3 * PRG_BANK_SIZE == 0xC000
    assert prg[0 * PRG_BANK_SIZE] == 0x00
    assert prg[1 * PRG_BANK_SIZE] == 0x01
    assert prg[2 * PRG_BANK_SIZE] == 0x02
    assert prg[2 * PRG_BANK_SIZE + 5] == 0x60  # RTS at bank 2's $8005
    assert prg[0xC000] == 0xA9  # LDA opcode at RESET ($C000)
    assert prg[0xC002] == 0x8D  # STA opcode at $C002
    assert (prg[0xC003] | (prg[0xC004] << 8)) == 0xFFF0
    assert prg[0xC005] == 0x20  # JSR opcode at $C005
    assert (prg[0xC006] | (prg[0xC007] << 8)) == 0x8005
    assert prg[0xC008] == 0x4C  # JMP opcode at $C008
    assert (prg[0xC009] | (prg[0xC00A] << 8)) == 0xC008
    assert prg[0xC00B] == 0x40  # RTI (NMI/IRQ handler)
    assert prg[0xFFF0] == 0x02  # bus-conflict byte at $FFF0
    assert (prg[0xFFFC] | (prg[0xFFFD] << 8)) == 0xC000  # RESET vector
    assert (prg[0xFFFA] | (prg[0xFFFB] << 8)) == 0xC00B  # NMI vector
    assert (prg[0xFFFE] | (prg[0xFFFF] << 8)) == 0xC00B  # IRQ vector

    _write_rom(outdir, "nesbanktest.nes", prg)

    prg2 = make_prg2()

    # Sanity-check the 3-deep JSR chain fixture before writing.
    assert len(prg2) == PRG_SIZE
    assert prg2[0 * PRG_BANK_SIZE] == 0x00
    assert prg2[1 * PRG_BANK_SIZE] == 0x01
    assert prg2[2 * PRG_BANK_SIZE] == 0x02
    b1 = 1 * PRG_BANK_SIZE
    b2 = 2 * PRG_BANK_SIZE
    assert prg2[b1 + 0x0010] == 0x20  # JSR opcode, bank 1 routine at $8010
    assert (prg2[b1 + 0x0011] | (prg2[b1 + 0x0012] << 8)) == 0xC020
    assert prg2[b1 + 0x0013] == 0x60  # RTS
    assert prg2[b2 + 0x0005] == 0x20  # JSR opcode, bank 2 routine at $8005
    assert (prg2[b2 + 0x0006] | (prg2[b2 + 0x0007] << 8)) == 0xC010
    assert prg2[b2 + 0x0008] == 0x60  # RTS
    assert prg2[0xC000] == 0xA9  # LDA opcode at RESET ($C000)
    assert prg2[0xC002] == 0x8D  # STA opcode at $C002
    assert (prg2[0xC003] | (prg2[0xC004] << 8)) == 0xFFE2
    assert prg2[0xC005] == 0x20  # JSR opcode at $C005
    assert (prg2[0xC006] | (prg2[0xC007] << 8)) == 0x8005
    assert prg2[0xC008] == 0x4C  # JMP opcode at $C008
    assert (prg2[0xC009] | (prg2[0xC00A] << 8)) == 0xC008
    assert prg2[0xC00B] == 0x40  # RTI (NMI/IRQ handler)
    assert prg2[0xC010] == 0xA9  # LDA opcode, trampoline1
    assert prg2[0xC012] == 0x8D  # STA opcode
    assert (prg2[0xC013] | (prg2[0xC014] << 8)) == 0xFFE1
    assert prg2[0xC015] == 0x20  # JSR opcode at $C015
    assert (prg2[0xC016] | (prg2[0xC017] << 8)) == 0x8010
    assert prg2[0xC01A] == 0x8D  # STA opcode (restore bank 2)
    assert (prg2[0xC01B] | (prg2[0xC01C] << 8)) == 0xFFE2
    assert prg2[0xC01D] == 0x60  # RTS
    assert prg2[0xC020] == 0xA9  # LDA opcode, trampoline2
    assert prg2[0xC022] == 0x8D  # STA opcode
    assert (prg2[0xC023] | (prg2[0xC024] << 8)) == 0xFFE3
    assert prg2[0xC025] == 0x20  # JSR opcode at $C025
    assert (prg2[0xC026] | (prg2[0xC027] << 8)) == 0x8030
    assert prg2[0xC02A] == 0x8D  # STA opcode (restore bank 1)
    assert (prg2[0xC02B] | (prg2[0xC02C] << 8)) == 0xFFE1
    assert prg2[0xC02D] == 0x60  # RTS
    assert prg2[0xC030] == 0x60  # RTS (bank-3 routine, dual-mapped w/ PRG_HI $C030)
    assert prg2[0xFFE0] == 0x00 and prg2[0xFFE1] == 0x01
    assert prg2[0xFFE2] == 0x02 and prg2[0xFFE3] == 0x03
    assert (prg2[0xFFFC] | (prg2[0xFFFD] << 8)) == 0xC000  # RESET vector
    assert (prg2[0xFFFA] | (prg2[0xFFFB] << 8)) == 0xC00B  # NMI vector
    assert (prg2[0xFFFE] | (prg2[0xFFFF] << 8)) == 0xC00B  # IRQ vector

    _write_rom(outdir, "nesbanktest2.nes", prg2)

    prgux = make_prg_uxhelper()

    # Sanity-check the helper-argument fixture (bead grm-hum) before writing.
    assert len(prgux) == PRG_SIZE
    # Banks 0-2 only: bank 3's marker lives at file offset 0xC000, which IS CPU $C000, so
    # RESET's first opcode overwrites it. Same in make_prg(); the marker is a convenience
    # for reading a hex dump, not something the fixture's criteria depend on.
    for bank in range(PRG_BANKS - 1):
        assert prgux[bank * PRG_BANK_SIZE] == bank
    assert prgux[3 * PRG_BANK_SIZE] == 0xA0  # LDY, i.e. RESET won the overlap
    assert prgux[1 * PRG_BANK_SIZE + 0x0010] == 0x60  # RTS at bank 1's $8010
    assert prgux[2 * PRG_BANK_SIZE + 0x0005] == 0x60  # RTS at bank 2's $8005
    # RESET
    assert prgux[0xC000] == 0xA0 and prgux[0xC001] == 0x02      # LDY #$02
    assert prgux[0xC002] == 0x20                                 # JSR
    assert (prgux[0xC003] | (prgux[0xC004] << 8)) == 0xC140
    assert prgux[0xC005] == 0x20
    assert (prgux[0xC006] | (prgux[0xC007] << 8)) == 0x8005
    assert prgux[0xC008] == 0xA4 and prgux[0xC009] == 0x10       # LDY $10
    assert prgux[0xC00A] == 0x20
    assert (prgux[0xC00B] | (prgux[0xC00C] << 8)) == 0xC140
    assert prgux[0xC00D] == 0x20
    assert (prgux[0xC00E] | (prgux[0xC00F] << 8)) == 0xC120
    assert prgux[0xC010] == 0x20
    assert (prgux[0xC011] | (prgux[0xC012] << 8)) == 0x8010
    assert prgux[0xC013] == 0x20
    assert (prgux[0xC014] | (prgux[0xC015] << 8)) == 0xC170
    assert prgux[0xC016] == 0x20
    assert (prgux[0xC017] | (prgux[0xC018] << 8)) == 0xC160
    assert prgux[0xC019] == 0x20
    assert (prgux[0xC01A] | (prgux[0xC01B] << 8)) == 0x8020
    assert prgux[0xC01C] == 0xA9 and prgux[0xC01D] == 0x09       # LDA #$09
    assert prgux[0xC01E] == 0x8D
    assert (prgux[0xC01F] | (prgux[0xC020] << 8)) == 0xFFD9
    assert prgux[0xC021] == 0x4C
    assert (prgux[0xC022] | (prgux[0xC023] << 8)) == 0xC021
    assert prgux[0xC024] == 0x40                                 # RTI
    # TailSwitch / SetBank2: the inter-function tail call
    assert prgux[0xC160] == 0xA9 and prgux[0xC161] == 0x03
    assert prgux[0xC162] == 0x8D
    assert (prgux[0xC163] | (prgux[0xC164] << 8)) == 0xFFD3
    assert prgux[0xC165] == 0x4C                                 # JMP -- tail call, not JSR
    assert (prgux[0xC166] | (prgux[0xC167] << 8)) == 0xC170
    assert prgux[0xC170] == 0xA9 and prgux[0xC171] == 0x02
    assert prgux[0xC172] == 0x8D
    assert (prgux[0xC173] | (prgux[0xC174] << 8)) == 0xFFD2
    assert prgux[0xC175] == 0x60                                 # RTS
    assert prgux[2 * PRG_BANK_SIZE + 0x0020] == 0x60             # bank 2 @ $8020
    # TwoSwitch ($C120): both switch sites, and the index chain between them
    assert prgux[0xC120] == 0xA9 and prgux[0xC121] == 0x03
    assert prgux[0xC122] == 0x8D
    assert (prgux[0xC123] | (prgux[0xC124] << 8)) == 0xFFD3
    assert prgux[0xC125] == 0xA9 and prgux[0xC126] == 0x00
    assert prgux[0xC127] == 0x0A                                 # ASL A
    assert prgux[0xC128] == 0xAA                                 # TAX
    assert prgux[0xC129] == 0xBD                                 # LDA abs,X
    assert (prgux[0xC12A] | (prgux[0xC12B] << 8)) == 0xD81E
    assert prgux[0xC12C] == 0xA8                                 # TAY
    assert prgux[0xC12D] == 0x99                                 # STA abs,Y
    assert (prgux[0xC12E] | (prgux[0xC12F] << 8)) == 0xFFD0
    assert prgux[0xC130] == 0x60                                 # RTS
    # SelectBank ($C140): the Contra idiom
    assert prgux[0xC140] == 0xB9                                 # LDA abs,Y
    assert (prgux[0xC141] | (prgux[0xC142] << 8)) == 0xFFD0
    assert prgux[0xC143] == 0x99                                 # STA abs,Y
    assert (prgux[0xC144] | (prgux[0xC145] << 8)) == 0xFFD0
    assert prgux[0xC146] == 0x60                                 # RTS
    # Tables. The bank table must be the identity so the bus-conflict AND is a no-op for a
    # correctly recovered bank; the index table must NOT be, or a scan that read the wrong
    # one would still produce the expected answer and the test would prove nothing.
    assert list(prgux[0xFFD0:0xFFD4]) == [0x00, 0x01, 0x02, 0x03]
    assert prgux[0xFFD9] == 0x09
    assert prgux[0xD81E] == 0x01
    assert 0xD81E not in range(0xFFD0, 0xFFD4)
    # Vectors.
    assert (prgux[0xFFFC] | (prgux[0xFFFD] << 8)) == 0xC000  # RESET vector
    assert (prgux[0xFFFA] | (prgux[0xFFFB] << 8)) == 0xC01B  # NMI vector
    assert (prgux[0xFFFE] | (prgux[0xFFFF] << 8)) == 0xC01B  # IRQ vector

    _write_rom(outdir, "nesuxhelpertest.nes", prgux)

    prgm = make_prg_mode()

    # Sanity-check the mode-dependent-layout fixture before writing (bead grm-aqf).
    assert len(prgm) == PRG_SIZE
    assert prgm[0 * PRG_BANK_SIZE] == 0x00  # bank 0 marker
    assert prgm[1 * PRG_BANK_SIZE] == 0x60  # bank 1's RTS replaced its marker (W8000_M0_B1::8000)
    assert prgm[2 * PRG_BANK_SIZE] == 0x02  # bank 2 marker
    assert prgm[2 * PRG_BANK_SIZE + 0x30] == 0x60  # RTS at WC000_M1_B2::C030
    # RESET phase (home mode).
    assert prgm[0xC000] == 0xA9  # LDA opcode at RESET ($C000)
    assert prgm[0xC002] == 0x8D  # STA opcode at $C002
    assert (prgm[0xC003] | (prgm[0xC004] << 8)) == 0x5000  # bank latch
    assert prgm[0xC005] == 0x20  # JSR opcode at $C005
    assert (prgm[0xC006] | (prgm[0xC007] << 8)) == 0x8000
    assert prgm[0xC008] == 0xA9  # LDA opcode at $C008
    assert prgm[0xC00A] == 0x8D  # STA opcode at $C00A
    assert (prgm[0xC00B] | (prgm[0xC00C] << 8)) == 0x6000  # mode latch
    assert prgm[0xC00D] == 0x4C  # JMP opcode at $C00D
    assert (prgm[0xC00E] | (prgm[0xC00F] << 8)) == 0x8040
    assert prgm[0xC010] == 0x40  # RTI (NMI/IRQ handler)
    # Mode-1 phase at PRG 0xC040 (executes as W8000_M1::8040).
    assert prgm[0xC040] == 0xA9  # LDA opcode at $8040
    assert prgm[0xC042] == 0x8D  # STA opcode at $8042
    assert (prgm[0xC043] | (prgm[0xC044] << 8)) == 0x5000  # bank latch inside overlay
    assert prgm[0xC045] == 0x20  # JSR opcode at $8045
    assert (prgm[0xC046] | (prgm[0xC047] << 8)) == 0xC030
    assert prgm[0xC048] == 0x4C  # JMP opcode at $8048
    assert (prgm[0xC049] | (prgm[0xC04A] << 8)) == 0x8048  # self idle
    # Vectors.
    assert (prgm[0xFFFC] | (prgm[0xFFFD] << 8)) == 0xC000  # RESET vector
    assert (prgm[0xFFFA] | (prgm[0xFFFB] << 8)) == 0xC010  # NMI vector
    assert (prgm[0xFFFE] | (prgm[0xFFFF] << 8)) == 0xC010  # IRQ vector

    _write_rom(outdir, "nesmodetest.nes", prgm, mapper=MAPPER_MODETEST)

    prgm3 = make_prg_mmc3()

    # Sanity-check the MMC3 select-data fixture before writing (bead grm-6a7.1).
    assert len(prgm3) == MMC3_PRG_SIZE
    for bank in range(MMC3_BANKS):
        if bank in (2, 3, 7):
            continue  # markers overwritten by routine RTS / RESET code below
        assert prgm3[bank * MMC3_BANK_SIZE] == bank
    assert prgm3[2 * MMC3_BANK_SIZE] == 0x60  # RTS: W8000_M0_B2::8000 / WC000_M1_B2::C000
    assert prgm3[3 * MMC3_BANK_SIZE] == 0x60  # RTS: WA000_B3::A000
    assert prgm3[0xE000] == 0xA9  # LDA opcode at RESET ($E000)
    assert prgm3[0xE002] == 0x8D and prgm3[0xE003] == 0x00 and prgm3[0xE004] == 0x80
    assert prgm3[0xE005] == 0xA9
    assert prgm3[0xE007] == 0x8D and prgm3[0xE008] == 0x01 and prgm3[0xE009] == 0x80
    assert prgm3[0xE00A] == 0x20  # JSR opcode at E00A
    assert (prgm3[0xE00B] | (prgm3[0xE00C] << 8)) == 0x8000
    assert prgm3[0xE00D] == 0xA9
    assert prgm3[0xE00F] == 0x8D and prgm3[0xE010] == 0x00 and prgm3[0xE011] == 0x80
    assert prgm3[0xE012] == 0xA9 and prgm3[0xE013] == 0xAA
    assert prgm3[0xE014] == 0x8D and prgm3[0xE015] == 0x01 and prgm3[0xE016] == 0x80
    assert prgm3[0xE017] == 0x20  # JSR opcode at E017
    assert (prgm3[0xE018] | (prgm3[0xE019] << 8)) == 0x8000
    assert prgm3[0xE01A] == 0xA9 and prgm3[0xE01B] == 0x07
    assert prgm3[0xE01C] == 0x8D and prgm3[0xE01D] == 0x00 and prgm3[0xE01E] == 0x80
    assert prgm3[0xE01F] == 0xA9 and prgm3[0xE020] == 0x03
    assert prgm3[0xE021] == 0x8D and prgm3[0xE022] == 0x01 and prgm3[0xE023] == 0x80
    assert prgm3[0xE024] == 0x20  # JSR opcode at E024
    assert (prgm3[0xE025] | (prgm3[0xE026] << 8)) == 0xA000
    assert prgm3[0xE027] == 0xA9 and prgm3[0xE028] == 0x46
    assert prgm3[0xE029] == 0x8D and prgm3[0xE02A] == 0x00 and prgm3[0xE02B] == 0x80
    assert prgm3[0xE02C] == 0x20  # JSR opcode at E02C
    assert (prgm3[0xE02D] | (prgm3[0xE02E] << 8)) == 0xC000
    assert prgm3[0xE02F] == 0x4C  # JMP opcode at E02F (self loop)
    assert (prgm3[0xE030] | (prgm3[0xE031] << 8)) == 0xE02F
    assert prgm3[0xE032] == 0x40  # RTI (NMI/IRQ handler)
    assert (prgm3[0xFFFC] | (prgm3[0xFFFD] << 8)) == 0xE000  # RESET vector
    assert (prgm3[0xFFFA] | (prgm3[0xFFFB] << 8)) == 0xE032  # NMI vector
    assert (prgm3[0xFFFE] | (prgm3[0xFFFF] << 8)) == 0xE032  # IRQ vector

    _write_rom(outdir, "nesmmc3test.nes", prgm3, mapper=MAPPER_MMC3)

    prgm3b = make_prg_mmc3_2()

    # Sanity-check the requires-on-entry fixture before writing (bead grm-6a7.2, extended
    # by grm-snu with CallerC/CallerD, and by grm-67g with the H2/CallerE/CallerF and
    # H3/CallerG inbound-argument-cell trio).
    assert len(prgm3b) == MMC3_PRG_SIZE
    assert prgm3b[0xE000] == 0x20 and (prgm3b[0xE001] | (prgm3b[0xE002] << 8)) == 0xE100
    assert prgm3b[0xE003] == 0x20 and (prgm3b[0xE004] | (prgm3b[0xE005] << 8)) == 0xE120
    assert prgm3b[0xE006] == 0x20 and (prgm3b[0xE007] | (prgm3b[0xE008] << 8)) == 0xE160
    assert prgm3b[0xE009] == 0x20 and (prgm3b[0xE00A] | (prgm3b[0xE00B] << 8)) == 0xE180
    assert prgm3b[0xE100] == 0xA9 and prgm3b[0xE101] == 0x06  # CallerA: LDA #$06
    assert prgm3b[0xE102] == 0x8D and (prgm3b[0xE103] | (prgm3b[0xE104] << 8)) == 0x8000
    assert prgm3b[0xE107] == 0x20 and (prgm3b[0xE108] | (prgm3b[0xE109] << 8)) == 0xE140
    assert prgm3b[0xE10A] == 0x60  # CallerA RTS
    assert prgm3b[0xE120] == 0xAD and (prgm3b[0xE121] | (prgm3b[0xE122] << 8)) == 0xE200
    assert prgm3b[0xE123] == 0x8D and (prgm3b[0xE124] | (prgm3b[0xE125] << 8)) == 0x8000
    assert prgm3b[0xE128] == 0x20 and (prgm3b[0xE129] | (prgm3b[0xE12A] << 8)) == 0xE140
    assert prgm3b[0xE12B] == 0x60  # CallerB RTS
    assert prgm3b[0xE160] == 0xA9 and prgm3b[0xE161] == 0x00  # CallerC: LDA #$00
    assert prgm3b[0xE162] == 0x8D and (prgm3b[0xE163] | (prgm3b[0xE164] << 8)) == 0x8000
    assert prgm3b[0xE167] == 0x20 and (prgm3b[0xE168] | (prgm3b[0xE169] << 8)) == 0xE140
    assert prgm3b[0xE16A] == 0x60  # CallerC RTS
    assert prgm3b[0xE180] == 0xA9 and prgm3b[0xE181] == 0x07  # CallerD: LDA #$07
    assert prgm3b[0xE182] == 0x8D and (prgm3b[0xE183] | (prgm3b[0xE184] << 8)) == 0x8000
    assert prgm3b[0xE187] == 0x20 and (prgm3b[0xE188] | (prgm3b[0xE189] << 8)) == 0xE140
    assert prgm3b[0xE18A] == 0x60  # CallerD RTS
    assert prgm3b[0xE140] == 0x8D and (prgm3b[0xE141] | (prgm3b[0xE142] << 8)) == 0x8001
    assert prgm3b[0xE143] == 0x60  # H RTS

    # grm-67g: inbound-argument-cell trio dispatch (moved the idle loop/RTI to make room).
    assert prgm3b[0xE00C] == 0x20 and (prgm3b[0xE00D] | (prgm3b[0xE00E] << 8)) == 0xE220
    assert prgm3b[0xE00F] == 0x20 and (prgm3b[0xE010] | (prgm3b[0xE011] << 8)) == 0xE240
    assert prgm3b[0xE012] == 0x20 and (prgm3b[0xE013] | (prgm3b[0xE014] << 8)) == 0xE280
    assert prgm3b[0xE015] == 0x4C and (prgm3b[0xE016] | (prgm3b[0xE017] << 8)) == 0xE015
    assert prgm3b[0xE018] == 0x40  # RTI (NMI/IRQ handler)

    # H2 ($E210): the smb3 FUN_ffc2 shape -- constant select write, data from $0720.
    assert prgm3b[0xE210] == 0xA9 and prgm3b[0xE211] == 0x47  # LDA #$47
    assert prgm3b[0xE212] == 0x8D and (prgm3b[0xE213] | (prgm3b[0xE214] << 8)) == 0x0721
    assert prgm3b[0xE215] == 0x8D and (prgm3b[0xE216] | (prgm3b[0xE217] << 8)) == 0x8000
    assert prgm3b[0xE218] == 0xAD and (prgm3b[0xE219] | (prgm3b[0xE21A] << 8)) == 0x0720
    assert prgm3b[0xE21B] == 0x8D and (prgm3b[0xE21C] | (prgm3b[0xE21D] << 8)) == 0x8001
    assert prgm3b[0xE21E] == 0x60  # H2 RTS

    # CallerE ($E220): positive case -- establishes select itself, stores the real bank
    # ($1B/27) immediately before the call, then loads a DECOY ($3F/63) into A right
    # before the JSR so a recovered r7=3 would expose register-sourcing. Both are in range
    # (8 PRG banks); an out-of-range bank is suppressed with a value-recovery warning.
    assert prgm3b[0xE220] == 0xA9 and prgm3b[0xE221] == 0x47  # LDA #$47
    assert prgm3b[0xE222] == 0x8D and (prgm3b[0xE223] | (prgm3b[0xE224] << 8)) == 0x8000
    assert prgm3b[0xE225] == 0xA9 and prgm3b[0xE226] == 0x05  # LDA #$05
    assert prgm3b[0xE227] == 0x8D and (prgm3b[0xE228] | (prgm3b[0xE229] << 8)) == 0x0720
    assert prgm3b[0xE22A] == 0xA9 and prgm3b[0xE22B] == 0x03  # LDA #$03 (decoy)
    assert prgm3b[0xE22C] == 0x20 and (prgm3b[0xE22D] | (prgm3b[0xE22E] << 8)) == 0xE210
    assert prgm3b[0xE22F] == 0x60  # CallerE RTS

    assert prgm3b[0xE230] == 0x60  # Harmless RTS

    # CallerF ($E240): intervening-call control -- establishes select itself, otherwise
    # identical to CallerE but with a JSR to Harmless breaking the forward scan.
    assert prgm3b[0xE240] == 0xA9 and prgm3b[0xE241] == 0x47  # LDA #$47
    assert prgm3b[0xE242] == 0x8D and (prgm3b[0xE243] | (prgm3b[0xE244] << 8)) == 0x8000
    assert prgm3b[0xE245] == 0xA9 and prgm3b[0xE246] == 0x05  # LDA #$05
    assert prgm3b[0xE247] == 0x8D and (prgm3b[0xE248] | (prgm3b[0xE249] << 8)) == 0x0720
    assert prgm3b[0xE24A] == 0x20 and (prgm3b[0xE24B] | (prgm3b[0xE24C] << 8)) == 0xE230
    assert prgm3b[0xE24D] == 0x20 and (prgm3b[0xE24E] | (prgm3b[0xE24F] << 8)) == 0xE210
    assert prgm3b[0xE250] == 0x60  # CallerF RTS

    # H3 ($E260) -- moved from $E250: self-written-cell control -- decoy write lands on
    # $0720 itself.
    assert prgm3b[0xE260] == 0xA9 and prgm3b[0xE261] == 0x47  # LDA #$47
    assert prgm3b[0xE262] == 0x8D and (prgm3b[0xE263] | (prgm3b[0xE264] << 8)) == 0x0720
    assert prgm3b[0xE265] == 0x8D and (prgm3b[0xE266] | (prgm3b[0xE267] << 8)) == 0x8000
    assert prgm3b[0xE268] == 0xAD and (prgm3b[0xE269] | (prgm3b[0xE26A] << 8)) == 0x0720
    assert prgm3b[0xE26B] == 0x8D and (prgm3b[0xE26C] | (prgm3b[0xE26D] << 8)) == 0x8001
    assert prgm3b[0xE26E] == 0x60  # H3 RTS

    # CallerG ($E280) -- moved from $E260: establishes select itself, then mirrors
    # CallerE's store shape exactly against H3 instead of H2.
    assert prgm3b[0xE280] == 0xA9 and prgm3b[0xE281] == 0x47  # LDA #$47
    assert prgm3b[0xE282] == 0x8D and (prgm3b[0xE283] | (prgm3b[0xE284] << 8)) == 0x8000
    assert prgm3b[0xE285] == 0xA9 and prgm3b[0xE286] == 0x05  # LDA #$05
    assert prgm3b[0xE287] == 0x8D and (prgm3b[0xE288] | (prgm3b[0xE289] << 8)) == 0x0720
    assert prgm3b[0xE28A] == 0x20 and (prgm3b[0xE28B] | (prgm3b[0xE28C] << 8)) == 0xE260
    assert prgm3b[0xE28D] == 0x60  # CallerG RTS

    assert (prgm3b[0xFFFC] | (prgm3b[0xFFFD] << 8)) == 0xE000  # RESET vector
    assert (prgm3b[0xFFFA] | (prgm3b[0xFFFB] << 8)) == 0xE018  # NMI vector
    assert (prgm3b[0xFFFE] | (prgm3b[0xFFFF] << 8)) == 0xE018  # IRQ vector

    _write_rom(outdir, "nesmmc3test2.nes", prgm3b, mapper=MAPPER_MMC3)

    prgs, labels = make_prg_serial()

    # Sanity-check the serial-shift fixture before writing (bead grm-hsv.1).
    assert len(prgs) == SERIAL_PRG_SIZE
    assert prgs[3 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B3::8000 (F-loop)
    assert prgs[5 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B5::8000
    assert prgs[6 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B6::8000
    bank7_file_base = 7 * PRG_BANK_SIZE
    assert prgs[bank7_file_base + 0x0200] == 0x11 and prgs[bank7_file_base + 0x0201] == 0x22
    vec = bank7_file_base + 0x3FFA  # CPU $FFFA -> file offset (bank 7 base + $3FFA)
    assert (prgs[vec + 2] | (prgs[vec + 3] << 8)) == labels['reset']  # RESET @ $FFFC
    assert (prgs[vec + 0] | (prgs[vec + 1] << 8)) == labels['rti']    # NMI @ $FFFA
    assert (prgs[vec + 4] | (prgs[vec + 5] << 8)) == labels['rti']    # IRQ @ $FFFE
    print("nesserialtest labels: " +
          ", ".join("%s=$%04X" % (k, v) for k, v in labels.items()))

    _write_rom(outdir, "nesserialtest.nes", prgs, mapper=MAPPER_SERIALTEST,
               prg_banks=SERIAL_BANKS)

    prgm1, m1labels = make_prg_mmc1()

    # Sanity-check the real MMC1 fixture before writing (bead grm-hsv.2).
    assert len(prgm1) == MMC1_PRG_SIZE
    assert prgm1[2 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B2::8000
    assert prgm1[5 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B5::8000
    assert prgm1[3 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B3::8000 (grm-nju relay site)
    assert prgm1[4 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B4::8000 (grm-nju mid-body site)
    m1bank7_base = 7 * PRG_BANK_SIZE
    assert (m1labels['switch_bank']) == 0xC200
    assert (m1labels['mode2_target']) == 0xC300
    # grm-nju regions. The mid-body entry must be the shadow helper's chain write 1 and
    # must NOT be its function entry -- that difference is the whole point of the fixture.
    assert (m1labels['shadow_entry']) == 0xC250
    assert (m1labels['shadow_midbody']) == 0xC252
    assert (m1labels['relay_to_entry']) == 0xC280
    assert (m1labels['relay_to_shadow']) == 0xC283
    assert (m1labels['relay_to_midbody']) == 0xC286
    # The shadow-ENTRY relay must sit below the MID-BODY relay, and its call site must
    # come first -- see the slot-order note in make_prg_mmc1().
    assert m1labels['relay_to_shadow'] < m1labels['relay_to_midbody']
    assert m1labels['shadow_jsr'] < m1labels['relay_mid_jsr']
    assert prgm1[m1bank7_base + 0x250] == 0xA5  # LDA zp opcode: the shadow prologue
    assert prgm1[m1bank7_base + 0x252] == 0x8D  # STA opcode: shadow chain write 1
    assert prgm1[m1bank7_base + 0x280] == 0x4C  # JMP opcode: relay to a function entry
    assert prgm1[m1bank7_base + 0x283] == 0x4C  # JMP opcode: relay to the shadow entry
    assert prgm1[m1bank7_base + 0x286] == 0x4C  # JMP opcode: relay into a function body
    assert (prgm1[m1bank7_base + 0x281] | (prgm1[m1bank7_base + 0x282] << 8)) == 0xC200
    assert (prgm1[m1bank7_base + 0x284] | (prgm1[m1bank7_base + 0x285] << 8)) == 0xC250
    assert (prgm1[m1bank7_base + 0x287] | (prgm1[m1bank7_base + 0x288] << 8)) == 0xC252
    # The three new call sites must sit before the bank-7 staging that precedes the mode
    # flip, or the mode-2 transition this fixture also pins would no longer hold.
    assert m1labels['relay_entry_jsr'] < m1labels['call3_jsr']
    assert m1labels['relay_mid_jsr'] < m1labels['call3_jsr']
    assert m1labels['shadow_jsr'] < m1labels['call3_jsr']
    assert prgm1[m1bank7_base + 0x200] == 0x8D  # STA opcode, helper's chain write 1
    assert prgm1[m1bank7_base + 0x300] == 0x60  # RTS at the mode-2 JSR target
    assert prgm1[m1bank7_base + 0x000] == 0xA9  # LDA opcode at RESET ($C000)
    assert prgm1[m1bank7_base + 0x002] == 0x8D  # STA opcode (reset dance) at $C002
    assert (prgm1[m1bank7_base + 0x003] | (prgm1[m1bank7_base + 0x004] << 8)) == 0x8000
    vec1 = m1bank7_base + 0x3FFA  # CPU $FFFA -> file offset (bank 7 base + $3FFA)
    assert (prgm1[vec1 + 2] | (prgm1[vec1 + 3] << 8)) == m1labels['reset']  # RESET @ $FFFC
    assert (prgm1[vec1 + 0] | (prgm1[vec1 + 1] << 8)) == m1labels['rti']    # NMI @ $FFFA
    assert (prgm1[vec1 + 4] | (prgm1[vec1 + 5] << 8)) == m1labels['rti']    # IRQ @ $FFFE
    print("nesmmc1test labels: " +
          ", ".join("%s=$%04X" % (k, v) for k, v in m1labels.items()))

    _write_rom(outdir, "nesmmc1test.nes", prgm1, mapper=MAPPER_MMC1, prg_banks=MMC1_BANKS)

    # nesmmc1overridetest.nes (bead grm-hsv.3): user placement override + provenance.
    prgm1o, m1olabels = make_prg_mmc1_override()
    m1obank7_base = 7 * PRG_BANK_SIZE
    assert prgm1o[3 * PRG_BANK_SIZE] == 0x60  # RTS at W8000_M3_B3::8000 target
    assert prgm1o[5 * PRG_BANK_SIZE] == 0x60  # RTS at W8000_M3_B5::8000 target
    assert prgm1o[m1obank7_base + 0x002] == 0x8D  # STA opcode (reset dance) at $C002
    assert prgm1o[m1obank7_base + 0x007] == 0xBD  # LDA abs,X opcode (opaque load) at $C007
    veco = m1obank7_base + 0x3FFC
    assert (prgm1o[veco] | (prgm1o[veco + 1] << 8)) == m1olabels['reset']  # RESET @ $FFFC
    print("nesmmc1overridetest labels: " +
          ", ".join("%s=$%04X" % (k, v) for k, v in m1olabels.items()))

    _write_rom(outdir, "nesmmc1overridetest.nes", prgm1o, mapper=MAPPER_MMC1,
               prg_banks=MMC1_BANKS)

    # neswrappertest.nes (bead grm-2dr, increment 1): pass-through-wrapper fixture.
    prgw, wlabels = make_prg_wrapper()
    wbank7_base = 7 * PRG_BANK_SIZE
    assert len(prgw) == MMC1_PRG_SIZE
    assert prgw[3 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B3::8000 (W1)
    assert prgw[6 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B6::8000 (W2)
    assert prgw[4 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B4::8000 (W3)
    # The wrapper/helper pairs must abut exactly -- that IS the shape under test.
    assert wlabels['single_helper'] == wlabels['single_wrapper'] + 2   # STA $20 is 2 bytes
    assert wlabels['inner_wrapper'] == wlabels['outer_wrapper'] + 2    # STA $21 is 2 bytes
    assert wlabels['helper2'] == wlabels['inner_wrapper'] + 2          # LDA $21 is 2 bytes
    assert wlabels['helper3'] == wlabels['jsr_pred'] + 3               # JSR is 3 bytes
    # The negative control is adjacent but NOT reachable by fallthrough (RTS in between).
    assert wlabels['helper4'] == wlabels['rts_pred'] + 3               # LDA #imm + RTS
    assert prgw[wbank7_base + 0x100] == 0x85  # STA zp opcode: single_wrapper
    assert prgw[wbank7_base + 0x102] == 0x8D  # STA abs opcode: single_helper chain write 1
    assert prgw[wbank7_base + 0x140] == 0x85  # STA zp opcode: outer_wrapper
    assert prgw[wbank7_base + 0x142] == 0xA5  # LDA zp opcode: inner_wrapper
    assert prgw[wbank7_base + 0x144] == 0x8D  # STA abs opcode: helper2 chain write 1
    assert prgw[wbank7_base + 0x180] == 0x20  # JSR opcode: jsr_pred
    assert prgw[wbank7_base + 0x183] == 0x8D  # STA abs opcode: helper3 chain write 1
    assert prgw[wbank7_base + 0x200] == 0xA9  # LDA imm opcode: rts_pred
    assert prgw[wbank7_base + 0x202] == 0x60  # RTS: rts_pred is terminal
    assert prgw[wbank7_base + 0x203] == 0x8D  # STA abs opcode: helper4 chain write 1
    vecw = wbank7_base + 0x3FFA  # CPU $FFFA -> file offset (bank 7 base + $3FFA)
    assert (prgw[vecw + 2] | (prgw[vecw + 3] << 8)) == wlabels['reset']  # RESET @ $FFFC
    assert (prgw[vecw + 0] | (prgw[vecw + 1] << 8)) == wlabels['rti']    # NMI @ $FFFA
    assert (prgw[vecw + 4] | (prgw[vecw + 5] << 8)) == wlabels['rti']    # IRQ @ $FFFE
    print("neswrappertest labels: " +
          ", ".join("%s=$%04X" % (k, v) for k, v in wlabels.items()))

    _write_rom(outdir, "neswrappertest.nes", prgw, mapper=MAPPER_MMC1, prg_banks=MMC1_BANKS)

    # nesrelaytest.nes (bead grm-2dr, increment 2): call-edge-wrapper fixture.
    prgr, rlabels = make_prg_relay()
    rbank7_base = 7 * PRG_BANK_SIZE
    assert len(prgr) == MMC1_PRG_SIZE
    assert prgr[3 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B3::8000 (R1)
    assert prgr[6 * PRG_BANK_SIZE] == 0x60  # RTS: W8000_M3_B6::8000 (R2)
    # The relay wrapper's shape IS the thing under test: store, reload, then the JSR.
    assert prgr[rbank7_base + 0x100] == 0x85  # STA zp opcode: relay_wrapper entry
    assert prgr[rbank7_base + 0x102] == 0xA5  # LDA zp opcode: the reload
    assert prgr[rbank7_base + 0x104] == 0x20  # JSR opcode: the relay call
    assert rlabels['relay_wrapper_jsr'] == rlabels['relay_wrapper'] + 4  # 2 + 2 bytes
    # Unlike a pass-through wrapper, the relay target must NOT abut the wrapper.
    assert rlabels['relay_helper'] > rlabels['relay_wrapper'] + 8
    # Negative controls must really be in the shape their names claim.
    assert prgr[rbank7_base + 0x120] == 0x20  # JSR: two_call_pred's first call
    assert prgr[rbank7_base + 0x123] == 0x20  # JSR: ...and its second, the disqualifier
    assert prgr[rbank7_base + 0x160] == 0xD0  # BNE opcode: branch_pred
    assert prgr[rbank7_base + 0x162] == 0xA2  # LDX imm: does NOT touch A (value gate passes)
    assert prgr[rbank7_base + 0x164] == 0x20  # JSR: branch_pred's relay
    assert rlabels['branch_pred_jsr'] == 0xC164  # the BNE's own target: both paths reach it
    assert prgr[rbank7_base + 0x180] == 0xA9  # LDA imm: clobber_pred eats the argument
    assert prgr[rbank7_base + 0x182] == 0x20  # JSR: clobber_pred's relay
    vecr = rbank7_base + 0x3FFA  # CPU $FFFA -> file offset (bank 7 base + $3FFA)
    assert (prgr[vecr + 2] | (prgr[vecr + 3] << 8)) == rlabels['reset']  # RESET @ $FFFC
    assert (prgr[vecr + 0] | (prgr[vecr + 1] << 8)) == rlabels['rti']    # NMI @ $FFFA
    assert (prgr[vecr + 4] | (prgr[vecr + 5] << 8)) == rlabels['rti']    # IRQ @ $FFFE
    print("nesrelaytest labels: " +
          ", ".join("%s=$%04X" % (k, v) for k, v in rlabels.items()))

    _write_rom(outdir, "nesrelaytest.nes", prgr, mapper=MAPPER_MMC1, prg_banks=MMC1_BANKS)

    # nesbandaitest.nes (bead grm-9ty): Bandai FCG/LZ93D50 register-file decode fixture.
    prgb = make_prg_bandai()
    assert len(prgb) == PRG_SIZE
    assert prgb[2 * PRG_BANK_SIZE + 0x0005] == 0x60  # RTS: PRG_LO_B2::8005 target
    bbank3_base = 3 * PRG_BANK_SIZE
    assert prgb[bbank3_base + 0x0000] == 0xA9 and prgb[bbank3_base + 0x0001] == 0x02  # LDA #$02
    assert prgb[bbank3_base + 0x0002] == 0x8D and \
        (prgb[bbank3_base + 0x0003] | (prgb[bbank3_base + 0x0004] << 8)) == 0x8008  # STA $8008
    assert prgb[bbank3_base + 0x0007] == 0x8D and \
        (prgb[bbank3_base + 0x0008] | (prgb[bbank3_base + 0x0009] << 8)) == 0x8000  # STA $8000 decoy
    assert prgb[bbank3_base + 0x000F] == 0x20 and \
        (prgb[bbank3_base + 0x0010] | (prgb[bbank3_base + 0x0011] << 8)) == 0x8005  # JSR $8005
    assert (prgb[bbank3_base + 0x3FFC] | (prgb[bbank3_base + 0x3FFD] << 8)) == 0xC000  # RESET vec
    _write_rom(outdir, "nesbandaitest.nes", prgb, mapper=MAPPER_BANDAI)


if __name__ == "__main__":
    main()
