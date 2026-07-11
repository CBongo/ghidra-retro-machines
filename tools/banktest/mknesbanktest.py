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
"""

import sys
import os

PRG_BANK_SIZE = 0x4000
PRG_BANKS = 4
PRG_SIZE = PRG_BANK_SIZE * PRG_BANKS
MAPPER = 2          # UxROM (nesbanktest / nesbanktest2)
MAPPER_MODETEST = 100  # synthetic nes-modetest board (NESdev-reserved test mapper)
MAPPER_MMC3 = 4        # MMC3 (nesmmc3test)

MMC3_BANK_SIZE = 0x2000
MMC3_BANKS = 8
MMC3_PRG_SIZE = MMC3_BANK_SIZE * MMC3_BANKS


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


def make_ines_header(prg_banks, chr_banks, mapper):
    h = bytearray(16)
    h[0:4] = b"NES\x1a"
    h[4] = prg_banks
    h[5] = chr_banks
    h[6] = (mapper & 0x0F) << 4  # low mapper nibble, no trainer/mirroring flags
    h[7] = mapper & 0xF0         # high mapper nibble; NES 2.0 bits (h[7] & 0x0C) left 0
    # bytes 8-15 stay zero: plain iNES 1.0, no DiskDude tail
    return bytes(h)


def _write_rom(outdir, filename, prg, mapper=MAPPER):
    header = make_ines_header(PRG_BANKS, 0, mapper)
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


if __name__ == "__main__":
    main()
