#!/usr/bin/env python3
"""Hand-assembles the NES banking-analyzer regression ROMs (bead grm-5tl.17,
extended by grm-5tl.13.3).

Usage: mknesbanktest.py <output-dir>

Writes nesbanktest.nes and nesbanktest2.nes (each: 16-byte iNES header + 4 x 16 KiB
PRG banks, no CHR) into <output-dir>. No dependencies beyond Python 3.

Both target the shipped UxROM board descriptor (machines/nes-uxrom.yaml, iNES mapper
2): a switchable 16 KiB window at $8000-$BFFF (computed window PRG_LO, home bank = 0,
memory-latch mechanism with bus_conflict) and a fixed 16 KiB window at $C000-$FFFF
(PRG_HI = PRG[last]) holding RESET/NMI/IRQ code and the vector table. This exercises
NesRomLoader's computed-window "home-in-base" overlay placement (PRG_LO_B1/_B2/_B3
FileBytes-backed overlay blocks) and NesBankingAnalyzer/BoardBankAnalyzer reference
retargeting through MemoryLatchBankSwitchStrategy's bus-conflict path.

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
"""

import sys
import os

PRG_BANK_SIZE = 0x4000
PRG_BANKS = 4
PRG_SIZE = PRG_BANK_SIZE * PRG_BANKS
MAPPER = 2  # UxROM


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


def make_ines_header(prg_banks, chr_banks, mapper):
    h = bytearray(16)
    h[0:4] = b"NES\x1a"
    h[4] = prg_banks
    h[5] = chr_banks
    h[6] = (mapper & 0x0F) << 4  # low mapper nibble, no trainer/mirroring flags
    h[7] = mapper & 0xF0         # high mapper nibble; NES 2.0 bits (h[7] & 0x0C) left 0
    # bytes 8-15 stay zero: plain iNES 1.0, no DiskDude tail
    return bytes(h)


def _write_rom(outdir, filename, prg):
    header = make_ines_header(PRG_BANKS, 0, MAPPER)
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


if __name__ == "__main__":
    main()
