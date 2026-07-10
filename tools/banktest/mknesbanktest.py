#!/usr/bin/env python3
"""Hand-assembles the NES banking-analyzer regression ROM (bead grm-5tl.17).

Usage: mknesbanktest.py <output-dir>

Writes nesbanktest.nes (16-byte iNES header + 4 x 16 KiB PRG banks, no CHR) into
<output-dir>. No dependencies beyond Python 3.

Targets the shipped UxROM board descriptor (machines/nes-uxrom.yaml, iNES mapper 2):
a switchable 16 KiB window at $8000-$BFFF (computed window PRG_LO, home bank = 0,
memory-latch mechanism with bus_conflict) and a fixed 16 KiB window at $C000-$FFFF
(PRG_HI = PRG[last]) holding RESET/NMI/IRQ code and the vector table. This exercises
NesRomLoader's computed-window "home-in-base" overlay placement (PRG_LO_B1/_B2/_B3
FileBytes-backed overlay blocks) and NesBankingAnalyzer/BoardBankAnalyzer reference
retargeting through MemoryLatchBankSwitchStrategy's bus-conflict path.

Bank layout (16 KiB each, PRG image is 4 banks = 64 KiB):
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
"""

import sys
import os

PRG_BANK_SIZE = 0x4000
PRG_BANKS = 4
PRG_SIZE = PRG_BANK_SIZE * PRG_BANKS
MAPPER = 2  # UxROM


def make_prg():
    prg = bytearray([0x00] * PRG_SIZE)

    # Bank markers at the first byte of each bank (offset $8000 once mapped in).
    for bank in range(PRG_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank

    # Bank 2's JSR target routine at CPU $8005 -> file offset 2*0x4000 + 5.
    bank2_rts_off = 2 * PRG_BANK_SIZE + 0x0005
    prg[bank2_rts_off] = 0x60  # RTS

    # Bank 3 == the fixed PRG_HI window; file offset == CPU address (see module doc).
    bank3_base = 3 * PRG_BANK_SIZE
    assert bank3_base == 0xC000

    def put(cpu_addr, data):
        off = bank3_base + (cpu_addr - 0xC000)
        prg[off:off + len(data)] = bytes(data)

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


def make_ines_header(prg_banks, chr_banks, mapper):
    h = bytearray(16)
    h[0:4] = b"NES\x1a"
    h[4] = prg_banks
    h[5] = chr_banks
    h[6] = (mapper & 0x0F) << 4  # low mapper nibble, no trainer/mirroring flags
    h[7] = mapper & 0xF0         # high mapper nibble; NES 2.0 bits (h[7] & 0x0C) left 0
    # bytes 8-15 stay zero: plain iNES 1.0, no DiskDude tail
    return bytes(h)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mknesbanktest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    prg = make_prg()
    header = make_ines_header(PRG_BANKS, 0, MAPPER)
    rom = header + prg

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

    path = os.path.join(outdir, "nesbanktest.nes")
    with open(path, "wb") as f:
        f.write(rom)
    print("wrote %s (%d bytes)" % (path, len(rom)))


if __name__ == "__main__":
    main()
