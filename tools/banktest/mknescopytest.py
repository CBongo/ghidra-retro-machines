#!/usr/bin/env python3
"""Hand-assembles the NES run-from-elsewhere copy-loop regression ROM (bead grm-1.7.6c).

Usage: mknescopytest.py <output-dir>

Writes nescopytest.nes (16-byte iNES header + 8 x 16 KiB PRG banks = 128 KiB, no CHR)
into <output-dir>. No dependencies beyond Python 3.

This is the ONLY automated coverage of CopyLoopAnalyzer running on something that is not
a C64 PRG. grm-1.7.6 widened the analyzer's gate from "the C64 loader ran" to "a
retro-machines descriptor map is present AND the language processor is 6502/6510", which
brings every NES board in. That only matters when the copy loop runs from a BANK OVERLAY,
which no C64 fixture can produce -- hence this ROM. It also pins the address re-homing
contract: LoopIdioms.indexedBase can only build an operand address in the EXECUTING
instruction's space, so the destination has to cross out of the overlay to be carved in
place. (It does so by itself -- OverlayAddressSpace.getAddress falls back to the base space
for an offset outside the overlay's defined blocks -- but nothing else in the suite would
notice if that stopped being true.) Everything here is arranged so the loop genuinely
executes inside a switchable PRG window while storing into base-space PRG RAM:

  * board: machines/nes-mmc1.yaml (iNES mapper 1), same 128 KiB Metroid-ish shape as
    nesmmc1test.nes. Its `memory.regions` declares PRG_RAM $6000-$7FFF kind: ram -- a
    plain, always-visible, base-space UNINITIALIZED block, which is exactly what
    TransferMaterializer.canCarve wants. The destination must therefore take the in-place
    carve (TransferPlacement.IN_PLACE -> block COPY_6c90 in the BASE space); an overlay
    placement here would mean the destination address never got re-homed out of the
    executing overlay -- see the re-homing note above.
  * prg_mode stays 3 (fix-last, the reset-dance convention and this board's home mode)
    throughout: W8000 switches on prg_bank, WC000 is pinned to PRG[last]. RESET runs in
    the fixed WC000 window (bank 7), so the code doing the bank switch never moves.
  * the copy loop lives in bank 1, which is NOT W8000's home bank (initial_state has
    prg_bank=0), so the loader realizes it as the overlay W8000_M3_B1 ($8000-$BFFF) and
    BoardBankAnalyzer retargets RESET's JMP $8000 into it. Every instruction of the loop
    is therefore disassembled at W8000_M3_B1::80xx, and its `STA $6C90,X` operand is born
    in that overlay space.

PRG bank layout (16 KiB each, PRG image is 8 banks = 128 KiB):
  bank 0 (W8000's home bank, visible in the base space at $8000-$BFFF): marker byte 0x00.
  bank 1 (W8000_M3_B1 overlay): the copy loop at $8000 and its payload at $8010.
  banks 2-6: marker bytes 0x02..0x06, never selected; just distinguishable filler.
  bank 7 (= PRG[last] = the fixed WC000 window): RESET code and the vector table.

Bank 7's CPU base is $C000 and WC000 maps PRG[last], so a CPU address $C000+x in that
window is PRG file offset (7 * 0x4000) + x; bank 1's CPU base under W8000 is $8000, so
CPU $8000+x is file offset (1 * 0x4000) + x. Both are written through put7()/put1()
below, which encode exactly those translations (the same trick every other NES fixture
generator in this directory uses).

RESET ($C000, executing in the fixed WC000 window; seed prg_mode=3/prg_bank=0/mirroring=0):
  C000  A9 80        LDA #$80        ; reset dance -- a bit-7-set write resets the shifter
  C002  8D 00 80     STA $8000       ; and forces prg_mode=3; idempotent re-assertion of
                                      ; the seed, making the whole state known
  C005  A9 01        LDA #$01        ; the bank number to commit: PRG bank 1
  C007  8D 00 E0     STA $E000       ; serial write 1 (bit 0 of A)          -- the fully
  C00A  4A           LSR A           ;                                        unrolled
  C00B  8D 00 E0     STA $E000       ; serial write 2                        5x STA/LSR
  C00E  4A           LSR A           ;                                        commit chain
  C00F  8D 00 E0     STA $E000       ; serial write 3                        every real
  C012  4A           LSR A           ;                                        MMC1 game
  C013  8D 00 E0     STA $E000       ; serial write 4                        emits (see
  C016  4A           LSR A           ;                                        the strategy
  C017  8D 00 E0     STA $E000       ; serial write 5 = the COMMIT; the write's own address
                                      ; bits 14:13 ($E000 -> 3) select the PRG bank
                                      ; register, so this lands prg_bank=1
  C01A  4C 00 80     JMP $8000       ; prg_mode=3 + prg_bank=1, both known -> retargeted
                                      ; to W8000_M3_B1::8000, which is what puts the copy
                                      ; loop below inside a bank overlay
  C01D  40           RTI             ; NMI/IRQ handler

The copy loop, at bank 1 offset 0 (= W8000_M3_B1::8000). It is the canonical
down-counting indexed copy CopyLoopAnalyzer recognizes, with the load and store on
DIFFERENT bases (a relocation, not an in-place decrypt) and a JMP into the destination
range to prove the copied bytes are code:

  8000  A2 04        LDX #$04        ; index 4..0 -> COPY_LEN = 5 bytes
  8002  BD 10 80     LDA $8010,X     ; source: bank 1's own payload -- an address INSIDE
                                      ; the executing overlay, so it stays an overlay
                                      ; address (W8000_M3_B1:8010) and the materializer
                                      ; reads the copied bytes straight out of bank 1
  8005  9D 90 6C     STA $6C90,X     ; destination: PRG_RAM $6C90 -- OUTSIDE the executing
                                      ; overlay's own $8000-$BFFF range, and the reason
                                      ; this fixture exists. Wherever the operand address
                                      ; is born, it has to end up naming the base-space
                                      ; PRG_RAM block or the in-place carve cannot happen.
                                      ; (Measured on Ghidra 12.1.2 it already is base-space:
                                      ; OverlayAddressSpace.getAddress(long) falls back to
                                      ; the overlayed space for an offset outside the
                                      ; overlay's defined region. This fixture pins that
                                      ; OUTCOME, not one particular way of reaching it.)
  8008  CA           DEX
  8009  10 F7        BPL $8002       ; back edge to the loop top (the LDA)
  800B  4C 90 6C     JMP $6C90       ; a jump INTO the copied range: the only evidence the
                                      ; payload is code -> disassemble + make a function
  800E  00 00                        ; filler, keeping the payload on a round $8010
  8010  A9 5A 85 10 60               ; the 5-byte payload (see below)

The payload is deliberately real, self-terminating 6502 code rather than an ascending
byte run like mkcopytest.py's C64 fixtures use: it is disassembled at the destination
(the JMP proves it is code), so a run that decoded into a trailing partial instruction
would spill disassembly past the 5-byte COPY_6c90 block. As executed at $6C90 it is:

  6C90  A9 5A        LDA #$5A        ; $5A is the recognizable marker byte -- if COPIED
                                      ; ever reads the wrong side of the copy this is what
                                      ; goes missing
  6C92  85 10        STA $10         ; store into zero-page RAM ($0000-$07FF region)
  6C94  60           RTS

Destination $6C90 is deliberately in the INTERIOR of PRG_RAM ($6000-$7FFF) rather than at
its start, so carveInPlace has to split a leftover fragment off each side -- the same
shape copydata.prg exercises for the C64 (PRG_RAM 6000-6c8f and PRG_RAM_6C95 6c95-7fff
survive around COPY_6c90, both still uninitialized).

Vectors: RESET -> $C000, NMI/IRQ -> $C01D (the lone RTI).
"""

import sys
import os

PRG_BANK_SIZE = 0x4000
PRG_BANKS = 8                 # 128 KiB, matching nesmmc1test.nes's shape
PRG_SIZE = PRG_BANK_SIZE * PRG_BANKS
MAPPER_MMC1 = 1               # real MMC1 board; see machines/nes-mmc1.yaml

COPY_BANK = 1                 # non-home for W8000 (initial_state prg_bank=0) -> overlay
COPY_SRC = 0x8010             # CPU address of the payload inside the bank-1 overlay
COPY_DST = 0x6C90             # CPU address in PRG_RAM ($6000-$7FFF), interior of the block
COPY_LEN = 5

# The copied payload: LDA #$5A / STA $10 / RTS. Real, terminating code -- see module doc.
PAYLOAD = bytes([0xA9, 0x5A, 0x85, 0x10, 0x60])


def _serial_commit(value, register_addr):
    """The fully unrolled MMC1 commit chain that lands `value` in the register selected by
    `register_addr`'s bits 14:13: LDA #value, then 5 x (STA register_addr) with an LSR A
    between consecutive writes (LSB first). 21 bytes."""
    out = [0xA9, value & 0xFF]                       # LDA #value
    lo, hi = register_addr & 0xFF, (register_addr >> 8) & 0xFF
    for i in range(5):
        out += [0x8D, lo, hi]                        # STA register_addr
        if i < 4:
            out += [0x4A]                            # LSR A
    return out


def make_prg():
    prg = bytearray([0x00] * PRG_SIZE)

    # Bank markers at the first byte of each bank, matching every other NES fixture here.
    # Bank 1's is immediately replaced by the copy loop and bank 7's by RESET's first
    # opcode -- both intentional.
    for bank in range(PRG_BANKS):
        prg[bank * PRG_BANK_SIZE] = bank

    bank1_base = COPY_BANK * PRG_BANK_SIZE
    bank7_base = (PRG_BANKS - 1) * PRG_BANK_SIZE

    def put1(cpu_addr, data):
        # Bank 1 seen through W8000 ($8000-$BFFF), i.e. the W8000_M3_B1 overlay.
        prg[bank1_base + (cpu_addr - 0x8000):
            bank1_base + (cpu_addr - 0x8000) + len(data)] = bytes(data)

    def put7(cpu_addr, data):
        # Bank 7 == PRG[last] == the fixed WC000 window ($C000-$FFFF).
        prg[bank7_base + (cpu_addr - 0xC000):
            bank7_base + (cpu_addr - 0xC000) + len(data)] = bytes(data)

    # --- RESET, in the fixed WC000 window ---------------------------------------
    put7(0xC000, [0xA9, 0x80])                       # LDA #$80
    put7(0xC002, [0x8D, 0x00, 0x80])                 # STA $8000 (reset dance -> prg_mode=3)
    put7(0xC005, _serial_commit(COPY_BANK, 0xE000))  # LDA #$01 + 5x STA $E000 -> prg_bank=1
    put7(0xC01A, [0x4C, 0x00, 0x80])                 # JMP $8000 -> W8000_M3_B1::8000
    put7(0xC01D, [0x40])                             # RTI (NMI/IRQ handler)

    # --- the copy loop, in bank 1 (the W8000_M3_B1 overlay) ----------------------
    put1(0x8000, [0xA2, COPY_LEN - 1])               # LDX #$04
    put1(0x8002, [0xBD, COPY_SRC & 0xFF, COPY_SRC >> 8])   # LDA $8010,X (source)
    put1(0x8005, [0x9D, COPY_DST & 0xFF, COPY_DST >> 8])   # STA $6C90,X (destination)
    put1(0x8008, [0xCA])                             # DEX
    put1(0x8009, [0x10, 0xF7])                       # BPL $8002 (back edge to the LDA)
    put1(0x800B, [0x4C, COPY_DST & 0xFF, COPY_DST >> 8])   # JMP $6C90 (into the copy)
    put1(COPY_SRC, PAYLOAD)                          # the copied payload

    # --- vector table (bank 7 == PRG[last] is what $FFFA-$FFFF reads) ------------
    put7(0xFFFA, [0x1D, 0xC0])                       # NMI   -> $C01D (RTI)
    put7(0xFFFC, [0x00, 0xC0])                       # RESET -> $C000
    put7(0xFFFE, [0x1D, 0xC0])                       # IRQ   -> $C01D (RTI)

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


def write_rom(outdir, filename, prg):
    rom = make_ines_header(PRG_BANKS, 0, MAPPER_MMC1) + prg
    path = os.path.join(outdir, filename)
    with open(path, "wb") as f:
        f.write(rom)
    print("wrote %s (%d bytes)" % (path, len(rom)))


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mknescopytest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    prg = make_prg()

    # Sanity-check every hand-computed offset/encoding in the module doc before writing.
    assert len(prg) == PRG_SIZE
    bank1 = COPY_BANK * PRG_BANK_SIZE
    bank7 = (PRG_BANKS - 1) * PRG_BANK_SIZE
    assert bank1 == 0x4000 and bank7 == 0x1C000

    # Untouched bank markers (0, 2..6) stay distinguishable filler.
    assert prg[0 * PRG_BANK_SIZE] == 0x00
    for bank in range(2, PRG_BANKS - 1):
        assert prg[bank * PRG_BANK_SIZE] == bank

    # RESET: reset dance, the unrolled prg_bank=1 commit chain, the JMP into the overlay.
    assert prg[bank7 + 0x0000] == 0xA9 and prg[bank7 + 0x0001] == 0x80   # LDA #$80
    assert prg[bank7 + 0x0002] == 0x8D and \
        (prg[bank7 + 0x0003] | (prg[bank7 + 0x0004] << 8)) == 0x8000     # STA $8000
    assert prg[bank7 + 0x0005] == 0xA9 and prg[bank7 + 0x0006] == COPY_BANK  # LDA #$01
    for i, off in enumerate((0x0007, 0x000B, 0x000F, 0x0013, 0x0017)):   # 5x STA $E000
        assert prg[bank7 + off] == 0x8D
        assert (prg[bank7 + off + 1] | (prg[bank7 + off + 2] << 8)) == 0xE000
        if i < 4:
            assert prg[bank7 + off + 3] == 0x4A                          # LSR A
    assert prg[bank7 + 0x001A] == 0x4C and \
        (prg[bank7 + 0x001B] | (prg[bank7 + 0x001C] << 8)) == 0x8000     # JMP $8000
    assert prg[bank7 + 0x001D] == 0x40                                   # RTI

    # The copy loop in bank 1, at overlay offsets $8000-$800D.
    assert prg[bank1 + 0x0000] == 0xA2 and prg[bank1 + 0x0001] == COPY_LEN - 1  # LDX #$04
    assert prg[bank1 + 0x0002] == 0xBD and \
        (prg[bank1 + 0x0003] | (prg[bank1 + 0x0004] << 8)) == COPY_SRC   # LDA $8010,X
    assert prg[bank1 + 0x0005] == 0x9D and \
        (prg[bank1 + 0x0006] | (prg[bank1 + 0x0007] << 8)) == COPY_DST   # STA $6C90,X
    assert prg[bank1 + 0x0008] == 0xCA                                   # DEX
    assert prg[bank1 + 0x0009] == 0x10 and prg[bank1 + 0x000A] == 0xF7   # BPL $8002
    # BPL is relative: (next instruction address) + rel must be the loop top ($8002).
    assert 0x800B + (prg[bank1 + 0x000A] - 0x100) == 0x8002
    assert prg[bank1 + 0x000B] == 0x4C and \
        (prg[bank1 + 0x000C] | (prg[bank1 + 0x000D] << 8)) == COPY_DST   # JMP $6C90
    # The payload sits exactly at the source base the LDA names, and nowhere overlaps
    # the loop body above it.
    assert COPY_SRC - 0x8000 >= 0x000E
    assert prg[bank1 + (COPY_SRC - 0x8000):
               bank1 + (COPY_SRC - 0x8000) + COPY_LEN] == PAYLOAD
    assert len(PAYLOAD) == COPY_LEN

    # The destination range lies wholly inside PRG_RAM's interior ($6000-$7FFF), so the
    # carve splits a leftover fragment off BOTH sides.
    assert 0x6000 < COPY_DST and COPY_DST + COPY_LEN - 1 < 0x7FFF

    # Vectors.
    vec = bank7 + 0x3FFA  # CPU $FFFA -> file offset (bank 7 base + $3FFA)
    assert (prg[vec + 0] | (prg[vec + 1] << 8)) == 0xC01D   # NMI   -> RTI
    assert (prg[vec + 2] | (prg[vec + 3] << 8)) == 0xC000   # RESET -> $C000
    assert (prg[vec + 4] | (prg[vec + 5] << 8)) == 0xC01D   # IRQ   -> RTI

    write_rom(outdir, "nescopytest.nes", prg)
    print("nescopytest: copy loop @ W8000_M3_B1::8000, src $%04X (bank %d), dst $%04X, "
          "len %d, payload %s" %
          (COPY_SRC, COPY_BANK, COPY_DST, COPY_LEN,
           " ".join("%02x" % b for b in PAYLOAD)))


if __name__ == "__main__":
    main()
