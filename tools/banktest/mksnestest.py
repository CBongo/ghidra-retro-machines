#!/usr/bin/env python3
"""Generate the deterministic SNES loader headless fixture (bead grm-9nxj.9).

Two synthetic cartridges, both LoROM, differing only in whether they carry the 512-byte
copier header that ten of eleven real-world dumps in this project's reference corpus have.
That pair is the point: copier detection is by FILE SIZE alone (size % 0x400 == 0x200), and
getting it wrong shifts EVERY offset in the image, so a fixture that only ever tests one of
the two would miss the class of bug most likely to occur.

The code at the reset vector is chosen to exercise what the loader has to get right rather
than to do anything meaningful: an 8-bit immediate (which the language must yield as a
CONSTANT, not a load -- bead grm-9nxj.2), a store to a named IO register, a REP that widens
the accumulator so the following immediate is three bytes rather than two, and a long
(24-bit) load reading through the cartridge's own high mirror.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bankgen  # noqa: E402

LOROM_HEADER_AT = 0x7FC0
BANK_SIZE = 0x8000
IMAGE_BANKS = 2                      # 64 KiB: two LoROM banks, enough for a mirror pair
RESET = 0x8000
NMI = 0x8020                         # native-mode NMI handler (bead grm-9nxj.5.2)
IRQ_EMU = 0x8030                     # emulation-mode IRQ/BRK stub
UNUSED = 0xFFFF                      # the usual filler for a vector nothing takes


def code():
    """The routine at the reset vector. Emulation mode on entry, as hardware leaves it."""
    return bytes([
        0x18,                        # CLC
        0xFB,                        # XCE          ; -> native mode
        0xA9, 0x0F,                  # LDA #$0F     ; 8-bit immediate (M=1 after XCE)
        0x8D, 0x00, 0x21,            # STA $2100    ; INIDISP, a named IO register
        0xC2, 0x20,                  # REP #$20     ; widen the accumulator
        0xA9, 0x34, 0x12,            # LDA #$1234   ; now a THREE-byte immediate
        0xAF, 0x00, 0x80, 0x80,      # LDA $808000  ; long read through the high mirror
        0x80, 0xFE,                  # BRA *        ; park
    ])


def nmi_handler():
    """Native NMI: entered with E=0. REP #$30 then a 16-bit immediate, so a handler decoded in
    the wrong mode is visible in the instruction lengths, not just in the context register."""
    return bytes([
        0xC2, 0x30,                  # REP #$30
        0xA9, 0x34, 0x12,            # LDA #$1234
        0x40,                        # RTI
    ])


def write_vectors(image, vectors):
    """The vector table at vectors+$04..$1F (i.e. $FFE4-$FFFF): RESET, the native NMI and the
    emulation IRQ point at code; every other slot, ABORT included, holds $FFFF."""
    slots = {0x04: UNUSED, 0x06: UNUSED, 0x08: UNUSED, 0x0A: NMI, 0x0E: UNUSED,
             0x14: UNUSED, 0x18: UNUSED, 0x1A: UNUSED, 0x1C: RESET, 0x1E: IRQ_EMU}
    for off, target in slots.items():
        image[vectors + off] = target & 0xFF
        image[vectors + off + 1] = (target >> 8) & 0xFF


def cartridge(title):
    image = bytearray(b"\xEE" * (BANK_SIZE * IMAGE_BANKS))
    image[RESET - 0x8000:RESET - 0x8000 + len(code())] = code()
    image[NMI - 0x8000:NMI - 0x8000 + len(nmi_handler())] = nmi_handler()
    image[IRQ_EMU - 0x8000] = 0x40   # RTI

    at = LOROM_HEADER_AT
    image[at:at + 21] = title.ljust(21).encode("ascii")
    image[at + 0x15] = 0x20          # map mode: LoROM, slow ROM
    image[at + 0x16] = 0x00          # chipset: ROM only
    image[at + 0x17] = 0x06          # ROM size: 1 << 6 KiB = 64 KiB
    image[at + 0x18] = 0x00          # RAM size: none

    # The checksum/complement PAIR is what makes the header's location detectable; the loader
    # checks the pair, not a sum over the image, so a fixed pair keeps the fixture stable.
    checksum = 0x1234
    image[at + 0x1C] = (checksum ^ 0xFFFF) & 0xFF
    image[at + 0x1D] = ((checksum ^ 0xFFFF) >> 8) & 0xFF
    image[at + 0x1E] = checksum & 0xFF
    image[at + 0x1F] = (checksum >> 8) & 0xFF

    # Vector table at $FFE0 (header + 0x20).
    write_vectors(image, at + 0x20)
    return bytes(image)


# grm-9nxj.5.3: the code after a call decoded at the width the callee LEAVES, not the caller's.
WIDTH_SETS8 = 0x8040                 # SEP #$20 / RTS: returns with an 8-bit accumulator
WIDTH_NEEDS8 = 0x8050                # CMP #$73 / BNE / NOP / NOP / RTS: an 8-bit immediate first


def width_reset():
    """Native, 16-bit A, then two calls. The language flows the CALLER's M=0 into $8007 and
    $800A, so without the analyzer the continuation's LDA #$12 and the second callee's CMP #$73
    both decode as 3-byte immediates."""
    return bytes([
        0x18,                        # 8000 CLC
        0xFB,                        # 8001 XCE          ; native
        0xC2, 0x30,                  # 8002 REP #$30     ; 16-bit A and index
        0x20, 0x40, 0x80,            # 8004 JSR $8040    ; leaves M=1
        0x20, 0x50, 0x80,            # 8007 JSR $8050    ; needs M=1 (entry consensus)
        0xA9, 0x12,                  # 800A LDA #$12     ; 8-bit immediate
        0x85, 0x10,                  # 800C STA $10
        0x80, 0xFE,                  # 800E BRA *
    ])


def width_cartridge(title):
    image = bytearray(cartridge(title))
    image[0:0x20] = b"\xEA" * 0x20
    image[0:len(width_reset())] = width_reset()
    image[WIDTH_SETS8 - 0x8000:WIDTH_SETS8 - 0x8000 + 3] = bytes([0xE2, 0x20, 0x60])
    image[WIDTH_NEEDS8 - 0x8000:WIDTH_NEEDS8 - 0x8000 + 7] = bytes(
        [0xC9, 0x73, 0xD0, 0x02, 0xEA, 0xEA, 0x60])
    # The shared vector table keeps NMI at $8020 / IRQ_EMU at $8030 (both outside this code).
    assert image[0:16] == width_reset()
    assert image[0x40:0x43] == bytes([0xE2, 0x20, 0x60])
    assert image[0x50:0x57] == bytes([0xC9, 0x73, 0xD0, 0x02, 0xEA, 0xEA, 0x60])
    return bytes(image)


def interleaved_hirom(title):
    """A 128 KiB HiROM image (logical layout), then stored with each 64 KiB unit's halves swapped."""
    size = 0x20000
    logical = bytearray(b"\xEE" * size)
    logical[RESET:RESET + len(code())] = code()      # logical $8000 = mirror of $C0:8000
    logical[NMI:NMI + len(nmi_handler())] = nmi_handler()
    logical[IRQ_EMU] = 0x40          # RTI

    at = 0xFFC0
    logical[at:at + 21] = title.ljust(21).encode("ascii")
    logical[at + 0x15] = 0x31        # map mode: HiROM, FastROM
    logical[at + 0x16] = 0x00
    logical[at + 0x17] = 0x07        # 128 KiB
    logical[at + 0x18] = 0x00
    checksum = 0x1234
    logical[at + 0x1C] = (checksum ^ 0xFFFF) & 0xFF
    logical[at + 0x1D] = ((checksum ^ 0xFFFF) >> 8) & 0xFF
    logical[at + 0x1E] = checksum & 0xFF
    logical[at + 0x1F] = (checksum >> 8) & 0xFF
    write_vectors(logical, at + 0x20)

    stored = bytearray(size)
    for unit in range(0, size, 0x10000):
        stored[unit:unit + 0x8000] = logical[unit + 0x8000:unit + 0x10000]
        stored[unit + 0x8000:unit + 0x10000] = logical[unit:unit + 0x8000]
    return bytes(stored)


def main():
    outdir = bankgen.outdir_arg(__file__)

    plain = cartridge("SNESTEST LOROM")
    bankgen.write_bytes(outdir, "snestest.smc", plain)

    # The same cartridge behind a copier header: the loader must detect it from the file size
    # and read every offset past it, producing an otherwise identical program.
    bankgen.write_bytes(outdir, "snestestcopier.smc", b"\x00" * 0x200 + cartridge("SNESTEST COPIER"))

    # grm-9nxj.19: an INTERLEAVED HiROM cartridge (the 32 KiB halves of each 64 KiB unit
    # swapped, as a copier may have dumped it). The loader's Auto layout must find the header
    # at logical $FFC0 (stored at $7FC0, the LoROM position) and de-interleave, so the program
    # is a HiROM one whose reset code is at $C0:8000 -- stored at FILE offset 0.
    bankgen.write_bytes(outdir, "snestestinterleaved.smc", interleaved_hirom("SNESTEST INTERLEAVED"))

    # grm-9nxj.5.3: call-width repair (continuation and callee entry).
    bankgen.write_bytes(outdir, "sneswidth.smc", width_cartridge("SNESWIDTH"))

    print("wrote SNES LoROM fixtures (plain and copier-headered) and an interleaved HiROM one to " + outdir)


if __name__ == "__main__":
    main()
