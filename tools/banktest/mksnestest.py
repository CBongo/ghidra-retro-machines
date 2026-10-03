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

LOROM_HEADER_AT = 0x7FC0
BANK_SIZE = 0x8000
IMAGE_BANKS = 2                      # 64 KiB: two LoROM banks, enough for a mirror pair
RESET = 0x8000


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


def cartridge(title):
    image = bytearray(b"\xEE" * (BANK_SIZE * IMAGE_BANKS))
    image[RESET - 0x8000:RESET - 0x8000 + len(code())] = code()

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

    # Vector table at $FFE0 (header + 0x20). Only RESET is meaningful here.
    vectors = at + 0x20
    image[vectors + 0x1C] = RESET & 0xFF
    image[vectors + 0x1D] = (RESET >> 8) & 0xFF
    return bytes(image)


def interleaved_hirom(title):
    """A 128 KiB HiROM image (logical layout), then stored with each 64 KiB unit's halves swapped."""
    size = 0x20000
    logical = bytearray(b"\xEE" * size)
    logical[RESET:RESET + len(code())] = code()      # logical $8000 = mirror of $C0:8000

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
    vectors = at + 0x20
    logical[vectors + 0x1C] = RESET & 0xFF
    logical[vectors + 0x1D] = (RESET >> 8) & 0xFF

    stored = bytearray(size)
    for unit in range(0, size, 0x10000):
        stored[unit:unit + 0x8000] = logical[unit + 0x8000:unit + 0x10000]
        stored[unit + 0x8000:unit + 0x10000] = logical[unit:unit + 0x8000]
    return bytes(stored)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mksnestest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    plain = cartridge("SNESTEST LOROM")
    with open(os.path.join(outdir, "snestest.smc"), "wb") as f:
        f.write(plain)

    # The same cartridge behind a copier header: the loader must detect it from the file size
    # and read every offset past it, producing an otherwise identical program.
    with open(os.path.join(outdir, "snestestcopier.smc"), "wb") as f:
        f.write(b"\x00" * 0x200 + cartridge("SNESTEST COPIER"))

    # grm-9nxj.19: an INTERLEAVED HiROM cartridge (the 32 KiB halves of each 64 KiB unit
    # swapped, as a copier may have dumped it). The loader's Auto layout must find the header
    # at logical $FFC0 (stored at $7FC0, the LoROM position) and de-interleave, so the program
    # is a HiROM one whose reset code is at $C0:8000 -- stored at FILE offset 0.
    with open(os.path.join(outdir, "snestestinterleaved.smc"), "wb") as f:
        f.write(interleaved_hirom("SNESTEST INTERLEAVED"))

    print("wrote SNES LoROM fixtures (plain and copier-headered) and an interleaved HiROM one to " + outdir)


if __name__ == "__main__":
    main()
