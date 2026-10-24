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
TRAMP_RAM = 0x0108                   # RAM trampoline the reset code fills (bead grm-9nxj.5.6)
TRAMP_HANDLER = 0x8040               # where the trampoline's JML lands
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


def tramp_code():
    """Reset code for the RAM-trampoline cartridge: native mode, 8-bit registers, write
    JML $00:8040 into $0108..$010B with immediate stores, enable NMI, then park on WAI."""
    return bytes([
        0x18,                        # CLC
        0xFB,                        # XCE          ; -> native mode
        0xE2, 0x30,                  # SEP #$30
        0xA9, 0x5C, 0x8D, 0x08, 0x01,  # LDA #$5C : STA $0108   ; JML opcode
        0xA9, 0x40, 0x8D, 0x09, 0x01,  # LDA #$40 : STA $0109   ; target low
        0xA9, 0x80, 0x8D, 0x0A, 0x01,  # LDA #$80 : STA $010A   ; target high
        0xA9, 0x00, 0x8D, 0x0B, 0x01,  # LDA #$00 : STA $010B   ; target bank
        0xA9, 0x80, 0x8D, 0x00, 0x42,  # LDA #$80 : STA $4200   ; NMITIMEN: enable NMI
        0xCB,                        # WAI
        0x80, 0xFD,                  # BRA -3       ; back to the WAI
    ])


def tramp_cartridge(title):
    """LoROM 64 KiB whose native NMI vector points at RAM $0108 (JML $008040, written by the
    reset code); only RESET and that vector are set, every other slot holds $FFFF."""
    image = bytearray(cartridge(title))
    image[RESET - 0x8000:RESET - 0x8000 + 0x40] = b"\xEE" * 0x40     # clear the plain fixture's code
    image[RESET - 0x8000:RESET - 0x8000 + len(tramp_code())] = tramp_code()
    image[NMI - 0x8000:NMI - 0x8000 + 0x20] = b"\xEE" * 0x20
    image[IRQ_EMU - 0x8000:IRQ_EMU - 0x8000 + 1] = b"\xEE"
    image[TRAMP_HANDLER - 0x8000:TRAMP_HANDLER - 0x8000 + len(nmi_handler())] = nmi_handler()
    vectors = LOROM_HEADER_AT + 0x20
    for off, target in {0x04: UNUSED, 0x06: UNUSED, 0x08: UNUSED, 0x0A: TRAMP_RAM, 0x0E: UNUSED,
                        0x14: UNUSED, 0x18: UNUSED, 0x1A: UNUSED, 0x1C: RESET,
                        0x1E: UNUSED}.items():
        image[vectors + off] = target & 0xFF
        image[vectors + off + 1] = (target >> 8) & 0xFF
    # Byte-level self-check (a typo'd operand would otherwise be blessed into the golden).
    r = RESET - 0x8000
    assert bytes(image[r:r + 4]) == bytes([0x18, 0xFB, 0xE2, 0x30])
    stores = [(0x5C, 0x0108), (0x40, 0x0109), (0x80, 0x010A), (0x00, 0x010B)]
    for i, (val, addr) in enumerate(stores):
        o = r + 4 + i * 5
        assert bytes(image[o:o + 5]) == bytes([0xA9, val, 0x8D, addr & 0xFF, addr >> 8]), i
    # the four stored bytes spell JML $008040 at $0108
    assert [v for v, _ in stores] == [0x5C, TRAMP_HANDLER & 0xFF, TRAMP_HANDLER >> 8, 0x00]
    assert bytes(image[r + 24:r + 29]) == bytes([0xA9, 0x80, 0x8D, 0x00, 0x42])
    assert bytes(image[r + 29:r + 32]) == bytes([0xCB, 0x80, 0xFD])
    h = TRAMP_HANDLER - 0x8000
    assert bytes(image[h:h + 6]) == bytes([0xC2, 0x30, 0xA9, 0x34, 0x12, 0x40])
    v = LOROM_HEADER_AT + 0x20
    assert bytes(image[v + 0x0A:v + 0x0C]) == bytes([0x08, 0x01])
    assert bytes(image[v + 0x1C:v + 0x1E]) == bytes([0x00, 0x80])
    return bytes(image)


TRAMP2_HANDLER_A = 0x80A0
TRAMP2_HANDLER_B = 0x80C0


def tramp2_code():
    """Reset code that installs SEVERAL handlers into the one trampoline, plus things the
    scanner must skip: an RTL ('disabled') store, a group whose target is RAM ($7E:1234), and a
    store of an unknown value. Group B writes its operand with a 16-bit STX."""
    def st8(val, addr):
        return [0xA9, val, 0x8D, addr & 0xFF, addr >> 8]
    c = [0x18, 0xFB, 0xE2, 0x30]
    for i, v in enumerate([0x5C, 0xA0, 0x80, 0x00]):          # group A: JML $0080A0
        c += st8(v, TRAMP_RAM + i)
    c += st8(0x6B, TRAMP_RAM)                                  # RTL: handler disabled
    c += st8(0x5C, TRAMP_RAM)                                  # group B: JML $0080C0
    c += [0xC2, 0x10, 0xA2, 0xC0, 0x80, 0x8E, 0x09, 0x01, 0xE2, 0x10]   # REP #$10 LDX #$80C0 STX $0109 SEP #$10
    c += st8(0x00, TRAMP_RAM + 3)
    for i, v in enumerate([0x5C, 0x34, 0x12, 0x7E]):          # group C: JML $7E1234 (RAM, excluded)
        c += st8(v, TRAMP_RAM + i)
    c += [0xAD, 0x40, 0x21, 0x8D, 0x08, 0x01]                  # LDA $2140 : STA $0108 (unknown value)
    c += [0x80, 0xFE]                                          # park
    return bytes(c)


def tramp2_cartridge(title):
    """Like tramp_cartridge, but the reset code installs two different handlers."""
    image = bytearray(cartridge(title))
    image[RESET - 0x8000:RESET - 0x8000 + 0xA0] = b"\xEE" * 0xA0     # clear the plain fixture's code
    image[RESET - 0x8000:RESET - 0x8000 + len(tramp2_code())] = tramp2_code()
    image[TRAMP2_HANDLER_A - 0x8000:TRAMP2_HANDLER_A - 0x8000 + len(nmi_handler())] = nmi_handler()
    handler_b = bytes([0xC2, 0x30, 0xA2, 0x01, 0x00, 0x40])        # REP #$30 / LDX #$0001 / RTI
    image[TRAMP2_HANDLER_B - 0x8000:TRAMP2_HANDLER_B - 0x8000 + len(handler_b)] = handler_b
    vectors = LOROM_HEADER_AT + 0x20
    for off, target in {0x04: UNUSED, 0x06: UNUSED, 0x08: UNUSED, 0x0A: TRAMP_RAM, 0x0E: UNUSED,
                        0x14: UNUSED, 0x18: UNUSED, 0x1A: UNUSED, 0x1C: RESET,
                        0x1E: UNUSED}.items():
        image[vectors + off] = target & 0xFF
        image[vectors + off + 1] = (target >> 8) & 0xFF
    # Byte-level self-check.
    r = RESET - 0x8000
    code = tramp2_code()
    assert bytes(image[r:r + len(code)]) == code
    assert code[4:9] == bytes([0xA9, 0x5C, 0x8D, 0x08, 0x01])           # group A opcode
    assert code[24:29] == bytes([0xA9, 0x6B, 0x8D, 0x08, 0x01])         # RTL store
    assert code.count(bytes([0x8E, 0x09, 0x01])) == 1                   # the 16-bit STX
    assert code.count(bytes([0xA9, 0x7E])) == 1                          # group C bank byte
    assert code[9:14] == bytes([0xA9, 0xA0, 0x8D, 0x09, 0x01])          # group A operand lo
    assert code[14:19] == bytes([0xA9, 0x80, 0x8D, 0x0A, 0x01])
    assert bytes([0xA2, 0xC0, 0x80, 0x8E, 0x09, 0x01]) in code          # group B: LDX/STX
    assert len(code) < TRAMP2_HANDLER_A - RESET
    h = TRAMP2_HANDLER_A - 0x8000
    assert bytes(image[h:h + 6]) == bytes([0xC2, 0x30, 0xA9, 0x34, 0x12, 0x40])
    b = TRAMP2_HANDLER_B - 0x8000
    assert bytes(image[b:b + 6]) == handler_b
    v = LOROM_HEADER_AT + 0x20
    assert bytes(image[v + 0x0A:v + 0x0C]) == bytes([0x08, 0x01])
    assert bytes(image[v + 0x1C:v + 0x1E]) == bytes([0x00, 0x80])
    return bytes(image)


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


# grm-9nxj.5.4: jump-table targets recovered and decoded at the dispatch's width.
JTAB_MASKED = 0x8060                 # JSR ($8060,X) table: AND #$03 caps it at 4 entries
JTAB_HANDLERS = [0x8070, 0x8078, 0x8080, 0x8088]
JTAB_DECOY = 0x8090                  # a 5th word that LOOKS like an entry, past the mask
JTAB_LOWEST = 0x80A0                 # JMP ($80A0,X) table: ends at its own lowest target
JTAB_LOWEST_HANDLERS = [0x80A6, 0x80AC, 0x80B2]


def jtab_reset():
    """Native, 8-bit A and 16-bit index, then two dispatches. Neither table's targets are
    reached by anything else, so without the analyzer none of them is decoded at all."""
    return bytes([
        0x18,                        # 8000 CLC
        0xFB,                        # 8001 XCE           ; native
        0xC2, 0x30,                  # 8002 REP #$30
        0xE2, 0x20,                  # 8004 SEP #$20      ; M=1 X=0
        0xA5, 0x10,                  # 8006 LDA $10
        0x29, 0x03,                  # 8008 AND #$03      ; index 0..3
        0x0A,                        # 800A ASL A
        0xAA,                        # 800B TAX
        0xFC, 0x60, 0x80,            # 800C JSR ($8060,X)
        0xA5, 0x11,                  # 800F LDA $11       ; unbounded index
        0x0A,                        # 8011 ASL A
        0xAA,                        # 8012 TAX
        0x7C, 0xA0, 0x80,            # 8013 JMP ($80A0,X)
    ])


def le16(v):
    return bytes([v & 0xFF, (v >> 8) & 0xFF])


def jtab_cartridge(title):
    image = bytearray(cartridge(title))
    image[0:0x20] = b"\xEA" * 0x20
    image[0:len(jtab_reset())] = jtab_reset()
    o = JTAB_MASKED - 0x8000
    image[o:o + 10] = b"".join(le16(h) for h in JTAB_HANDLERS + [JTAB_DECOY])
    # Each handler starts with an accumulator immediate: two bytes at M=1, three at M=0.
    for i, h in enumerate(JTAB_HANDLERS + [JTAB_DECOY]):
        image[h - 0x8000:h - 0x8000 + 5] = bytes([0xA9, 0x12 + i, 0x85, 0x20, 0x60])
    o = JTAB_LOWEST - 0x8000
    image[o:o + 6] = b"".join(le16(h) for h in JTAB_LOWEST_HANDLERS)
    for i, h in enumerate(JTAB_LOWEST_HANDLERS):
        # LDA #imm / STA $22 / BRA * -- six bytes, so the handlers abut.
        image[h - 0x8000:h - 0x8000 + 6] = bytes([0xA9, 0x21 + i, 0x85, 0x22, 0x80, 0xFE])
    assert image[0:len(jtab_reset())] == jtab_reset()
    assert image[0x20] != 0xEA       # the NMI handler at $8020 is untouched
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
    # grm-9nxj.5.4: JSR/JMP (abs,X) tables recovered, bounded, and decoded at the dispatch width.
    bankgen.write_bytes(outdir, "snesjtab.smc", jtab_cartridge("SNESJTAB"))
    # grm-9nxj.5.6: the native NMI vector points at RAM ($0108) that the reset code fills with
    # JML $008040; the analyzer must find $8040 from those constant stores and seed it as the NMI handler.
    bankgen.write_bytes(outdir, "snestramp.smc", tramp_cartridge("SNESTEST TRAMP"))

    # Several handlers installed into the same trampoline (each a real handler at some phase),
    # an RTL "disabled" store and a RAM-target group that must be skipped.
    bankgen.write_bytes(outdir, "snestramp2.smc", tramp2_cartridge("SNESTEST TRAMP2"))

    print("wrote SNES LoROM fixtures (plain and copier-headered) and an interleaved HiROM one to " + outdir)


if __name__ == "__main__":
    main()
