#!/usr/bin/env python3
"""Generate C64 PRGs that exercise arbitrary-address and wrapping loads.

Usage: mkprgloadtest.py <output-dir>

The fixtures deliberately contain conspicuous marker bytes rather than useful
programs, except for c000emutest, which is a small in-place decrypt loop used to
prove that base-space code loaded at $C000 is visible to EmulationRecovery.
"""

import os
import sys

# mkemutest.py lives alongside this script. `python -I` does not put the script directory
# on sys.path, so add it explicitly before importing siblings.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bankgen  # noqa: E402
import mkemutest  # noqa: E402


def write_prg(outdir, name, load_address, payload):
    path = bankgen.write_prg(outdir, name, load_address, payload)
    print("wrote %s (%d payload bytes at $%04X)" %
          (path, len(payload), load_address))


def placement_payload():
    """$A000-$FFFF, crossing every banked window and base RAM $C000."""
    payload = bytearray([0x5a] * 0x6000)
    for address, marker in (
            (0xA000, b"A000"),
            (0xBFFC, b"BEND"),
            (0xC000, b"C000"),
            (0xCFFC, b"CEND"),
            (0xD000, b"D000"),
            (0xDFFC, b"DEND"),
            (0xE000, b"E000"),
            (0xFFFC, b"EEND")):
        offset = address - 0xA000
        payload[offset:offset + len(marker)] = marker
    return payload


def wrapping_payload():
    """$FFFC-$FFFF then $0000-$0303, including P6510 and low-RAM vectors."""
    payload = bytearray([0x77] * (4 + 0x304))
    payload[0:4] = bytes((0xfc, 0xfd, 0xfe, 0xff))
    payload[4:8] = bytes((0xd0, 0xd1, 0x02, 0x03))  # $0000-$0003
    payload[4 + 0x300:4 + 0x304] = b"VECT"          # $0300-$0303
    # grm-t3n.5: this payload runs over the KERNAL LOAD store pointer $AE/$AF, and a store
    # there steers the rest of the load. Keep the pointer's own bytes consistent with plain
    # sequential loading ($AE <- $AE so the INC leaves $AF; $AF <- 0 so the high byte stays 0).
    payload[4 + 0x93] = 0x00  # the verify flag $93 must stay clear or LOAD stops storing
    payload[4 + 0xAE] = 0xAE
    payload[4 + 0xAF] = 0x00
    return payload


def straddling_payload():
    """$FF00-$FFFF then 1 byte at $0000, straddling the P6510 DDR/PORT struct
    (grm-z15.2): the wrap places exactly the DDR byte ($0000) in an initialized
    block while PORT ($0001) stays uninitialized."""
    payload = bytearray([0x5a] * 0x100)
    payload[0xfc:0x100] = bytes((0xfc, 0xfd, 0xfe, 0xff))
    payload += bytes((0xdd,))  # wraps to $0000 -- P6510 DDR marker byte
    return payload


def no_wrap_payload():
    """2 bytes at $FFFE: ends exactly at $FFFF, no wrap (bead grm-gea)."""
    return bytes((0x10, 0x11))


def wrap_one_payload():
    """3 bytes at $FFFE: the 3rd byte wraps into $0000 (P6510 DDR), the
    minimal wrap case -- one byte over the no-wrap boundary (bead grm-gea)."""
    return bytes((0x10, 0x11, 0x12))


def full_space_payload():
    """Exactly 65536 (0x10000) bytes -- the largest payload a 16-bit CBM image
    can hold. Loaded at $0000 this fills the address space with no wrap (any
    other load address would wrap a full-length payload). Byte i is
    (i >> 8) & 0xFF, so -- since address == source offset when load_addr is 0
    -- the byte at any address directly encodes that address's high byte, and
    "source offsets preserved" reduces to reading a handful of addresses back
    (bead grm-gea)."""
    payload = bytearray(((i >> 8) & 0xff) for i in range(0x10000))
    # grm-t3n.5: the file covers the KERNAL LOAD store pointer $AE/$AF, so those two bytes must
    # keep it moving sequentially ($AE <- $AE, then the INC leaves $AF; $AF stays 0 = high byte).
    payload[0xAE] = 0xAE
    return bytes(payload)


def overflow_payload():
    """65537 (0x10001) bytes -- one byte over the 16-bit CBM image limit.
    AbstractCbmPrgLoader.load() rejects this outright (grm-gea); the load
    address is irrelevant since the length check runs before any placement,
    so $0000 keeps this fixture simple."""
    return bytes((i & 0xff) for i in range(0x10001))


def autostart_vector_payload():
    """$0326-$0342 (grm-w0j7): IBSOUT ($0326) = $0340, everything else zero (zero words are
    padding and must NOT yield entries), code at $0340: LDA #1 ; RTS."""
    payload = bytearray(0x340 + 3 - 0x326)
    payload[0:2] = bytes((0x40, 0x03))
    payload[0x340 - 0x326:] = bytes((0xa9, 0x01, 0x60))
    assert payload[-3:] == b"\xa9\x01\x60" and len(payload) == 0x1d
    return payload


def autostart_stack_payload():
    """$0100-$0202 (grm-w0j7): the whole stack page filled with the word $01FF (RTS target
    $0200), then code at $0200: LDA #2 ; RTS. The odd parity reads $FF01, so the loader must
    pick the candidate whose target is inside the PRG."""
    payload = bytearray()
    for i in range(0x100):
        payload.append(0xff if i % 2 == 0 else 0x01)
    payload += bytes((0xa9, 0x02, 0x60))
    assert len(payload) == 0x103
    return payload


def autostart_hardware_payload():
    """$FFFA-$FFFF (grm-w0j7): NMI=$FE43, RESET=$FCE2, IRQ=$FF48 -- all KERNAL addresses,
    i.e. OUTSIDE the PRG's own bytes (label + entry point, no function)."""
    return bytes((0x43, 0xfe, 0xe2, 0xfc, 0x48, 0xff))


def kload_redirect_payload():
    """Loaded at $00AC (grm-t3n.5): the file covers the KERNAL LOAD store pointer $AE/$AF, so
    it steers its own remaining bytes. +2 stores $AC at $AE (pointer back to $AD), +3 stores
    again at $AD (the later store wins over +1), +4 stores $AE at $AE (pointer to $AF),
    +5 stores $03 at $AF (pointer hi) so +6.. land at $03B0, not at $00B0."""
    return bytes((0x11, 0x12, 0xac, 0x13, 0xae, 0x03, 0xa9, 0x07, 0x60))


def main():
    outdir = bankgen.outdir_arg(__file__)
    write_prg(outdir, "autostartvectest.prg", 0x0326, autostart_vector_payload())
    write_prg(outdir, "autostartstacktest.prg", 0x0100, autostart_stack_payload())
    write_prg(outdir, "autostarthwtest.prg", 0xfffa, autostart_hardware_payload())
    write_prg(outdir, "kloadredirecttest.prg", 0x00ac, kload_redirect_payload())
    write_prg(outdir, "prgplacementtest.prg", 0xa000, placement_payload())
    write_prg(outdir, "prgwraptest.prg", 0xfffc, wrapping_payload())
    # grm-z15.2: 0x101-byte payload at $FF00 wraps exactly 1 byte to $0000,
    # straddling the P6510 R6510 struct (DDR@$0000 initialized, PORT@$0001 not).
    write_prg(outdir, "prgstraddletest.prg", 0xff00, straddling_payload())
    # bead grm-w8a: shares mkemutest.py's build() (parameterized by load address)
    # instead of duplicating the byte-identical-but-for-operand-bytes payload.
    write_prg(outdir, "c000emutest.prg", 0xc000, mkemutest.build(0xc000))
    # grm-z15.1: load address $0000 lands the entry point in the non-executable
    # P6510 io block -- proves an external entry point is still recorded there.
    write_prg(outdir, "prgentrytest.prg", 0x0000, bytes((0x01, 0x02, 0x03)))
    # grm-z15.1: a 2-byte PRG (load-address header only, zero payload) -- proves
    # the loader still builds the full memory map and labels the load address.
    write_prg(outdir, "prgemptytest.prg", 0x0801, b"")
    # grm-gea: exhaustive size/wrap-boundary coverage, following up grm-dvx.
    write_prg(outdir, "prgnowraptest.prg", 0xfffe, no_wrap_payload())
    write_prg(outdir, "prgwrap1test.prg", 0xfffe, wrap_one_payload())
    write_prg(outdir, "prgfulltest.prg", 0x0000, full_space_payload())
    write_prg(outdir, "prgoverflowtest.prg", 0x0000, overflow_payload())


if __name__ == "__main__":
    main()
