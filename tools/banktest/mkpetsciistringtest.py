#!/usr/bin/env python3
"""Hand-assembles the PetsciiStringAnalyzer regression PRG (bead grm-1.4.4).

Usage: mkpetsciistringtest.py <output-dir>

Writes petsciistringtest.prg (2-byte little-endian load-address header, a
one-instruction RTS stub, then a labeled PETSCII data section) into
<output-dir>. No dependencies beyond Python 3.

The data section exercises (descriptor: machines/c64.yaml system.text,
variant unshifted_graphics, min_length 4):
  - STR_A: a null-terminated PETSCII run of uppercase letters/digits, exactly
    min_length (4) long -- short enough that Ghidra's own ASCII Strings
    analyzer (default minimum length 5) does not also claim it, so the only
    typed data at this address is PetsciiStringAnalyzer's.
  - STR_B: an unterminated PETSCII run (ends at a non-zero, non-matching
    byte) exactly min_length long -- proves fixed-length typing; ASCII's
    analyzer requires null termination by default, so it never touches an
    unterminated run regardless of length.
  - STR_C: a 3-byte decoy (below min_length) that must stay untyped.
  - STR_D: a run of bytes outside the PETSCII printable/identity range
    (0x61-0x64, below PETSCII's 0x20-0x5F band) that must never match the
    recognizer, proving the graphics/control negative case.
  - STR_E: an unterminated ASCII-range punctuation/digit run ("1,2;3"),
    proving punctuation/digits count as PETSCII text same as letters.

Each string is bounded by a single 0x80 separator byte (outside both the
PETSCII recognizer's range and ASCII's range) so adjacent runs never merge
into one sequence.

The per-criterion checks live in VerifyBankTest.java; the golden behavior
dump lives in expected/petsciistringtest.dump.
"""

import sys
import os

LOAD_ADDR = 0x2000

SEPARATOR = 0x80


def prg(code_bytes):
    """Prefix code with the 2-byte little-endian load address header."""
    return bytes([LOAD_ADDR & 0xFF, LOAD_ADDR >> 8]) + bytes(code_bytes)


def build():
    out = bytearray()
    labels = {}

    def emit(name, data_bytes):
        labels[name] = LOAD_ADDR + len(out)
        out.extend(data_bytes)

    # Tiny ML stub: RTS. The loader marks a function here (non-BASIC-start
    # PRG); disassembly stops immediately, leaving the data section below
    # untouched (undefined) for the analyzer to type.
    emit("entry", [0x60])

    # STR_A: null-terminated "TEST" (4 chars == min_length; ASCII's own
    # analyzer needs >= 5, so it never claims this address).
    emit("str_a", [ord(c) for c in "TEST"] + [0x00])

    # STR_B: unterminated "ABCD" (4 chars), followed by a non-zero,
    # non-matching separator byte -- fixed-length typing, no terminator.
    emit("str_b", [ord(c) for c in "ABCD"])
    emit("sep1", [SEPARATOR])

    # STR_C: 3-byte decoy ("HI!"), below min_length -- must stay untyped.
    emit("str_c", [ord(c) for c in "HI!"])
    emit("sep2", [SEPARATOR])

    # STR_D: graphics/control bytes outside the PETSCII recognizer's
    # 0x20-0x5F band -- must never be detected, regardless of variant.
    emit("str_d", [0x61, 0x62, 0x63, 0x64])
    emit("sep3", [SEPARATOR])

    # STR_E: unterminated ASCII-range punctuation/digit run, 5 chars.
    emit("str_e", [ord(c) for c in "1,2;3"])
    emit("sep4", [SEPARATOR])

    return bytes(out), labels


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkpetsciistringtest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    code, labels = build()
    path = os.path.join(outdir, "petsciistringtest.prg")
    with open(path, "wb") as f:
        f.write(prg(code))
    print("wrote %s (%d bytes); labels: %s" %
          (path, 2 + len(code),
           ", ".join("%s=$%04X" % (name, addr) for name, addr in labels.items())))


if __name__ == "__main__":
    main()
