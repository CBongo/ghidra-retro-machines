#!/usr/bin/env python3
"""Hand-assembles the C64BasicAnalyzer regression PRG (bead grm-odt.1).

Usage: mkbasictest.py <output-dir>

Writes c64basictest.prg (2-byte little-endian load-address header, then a
hand-tokenized BASIC V2 program, then a tiny machine-language routine) into
<output-dir>. No dependencies beyond Python 3.

The program exercises:
  - a FOR/TO line with the "=" operator token (multi-token, non-string line)
  - a PRINT line with a quoted string containing a control-code byte ({clr},
    $93) and a byte >= $80 that is NOT a token because it is inside quotes
    (proves the "everything inside quotes is raw PETSCII" rule)
  - a REM line whose body contains a byte that collides with a real token
    value ($99, PRINT's token elsewhere) and a literal quote character,
    proving REM's rest-of-line-is-raw-PETSCII handling (no tokenizing, no
    quote-toggle) rather than crashing or mis-rendering
  - a DATA line followed by a colon and more (re-tokenized) statement text,
    proving DATA gets no special raw-text treatment (real BASIC 2 tokenizes
    DATA argument text like anywhere else outside quotes -- see
    C64BasicAnalyzer's class comment)
  - a SYS line with a decimal literal address, followed immediately by a
    tiny machine-language routine at that exact address (JSR to a
    sub-routine, then RTS), so C64BasicAnalyzer's SYS-target function mark
    can be checked against real disassemblable code

The per-criterion checks live in VerifyBankTest.java; the golden behavior
dump lives in expected/c64basictest.dump.
"""

import sys
import os

LOAD_ADDR = 0x0801


def prg(code_bytes):
    """Prefix code with the 2-byte little-endian load address header."""
    return bytes([LOAD_ADDR & 0xFF, LOAD_ADDR >> 8]) + bytes(code_bytes)


def line_bytes(line_number, text_bytes):
    """Text bytes (no link) for one BASIC line: line number + text + $00
    terminator. The link is filled in later once addresses are known."""
    return bytes([line_number & 0xFF, line_number >> 8]) + bytes(text_bytes) + bytes([0x00])


# ---------------------------------------------------------------------------
# Line bodies (line number + tokenized text + terminator; link filled in below)
# ---------------------------------------------------------------------------

# 10 FOR I=1 TO 10
LINE10 = line_bytes(10, [
    0x81,               # FOR
    0x20,               # ' '
    ord('I'),
    0xB2,               # '='
    ord('1'),
    0x20,               # ' '
    0xA4,               # TO
    0x20,               # ' '
    ord('1'), ord('0'),
])

# 20 PRINT"{clr}HI{$a0}"
LINE20 = line_bytes(20, [
    0x99,               # PRINT
    0x22,               # "
    0x93,               # {clr} control code, inside quotes -> literal, never a token
    ord('H'), ord('I'),
    0xA0,               # graphics byte >= $80, inside quotes -> literal, never a token
    0x22,               # "
])

# 30 REM<$99>"OK   (REM body: byte $99 collides with the PRINT token value but
# must render as its raw PETSCII control-code escape, not as "PRINT"; the
# quote byte must render literally too, with no quote-state toggle)
LINE30 = line_bytes(30, [
    0x8F,               # REM
    0x99,               # raw PETSCII (would be PRINT token if tokenizing were active)
    0x22,               # raw PETSCII "
    0x20, ord('O'), ord('K'),
])

# 40 DATA 1,2:PRINT 3  (colon continuation; PRINT after the colon is a real
# token -- DATA text is not specially protected from tokenizing)
LINE40 = line_bytes(40, [
    0x83,               # DATA
    0x20, ord('1'), ord(','), ord('2'),
    0x3A,               # :
    0x99,               # PRINT (re-tokenized after the colon)
    0x20, ord('3'),
])

# 50 SYS <addr> -- the decimal literal is patched in once the ML address is known.
SYS_PREFIX = bytes([0x9E, 0x20])  # SYS<space>

# ML routine placed immediately after the BASIC program's end-of-program
# terminator: JSR sub / RTS / sub: RTS.
ML_CODE = bytes([
    0x20, 0x00, 0x00,   # JSR sub (operand patched below once sub's address is known)
    0x60,               # RTS
    0x60,               # sub: RTS
])


def build():
    # Lay out LINE10..LINE40 first (their sizes are fixed and independent of
    # the SYS target address), tracking addresses as we go.
    addr = LOAD_ADDR
    bodies = [LINE10, LINE20, LINE30, LINE40]
    line_addrs = []
    for body in bodies:
        line_addrs.append(addr)
        addr += 2 + len(body)  # link(2) + (lineno+text+terminator)

    # LINE50 (the SYS line) starts here; its own size is fixed once we know the
    # SYS target is a 4-digit decimal address (true for any address in this
    # small fixture, which lands well under 10000).
    line50_addr = addr
    sys_text_len_before_ml = 2 + (2 + len(SYS_PREFIX) + 4 + 1)  # link+lineno+prefix+4digits+term
    ml_addr = line50_addr + sys_text_len_before_ml + 2  # +2 for the master end-of-program link
    assert 1000 <= ml_addr <= 9999, "fixture assumption: 4-digit SYS target"

    sys_digits = ("%04d" % ml_addr).encode("ascii")
    line50_text = bytes([50 & 0xFF, 50 >> 8]) + SYS_PREFIX + sys_digits + bytes([0x00])
    bodies.append(line50_text)
    line_addrs.append(line50_addr)

    # Now that every line's address is known, fill in each line's link field
    # (address of the next line) and append the master end-of-program link.
    out = bytearray()
    for i, (body, la) in enumerate(zip(bodies, line_addrs)):
        next_addr = line_addrs[i + 1] if i + 1 < len(bodies) else (ml_addr - 2)
        out += bytes([next_addr & 0xFF, next_addr >> 8])
        out += body
    out += bytes([0x00, 0x00])  # master end-of-program link

    assert LOAD_ADDR + len(out) == ml_addr, \
        "computed ML address does not match end of BASIC program bytes"

    sub_addr = ml_addr + 3 + 1  # past JSR(3) + RTS(1)
    ml = bytearray(ML_CODE)
    ml[1] = sub_addr & 0xFF
    ml[2] = sub_addr >> 8
    out += ml

    return bytes(out), ml_addr, sub_addr, line_addrs


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkbasictest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    code, ml_addr, sub_addr, line_addrs = build()
    path = os.path.join(outdir, "c64basictest.prg")
    with open(path, "wb") as f:
        f.write(prg(code))
    print("wrote %s (%d bytes); ML entry at $%04X (sub at $%04X); line addrs: %s" %
          (path, 2 + len(code), ml_addr, sub_addr,
           ", ".join("$%04X" % a for a in line_addrs)))


if __name__ == "__main__":
    main()
