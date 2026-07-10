#!/usr/bin/env python3
"""Hand-assembles the two C64 banking-analyzer regression PRGs.

Usage: mkbanktest.py <output-dir>

Writes banktest.prg and banktest2.prg (2-byte little-endian load-address
header, then code) into <output-dir>. No dependencies beyond Python 3.

These programs exercise C64BankingAnalyzer's forward per-bit dataflow of the
$01 bank state, the masked-RMW backward scan, partial-knowledge comments,
unknown-state WARNING bookmarks, and overlay reference retargeting. The
per-criterion checks live in VerifyBankTest.java; the golden behavior dumps
live in expected/.
"""

import sys
import os

LOAD_ADDR = 0x0801


def prg(code_bytes):
    """Prefix code with the 2-byte little-endian load address header."""
    return bytes([LOAD_ADDR & 0xFF, LOAD_ADDR >> 8]) + bytes(code_bytes)


# ---------------------------------------------------------------------------
# banktest.prg -- basic reference retargeting (load $0801)
#
# 0801  A9 37     LDA #$37
# 0803  85 01     STA $01      ; bank -> 7 (fully known; same as initial)
# 0805  8D 00 A0  STA $A000    ; C3: write under BASIC ROM -> RAM_A000 overlay
# 0808  20 D2 FF  JSR $FFD2    ; C4: KERNAL is home in state 7 -> untouched
# 080B  A9 35     LDA #$35
# 080D  85 01     STA $01      ; bank -> 5
# 080F  AD 00 A0  LDA $A000    ; C1: read -> RAM_A000 overlay, primary
# 0812  8D 00 E0  STA $E000    ; C2: write -> RAM_E000 overlay
# 0815  60        RTS
# ---------------------------------------------------------------------------
BANKTEST = [
    0xA9, 0x37,          # LDA #$37
    0x85, 0x01,          # STA $01
    0x8D, 0x00, 0xA0,    # STA $A000
    0x20, 0xD2, 0xFF,    # JSR $FFD2
    0xA9, 0x35,          # LDA #$35
    0x85, 0x01,          # STA $01
    0xAD, 0x00, 0xA0,    # LDA $A000
    0x8D, 0x00, 0xE0,    # STA $E000
    0x60,                # RTS
]

# ---------------------------------------------------------------------------
# banktest2.prg -- masked-RMW resolution, partial knowledge, warnings, merge
# (load $0801)
#
# 0801  A9 35     LDA #$35
# 0803  85 01     STA $01      ; bank -> 5 (known)
# 0805  A5 01     LDA $01
# 0807  29 FE     AND #$FE
# 0809  85 01     STA $01      ; C1: in-state fallback resolves exactly -> bank -> 4
# 080B  A5 01     LDA $01
# 080D  29 F8     AND #$F8
# 080F  09 05     ORA #$05
# 0811  85 01     STA $01      ; C2: mask algebra alone -> bank -> 5
# 0813  AD 00 04  LDA $0400
# 0816  85 01     STA $01      ; C3: undeterminable -> WARNING, no comment
# 0818  A5 01     LDA $01
# 081A  09 04     ORA #$04
# 081C  85 01     STA $01      ; C4: partial -> bank -> 7? [known: CHAREN=1; ...]
# 081E  A9 35     LDA #$35
# 0820  20 43 08  JSR $0843    ; sub
# 0823  85 01     STA $01      ; C5: call clobbers pending immediate -> WARNING
# 0825  A5 01     LDA $01
# 0827  A2 34     LDX #$34
# 0829  86 01     STX $01      ; bank -> 4 (STX immediate, fully known)
# 082B  09 02     ORA #$02
# 082D  85 01     STA $01      ; C6: backward scan crosses STX $01 -> must NOT
#                              ;     inherit in-state; partial [known: HIRAM=1;...]
# 082F  AD 02 04  LDA $0402
# 0832  F0 07     BEQ $083B    ; pathb
# 0834  A9 35     LDA #$35     ; patha
# 0836  85 01     STA $01      ; bank -> 5
# 0838  4C 3F 08  JMP $083F    ; join
# 083B  A9 34     LDA #$34     ; pathb
# 083D  85 01     STA $01      ; bank -> 4
# 083F  AD 00 A0  LDA $A000    ; C7 (join): merge keeps agreeing bits
#                              ;     (5 vs 4 agree HIRAM=0, CHAREN=1); effective 5
#                              ;     -> RAM_A000 overlay READ ref
# 0842  60        RTS
# 0843  60        RTS          ; sub
# ---------------------------------------------------------------------------
BANKTEST2 = [
    0xA9, 0x35,          # 0801 LDA #$35
    0x85, 0x01,          # 0803 STA $01
    0xA5, 0x01,          # 0805 LDA $01
    0x29, 0xFE,          # 0807 AND #$FE
    0x85, 0x01,          # 0809 STA $01      (C1)
    0xA5, 0x01,          # 080B LDA $01
    0x29, 0xF8,          # 080D AND #$F8
    0x09, 0x05,          # 080F ORA #$05
    0x85, 0x01,          # 0811 STA $01      (C2)
    0xAD, 0x00, 0x04,    # 0813 LDA $0400
    0x85, 0x01,          # 0816 STA $01      (C3)
    0xA5, 0x01,          # 0818 LDA $01
    0x09, 0x04,          # 081A ORA #$04
    0x85, 0x01,          # 081C STA $01      (C4)
    0xA9, 0x35,          # 081E LDA #$35
    0x20, 0x43, 0x08,    # 0820 JSR $0843
    0x85, 0x01,          # 0823 STA $01      (C5)
    0xA5, 0x01,          # 0825 LDA $01
    0xA2, 0x34,          # 0827 LDX #$34
    0x86, 0x01,          # 0829 STX $01
    0x09, 0x02,          # 082B ORA #$02
    0x85, 0x01,          # 082D STA $01      (C6)
    0xAD, 0x02, 0x04,    # 082F LDA $0402
    0xF0, 0x07,          # 0832 BEQ $083B
    0xA9, 0x35,          # 0834 LDA #$35
    0x85, 0x01,          # 0836 STA $01
    0x4C, 0x3F, 0x08,    # 0838 JMP $083F
    0xA9, 0x34,          # 083B LDA #$34
    0x85, 0x01,          # 083D STA $01
    0xAD, 0x00, 0xA0,    # 083F LDA $A000    (C7)
    0x60,                # 0842 RTS
    0x60,                # 0843 RTS (sub)
]


# ---------------------------------------------------------------------------
# banktest3.prg -- the two P1 value-recovery fixes (beads grm-5tl.1 / grm-5tl.2)
# (load $0801)
#
# 0801  A2 34     LDX #$34     ; bank arg 4 ($34 & 7) in X
# 0803  A9 AA     LDA #$AA     ; unrelated immediate in A ($AA & 7 = 2)
# 0805  20 12 08  JSR $0812    ; B1: helper takes bank in X (STX $01); the recovered
#                              ;     bank must come from X (4), NOT the A-first guess (2)
# 0808  AD 04 04  LDA $0404    ; condition (A undetermined on the taken path)
# 080B  F0 02     BEQ $080F    ; -> join store, skipping the LDA #$36
# 080D  A9 36     LDA #$36     ; fall-through path: A=$36
# 080F  85 01     STA $01      ; A1: branch-join store -- reached with A=$36 (fall) and
#                              ;     A=undetermined (taken); must be ambiguous -> WARNING,
#                              ;     NOT a confident fold of $36 ("bank -> 6")
# 0811  60        RTS
# 0812  86 01     STX $01      ; helper body: bank field is the caller's X -> caller-supplied
# 0814  60        RTS
# ---------------------------------------------------------------------------
BANKTEST3 = [
    0xA2, 0x34,          # 0801 LDX #$34
    0xA9, 0xAA,          # 0803 LDA #$AA
    0x20, 0x12, 0x08,    # 0805 JSR $0812
    0xAD, 0x04, 0x04,    # 0808 LDA $0404
    0xF0, 0x02,          # 080B BEQ $080F
    0xA9, 0x36,          # 080D LDA #$36
    0x85, 0x01,          # 080F STA $01      (A1)
    0x60,                # 0811 RTS
    0x86, 0x01,          # 0812 STX $01      (B1 helper body)
    0x60,                # 0814 RTS
]


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: mkbanktest.py <output-dir>")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    for name, code in (("banktest.prg", BANKTEST), ("banktest2.prg", BANKTEST2),
                       ("banktest3.prg", BANKTEST3)):
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(prg(code))
        print("wrote %s (%d bytes)" % (path, 2 + len(code)))

    # Sanity-check the hand-computed branch/jump targets in BANKTEST2.
    assert BANKTEST2[0x0832 - LOAD_ADDR] == 0xF0
    assert (0x0834 + BANKTEST2[0x0833 - LOAD_ADDR]) == 0x083B  # BEQ -> pathb
    assert BANKTEST2[0x0838 - LOAD_ADDR] == 0x4C
    assert BANKTEST2[0x0839 - LOAD_ADDR] | (BANKTEST2[0x083A - LOAD_ADDR] << 8) == 0x083F
    assert BANKTEST2[0x0820 - LOAD_ADDR] == 0x20
    assert BANKTEST2[0x0821 - LOAD_ADDR] | (BANKTEST2[0x0822 - LOAD_ADDR] << 8) == 0x0843
    assert BANKTEST2[0x0843 - LOAD_ADDR] == 0x60

    # Sanity-check banktest3's JSR/branch targets.
    assert BANKTEST3[0x0805 - LOAD_ADDR] == 0x20  # JSR
    assert BANKTEST3[0x0806 - LOAD_ADDR] | (BANKTEST3[0x0807 - LOAD_ADDR] << 8) == 0x0812
    assert BANKTEST3[0x080B - LOAD_ADDR] == 0xF0  # BEQ
    assert (0x080D + BANKTEST3[0x080C - LOAD_ADDR]) == 0x080F  # BEQ -> join store
    assert BANKTEST3[0x0812 - LOAD_ADDR] == 0x86  # STX $01 (helper body)


if __name__ == "__main__":
    main()
