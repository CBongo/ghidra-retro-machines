#!/usr/bin/env python3
"""Minimal NMOS 6502 disassembler for reading the PINNED real-ROM images directly.

Usage:
  dis6502.py <rom.nes> <map> <start_hex> <end_hex>      disassemble [start, end)
  dis6502.py <rom.nes> <map> words <start_hex> <count>  dump little-endian words (tables)
  dis6502.py --find <row-id>                            print the image for a manifest row

<map> places PRG bytes in a 64 KiB CPU view:
  <n>               32 KiB PRG bank n at $8000-$FFFF (NROM/AxROM/MMC1 32K mode)
  o<off>@<addr>     PRG offset <off> placed at <addr>, both hex -- any bank size/window,
                    e.g. o3c000@8000 is MMC3 8K bank 30 at $8000, o34000@a000 bank 26 at $A000

--find matches the row's sha256 from tools/banktest/realrom/manifest*.tsv against every
.nes file (depth 1) in the space-separated dirs of $GRM_ROM_DIR. Run from the repo root.

Why this exists: a listing quoted in a bead, or a golden's sample, is not ground truth --
decode the image (see the disassemble-the-pinned-rom-before-trusting-a-listing bd memory).
Used for grm-2m07, grm-3er5, grm-ujj5, grm-h0oa. Undocumented opcodes print as .byte.
No dependencies beyond Python 3.
"""
import glob
import hashlib
import os
import sys

OPS = {}
def op(code, mn, mode):
    OPS[code] = (mn, mode)

MODES = {'imp': 1, 'acc': 1, 'imm': 2, 'zp': 2, 'zpx': 2, 'zpy': 2, 'izx': 2, 'izy': 2,
         'rel': 2, 'abs': 3, 'abx': 3, 'aby': 3, 'ind': 3}
table = """
00 BRK imp|01 ORA izx|05 ORA zp|06 ASL zp|08 PHP imp|09 ORA imm|0a ASL acc|0d ORA abs|0e ASL abs
10 BPL rel|11 ORA izy|15 ORA zpx|16 ASL zpx|18 CLC imp|19 ORA aby|1d ORA abx|1e ASL abx
20 JSR abs|21 AND izx|24 BIT zp|25 AND zp|26 ROL zp|28 PLP imp|29 AND imm|2a ROL acc|2c BIT abs|2d AND abs|2e ROL abs
30 BMI rel|31 AND izy|35 AND zpx|36 ROL zpx|38 SEC imp|39 AND aby|3d AND abx|3e ROL abx
40 RTI imp|41 EOR izx|45 EOR zp|46 LSR zp|48 PHA imp|49 EOR imm|4a LSR acc|4c JMP abs|4d EOR abs|4e LSR abs
50 BVC rel|51 EOR izy|55 EOR zpx|56 LSR zpx|58 CLI imp|59 EOR aby|5d EOR abx|5e LSR abx
60 RTS imp|61 ADC izx|65 ADC zp|66 ROR zp|68 PLA imp|69 ADC imm|6a ROR acc|6c JMP ind|6d ADC abs|6e ROR abs
70 BVS rel|71 ADC izy|75 ADC zpx|76 ROR zpx|78 SEI imp|79 ADC aby|7d ADC abx|7e ROR abx
81 STA izx|84 STY zp|85 STA zp|86 STX zp|88 DEY imp|8a TXA imp|8c STY abs|8d STA abs|8e STX abs
90 BCC rel|91 STA izy|94 STY zpx|95 STA zpx|96 STX zpy|98 TYA imp|99 STA aby|9a TXS imp|9d STA abx
a0 LDY imm|a1 LDA izx|a2 LDX imm|a4 LDY zp|a5 LDA zp|a6 LDX zp|a8 TAY imp|a9 LDA imm|aa TAX imp|ac LDY abs|ad LDA abs|ae LDX abs
b0 BCS rel|b1 LDA izy|b4 LDY zpx|b5 LDA zpx|b6 LDX zpy|b8 CLV imp|b9 LDA aby|ba TSX imp|bc LDY abx|bd LDA abx|be LDX aby
c0 CPY imm|c1 CMP izx|c4 CPY zp|c5 CMP zp|c6 DEC zp|c8 INY imp|c9 CMP imm|ca DEX imp|cc CPY abs|cd CMP abs|ce DEC abs
d0 BNE rel|d1 CMP izy|d5 CMP zpx|d6 DEC zpx|d8 CLD imp|d9 CMP aby|dd CMP abx|de DEC abx
e0 CPX imm|e1 SBC izx|e4 CPX zp|e5 SBC zp|e6 INC zp|e8 INX imp|e9 SBC imm|ea NOP imp|ec CPX abs|ed SBC abs|ee INC abs
f0 BEQ rel|f1 SBC izy|f5 SBC zpx|f6 INC zpx|f8 SED imp|f9 SBC aby|fd SBC abx|fe INC abx
"""
for chunk in table.replace('\n', '|').split('|'):
    chunk = chunk.strip()
    if chunk:
        c, mn, mode = chunk.split()
        op(int(c, 16), mn, mode)


def load(path, bank):
    """bank: int 32K bank at $8000, or 'o<hex>@<hex>' = PRG offset placed at an address."""
    d = open(path, 'rb').read()
    prg = d[16:16 + d[4] * 0x4000]
    if isinstance(bank, str) and bank.startswith('o'):
        off, at = bank[1:].split('@')
        off, at = int(off, 16), int(at, 16)
        mem = bytearray(0x8000)
        n = min(0x10000 - at, len(prg) - off)
        mem[at - 0x8000:at - 0x8000 + n] = prg[off:off + n]
        return bytes(mem)
    return prg[bank * 0x8000:(bank + 1) * 0x8000]


def fmt(mem, a):
    b = mem[a - 0x8000]
    if b not in OPS:
        return 1, '.byte $%02x' % b
    mn, mode = OPS[b]
    n = MODES[mode]
    lo = mem[a - 0x8000 + 1] if n > 1 else 0
    w = lo | (mem[a - 0x8000 + 2] << 8) if n > 2 else 0
    s = {'imp': '', 'acc': 'A', 'imm': '#$%02x' % lo, 'zp': '$%02x' % lo, 'zpx': '$%02x,X' % lo,
         'zpy': '$%02x,Y' % lo, 'izx': '($%02x,X)' % lo, 'izy': '($%02x),Y' % lo,
         'rel': '$%04x' % ((a + 2 + (lo - 256 if lo > 127 else lo)) & 0xffff),
         'abs': '$%04x' % w, 'abx': '$%04x,X' % w, 'aby': '$%04x,Y' % w, 'ind': '($%04x)' % w}[mode]
    return n, (mn + ' ' + s).strip()


def find(row_id):
    sha = None
    for m in glob.glob('tools/banktest/realrom/manifest*.tsv'):
        for line in open(m, encoding='utf-8'):
            f = line.rstrip('\n').split('\t')
            if len(f) > 2 and f[0] == row_id:
                sha = f[2]
    if sha is None:
        sys.exit('no manifest row ' + row_id)
    for d in os.environ.get('GRM_ROM_DIR', '').split():
        for p in glob.glob(os.path.join(d, '*')):
            if p.lower().endswith('.nes') and \
                    hashlib.sha256(open(p, 'rb').read()).hexdigest() == sha:
                print(p)
                return
    sys.exit('row %s (sha256 %s...) not found under $GRM_ROM_DIR' % (row_id, sha[:12]))


def main():
    if sys.argv[1] == '--find':
        find(sys.argv[2])
        return
    path, bank = sys.argv[1], (sys.argv[2] if sys.argv[2].startswith('o') else int(sys.argv[2]))
    mem = load(path, bank)
    if sys.argv[3] == 'words':
        a, cnt = int(sys.argv[4], 16), int(sys.argv[5])
        for i in range(cnt):
            o = a + 2 * i - 0x8000
            print('%04x: %04x' % (a + 2 * i, mem[o] | mem[o + 1] << 8))
        return
    a, end = int(sys.argv[3], 16), int(sys.argv[4], 16)
    while a < end:
        n, s = fmt(mem, a)
        raw = ' '.join('%02x' % mem[a - 0x8000 + k] for k in range(n))
        print('%04x  %-9s %s' % (a, raw, s))
        a += n


if __name__ == '__main__':
    main()
