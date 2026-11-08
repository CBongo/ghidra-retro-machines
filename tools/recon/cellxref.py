#!/usr/bin/env python3
"""cellxref.py -- find who touches a RAM cell, and who calls a routine, across every PRG bank.

Written for bead grm-5tl.20.1 (Metroid Stage A: who writes the bank-request cell $24?) and
grm-5tl.20.2.  For a plain disassembly use tools/banktest/dis6502.py (e.g. a mapper-1 fixed bank:
`dis6502.py ROM o1c000@c000 c000 c040`); this tool only does the cross-bank searches.

usage (ROM is a path to an .nes file, or `--find ROW-ID` for a pinned manifest row, resolved
through dis6502's --find from $GRM_ROM_DIR):
  python -I tools/recon/cellxref.py ROM --grep CELLHEX     readers AND writers of the cell, with
                                                          context (3 instrs before, 4 from the access)
  python -I tools/recon/cellxref.py ROM --writers CELLHEX  writers only, every bank, plain list
                                                          (store/INC/DEC/shift; also indexed store/INC/DEC bases
                                                          that can reach the cell)
  python -I tools/recon/cellxref.py ROM --calls TARGETHEX  JSR sites to a CPU address, any bank,
                                                          with the 4 preceding instructions
  e.g.  python -I tools/recon/cellxref.py --find metroid_u --grep 24

Banks are 16K; the last bank is labelled FIX (it sits at $C000, fixed-last layouts: MMC1 mode 3,
UxROM, MMC3-style), the others bkN at $8000.  Addresses printed are CPU addresses in that
bank's window.

Limits (recon, not proof):
  * Byte-pattern search over the whole PRG, validated only by "a decode chain of <= 14 bytes
    ends here".  Data bytes that happen to look like `85 24` are included (data coincidences),
    and operands split by a desynchronised chain are missed.
  * --grep keeps one hit per access position and drops hits with no plausible preceding code.
  * Absolute forms are matched at the exact cell address only (no mirrors: $0824 vs $24 are
    different patterns; mirrored RAM $0000-$1FFF is not folded).
  * --writers' indexed-base lists (STA $nn,X etc. with base <= cell) are possible writers only.
  * No NMI-vs-main-loop placement, no indirect jumps/computed calls (JMP (x), RTS tricks, pointer
    tables), and no banked-call convention knowledge: a call through a bank-switch trampoline
    shows as the JSR to the trampoline, not to the final target.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rom6502  # noqa: E402

ZP_ACCESS = (0x85, 0x86, 0x84, 0xE6, 0xC6, 0xA5, 0xA4, 0xA6)    # sta stx sty inc dec lda ldy ldx
ABS_ACCESS = (0x8D, 0x8E, 0x8C, 0xEE, 0xCE, 0xAD, 0xAC, 0xAE)
WRITERS = {'STA', 'STX', 'STY', 'INC', 'DEC', 'ASL', 'LSR', 'ROL', 'ROR'}


def label(i, n):
    return 'FIX ' if i >= n - 0x4000 else 'bk%d ' % (i // 0x4000)


def cpu(i, n):
    return rom6502.cpu_of(n, i) if i >= n - 0x4000 else 0x8000 + (i % 0x4000)


def show(prg, o, ins):
    return '%04x  %s' % (cpu(o, len(prg)), rom6502.fmt_ins(ins, cpu(o, len(prg))))


def do_grep(prg, cell):
    n = len(prg)
    for i in range(n - 2):
        zp = cell < 256 and prg[i] in ZP_ACCESS and prg[i + 1] == cell
        ab = prg[i] in ABS_ACCESS and prg[i + 1] == (cell & 255) and prg[i + 2] == (cell >> 8)
        if not (zp or ab):
            continue
        ch = rom6502.chain_back(prg, i, 14, max(0, i - 14))
        if not ch:
            continue
        tail, j = [], i
        for _ in range(4):
            ins = rom6502.decode(prg, j)
            if not ins:
                break
            tail.append((j, ins))
            j += ins[2]
        print(label(i, n) + ' | '.join(show(prg, o, x) for o, x in ch[-3:]) + '  >>  '
              + ' | '.join(show(prg, o, x) for o, x in tail))


def do_writers(prg, cell):
    n = len(prg)
    for bank in range(n // 0x4000):
        base = bank * 0x4000
        a = base
        hits = []
        while a < base + 0x4000:
            ins = rom6502.decode(prg, a)
            if ins is None or a + ins[2] > base + 0x4000:
                a += 1
                continue
            mn, mode, ln, _b = ins
            v = rom6502.operand(ins)
            if mn in WRITERS:
                if mode in ('zp', 'abs') and v == cell:
                    hits.append((a, ins, ''))
                elif mode in ('zpx', 'zpy', 'abx', 'aby') and v is not None and v <= cell \
                        and mn in ('STA', 'STX', 'STY', 'INC', 'DEC'):
                    hits.append((a, ins, '   [indexed base <= cell: possible]'))
            a += ln
        print(('FIXED' if bank == n // 0x4000 - 1 else 'BANK %d' % bank))
        for a, ins, note in hits:
            print('  ' + show(prg, a, ins) + note)


def do_calls(prg, target):
    n = len(prg)
    i = prg.find(b'\x20')
    while i != -1:
        if i + 2 < n and prg[i + 1] | prg[i + 2] << 8 == target:
            ch = rom6502.chain_back(prg, i, 16, max(0, i - 16))
            print(label(i, n) + ' | '.join(show(prg, o, x) for o, x in ch[-4:]) + '  >> JSR  @%04x' % cpu(i, n))
        i = prg.find(b'\x20', i + 1)


def main():
    a = sys.argv[1:]
    if a[:1] == ['--find'] and len(a) >= 2:
        path, a = rom6502.find_rom(a[1]), a[2:]
    elif a:
        path, a = a[0], a[1:]
    else:
        sys.exit(__doc__)
    if len(a) != 2 or a[0] not in ('--grep', '--writers', '--calls'):
        sys.exit(__doc__)
    r = rom6502.parse_ines(path)
    if r is None:
        sys.exit('not an iNES file: ' + path)
    prg = r[1]
    val = int(a[1], 16)
    {'--grep': do_grep, '--writers': do_writers, '--calls': do_calls}[a[0]](prg, val)


if __name__ == '__main__':
    main()
