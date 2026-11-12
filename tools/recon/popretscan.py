"""Byte-level survey of 6502 "pop-return" helpers (bead grm-ed6h).

The shape (Metroid c376):  LDA #$00 / STA $07a1,X / PLA / PLA / RTS
A subroutine that discards its own return address and so returns to its CALLER'S caller. From
the JSR site's point of view such a call does not fall through.

Scan, not a flow walk, and mapping-agnostic: every JSR abs operand A in the PRG is a candidate
entry; each PRG offset o with o % 0x2000 == A % 0x2000 (every common NES window is 8K-aligned)
is decoded linearly from o, up to --max instructions, until the first RTS/RTI/JMP/BRK. The
routine is reported if, just before that terminator, the net stack effect from entry is -2
(two more pulls than pushes), counting PLA/PLP as -1, PHA/PHP as +1, and TSX/INX/INX/TXS as -2.
A JSR inside the body ends the decode (unknown callee stack effect). A conditional branch before
the pops marks the hit 'cond' (another path may return normally); otherwise 'pure'.
A pulled byte that is then stored or transferred (PLA / STA, PLA / TAX ...) marks the hit 'uses'
-- that is the JumpEngine / inline-argument idiom (InlineJumpTableDispatchAnalyzer), not a
discard.

Usage (run from the repo root; ROM dirs come from $GRM_ROM_DIR, never hardcoded):
    python -I tools/recon/popretscan.py --all-rows
    python -I tools/recon/popretscan.py --find metroid_u -v
    python -I tools/recon/popretscan.py path/to/game.nes ...
Output per row: helpers by kind with their JSR call-site counts; -v lists each helper's body.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rom6502  # noqa: E402
import twolevelscan  # noqa: E402  (shares its manifest row reader)

PUSH = {'PHA': 1, 'PHP': 1, 'PLA': -1, 'PLP': -1}
USE_AFTER_PLA = {'STA', 'TAX', 'TAY', 'AND', 'ORA', 'EOR', 'ADC', 'SBC', 'CMP', 'ASL', 'LSR',
                 'ROL', 'ROR'}


def classify(d, o, maxn):
    """Decode from PRG offset o. Returns (kind, body) for a pop-return helper, else None."""
    i, net, cond, uses, body = o, 0, False, False, []
    prev = None
    for _ in range(maxn):
        ins = rom6502.decode(d, i)
        if ins is None:
            return None
        mn = ins[0]
        body.append((i, ins))
        if mn in ('RTS', 'RTI', 'JMP', 'BRK'):
            if mn == 'BRK' or net != -2:
                return None
            kind = 'uses' if uses else ('cond' if cond else 'pure')
            return kind, body
        if mn == 'JSR':
            return None
        if mn in PUSH:
            net += PUSH[mn]
        if prev == 'PLA' and mn in USE_AFTER_PLA:
            uses = True
        if mn == 'TXS' and len(body) >= 4 and \
                [b[1][0] for b in body[-4:]] == ['TSX', 'INX', 'INX', 'TXS']:
            net -= 2
        if ins[1] == 'rel':
            cond = True
        prev = mn
        i += ins[2]
    return None


def scan(d, maxn):
    """{entry_cpu_addr: (kind, prg_off, body, ncalls)} over every JSR target in d."""
    calls = {}
    for i in range(len(d) - 2):
        if d[i] == 0x20:
            a = d[i + 1] | d[i + 2] << 8
            if a >= 0x8000:
                calls[a] = calls.get(a, 0) + 1
    out, seen = {}, set()
    for a, n in calls.items():
        for o in range(a % 0x2000, len(d), 0x2000):
            r = classify(d, o, maxn)
            # identical bodies at the same CPU address in several banks count once
            key = (a, bytes(d[r[1][0][0]:r[1][-1][0] + r[1][-1][1][2]])) if r else None
            if r and key not in seen:
                seen.add(key)
                out[(a, o)] = (r[0], r[1], n)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('roms', nargs='*')
    ap.add_argument('--find', action='append', default=[])
    ap.add_argument('--all-rows', action='store_true')
    ap.add_argument('--max', type=int, default=24, help='max instructions decoded per entry')
    ap.add_argument('-v', action='store_true', help='list each helper body')
    a = ap.parse_args()
    targets = [(p, p) for p in a.roms]
    ids = a.find + (twolevelscan.rows() if a.all_rows else [])
    found = rom6502.dis6502.find_many(ids)   # one hashing pass for every row
    for rid in ids:
        if rid in found:
            targets.append((rid, found[rid]))
        else:
            print(f'{rid}: ROM not found')
    tot = {}
    for name, path in targets:
        r = rom6502.parse_ines(path)
        if r is None:
            continue
        _, d = r
        hits = scan(d, a.max)
        if not hits:
            continue
        summ = {}
        for kind, _body, n in hits.values():
            s = summ.setdefault(kind, [0, 0])
            s[0] += 1
            s[1] += n
            t = tot.setdefault(kind, [0, 0, 0])
            t[0] += 1
            t[1] += n
        for k in summ:
            tot[k][2] += 1
        print(f'{name}: ' + ', '.join(f'{k} {v[0]} helper(s)/{v[1]} JSR(s)'
                                      for k, v in sorted(summ.items())))
        if a.v:
            for (addr, off), (kind, body, n) in sorted(hits.items()):
                if kind == 'uses':
                    continue
                text = ' / '.join(rom6502.fmt_ins(ins, addr + (bo - off)) for bo, ins in body)
                print(f'  {kind:4} ${addr:04x} (prg {off:05x}, {n} JSR): {text}')
    print('TOTAL: ' + ', '.join(f'{k} {v[0]} helper(s)/{v[1]} JSR(s) in {v[2]} row(s)'
                                for k, v in sorted(tot.items())))


if __name__ == '__main__':
    main()
