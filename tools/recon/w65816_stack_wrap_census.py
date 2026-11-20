"""Count 65816 vector cases whose NATIVE-mode stack access wraps at the 16-bit S boundary (grm-9nxj.44).

Why: the "3-byte SP" language variant models S as a 24-bit register so the stock decompiler sees
`*:1 SP` as a stack reference. It is exact until S crosses $0000/$FFFF in native mode, where the
hardware wraps inside bank 0 and the 24-bit model runs to $FFFFFF / $010000. This census sizes
that divergence in the SingleStepTests corpus so the vector harness can classify it.

A case counts when its initial e == 0 and either
  * push/pull: initial s plus the signed 16-bit change in s leaves [0, $FFFF] (a lower bound:
    an instruction that pushes then pulls back across the boundary is not caught), or
  * stack-relative (opcode $x3): s + d (+1 for the word / pointer high byte) passes $FFFF.

usage: python -I tools/recon/w65816_stack_wrap_census.py [<vectors v1 dir>]
       (default: $GRM_W65816_VECTORS/v1)
"""
import json
import os
import sys


def signed16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.environ['GRM_W65816_VECTORS'], 'v1')
    total = 0
    rows = []
    for name in sorted(os.listdir(d)):
        if not name.endswith('.n.json'):
            continue
        op = int(name[:2], 16)
        if op in (0x1B, 0x9A, 0xFB):
            continue  # TCS/TXS/XCE load S outright; a delta test misreads them
        with open(os.path.join(d, name)) as f:
            cases = json.load(f)
        hit = 0
        for c in cases:
            i, fin = c['initial'], c['final']
            if i['e'] != 0:
                continue
            s0 = i['s']
            moved = s0 + signed16(fin['s'] - s0)
            wrap = moved < 0 or moved > 0xFFFF
            if not wrap and (op & 0x0F) == 0x03:
                pc = (i['pbr'] << 16) | i['pc']
                ram = dict((a, v) for a, v in i['ram'])
                dd = ram.get((pc & 0xFF0000) | ((pc + 1) & 0xFFFF))
                if dd is not None and s0 + dd + 1 > 0xFFFF:
                    wrap = True
            if wrap:
                hit += 1
        total += len(cases)
        if hit:
            rows.append((name, hit, len(cases)))
    for name, hit, n in rows:
        print('%-10s %5d / %d' % (name, hit, n))
    print('native stack-wrap cases: %d of %d total cases (%d opcode files)' %
          (sum(r[1] for r in rows), total, len(rows)))


main()
