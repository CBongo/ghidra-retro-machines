"""Byte-level survey for the two-level zero-page pointer dispatch (bead grm-gipk.23).

The shape (cv3 bank 20, $8505..$8524):
    LDA T,X|Y / ASL / TAY / LDA T+1,Y ...  -> STA zp1 / STA zp1+1     (outer table, indexed)
    [LDA abs,X / AND #imm / ASL] TAY / LDA (zp1),Y -> STA zp2 / INY / LDA (zp1),Y -> STA zp2+1
    JMP (zp2)

Scan, not a flow walk: every JMP (zp) is a candidate; each linear decode that lands exactly on
it (up to --back bytes earlier) is tried. Registers and zero-page addresses are not fixed.

Usage (run from the repo root; ROM dirs come from $GRM_ROM_DIR, never hardcoded):
    python -I tools/recon/twolevelscan.py --all-rows
    python -I tools/recon/twolevelscan.py --find cv3 --find zelda
    python -I tools/recon/twolevelscan.py path/to/game.nes ...
Output per hit: PRG offset, CPU address, outer table T, inner cap (from an AND #imm before the
inner TAY, else '?'), and the first outer-table words ('ok' = they all land in $8000-$FFFF).
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rom6502  # noqa: E402


def rows():
    out = []
    for m in sorted(glob.glob('tools/banktest/realrom/manifest*.tsv')):
        for line in open(m, encoding='utf-8'):
            f = line.rstrip('\n').split('\t')
            if len(f) > 3 and f[0] != 'id' and f[3].isdigit() and f[0] not in out:
                out.append(f[0])
    return out


def windows(d, p, back):
    """Every linear decode (list of (off, ins)) that starts within `back` bytes and lands on p."""
    for s in range(max(0, p - back), p):
        i, out = s, []
        while i < p:
            ins = rom6502.decode(d, i)
            if ins is None:
                out = None
                break
            out.append((i, ins))
            i += ins[2]
        if out and i == p:
            yield out


def match(L, jz):
    """Match instruction list L (ending just before JMP (jz)). Returns (T, cap) or None."""
    n = len(L)
    mn = [x[1][0] for x in L]
    md = [x[1][1] for x in L]
    op = [rom6502.operand(x[1]) for x in L]
    # inner pair: LDA (z1),Y -> STA jz ; INY ; LDA (z1),Y -> STA jz+1
    for a in range(n):
        if not (mn[a] == 'LDA' and md[a] == 'izy' and a + 1 < n and mn[a + 1] == 'STA'
                and md[a + 1] == 'zp' and op[a + 1] == jz and n - a <= 14):
            continue
        z1 = op[a]
        ok = False
        for b in range(a + 2, min(n - 1, a + 5)):
            if (mn[b] == 'LDA' and md[b] == 'izy' and op[b] == z1 and mn[b + 1] == 'STA'
                    and md[b + 1] == 'zp' and op[b + 1] == jz + 1 and 'INY' in mn[a + 2:b]):
                ok = True
        if not ok:
            continue
        # outer stores to z1 / z1+1 within 16 instrs before a
        lo, hi = {}, {}
        for k in range(max(1, a - 16), a):
            if mn[k] == 'STA' and md[k] == 'zp' and mn[k - 1] == 'LDA' and md[k - 1] in ('abx', 'aby'):
                if op[k] == z1:
                    lo[k] = op[k - 1]
                elif op[k] == z1 + 1:
                    hi[k] = op[k - 1]
        for kl, tl in lo.items():
            for kh, th in hi.items():
                if th == tl + 1 or tl == th + 1:
                    cap = '?'
                    for k in range(a - 1, max(kl, kh), -1):
                        if mn[k] == 'AND' and md[k] == 'imm':
                            cap = str(op[k] + 1)
                            break
                    return min(tl, th), cap
    return None


def scan(d, back):
    hits = {}
    for p in range(len(d) - 2):
        if d[p] != 0x6C or d[p + 2] != 0 or d[p + 1] > 0xFE:
            continue
        jz = d[p + 1]
        for L in windows(d, p, back):
            m = match(L, jz)
            if m:
                hits[p] = (jz,) + m
                break
    return hits


def pc_of(d, p):
    if p >= len(d) - 0x4000:
        return rom6502.cpu_of(len(d), p)
    return 0x8000 + (p & 0x3FFF)


def table_words(d, p, T, cnt=4):
    """First words of the outer table, resolved in the JMP's own bank view."""
    if T < 0x8000:
        return None
    if T >= 0xC000:
        base = len(d) - 0x4000 + (T - 0xC000)
    else:
        base = (p & ~0x3FFF) + (T - 0x8000)
    if base + 2 * cnt > len(d):
        return None
    return [d[base + 2 * i] | d[base + 2 * i + 1] << 8 for i in range(cnt)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('roms', nargs='*')
    ap.add_argument('--find', action='append', default=[])
    ap.add_argument('--all-rows', action='store_true')
    ap.add_argument('--back', type=int, default=100)
    a = ap.parse_args()
    items = [(os.path.basename(r), r) for r in a.roms]
    ids = a.find + (rows() if a.all_rows else [])
    for rid in ids:
        try:
            path = rom6502.find_rom(rid)
        except SystemExit:
            print('# %s: ROM not found' % rid, file=sys.stderr)
            continue
        if path:
            items.append((rid, path))
    print('row\tprg_off\tcpu\tzp_jmp\touter_T\tcap\touter_words')
    for name, path in items:
        pr = rom6502.parse_ines(path)
        if pr is None:
            continue
        d = pr[1]
        for p, (jz, T, cap) in sorted(scan(d, a.back).items()):
            w = table_words(d, p, T)
            if w is None:
                ws = 'T not in ROM'
            else:
                good = all(0x8000 <= x <= 0xFFFF for x in w)
                ws = ' '.join('%04x' % x for x in w) + (' ok' if good else ' BAD')
            print('%s\t0x%x\t$%04x\t$%02x\t$%04x\t%s\t%s' % (name, p, pc_of(d, p), jz, T, cap, ws))


if __name__ == '__main__':
    main()
