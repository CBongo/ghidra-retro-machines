#!/usr/bin/env python3
"""bankdiff.py -- classify a fixed-bank call target's CODE in each switchable bank, by flow closure.

Written for bead grm-5tl.20.1 (Metroid Stage A).  Question it answers: the fixed bank has
`JSR $80B0` (a target in the switchable window); the callee is whatever the CURRENT bank holds
there.  Is it the same routine in every bank (a shared-library entry, safe to treat as one
function), per-bank different code (a dispatcher), or not code at all (a data window)?

usage:  python -I tools/recon/bankdiff.py ROM|--find ROW-ID [options]
  --targets 80b0,95c3   classify these CPU addresses (default: auto = every JSR/JMP abs in the
                        fixed bank, found by linear sweep, whose target is $8000-$BFFF)
  --ref N               reference bank the others are compared against (default 1)
  --sumbanks A-B        banks counted in the closing per-class tallies (default: all switchable)
  --noreturn A,B        CPU addresses of JSR targets that never return to the caller (inline-data
                        trampolines): the closure walk stops after a JSR to them.  Game specific:
                        Metroid uses c27c (bank-switch trampoline) and 8024.  Without it the walk
                        runs into inline data after such a call and reports 'e'.
  --detail 95c3         for one target, also print every JSR/JMP in its closure whose operand
                        differs between banks (the per-bank dispatch targets)
  --reach               for fixed-bank JSR/JMP byte patterns the linear sweep did NOT see
                        (data coincidences or desync), say whether a vector-seeded flow walk
                        reaches them as an instruction start
  e.g.  python -I tools/recon/bankdiff.py --find metroid_u --noreturn c27c,8024 --sumbanks 1-5

Layout assumed: 16K banks, the LAST bank fixed at $C000-$FFFF, the switchable window at
$8000-$BFFF (MMC1 mode 3, UxROM/mapper 2, MMC3 with a swapped $8000/$A000 pair is NOT modelled).
Per-bank output string: one class letter per bank 0..N-2:
  -  the reference bank          b  identical closure bytes to the reference
  c  same opcodes, operands differ (not a JSR/JMP operand)    c*  same, but a JSR/JMP operand differs
  d  different structure         e  closure hit invalid opcode / BRK / ran off the window, or empty
  ?  the reference bank itself is not clean code, so no comparison
`groups=` assigns letters A,B,... to banks with byte-identical closures.

Limits (recon, not proof): the closure follows direct flow only (branches, JSR/JMP abs inside
$8000-$BFFF); indirect jumps (JMP (x)), RTS-trick dispatch and jump tables are NOT followed, so
two banks can look identical while a table they index differs.  Calls into the fixed bank end a
path (fixed code is shared by definition).  The linear sweep that finds sites can desync on
inline data, missing or inventing sites (hence --reach).  No NMI-vs-main-loop placement.
Opcodes: the shared tools/banktest/dis6502.py table, official NMOS only.
"""
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rom6502  # noqa: E402

FLOW = ('JSR', 'JMP')


class Rom:
    def __init__(self, prg):
        self.nb = len(prg) // 0x4000
        self.banks = [prg[i * 0x4000:(i + 1) * 0x4000] for i in range(self.nb)]

    def byte(self, bank, a):
        return self.banks[-1][a - 0xC000] if a >= 0xC000 else self.banks[bank][a - 0x8000]

    def dec(self, bank, a):
        """(opcode, mnemonic, mode, length, bytes) at CPU address a as seen with `bank` mapped."""
        if a + 1 > 0x10000:
            return None
        o = self.byte(bank, a)
        spec = rom6502.OPS.get(o)
        if spec is None:
            return None
        n = rom6502.LEN[spec[1]]
        if a + n > 0x10000:
            return None
        return o, spec[0], spec[1], n, bytes(self.byte(bank, a + i) for i in range(n))


def closure(rom, bank, entry, noret):
    """Direct-flow closure of code at `entry` in window $8000-$BFFF of `bank`.

    Returns (seen, bad): seen maps address -> (bytes, opcode, mnemonic, mode); bad lists
    (addr, reason) for invalid opcodes, BRK and instructions running off the window.
    """
    seen, work, bad = {}, [entry], []
    while work:
        a = work.pop()
        while 0x8000 <= a < 0xC000 and a not in seen:
            r = rom.dec(bank, a)
            if r is None:
                bad.append((a, 'invalid'))
                break
            o, mn, mode, n, bs = r
            if a + n > 0xC000:
                bad.append((a, 'runoff'))
                break
            seen[a] = (bs, o, mn, mode)
            if mn == 'BRK':
                bad.append((a, 'BRK'))
                break
            if mode == 'rel':
                work.append(a + 2 + (bs[1] - 256 if bs[1] > 127 else bs[1]))
                a += n
                continue
            if mn == 'JSR':
                tg = bs[1] | bs[2] << 8
                if 0x8000 <= tg < 0xC000:
                    work.append(tg)
                if tg in noret:
                    break
                a += n
                continue
            if mn == 'JMP':
                if mode == 'abs':
                    tg = bs[1] | bs[2] << 8
                    if 0x8000 <= tg < 0xC000:
                        work.append(tg)
                break
            if mn in ('RTS', 'RTI'):
                break
            a += n
    return seen, bad


def sites_in_fixed(rom):
    """Linear sweep of the fixed bank: {target: [(site, mnemonic)]} for JSR/JMP abs to $8000-$BFFF."""
    sites, lin = {}, set()
    a = 0xC000
    while a < 0x10000:
        r = rom.dec(rom.nb - 1, a)
        if r is None:
            a += 1
            continue
        o, mn, mode, n, bs = r
        if o in (0x20, 0x4C):
            t = bs[1] | bs[2] << 8
            if 0x8000 <= t < 0xC000:
                sites.setdefault(t, []).append((a, mn))
                lin.add(a)
        elif mn == 'JMP' and mode == 'ind':
            print('JMP ind', hex(a), bs.hex())
        a += n
    return sites, lin


def reach_report(rom, lin):
    fixed = rom.banks[-1]

    def g(a):
        return fixed[a - 0xC000]
    work = [g(v) | g(v + 1) << 8 for v in (0xFFFA, 0xFFFC, 0xFFFE)]
    for a in range(0xC000, 0x10000):          # seed: linear-decoded fixed-bank flow targets
        r = rom.dec(rom.nb - 1, a)
        if r and r[0] in (0x20, 0x4C) and a in lin:
            t = r[4][1] | r[4][2] << 8
            if t >= 0xC000:
                work.append(t)
    seen = {}
    while work:
        a = work.pop()
        while 0xC000 <= a < 0x10000 and a not in seen:
            r = rom.dec(rom.nb - 1, a)
            if r is None:
                break
            o, mn, mode, n, bs = r
            seen[a] = mn
            if mode == 'rel':
                work.append(a + 2 + (bs[1] - 256 if bs[1] > 127 else bs[1]))
            if mn in FLOW and mode == 'abs':
                t = bs[1] | bs[2] << 8
                if t >= 0xC000:
                    work.append(t)
            if mn in ('JMP', 'RTS', 'RTI'):
                break
            a += n
    raw = []
    for a in range(0xC000, 0xFFFD):
        if g(a) in (0x20, 0x4C) and 0x8000 <= (g(a + 1) | g(a + 2) << 8) < 0xC000 and a not in lin:
            raw.append(a)
    print('raw-only (not seen by the linear sweep):', [hex(x) for x in raw])
    for a in raw:
        t = g(a + 1) | g(a + 2) << 8
        print('  %04x %02x -> %04x  %s' % (a, g(a), t,
              'reachable instruction start' if seen.get(a) in FLOW else 'not an instruction start'))


def classify(rom, targets, sites, ref, noret, sumbanks, detail):
    nsw = rom.nb - 1
    tot = collections.defaultdict(collections.Counter)
    for t in sorted(targets):
        sig = {bk: closure(rom, bk, t, noret) for bk in range(nsw)}
        groups, out = [], []
        for bk in range(nsw):
            seen, bad = sig[bk]
            if bad or not seen:
                out.append('E')
                continue
            for gi, gs in enumerate(groups):
                if set(gs) == set(seen) and all(gs[k][0] == seen[k][0] for k in seen):
                    out.append(chr(65 + gi))
                    break
            else:
                groups.append(seen)
                out.append(chr(65 + len(groups) - 1))
        rs, rbad = sig[ref]
        ref_ok = not rbad and rs
        cl = []
        for bk in range(nsw):
            seen, bad = sig[bk]
            if bad or not seen:
                c = 'e'
            elif not ref_ok:
                c = '?'
            elif bk == ref:
                c = '-'
            elif out[bk] == out[ref]:
                c = 'b'
            elif set(seen) == set(rs) and all(seen[k][1] == rs[k][1] for k in seen):
                fl = [k for k in seen if seen[k][2] in FLOW and seen[k][0] != rs[k][0]]
                c = 'c*' if fl else 'c'
            else:
                c = 'd'
            cl.append(c)
            if bk in sumbanks:
                tot[bk][c] += 1
        sl = sites.get(t)
        print('%04x sites=%-26s size%d=%-4s groups=%s cls=%s' % (
            t, ' '.join('%x' % a for a, _ in sl) if sl else '-', ref, len(rs) if ref_ok else 'E',
            ''.join(out), ' '.join(cl)))
        if detail == t and ref_ok:
            flows = sorted(k for bk in range(nsw) if not sig[bk][1] for k in sig[bk][0]
                           if sig[bk][0][k][2] in FLOW)
            for k in sorted(set(flows)):
                per = {}
                for bk in range(nsw):
                    if k in sig[bk][0] and not sig[bk][1]:
                        bs = sig[bk][0][k][0]
                        per[bk] = bs[1] | bs[2] << 8
                if len(set(per.values())) > 1:
                    print('   %04x %s' % (k, ' '.join('b%d=%04x' % (b, v) for b, v in sorted(per.items()))))
    return tot


def parse_bank_range(s, nsw):
    if not s:
        return set(range(nsw))
    a, _, b = s.partition('-')
    return set(range(int(a), int(b or a) + 1))


def opt(args, name):
    return args[args.index(name) + 1] if name in args else None


def main():
    args = sys.argv[1:]
    if not args or args[0] == '-h':
        sys.exit(__doc__)
    if args[0] == '--find':
        path = rom6502.find_rom(args[1])
    else:
        path = args[0]
    r = rom6502.parse_ines(path)
    if r is None:
        sys.exit('not an iNES file: ' + path)
    rom = Rom(r[1])
    if rom.nb < 3:
        sys.exit('need >= 3 16K banks (one fixed, >= 2 switchable)')
    nsw = rom.nb - 1
    ref = int(opt(args, '--ref') or 1)
    noret = {int(x, 16) for x in (opt(args, '--noreturn') or '').split(',') if x}
    sumbanks = parse_bank_range(opt(args, '--sumbanks'), nsw)
    sites, lin = sites_in_fixed(rom)
    print('LINEAR sites:', sum(len(v) for v in sites.values()), 'targets', len(sites))
    tl = opt(args, '--targets')
    targets = {int(x, 16) for x in tl.split(',')} if tl else set(sites)
    detail = int(opt(args, '--detail'), 16) if opt(args, '--detail') else None
    if '--reach' in args:
        reach_report(rom, lin)
    tot = classify(rom, targets, sites, ref, noret, sumbanks, detail)
    for bk in sorted(tot):
        print(bk, dict(tot[bk]))


if __name__ == '__main__':
    main()
