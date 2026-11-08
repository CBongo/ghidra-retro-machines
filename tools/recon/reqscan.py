#!/usr/bin/env python3
"""reqscan.py -- byte-level corpus scan for request/fulfil bank switches in NES ROMs.

Written for bead grm-5tl.20.2 (which titles keep a bank number in RAM and fulfil it later,
Metroid-style, vs. switching with an immediate at the call site).

usage:  python -I tools/recon/reqscan.py OUT.json "DIR;DIR..." [--only SUBSTR]
   or:  python -I tools/recon/reqscan.py OUT.json --rom-dir   (dirs from $GRM_ROM_DIR, read like
        realrom-test.sh: ';'-separated if it contains ';', else whitespace-separated)

Per ROM (.nes, depth 1 of each dir; duplicate PRG hashes and GoodNES-tagged hacks/bad dumps are
skipped; mappers with no switchable PRG are skipped): finds mapper-register store clusters
(abs stores to >= $8000) in the fixed (last 16K) bank, the enclosing helper window, RAM cells
loaded in it, the argument kind at each JSR into it, and writer statistics for each loaded RAM
cell.  OUT.json is consumed by tools/recon/reqrank.py.  The JSON is an output: do not commit it.

Heuristic limits (read results as leads, not facts):
  * Linear decode only, no control flow: a helper "window" is guessed by walking back from a
    store to the nearest RTS/RTI/JMP/BRK, so helper entries can be wrong (too early / too late)
    and a helper entered mid-way is missed.
  * Fixed-last-16K layouts only (MMC1 mode 3, UxROM, MMC3 fixed banks); no per-mapper register
    knowledge beyond "abs store >= $8000".
  * Indirect jumps (JMP (ind), RTS-trick dispatch) and calls from switchable banks into the
    helper are not followed; only the byte pattern JSR helper is counted, so it can also count
    data coincidences.
  * Writer counts are byte-pattern matches (e.g. 85 24) validated only by a plausible preceding
    decode, so they include data coincidences; they say nothing about NMI vs main-loop placement.
Opcode decoding is the shared tools/banktest/dis6502.py table via tools/recon/rom6502.py.
"""
import collections
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rom6502 import TERM, chain_back, cpu_of, decode, operand  # noqa: E402
from rom6502 import parse_ines as parse  # noqa: E402

def scan(path):
    r = parse(path)
    if r is None: return None
    mapper, prg = r
    n = len(prg)
    res = {'mapper': mapper, 'prg': n, 'helpers': []}
    if n < 0x8000 or mapper in (0, 3, 11, 13, 66, 79, 140, 87, 185): return res
    fixed0 = n - 0x4000
    # 1. mapper-register stores in fixed bank
    stores = []
    for p in range(fixed0, n - 2):
        if prg[p] in (0x8D, 0x8E, 0x8C, 0x99, 0x9D) and prg[p+2] >= 0x80:
            stores.append(p)
    # chain validate and cluster
    seen_entries = {}
    for p in stores:
        chain = chain_back(prg, p, 140, fixed0)
        if len(chain) < 2: continue
        # trim at last terminator
        k = 0
        for j, (_o, ins) in enumerate(chain):
            if ins[0] in TERM: k = j + 1
        win = chain[k:]
        if not win: continue
        entry = win[0][0]
        e = seen_entries.setdefault(entry, {'entry': entry, 'stores': [], 'win': win})
        e['stores'].append(p)
        if len(win) > len(e['win']): e['win'] = win
    # drop entries that are subsets (same stores) -- keep earliest entry per store set
    for entry, e in sorted(seen_entries.items()):
        win = e['win']
        last = max(e['stores'])
        loads = []   # RAM cells loaded in window (before last store)
        for _o, ins in win:
            mn, mode, ln, b = ins
            if mn in ('LDA','LDX','LDY','ORA','AND','EOR','CMP','ADC','SBC') and mode in ('zp','abs','zpx','abx','aby','izy','izx'):
                a = operand(ins)
                if mode in ('zp','zpx') or (mode in ('abs',) and a < 0x800) :
                    loads.append((mn, mode, a))
                elif mode in ('abx','aby') and mn in ('LDA','LDX','LDY'):
                    loads.append((mn, mode + '@' + hex(a), a))
        hdr = {'entry': entry, 'cpu': cpu_of(n, entry), 'stores': [cpu_of(n, s) for s in sorted(set(e['stores']))],
               'storeAddrs': sorted(set(hex(prg[s+1] | prg[s+2] << 8) for s in e['stores'])),
               'loads': [(a, b, hex(c)) for a, b, c in loads],
               'ninstr': len(win),
               'text': ' ; '.join('%04x %s %s' % (cpu_of(n, o), ins[0], ('%x' % operand(ins)) if operand(ins) is not None else '') for o, ins in win[:40])}
        # lsr in window?
        hdr['hasLSR'] = any(ins[0] == 'LSR' and ins[1] == 'acc' for o, ins in win)
        # 2. call sites
        lo_cpu = cpu_of(n, entry); hi_cpu = cpu_of(n, last)
        calls = []
        wclears = clears(win)
        i = prg.find(b'\x20')
        while i != -1 and i < n - 2:
            tgt = prg[i+1] | prg[i+2] << 8
            if lo_cpu <= tgt <= hi_cpu:
                ch = chain_back(prg, i, 24, max(0, i - 24))
                # ensure chain reasonable
                kind = 'unknown'
                src = None
                cut = 0
                for j, (_o, ins) in enumerate(ch):
                    if ins[0] in TERM or ins[0] == 'JSR': cut = j + 1
                ch = ch[cut:]
                for _o, ins in reversed(ch):
                    mn, mode, ln, b = ins
                    if mn in ('LDA',):
                        if mode == 'imm': kind = 'A=imm'
                        elif mode in ('zp','abs') : kind = 'A=ram'; src = operand(ins)
                        else: kind = 'A=' + mode; src = operand(ins)
                        break
                    if mn in ('TYA','TXA') or (mn in ('PLA',)): kind = 'A=' + mn; break
                    if mn in ('LDY','LDX') and mode == 'imm': kind = 'XY=imm(no A load)'; break
                    if mn in ('LDY','LDX'):
                        kind = mn + '=' + mode; src = operand(ins); break
                    if mn in ('ORA','AND','EOR','ADC','SBC','ASL','LSR','ROL','ROR'): kind = 'A=alu'; break
                if not ch: kind = 'noprev'
                rd = set(operand(ins) for o, ins in ch if ins[0] in ('LDA','LDX','LDY') and (ins[1]=='zp' or (ins[1]=='abs' and operand(ins)<0x800)))
                aft = []
                j2 = i + 3
                for _ in range(5):
                    ins2 = decode(prg, j2)
                    if ins2 is None or ins2[0] in TERM: break
                    aft.append((j2, ins2)); j2 += ins2[2]
                clr = clears(ch) | clears(aft) | wclears
                calls.append((i, tgt, kind, src, sorted(hex(x) for x in rd & clr), sorted(hex(x) for x in rd)))
            i = prg.find(b'\x20', i + 1)
        hdr['ncalls'] = len(calls)
        hdr['callKinds'] = dict(collections.Counter(c[2] for c in calls))
        hdr['callSrcRam'] = dict(collections.Counter(hex(c[3]) for c in calls if c[3] is not None and c[2] in ('A=ram','LDY=zp','LDX=zp','LDY=abs','LDX=abs')))
        hdr['callOffs'] = [c[0] for c in calls]
        # direct A source of the first store
        fs = min(e['stores'])
        src = None
        for o, ins in reversed(win):
            if o >= fs: continue
            if ins[0] in ('LDA',):
                if ins[1] in ('zp','abs') and operand(ins) < 0x800: src = ('ram', operand(ins))
                elif ins[1] in ('abx','aby','zpx','izy','izx'): src = ('tbl', operand(ins))
                elif ins[1] == 'imm': src = ('imm', operand(ins))
                break
            if ins[0] in ('TYA','TXA','PLA'): src = (ins[0], 0); break
            if ins[0] in ('ORA','AND','EOR','ADC','SBC'): continue
        hdr['aSrc'] = src
        if src and src[0] == 'ram':
            cell = src[1]
            rd = 0
            for pat in ([bytes([0xA5,cell]),bytes([0xA4,cell]),bytes([0xA6,cell])] if cell < 256 else []) + [bytes([0xAD,cell&255,cell>>8]),bytes([0xAC,cell&255,cell>>8]),bytes([0xAE,cell&255,cell>>8])]:
                q = prg.find(pat)
                while q != -1:
                    if not any(o == q for o, _ in win) and chain_back(prg, q, 8, max(0, q-8)): rd += 1
                    q = prg.find(pat, q+1)
            hdr['aSrcReaders'] = rd
            hdr['aSrcWriters'] = writers(prg, cell, n, set(), lo_cpu, hi_cpu, fixed0, win)
        hdr['readClear'] = dict(collections.Counter(x for c in calls for x in c[4]))
        hdr['readers'] = dict(collections.Counter(x for c in calls for x in c[5]))
        hdr['winClears'] = sorted(hex(x) for x in wclears)
        # 3. cell writer stats for cells loaded in window (and ram call srcs)
        cells = set(a for (mn, md, a) in loads if '@' not in md and a < 0x800)
        cells |= set(c[3] for c in calls if c[3] is not None and c[2] in ('A=ram','LDY=zp','LDX=zp','LDY=abs','LDX=abs') and c[3] < 0x800)
        cinfo = {}
        callset = set(c[0] for c in calls)
        for cell in sorted(cells):
            w = writers(prg, cell, n, callset, lo_cpu, hi_cpu, fixed0, e['win'])
            cinfo[hex(cell)] = w
        hdr['cells'] = cinfo
        res['helpers'].append(hdr)
    return res

def clears(seq):
    out = set()
    for k in range(len(seq) - 1):
        a = seq[k][1]; b = seq[k+1][1]
        if a[0] in ('LDA','LDX','LDY') and a[1] == 'imm' and a[3][0] == 0 and b[0] in ('STA','STX','STY') and b[1] in ('zp','abs'):
            if (a[0],b[0]) in (('LDA','STA'),('LDX','STX'),('LDY','STY')):
                out.add(operand(b))
    return out

def writers(prg, cell, n, callset, lo_cpu, hi_cpu, fixed0, win):
    pats = []
    # zp forms
    if cell < 0x100:
        pats += [(bytes([0x85, cell]), 'STA'), (bytes([0x86, cell]), 'STX'), (bytes([0x84, cell]), 'STY'),
                 (bytes([0xE6, cell]), 'INC'), (bytes([0xC6, cell]), 'DEC'),
                 (bytes([0x46, cell]), 'LSR'), (bytes([0x06, cell]), 'ASL'), (bytes([0x66, cell]), 'ROR'), (bytes([0x26, cell]), 'ROL')]
    pats += [(bytes([0x8D, cell & 255, cell >> 8]), 'STA'), (bytes([0x8E, cell & 255, cell >> 8]), 'STX'), (bytes([0x8C, cell & 255, cell >> 8]), 'STY'),
             (bytes([0xEE, cell & 255, cell >> 8]), 'INC'), (bytes([0xCE, cell & 255, cell >> 8]), 'DEC')]
    kinds = collections.Counter(); adj = 0; tot = 0; clears = 0; inhelper = 0
    for pat, nm in pats:
        i = prg.find(pat)
        while i != -1:
            # validate: decodable chain into this position (len>=1)
            if i >= 0:
                # prev instruction kind
                ch = chain_back(prg, i, 12, max(0, i - 12))
                prev = ch[-1][1] if ch else None
                kind = nm
                if nm == 'STA' and prev:
                    if prev[0] == 'LDA' and prev[1] == 'imm':
                        kind = 'STA<-imm' + ('0' if prev[3][0] == 0 else '')
                        if prev[3][0] == 0: clears += 1
                    elif prev[0] == 'LDA' and prev[1] in ('abx','aby'): kind = 'STA<-table'
                    elif prev[0] == 'LDA': kind = 'STA<-copy'
                    elif prev[0] in ('TYA','TXA'): kind = 'STA<-' + prev[0]
                    elif prev[0] in ('INY','INX','DEY','DEX'): kind = 'STA<-' + prev[0]
                    elif prev[0] in ('ORA','AND','ADC','SBC','ASL','LSR','EOR','ROL','ROR'): kind = 'STA<-alu'
                    else: kind = 'STA<-' + prev[0]
                elif nm in ('STX','STY') and prev:
                    kind = nm + '<-' + prev[0] + ('imm' if prev[1] == 'imm' else '')
                # adjacency: JSR/JMP within next 4 instrs to helper range
                ln = 2 if len(pat) == 2 else 3
                j = i + ln; found = False
                for _ in range(5):
                    ins = decode(prg, j)
                    if ins is None: break
                    if ins[0] in ('JSR','JMP') and ins[2] == 3:
                        t = ins[3][0] | ins[3][1] << 8
                        if lo_cpu - 2 <= t <= hi_cpu: found = True
                        break
                    if ins[0] in ('RTS','RTI'): break
                    j += ins[2]
                inw = any(o == i for o, _ in win) if fixed0 <= i else False
                if inw: inhelper += 1
                else:
                    tot += 1
                    if found: adj += 1
                    kinds[kind] += 1
            i = prg.find(pat, i + 1)
    return {'writers': tot, 'adjacentToHelperCall': adj, 'inHelperWindow': inhelper, 'kinds': dict(kinds)}

def collect(dirs):
    out = []
    for d in dirs:
        if not os.path.isdir(d): print('missing dir', d, file=sys.stderr); continue
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if os.path.isfile(p) and f.lower().endswith('.nes'):
                out.append(p)
    return out

def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    outp = sys.argv[1]
    if len(sys.argv) < 3 or sys.argv[2].startswith('--'):
        raw = os.environ.get('GRM_ROM_DIR', '') if '--rom-dir' in sys.argv else ''
        if not raw:
            sys.exit(__doc__)
        dirs = [d.strip() for d in raw.split(';')] if ';' in raw else raw.split()
    else:
        dirs = sys.argv[2].split(';')
    only = None
    if '--only' in sys.argv: only = sys.argv[sys.argv.index('--only') + 1].lower()
    files = collect(dirs)
    seen = {}
    results = {}
    skipped = 0
    for p in files:
        name = os.path.basename(p)
        if only and only not in name.lower(): continue
        try: pr = parse(p)
        except Exception: continue
        if pr is None: continue
        mapper, prg = pr
        h = hashlib.sha1(prg).hexdigest()
        if h in seen: skipped += 1; continue
        # [!] filter for GoodNES-style tagged names: skip if has [b..] [h..] [o..] [f..] [t..] tags or (Hack)
        if re.search(r'\[(b|h|o|f|t|T|p|a)\d*[^\]]*\]|\(Hack\)|\(PD\)|\(Unl\)|\(Pirate\)|\(Beta\)|\(Proto', name) and '[!]' not in name:
            skipped += 1; continue
        seen[h] = name
        try:
            r = scan(p)
        except Exception as ex:
            r = {'error': repr(ex), 'mapper': mapper}
        if r is not None:
            r['path'] = p
            results[name] = r
    json.dump(results, open(outp, 'w'))
    mc = collections.Counter(r['mapper'] for r in results.values())
    print('scanned', len(results), 'skipped/deduped', skipped, 'per mapper', sorted(mc.items()))

if __name__ == '__main__':
    main()
