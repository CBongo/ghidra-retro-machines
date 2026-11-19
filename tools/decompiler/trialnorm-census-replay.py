"""Replay a SwitchLabelCensus site list through two decomp_dbg builds (written for grm-hf5h.34).

Question: how many census switch sites does JumpBasicOverride::trialNorm's 10-consecutive-miss
tolerance explain? Control = the installed candidate's debug build, patched = the same tree plus
tools/decompiler/apply-hf5h31.py and a trace line ("HF5H34 trialNorm succeeded past tolerance").

Inputs are the per-row debug XMLs written by DecompileSiteProbe (GRM_DECOMPILE_DEBUG_DIR, run as
REALROM_EXTRA_POSTSCRIPT with --only <row>), laid out as <capdir>/<row>/<space>_<site>.xml, and the
probe's per-row log (<workdir>/<row>/<row>.log, "DECOMP <site> fn=<name>@<addr> ...") for the function
name. Each XML is prepared (overlay spaces renamed, branch overrides dropped) and the function's
captured bytes are SPLICED from the ROM: a capture holds only the bytes the original decompile read,
and under the stock tolerance the original stopped reading the table early. Every captured ROM
chunk is located in the ROM (NES, masked match) or mapped by bus address (SNES) and extended
forward by --extend bytes (default 0x400).

usage: python -I tools/decompiler/trialnorm-census-replay.py --capdir D --workdir W --outdir O
         --ctl-bin ~/hf5h14/c15/cpp/decomp_dbg --new-bin ~/hf5h34/c16/cpp/decomp_dbg
         --sleighhome-65816 ~/hf5h31/ctl/sh [--sleighhome-nes <ghidra install>] [--rows a,b]
ROM dirs come from GRM_ROM_DIR / GRM_SNES_ROM_DIR (';'-separated), pins from the realrom manifests.
WSL paths are given as seen from WSL; the bins and sleigh homes are WSL paths. The SNES language
needs a .sla compiled by the replay tree's own sleigh (see the 65816-replay-sla bd memory).
"""
import argparse
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
MANIFESTS = ['manifest.tsv', 'manifest-gme.tsv', 'manifest-snes-analysis.tsv', 'manifest-goodnes.tsv']


def manifest_rows():
    rows = {}
    for m in MANIFESTS:
        p = os.path.join(ROOT, 'tools', 'banktest', 'realrom', m)
        if not os.path.exists(p):
            continue
        for ln in open(p, encoding='utf-8'):
            if ln.startswith('#') or not ln.strip():
                continue
            f = ln.rstrip('\n').split('\t')
            if len(f) > 4:
                rows.setdefault(f[0], (f[2], f[4]))
    return rows


def find_rom(sha, dirs):
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            p = os.path.join(d, fn)
            if os.path.isfile(p) and os.path.getsize(p) < 16 * 1024 * 1024:
                if hashlib.sha256(open(p, 'rb').read()).hexdigest() == sha:
                    return p
    return None


def chunks(xml):
    out = []
    for m in re.finditer(r'<bytechunk space="([^"]*)" offset="0x([0-9a-f]+)"([^>]*)>(.*?)</bytechunk>', xml, re.S):
        out.append((m.group(1), int(m.group(2), 16), bytes.fromhex(''.join(m.group(4).split()))))
    return out


def locate_nes(rom, data):
    """PRG offset (file offset - 16) of the ROM place that equals data wherever data is nonzero."""
    nz = [i for i, b in enumerate(data) if b]
    if len(nz) < 8:
        return None
    best = None
    for i in nz[:200]:
        anchor = data[i:i + 8]
        if len(anchor) < 8 or 0 in anchor[:2]:
            continue
        best = i
        break
    if best is None:
        return None
    hits = []
    pos = rom.find(data[best:best + 8])
    while pos >= 0:
        base = pos - best
        if base >= 16 and base + len(data) <= len(rom):
            seg = rom[base:base + len(data)]
            if all(seg[i] == data[i] for i in nz):
                hits.append(base - 16)
        pos = rom.find(data[best:best + 8], pos + 1)
    return hits[0] if hits else None


def wsl(cmd):
    return subprocess.run(['wsl', '-e', 'bash', '-lc', cmd], capture_output=True, text=True, errors='replace')


def wslpath(p):
    p = os.path.abspath(p).replace('\\', '/')
    return '/mnt/' + p[0].lower() + p[2:]


def kinds(c):
    """All switch case-label lists in the printed C, as a list of label strings."""
    sw = []
    for m in re.finditer(r'switch\((.*?)\)', c):
        sw.append(m.start())
    sw.append(len(c))
    res = []
    for a, b in zip(sw, sw[1:], strict=False):
        labs = re.findall(r'\bcase (0x[0-9a-fA-F]+|\d+):', c[a:b])
        res.append(labs)
    return res


def classify(labs):
    """index (gcd 1, small), offset (all multiples of a step >1 from 0), address (labels look like
    code addresses: min >= 0x100 and no common small stride), else sparse. Case labels the
    decompiler groups (shared bodies) are absent, so stride is by gcd, not by gaps."""
    import math
    try:
        v = sorted({int(x, 0) for x in labs})
    except ValueError:
        return 'none'
    if len(v) < 2:
        return 'none'
    g = 0
    for x in v:
        g = math.gcd(g, x)
    if v[0] >= 0x100 and g < 8:
        return 'address'
    if g == 1:
        return 'index'
    return 'offset'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--capdir', required=True)
    ap.add_argument('--workdir', required=True, help='DecompileSiteProbe REALROM_WORK_DIR (row logs)')
    ap.add_argument('--outdir', required=True)
    ap.add_argument('--ctl-bin', required=True)
    ap.add_argument('--new-bin', required=True)
    ap.add_argument('--sleighhome-65816', required=True)
    ap.add_argument('--sleighhome-nes', default='')
    ap.add_argument('--rows', default='')
    ap.add_argument('--sites', default='', help='only these site keys (file stems), comma-separated')
    ap.add_argument('--drop-callreturn', action='store_true',
                    help='drop callreturn flow overrides first: the console refuses them where the capture '
                    'applied one to a conditional branch ("Do not currently support CBRANCH overrides"). '
                    'Changes the function body; pair with a large --extend')
    ap.add_argument('--extend', type=lambda x: int(x, 0), default=0x400)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    mf = manifest_rows()
    nes_dirs = os.environ.get('GRM_ROM_DIR', '').split(';')
    snes_dirs = os.environ.get('GRM_SNES_ROM_DIR', '').split(';')
    rows = a.rows.split(',') if a.rows else sorted(os.listdir(a.capdir))
    print('row\tsite\tfn\tctl_kinds\tnew_kinds\ttrace\tctl_labels\tnew_labels')
    for row in rows:
        snes = row.startswith('w_')
        sha, _ = mf.get(row, (None, None))
        rom_path = find_rom(sha, snes_dirs if snes else nes_dirs) if sha else None
        if not rom_path:
            print('%s\t-\t-\tROM NOT FOUND' % row)
            continue
        rom = open(rom_path, 'rb').read()
        log = open(os.path.join(a.workdir, row, row + '.log'), encoding='utf-8', errors='replace').read()
        # the headless log wraps long lines (sometimes at the space before fn=): unwrap first
        log = re.sub(r'\r?\n(?!(?:INFO|WARN|ERROR|DEBUG|TRACE)\s)', '', log)
        fns = dict(re.findall(r'DECOMP (\S+?)\s*fn=(\S+?)@', log))
        hirom = row in ('w_ff3', 'w_ct')
        for fn_xml in sorted(os.listdir(os.path.join(a.capdir, row))):
            if not fn_xml.endswith('.xml'):
                continue
            site_key = fn_xml[:-4]
            if a.sites and site_key not in a.sites.split(','):
                continue
            fn = next((v for k, v in fns.items() if re.sub(r'[^A-Za-z0-9_]+', '_', k) == site_key), None)
            if not fn:
                print('%s\t%s\t-\tno fn in probe log' % (row, site_key))
                continue
            src = os.path.join(a.capdir, row, fn_xml)
            xml = open(src).read()
            if a.drop_callreturn:
                xml = re.sub(r'<flow type="callreturn">\s*<addr[^>]*/>\s*<addr[^>]*/>\s*</flow>\s*', '', xml)
                src = os.path.join(a.outdir, row + '__' + fn_xml + '.nocr')
                open(src, 'w').write(xml)
            dst = os.path.join(a.outdir, row + '__' + fn_xml)
            args = [sys.executable, '-I', os.path.join(HERE, 'debugxml-replay.py'), src, dst,
                    '--drop-branch-overrides']
            if snes:
                args += ['--rom', rom_path, '--map', 'hirom' if hirom else 'lorom']
            else:
                args += ['--rom', rom_path]
                for sp in sorted({c[0] for c in chunks(xml) if c[0] != 'RAM' and c[0] != 'register'
                                  and c[0] != 'unique' and c[0] != 'stack'}):
                    args += ['--overlay', sp]
            for spc, off, data in chunks(xml):
                if snes and spc == 'bus':
                    args += ['--bus-chunk', '%x:%x' % (off, len(data) + a.extend)]
                elif not snes and spc not in ('register', 'unique', 'stack', 'const'):
                    po = locate_nes(rom, data)
                    if po is not None:
                        args += ['--chunk', '%x:%x:%x' % (po, off, min(len(data) + a.extend, 0x10000 - off))]
            r = subprocess.run(args, capture_output=True, text=True)
            if r.returncode:
                print('%s\t%s\t%s\tPREP FAILED %s' % (row, site_key, fn, r.stderr.strip()[-200:]))
                continue
            cmd = os.path.join(a.outdir, row + '__' + site_key + '.cmd')
            with open(cmd, 'w', newline='\n') as f:
                f.write('restore %s\nload function %s\ndecompile\nprint C\nquit\n' % (os.path.basename(dst), fn))
            res = []
            for binp in (a.ctl_bin, a.new_bin):
                home = a.sleighhome_65816 if snes else a.sleighhome_nes
                w = wsl('cd %s && SLEIGHHOME=%s %s < %s 2>&1' % (wslpath(a.outdir), home, binp, wslpath(cmd)))
                res.append(w.stdout)
            for tag, txt in zip(("ctl", "new"), res, strict=False):
                open(os.path.join(a.outdir, row + '__' + site_key + '.' + tag + '.out'), 'w').write(txt)
            ck, nk = kinds(res[0]), kinds(res[1])
            trace = len(re.findall(r'HF5H34', res[1]))
            fmt = lambda ks: ','.join(classify(k) for k in ks) or 'noswitch'
            show = lambda ks: ' | '.join(','.join(k[:6]) for k in ks)
            print('%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' % (row, site_key, fn, fmt(ck), fmt(nk), 'TRACE x%d' % trace if trace else '-',
                                                    show(ck), show(nk)))
            sys.stdout.flush()


if __name__ == '__main__':
    main()
