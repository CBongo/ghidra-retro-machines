"""Prepare a Ghidra decompiler debug XML for replay in the console decompiler (decomp_dbg).

Written for grm-hf5h.4 (cv3 W8000_B4::80a1). The XML comes from
tools/banktest/DecompileSiteProbe.java with GRM_DECOMPILE_DEBUG_DIR set (run as
REALROM_EXTRA_POSTSCRIPT through realrom-test.sh). Three things stop it replaying as written:

  1. Overlay spaces (NES bank windows such as W8000_B4) are not declared in the XML, so restore
     fails with "Unknown address space name". --overlay renames every overlay space to the space
     it overlays (default RAM). That is sound only when the function and every byte it reads live
     in that one overlay plus non-banked memory.
  2. A "branch" flow override on a conditional branch makes the console refuse the function
     ("Could not apply BRANCH override"). --drop-branch-overrides removes them; they do not affect
     switch recovery.
  3. The image holds only the bytes the ORIGINAL decompile read. A candidate build that reads more
     (e.g. a jump table the trivial model never touched) gets DataUnavailError and fails for that
     reason alone. --chunk PRG_OFF:CPU_ADDR:LEN (hex) splices bytes from the iNES ROM in readonly.
     Splices overwrite the image's bytes (existing chunks are merged and re-emitted), because a
     chunk that spans bytes the original decompile never read holds zeros there and the loader
     answers from the first chunk covering an address.

  4. (grm-hf5h.10) SNES 65816 rows: --rom <file.sfc|.smc> --map lorom|hirom --bus-chunk ADDR:LEN
     (hex, 24-bit bus address) splices ROM bytes into space "bus" the same way. A 512-byte copier
     header is detected from the file size and skipped. The space name is --space (default bus).
     The 65816 language is this extension's, so also point SLEIGHHOME at a tree holding its .sla
     (<home>/Ghidra/Processors/65816/data/languages/w65816.{ldefs,sla,pspec,cspec}).

  5. (grm-hf5h.17's follow-up) A switch override's scope (jmp_<addr>) can name a parent id the
     XML never defines; restore aborts AND skips <context_points>, so the replay quietly runs
     without M/X width context. Such orphan scopes are always dropped (noted on stdout).

Usage:
  python -I tools/decompiler/debugxml-replay.py <in.xml> <out.xml> [--overlay NAME[=BASE]]...
      [--drop-branch-overrides] [--rom <file.nes> --chunk OFF:ADDR:LEN ...]
Then, in WSL with decomp_dbg built from the candidate tree and SLEIGHHOME=<Ghidra install>:
  restore <out.xml> / load function <name> / decompile / print C
"""
import argparse
import re


SCOPE_RE = re.compile(r'<scope name="([^"]*)" id="(0x[0-9a-fA-F]+)">\s*<parent id="(0x[0-9a-fA-F]+)"/>'
                      r'.*?</scope>\n?', re.S)


def drop_orphan_scopes(s):
    """Remove top-level <scope> blocks whose parent id is not defined in the XML (always on).

    A switch override's namespace (jmp_<addr>) can name a parent scope the probe never wrote.
    restore then aborts with "Could not find scope matching id", and the abort also skips
    <context_points>, so the replay runs without context (65816 M/X widths) and silently
    decompiles something else (grm-hf5h.17). Repeats until stable, since a drop can orphan a child.
    """
    while True:
        defined = {int(m.group(1), 16) for m in re.finditer(r'<scope name="[^"]*" id="(0x[0-9a-fA-F]+)">', s)}
        defined.add(0)
        orphans = [m for m in SCOPE_RE.finditer(s) if int(m.group(3), 16) not in defined]
        if not orphans:
            return s
        for m in reversed(orphans):
            print('dropped scope %s (id %s): parent %s not in XML' % m.groups())
            s = s[:m.start()] + s[m.end():]


def splice_image(s, splices):
    """Overlay (space, addr, bytes) splices onto the XML's <binaryimage>, rewriting its chunks.

    The loader answers from the FIRST chunk that covers an address, and a chunk spanning bytes the
    original decompile never read holds zeros there, so a spliced chunk cannot simply be added: the
    existing chunks are merged into one byte map, the splices overwrite it, and contiguous runs
    are written back out.
    """
    m = re.search(r'<binaryimage[^>]*>\s*', s)
    e = s.index('</binaryimage>')
    mem = {}
    # Each byte keeps its chunk's readonly flag: re-emitting writable RAM as readonly would let the
    # decompiler fold it as a constant and change the replay. Splices (ROM bytes) are readonly.
    for cm in re.finditer(r'<bytechunk space="([^"]*)" offset="0x([0-9a-f]+)"([^>]*)>(.*?)</bytechunk>',
                          s[m.end():e], re.S):
        ro = 'readonly="true"' in cm.group(3)
        data = bytes.fromhex(''.join(cm.group(4).split()))
        for i, bt in enumerate(data):
            mem[(cm.group(1), int(cm.group(2), 16) + i)] = (bt, ro)
    for spc, addr, data in splices:
        for i, bt in enumerate(data):
            mem[(spc, addr + i)] = (bt, True)
    out = ''
    run = None                  # (space, start, readonly, bytearray)
    for key in sorted(mem) + [None]:
        if run and (key is None or key != (run[0], run[1] + len(run[3])) or mem[key][1] != run[2]):
            out += '<bytechunk space="%s" offset="0x%x"%s>\n%s\n</bytechunk>\n' % (
                run[0], run[1], ' readonly="true"' if run[2] else '', bytes(run[3]).hex())
            run = None
        if key is not None:
            if run is None:
                run = (key[0], key[1], mem[key][1], bytearray())
            run[3].append(mem[key][0])
    return s[:m.end()] + out + s[e:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('inp')
    ap.add_argument('out')
    ap.add_argument('--overlay', action='append', default=[], help='NAME or NAME=BASE (BASE default RAM)')
    ap.add_argument('--drop-branch-overrides', action='store_true')
    ap.add_argument('--rom')
    ap.add_argument('--chunk', action='append', default=[], help='PRG_OFF:CPU_ADDR:LEN, hex (iNES)')
    ap.add_argument('--bus-chunk', action='append', default=[], help='ADDR:LEN, hex (SNES, needs --map)')
    ap.add_argument('--map', choices=['lorom', 'hirom'])
    ap.add_argument('--space', default='bus')
    a = ap.parse_args()
    with open(a.inp) as f:
        s = f.read()
    for spec in a.overlay:
        name, _, base = spec.partition('=')
        base = base or 'RAM'
        s = s.replace('space="%s"' % name, 'space="%s"' % base)
    s = drop_orphan_scopes(s)
    if a.drop_branch_overrides:
        s, n = re.subn(r'<flow type="branch">\s*<addr[^>]*/>\s*<addr[^>]*/>\s*</flow>\s*', '', s)
        print('dropped %d branch override(s)' % n)
    splices = []                # (space, address, bytes)
    if a.bus_chunk:
        if not (a.rom and a.map):
            ap.error('--bus-chunk needs --rom and --map')
        with open(a.rom, 'rb') as f:
            rom = f.read()
        hdr = 512 if len(rom) % 1024 == 512 else 0
        for c in a.bus_chunk:
            addr, ln = (int(x, 16) for x in c.split(':'))
            if a.map == 'hirom':
                off = addr & 0x3fffff
            else:
                off = ((addr >> 16) & 0x7f) * 0x8000 + (addr & 0x7fff)
            splices.append((a.space, addr, rom[hdr + off:hdr + off + ln]))
            print('spliced 0x%x+%d (file off 0x%x)' % (addr, ln, hdr + off))
    if a.chunk:
        if not a.rom:
            ap.error('--chunk needs --rom')
        with open(a.rom, 'rb') as f:
            rom = f.read()
        for c in a.chunk:
            off, addr, ln = (int(x, 16) for x in c.split(':'))
            splices.append(('RAM', addr, rom[16 + off:16 + off + ln]))
            print('spliced 0x%x+%d' % (addr, ln))
    if splices:
        s = splice_image(s, splices)
    with open(a.out, 'w') as f:
        f.write(s)


if __name__ == '__main__':
    main()
