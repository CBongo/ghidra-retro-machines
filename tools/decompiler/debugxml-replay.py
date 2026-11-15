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

Usage:
  python -I tools/decompiler/debugxml-replay.py <in.xml> <out.xml> [--overlay NAME[=BASE]]...
      [--drop-branch-overrides] [--rom <file.nes> --chunk OFF:ADDR:LEN ...]
Then, in WSL with decomp_dbg built from the candidate tree and SLEIGHHOME=<Ghidra install>:
  restore <out.xml> / load function <name> / decompile / print C
"""
import argparse
import re


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('inp')
    ap.add_argument('out')
    ap.add_argument('--overlay', action='append', default=[], help='NAME or NAME=BASE (BASE default RAM)')
    ap.add_argument('--drop-branch-overrides', action='store_true')
    ap.add_argument('--rom')
    ap.add_argument('--chunk', action='append', default=[], help='PRG_OFF:CPU_ADDR:LEN, hex')
    a = ap.parse_args()
    with open(a.inp) as f:
        s = f.read()
    for spec in a.overlay:
        name, _, base = spec.partition('=')
        base = base or 'RAM'
        s = s.replace('space="%s"' % name, 'space="%s"' % base)
    if a.drop_branch_overrides:
        s, n = re.subn(r'<flow type="branch">\s*<addr[^>]*/>\s*<addr[^>]*/>\s*</flow>\s*', '', s)
        print('dropped %d branch override(s)' % n)
    if a.chunk:
        if not a.rom:
            ap.error('--chunk needs --rom')
        with open(a.rom, 'rb') as f:
            rom = f.read()
        chunks = ''
        for c in a.chunk:
            off, addr, ln = (int(x, 16) for x in c.split(':'))
            data = rom[16 + off:16 + off + ln]
            chunks += '<bytechunk space="RAM" offset="0x%x" readonly="true">\n%s\n</bytechunk>\n' % (
                addr, data.hex())
            print('spliced 0x%x+%d' % (addr, len(data)))
        i = s.find('<bytechunk')
        if i < 0:
            raise SystemExit('no <bytechunk> in the XML to insert before')
        s = s[:i] + chunks + s[i:]
    with open(a.out, 'w') as f:
        f.write(s)


if __name__ == '__main__':
    main()
