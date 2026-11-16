"""Describe the 65816 indirect-jump dispatches in a decompiler debug XML (written for grm-hf5h.10).

For every <jumptable> override in the XML (tools/banktest/DecompileSiteProbe.java with
GRM_DECOMPILE_DEBUG_DIR), decode the instruction at the switch address from the XML's byte image
and print its mnemonic, the operand, the instruction bytes before it, and the --bus-chunk
argument tools/decompiler/debugxml-replay.py needs to splice the table it reads from the ROM.

Usage:
  python -I tools/decompiler/debugxml-dispatch.py <site.xml> [--entries N]
"""
import argparse
import re

OPS = {0x7c: ('JMP (abs,X)', 2), 0x6c: ('JMP (abs)', 2), 0xdc: ('JML [abs]', 2),
       0xfc: ('JSR (abs,X)', 2), 0x4c: ('JMP abs', 2), 0x5c: ('JML long', 3)}


def image(s):
    mem = {}
    for cm in re.finditer(r'<bytechunk space="([^"]*)" offset="0x([0-9a-f]+)"[^>]*>(.*?)</bytechunk>', s, re.S):
        data = bytes.fromhex(''.join(cm.group(3).split()))
        for i, bt in enumerate(data):
            mem[int(cm.group(2), 16) + i] = bt
    return mem


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('xml')
    ap.add_argument('--entries', type=int, default=0, help='table entries to splice (default: dest count + 4)')
    a = ap.parse_args()
    with open(a.xml) as f:
        s = f.read()
    mem = image(s)
    for jm in re.finditer(r'<jumptable>\s*<addr space="[^"]*" offset="0x([0-9a-f]+)"/>(.*?)</jumptable>', s, re.S):
        sw = int(jm.group(1), 16)
        dests = re.findall(r'<dest space="[^"]*" offset="0x([0-9a-f]+)"', jm.group(2))
        op = mem.get(sw)
        name, n = OPS.get(op, ('opcode %02x' % (op or 0), 0))
        operand = sum(mem.get(sw + 1 + i, 0) << (8 * i) for i in range(n))
        before = ' '.join('%02x' % mem.get(x, 0) for x in range(sw - 8, sw))
        print('switch %06x  %s $%04x  dests=%d  bytes before: %s' % (sw, name, operand, len(dests), before))
        if op in (0x7c, 0x6c, 0xdc):
            ent = 3 if op == 0xdc else 2
            cnt = a.entries or len(dests) + 4
            base = (sw & 0xff0000) | operand if op == 0x7c else operand
            print('   table %06x  --bus-chunk %x:%x' % (base, base, ent * cnt))


if __name__ == '__main__':
    main()
