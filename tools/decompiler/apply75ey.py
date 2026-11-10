"""Apply the grm-75ey local decompiler patch set to a Ghidra decompiler C++ tree.

The patch set is today's shipped one: the GP-6936 fix (space.cc/translate.cc) plus the grm-6m24
hunk that lifts the GP-6945 bad-data cap (architecture.cc). Each hunk is an exact-anchor
substitution that fails loudly if the anchor is not unique, so it doubles as a drift check on a
new Ghidra tag. Line endings are preserved. Written for grm-gipk.25 / grm-hf5h so a CONTROL
(shipped) and a CANDIDATE decompile.exe can be rebuilt from one stock tree.

Usage: python -I tools/decompiler/apply75ey.py <decompile/cpp dir>
Then build with tools/decompiler/build.sh and place the result with tools/banktest/mkshadow.ps1.
"""
import sys
import os

cpp = sys.argv[1]


def sub(name, old, new):
    p = os.path.join(cpp, name)
    with open(p, 'rb') as f:
        s = f.read().decode('latin-1')
    nl = '\r\n' if '\r\n' in s else '\n'
    old = old.replace('\n', nl)
    new = new.replace('\n', nl)
    if s.count(old) != 1:
        sys.exit('anchor not unique/found in %s: %r' % (name, old[:60]))
    s = s.replace(old, new)
    with open(p, 'wb') as f:
        f.write(s.encode('latin-1'))


sub('space.cc',
    "  pointerUpperBound -= bufferSize;\n}\n",
    "  pointerUpperBound -= bufferSize;\n"
    "  // A range running off the top of a processor space wraps on real hardware: address\n"
    "  // arithmetic in such a space is modulo its size.  A truncated space is a logical window\n"
    "  // onto a larger space, not the full modular range, so it does not wrap.\n"
    "  if (type == IPTR_PROCESSOR && (flags & truncated) == 0)\n"
    "    flags |= allows_wrapped_range;\n"
    "  else\n"
    "    flags &= ~allows_wrapped_range;\n"
    "}\n")
sub('translate.cc', "  setFlags(allows_wrapped_range);\n", "")
sub('translate.cc', "  setFlags(programspecific | allows_wrapped_range);\n", "  setFlags(programspecific);\n")
sub('translate.cc',
    "    return addr;\t\t// Size is ignored\n  uintb dist",
    "    return addr;\t\t// Size is ignored\n"
    "  if (spc->getType() == IPTR_SPACEBASE)\n"
    "    return addr;\t\t// Offsets in a spacebase are signed displacements from a base\n"
    "\t\t\t// register, not addresses in a bounded space.  A range that\n"
    "\t\t\t// crosses offset 0 is contiguous within the frame, not wrapped.\n"
    "  uintb dist")
sub('architecture.cc', "  max_baddata = 4;",
    "  max_baddata = 0xffffffff;\t// local patch (grm-6m24): no GP-6945 cap; banked ROMs flow into unresolved windows")
print('ok')
