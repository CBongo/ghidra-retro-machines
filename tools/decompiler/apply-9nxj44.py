"""PROTOTYPE (grm-9nxj.44): let RuleLoadVarnode/RuleStoreVarnode see a stack reference through
INT_ZEXT when the spacebase register is narrower than its containing space (65816: 16-bit SP,
24-bit bus; push/pull form the address as zext(SP)).

NOT INSTALLED, NOT GATED. Measured only in WSL decomp_dbg replay (stacked on the candidate-17
tree, ~/hf5h21/c14t) on ff2 FUN_0182cd; see the grm-9nxj.44 comment. Alone it folds straight-line
push/pull pairs; stack slots across a call still need SP in <unaffected> and a callee extrapop of
2 (JSR) / 3 (JSL), or the pull after a JSR forwards the return-address byte instead.

usage: python -I tools/decompiler/apply-9nxj44.py <decompile cpp dir>
"""
import os
import sys


def edit(path, pairs):
    s = open(path, newline='').read()
    nl = '\r\n' if '\r\n' in s else '\n'
    for old, new in pairs:
        old = old.replace('\n', nl)
        new = new.replace('\n', nl)
        assert s.count(old) == 1, 'anchor not unique/found in %s: %r' % (path, old[:80])
        s = s.replace(old, new, 1)
    open(path, 'w', newline='').write(s)
    print('patched', path)


d = sys.argv[1]
edit(os.path.join(d, 'ruleaction.cc'), [(
    '  if (!vn->isWritten()) return (AddrSpace *)0;\n'
    '  op = vn->getDef();\n'
    '  if (op->code() != CPUI_INT_ADD) return (AddrSpace *)0;\n',
    '  if (!vn->isWritten()) return (AddrSpace *)0;\n'
    '  op = vn->getDef();\n'
    '  // grm-9nxj.44: a stack pointer narrower than its containing space reaches LOAD/STORE\n'
    '  // zero-extended (65816: zext(SP) into the 24-bit bus). The stack space\'s own offsets\n'
    '  // wrap at the register width, so zext(SP + c) is exactly stack offset c.\n'
    '  if (op->code() == CPUI_INT_ZEXT && vn->getSize() == spc->getAddrSize()) {\n'
    '    Varnode *inner = op->getIn(0);\n'
    '    if (inner->getSize() >= vn->getSize()) return (AddrSpace *)0;\n'
    '    retspace = vnSpacebase(glb,inner,val,spc);\n'
    '    if (retspace == (AddrSpace *)0 || retspace->getType() != IPTR_SPACEBASE) return (AddrSpace *)0;\n'
    '    if (retspace->getAddrSize() != inner->getSize()) return (AddrSpace *)0;\n'
    '    return retspace;\n'
    '  }\n'
    '  if (op->code() != CPUI_INT_ADD) return (AddrSpace *)0;\n',
)])
