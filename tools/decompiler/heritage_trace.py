"""Inject heritage diagnostics into a SCRATCH COPY of a Ghidra decompiler C++ tree (grm-hf5h.6).

Written to diagnose "Low-level Error: Overlapping input varnodes" on 6502 (the stack-space
wraparound of the JSR return-address push) and the size-0 varnodes a stock typo produced; kept
because the same questions -- which two varnodes collide, where each was born, which pass made
a malformed varnode -- recur for any heritage failure. Never apply it to a tree that builds a
binary meant for install: it changes error text and writes a trace file.

What it adds (each hook is an exact-anchor substitution that fails loudly if its anchor is not
unique, so it also detects drift on a new Ghidra tag; CRLF/LF line endings are preserved):
  1. funcdata_varnode.cc: the "Overlapping input varnodes" exception names both varnodes, up to
     six readers of the old one, and the caller (tag, heritage pass, the op being renamed). The
     tag is set at heritage.cc's setInputVarnode call sites (guardInput holes/tail, renameRecurse
     reads and MULTIEQUAL inputs); any other caller reports tag=?.
  2. heritage.cc Heritage::heritage: per heritaged space, one "heritage fn=.. pass=.. space=.."
     line, plus every varnode that wraps past the top of its space and every size-0 varnode.
  3. funcdata_varnode.cc newVarnode/newVarnodeOut: a "zeronew <retaddr> base <&grmTrace>" line for
     each size-0 creation. Resolve the caller with
       printf '%x' $((<nm address of ghidra::grmTrace> + retaddr - base))   then
       addr2line -f -C -e <exe> 0x<that>   (or nm -C --numeric-sort and take the symbol below it).
  4. action.cc Action::perform: one "act <fn> <name>" line per action when GRM_DEC_TRACE_ACT is set
     (large).
Hooks 2-4 append to the file named by the GRM_DEC_TRACE environment variable (unset: silent).
The variable reaches decompile.exe through analyzeHeadless, e.g.
  GRM_DEC_TRACE=<scratch>/trace.txt bash tools/banktest/realrom-test.sh check --only <row> --no-build
with a shadow install (tools/banktest/mkshadow.ps1) holding the traced build.

Usage: python -I tools/decompiler/heritage_trace.py <decompile/cpp dir>
Then build with tools/decompiler/build.sh.
"""
import os
import sys


def sub(cpp, name, old, new):
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


TRACE_FN = (
    "void grmTrace(const string &s) { const char *p = getenv(\"GRM_DEC_TRACE\"); if (p == 0) return;"
    " FILE *f = fopen(p, \"a\"); if (f == 0) return; fprintf(f, \"%s\\n\", s.c_str()); fclose(f); }\n"
    "const char *g_ovl_tag = \"?\";\nPcodeOp *g_ovl_op = (PcodeOp *)0;\n"
    "static string ovlDesc(Varnode *v) { ostringstream s; v->printRaw(s); s << \" sz=\" << dec << v->getSize();"
    " int4 n=0; for(list<PcodeOp *>::const_iterator it=v->beginDescend();it!=v->endDescend() && n<6;++it,++n)"
    " { s << \" | rd@\" << hex << (*it)->getAddr().getOffset() << \": \"; (*it)->printRaw(s); } return s.str(); }\n")

ZERO_HOOK = ("  if (s == 0) { ostringstream zm; zm << \"zeronew \" << hex"
             " << (uintptr_t)__builtin_return_address(0) << \" base \" << (uintptr_t)&grmTrace; grmTrace(zm.str()); }\n")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    cpp = sys.argv[1]
    sub(cpp, 'funcdata_varnode.cc', "namespace ghidra {\n", "namespace ghidra {\n\n" + TRACE_FN)
    sub(cpp, 'funcdata_varnode.cc', "\tthrow LowlevelError(\"Overlapping input varnodes\");",
        "\t{ ostringstream m; m << \"Overlapping input varnodes [tag=\" << g_ovl_tag << \" pass=\" << dec << getHeritagePass()"
        " << \" NEW \" << ovlDesc(vn) << \" ;; OLD \" << ovlDesc(invn);"
        " if (g_ovl_op != (PcodeOp *)0) { m << \" ;; AT@\" << hex << g_ovl_op->getAddr().getOffset() << \": \"; g_ovl_op->printRaw(m); }"
        " m << \"]\"; throw LowlevelError(m.str()); }")
    for sig in ("Varnode *Funcdata::newVarnodeOut(int4 s,const Address &m,PcodeOp *op)\n\n{\n",
                "Varnode *Funcdata::newVarnode(int4 s,const Address &m,Datatype *ct)\n\n{\n"):
        sub(cpp, 'funcdata_varnode.cc', sig, sig + ZERO_HOOK)

    sub(cpp, 'heritage.cc', "namespace ghidra {\n",
        "namespace ghidra {\n\nextern void grmTrace(const string &s);\nextern const char *g_ovl_tag;\nextern PcodeOp *g_ovl_op;\n")
    sub(cpp, 'heritage.cc',
        "\tvn = fd->newVarnode(sz,Address(addr.getSpace(),cur));\n\tvn = fd->setInputVarnode(vn);",
        "\tvn = fd->newVarnode(sz,Address(addr.getSpace(),cur));\n\tg_ovl_tag=\"guardInput-hole\"; g_ovl_op=(PcodeOp *)0;\n"
        "\tvn = fd->setInputVarnode(vn);")
    sub(cpp, 'heritage.cc',
        "      vn = fd->newVarnode(sz,Address(addr.getSpace(),cur));\n      vn = fd->setInputVarnode(vn);",
        "      vn = fd->newVarnode(sz,Address(addr.getSpace(),cur));\n      g_ovl_tag=\"guardInput-tail\"; g_ovl_op=(PcodeOp *)0;\n"
        "      vn = fd->setInputVarnode(vn);")
    sub(cpp, 'heritage.cc',
        "\t  vnnew = fd->setInputVarnode(vnnew);\n\t  stack.push_back(vnnew);\n\t}\n\telse\n\t  vnnew = stack.back();\n\t\t\t\t// INDIRECTs",
        "\t  g_ovl_tag=\"rename-read\"; g_ovl_op=op;\n\t  vnnew = fd->setInputVarnode(vnnew);\n\t  stack.push_back(vnnew);\n"
        "\t}\n\telse\n\t  vnnew = stack.back();\n\t\t\t\t// INDIRECTs")
    sub(cpp, 'heritage.cc',
        "\tif (stack.empty()) {\n\t  vnnew = fd->newVarnode(vnin->getSize(),vnin->getAddr());\n\t  vnnew = fd->setInputVarnode(vnnew);\n"
        "\t  stack.push_back(vnnew);\n\t}\n\telse\n\t  vnnew = stack.back();\n\tfd->opSetInput(multiop",
        "\tif (stack.empty()) {\n\t  vnnew = fd->newVarnode(vnin->getSize(),vnin->getAddr());\n\t  g_ovl_tag=\"rename-multi\"; g_ovl_op=multiop;\n"
        "\t  vnnew = fd->setInputVarnode(vnnew);\n\t  stack.push_back(vnnew);\n\t}\n\telse\n\t  vnnew = stack.back();\n\tfd->opSetInput(multiop")
    sub(cpp, 'heritage.cc',
        "    if (info->hasCallPlaceholders)\n      clearStackPlaceholders(info);\n",
        "    if (info->hasCallPlaceholders)\n      clearStackPlaceholders(info);\n"
        "    { ostringstream m; m << \"heritage fn=\" << hex << fd->getAddress().getOffset() << \" pass=\" << dec << pass"
        " << \" space=\" << info->space->getName(); grmTrace(m.str()); }\n"
        "    for(VarnodeLocSet::const_iterator wi=fd->beginLoc(info->space);wi!=fd->endLoc(info->space);++wi) {\n"
        "      Varnode *w = *wi;\n"
        "      bool zero = (w->getSize() == 0);\n"
        "      if (!zero && (uintb)(w->getSize() - 1) <= w->getSpace()->getHighest() - w->getOffset()) continue;\n"
        "      ostringstream m; m << (zero ? \"zero\" : \"wrap\") << \" fn=\" << hex << fd->getAddress().getOffset()"
        " << \" pass=\" << dec << pass << \" \"; w->printRaw(m);\n"
        "      if (w->isWritten()) { m << \" def@\" << hex << w->getDef()->getAddr().getOffset() << \": \"; w->getDef()->printRaw(m); }\n"
        "      int4 n=0; for(list<PcodeOp *>::const_iterator it=w->beginDescend();it!=w->endDescend()&&n<2;++it,++n)"
        " { m << \" rd@\" << hex << (*it)->getAddr().getOffset() << \": \"; (*it)->printRaw(m); }\n"
        "      grmTrace(m.str());\n"
        "    }\n")

    sub(cpp, 'action.cc', "int4 Action::perform(Funcdata &data)\n\n{\n",
        "extern void grmTrace(const string &s);\n"
        "int4 Action::perform(Funcdata &data)\n\n{\n"
        "  if (getenv(\"GRM_DEC_TRACE_ACT\") != 0) { ostringstream m; m << \"act \" << hex"
        " << data.getAddress().getOffset() << \" \" << name; grmTrace(m.str()); }\n")
    print('heritage trace hooks applied to', cpp)


main()
