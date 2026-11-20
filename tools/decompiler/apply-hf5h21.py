"""Candidate 16 part (grm-hf5h.21): stacked on candidate 14 (tools/decompiler/apply-hf5h11.py,
apply-hf5h11-c13.py, apply-hf5h20.py); independent of apply-hf5h31.py, either order.

ROOT CAUSE. cv3 RAM::e137 (inlined into FUN_W8000_B22__bcf9, FUN_W8000_B2__8514, FUN_W8000_B2__890c:
LDA $6d; ASL A; BCS away; TAY; LDA $9f31,Y; JMP ($0044)) printed switch(A<<1) with offset labels
although the BCS proves A < 0x80, which would make switch(A) with index labels exact (candidate 12's
shiftStepAllowed passes it). Live tracing of the final decompile showed findUnnormalized never gets
that far: the doubled index feeds the address add `$9f31 + Y`, so RuleShift2Mult has already turned
the INT_LEFT into `INT_MULT x,2` by the time the final model is derived, and findUnnormalized only
steps back over INT_LEFT. Its guard (`!onlyModel && def != INT_LEFT`) breaks on the MULT.

FIX. Treat INT_MULT by a constant power of two >= 2 as a left shift by its log2, everywhere the
shift step looks at INT_LEFT: findUnnormalized (guard and step) and findPieceShift. backup2Switch
reverses the step through TypeOp::recoverInputBinary, which INT_MULT lacks (the base class throws a
LowlevelError, not an EvaluationError), so OpBehaviorIntMult::recoverInputBinary is added mirroring
OpBehaviorIntLeft: for a power-of-two constant it returns out >> log2, throwing EvaluationError when
out has low bits set; any other constant defers to the base class as before. The exact / masked /
declined decision (guardsBoundBelow, shiftStepAllowed) is unchanged.

usage: python -I tools/decompiler/apply-hf5h21.py <decompile cpp dir already patched to candidate 14>
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

edit(os.path.join(d, 'jumptable.cc'), [
    ("""void JumpBasic::findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)

{
  int4 i,j;
""",
     """/// An INT_LEFT by a constant, or an INT_MULT by a constant power of two (RuleShift2Mult rewrites the
/// former into the latter when the result feeds an address add), scales its input by 2^c.
/// \\param op is the PcodeOp to test
/// \\return c, or -1 if \\b op is not such a scaling
static int4 leftShiftAmount(const PcodeOp *op)

{
  if (op->numInput() != 2 || !op->getIn(1)->isConstant()) return -1;
  uintb c = op->getIn(1)->getOffset();
  if (op->code() == CPUI_INT_LEFT)
    return (c > 0xffff) ? 0xffff : (int4)c;
  if (op->code() == CPUI_INT_MULT) {
    if (c < 2 || (c & (c-1)) != 0) return -1;
    int4 sa = 0;
    while((((uintb)1) << sa) != c) sa += 1;
    return sa;
  }
  return -1;
}

void JumpBasic::findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)

{
  int4 i,j;
"""),
    ("    if (!onlyModel && switchvn->getDef()->code() != CPUI_INT_LEFT) break;\n",
     "    if (!onlyModel && leftShiftAmount(switchvn->getDef()) < 0) break;\n"),
    ("""    case CPUI_INT_LEFT:
    {
      // An index scaled by a shift""",
     """    case CPUI_INT_LEFT:
    case CPUI_INT_MULT:
    {
      // An index scaled by a shift"""),
    ("""      if (j != 0 || !normop->getIn(1)->isConstant()) break;
      int4 sz = normop->getOut()->getSize();
      if (normop->getIn(1)->getOffset() >= 8*sz) break;
      if (testvn->getSize() != sz) break;
      uintb lowmask = calc_mask(sz) >> normop->getIn(1)->getOffset();
""",
     """      int4 sa = leftShiftAmount(normop);
      if (j != 0 || sa < 0) break;
      int4 sz = normop->getOut()->getSize();
      if (sa >= 8*sz) break;
      if (testvn->getSize() != sz) break;
      uintb lowmask = calc_mask(sz) >> sa;
"""),
    ("""  if (sop->code() != CPUI_INT_LEFT || !sop->getIn(1)->isConstant()) return;
  Varnode *invn = sop->getIn(0);
  int4 sz = lo->getSize();
  uintb sa = sop->getIn(1)->getOffset();
""",
     """  if (leftShiftAmount(sop) < 0) return;
  Varnode *invn = sop->getIn(0);
  int4 sz = lo->getSize();
  uintb sa = leftShiftAmount(sop);
"""),
])

edit(os.path.join(d, 'opbehavior.hh'), [
    ("""  OpBehaviorIntMult(void): OpBehavior(CPUI_INT_MULT,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
""",
     """  OpBehaviorIntMult(void): OpBehavior(CPUI_INT_MULT,false) {}	///< Constructor
  virtual uintb evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const;
  virtual uintb recoverInputBinary(int4 slot,int4 sizeout,uintb out,int4 sizein,uintb in) const;
"""),
])

edit(os.path.join(d, 'opbehavior.cc'), [
    ("""uintb OpBehaviorIntMult::evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const

{
  uintb res = (in1 * in2) & calc_mask(sizeout);
  return res;
}
""",
     """uintb OpBehaviorIntMult::evaluateBinary(int4 sizeout,int4 sizein,uintb in1,uintb in2) const

{
  uintb res = (in1 * in2) & calc_mask(sizeout);
  return res;
}

uintb OpBehaviorIntMult::recoverInputBinary(int4 slot,int4 sizeout,uintb out,int4 sizein,uintb in) const

{
  if (in < 2 || (in & (in-1)) != 0)	// Only a power of two is a left shift
    return OpBehavior::recoverInputBinary(slot,sizeout,out,sizein,in);
  int4 sa = 0;
  while((((uintb)1) << sa) != in) sa += 1;
  if (sa >= sizeout*8)
    return OpBehavior::recoverInputBinary(slot,sizeout,out,sizein,in);
  if (((out<<(8*sizeout-sa))&calc_mask(sizeout))!=0)
    throw EvaluationError("Output is not in range of multiplication by a power of two");
  return out >> sa;
}
"""),
])
