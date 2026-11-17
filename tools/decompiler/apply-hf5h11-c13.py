"""Candidate 13 (grm-hf5h.11, 65816): stacked on candidate 12 (tools/decompiler/apply-hf5h11.py).

A 65816 dispatch with M set shifts the 8-bit A and then copies B:A to the 16-bit X, so the switch
variable is CONCAT11(B, A<<1). Candidate 12 cannot step through the CONCAT. This patch labels such a
switch by (A & 0x7f) (or A when bit 7 is proven clear), using candidate 12's decline rules. UNLIKE the
6502 masked case, which is exact unconditionally, this rests on the IN-BOUNDS assumption jump-table
recovery already makes: with at most lowmask+1 table entries a nonzero B would index past the table,
so B is taken to be 0. It declines when B is a nonzero constant, and it reverts to offset labels when
any label value has a nonzero high part, is not a multiple of the stride, or the table has more than
lowmask+1 entries. With M clear the ASL is 16-bit and candidate 12's INT_LEFT step already applies
(lowmask 0x7fff, exact).

usage: python -I tools/decompiler/apply-hf5h11-c13.py <decompile cpp dir already patched by
       tools/decompiler/apply-hf5h11.py>   (candidate 13 sha256 494b16bb...)
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

edit(os.path.join(d, 'jumptable.hh'), [
    ("""  mutable bool shiftRevert;		///< Label values did not reverse through the shift: switch on \\b shiftvn instead
""",
     """  mutable bool shiftRevert;		///< Label values did not reverse through the shift: switch on \\b shiftvn instead
  int4 pieceShift;			///< Shift amount when \\b switchvn was reached through CONCAT(hi, i << c) (0 = not)
  int4 pieceLoSize;			///< Size in bytes of the low piece of that CONCAT
"""),
    ("""  Varnode *labelVarnode(void) const { return shiftRevert ? shiftvn : switchvn; }	///< Varnode the labels are computed for
""",
     """  Varnode *labelVarnode(void) const { return shiftRevert ? shiftvn : switchvn; }	///< Varnode the labels are computed for
  void findPieceShift(int4 pathPos);	///< Step from CONCAT(hi, i << c) to \\b i (65816 B:A after an 8-bit ASL)
  uintb labelValue(Funcdata *fd,uintb val) const;	///< Label for a normalized value, given the steps taken
"""),
    ("""switchMask = 0; shiftvn = (Varnode *)0; shiftRevert = false; }	///< Construct given a parent JumpTable""",
     """switchMask = 0; shiftvn = (Varnode *)0; shiftRevert = false; pieceShift = 0; pieceLoSize = 0; }	///< Construct given a parent JumpTable"""),
])

edit(os.path.join(d, 'jumptable.cc'), [
    # resets
    ("""  switchvn = normalvn;
  switchMask = 0;
  shiftvn = (Varnode *)0;
  shiftRevert = false;
  markModel(true);""",
     """  switchvn = normalvn;
  switchMask = 0;
  shiftvn = (Varnode *)0;
  shiftRevert = false;
  pieceShift = 0;
  pieceLoSize = 0;
  markModel(true);"""),
    ("""void JumpBasic2::findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)

{
  switchMask = 0;
  shiftvn = (Varnode *)0;
  shiftRevert = false;
""",
     """void JumpBasic2::findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)

{
  switchMask = 0;
  shiftvn = (Varnode *)0;
  shiftRevert = false;
  pieceShift = 0;
  pieceLoSize = 0;
"""),
    ("""  if (istwoleaf) { switchMask = 0; shiftvn = (Varnode *)0; shiftRevert = false; return; }""",
     """  if (istwoleaf) { switchMask = 0; shiftvn = (Varnode *)0; shiftRevert = false; pieceShift = 0; pieceLoSize = 0; return; }"""),
    # hook at the end of findUnnormalized
    ("""    if (switchvn != testvn) break;
    i += 1;
  }
  markModel(false);
}""",
     """    if (switchvn != testvn) break;
    i += 1;
  }
  if (shiftvn == (Varnode *)0 && countleftright < maxleftright && switchvn->isWritten() &&
      switchvn->getDef()->code() == CPUI_PIECE)
    findPieceShift(pathMeld.numCommonVarnode());
  markModel(false);
}

/// The switch variable is CONCAT(hi, i << c): on the 65816 with M set, an 8-bit ASL A followed by a
/// 16-bit TAX copies B:A into the index register.  The dispatch reads entry (hi << (8*lo-c)) | (i &
/// lowmask) of the table, and this step labels it by (i & lowmask) alone.  That rests on the
/// in-bounds assumption jump-table recovery already makes, NOT on data-flow: a table of at most
/// lowmask+1 entries is indexed past its end by any nonzero \\b hi, so \\b hi is taken to be 0.
/// checkShiftReversal enforces the table bound and reverts the step if any label value has a nonzero
/// high part.  A constant nonzero \\b hi declines, and so do candidate 12's rules (shiftStepAllowed).
/// \\param pathPos is passed to shiftStepAllowed: path Varnodes before it count as the near side
void JumpBasic::findPieceShift(int4 pathPos)

{
  PcodeOp *pop = switchvn->getDef();
  Varnode *hi = pop->getIn(0);
  Varnode *lo = pop->getIn(1);
  if (hi->isConstant() && hi->getOffset() != 0) return;	// B is provably nonzero
  if (!lo->isWritten()) return;
  PcodeOp *sop = lo->getDef();
  if (sop->code() != CPUI_INT_LEFT || !sop->getIn(1)->isConstant()) return;
  Varnode *invn = sop->getIn(0);
  int4 sz = lo->getSize();
  uintb sa = sop->getIn(1)->getOffset();
  if (sa == 0 || sa >= 8*sz || invn->getSize() != sz) return;
  uintb lowmask = calc_mask(sz) >> sa;
  int4 res = 2;
  if ((invn->getNZMask() & ~lowmask) != 0 && !guardsBoundBelow(invn,lowmask)) {
    res = shiftStepAllowed(sop,invn,pathPos,lowmask);
    if (res == 0) return;
  }
  if (res == 1)
    switchMask = lowmask;
  shiftvn = switchvn;
  switchvn = invn;
  pieceShift = sa;
  pieceLoSize = sz;
}

/// \\param fd is the function containing the switch
/// \\param val is a value of the normalized switch variable
/// \\return the case label for it
uintb JumpBasic::labelValue(Funcdata *fd,uintb val) const

{
  if (pieceShift != 0 && !shiftRevert) {
    uintb lomask = calc_mask(pieceLoSize);
    if ((val & ~lomask) != 0 || (val & ((((uintb)1) << pieceShift) - 1)) != 0)
      throw EvaluationError("Value is not an in-bounds scaled index");
    return val >> pieceShift;
  }
  return backup2Switch(fd,val,normalvn,labelVarnode());
}"""),
    # checkShiftReversal: piece mode validation
    ("""  shiftRevert = false;
  if (shiftvn == (Varnode *)0) return;
  for(int4 k=0;k<vals.size();++k) {""",
     """  shiftRevert = false;
  if (shiftvn == (Varnode *)0) return;
  if (pieceShift != 0) {	// In-bounds assumption: every value must be a scaled index in the low piece
    uintb lowmask = calc_mask(pieceLoSize) >> pieceShift;
    if (vals.size() > lowmask + 1) { shiftRevert = true; return; }
    for(int4 k=0;k<vals.size();++k) {
      try {
	labelValue(fd,vals[k]);
      } catch(EvaluationError &err) {
	shiftRevert = true;
	return;
      }
    }
    return;
  }
  for(int4 k=0;k<vals.size();++k) {"""),
    ("""	switchval = backup2Switch(fd,val,normalvn,labelVarnode());	// Do reverse emulation to get original switch value""",
     """	switchval = labelValue(fd,val);	// Do reverse emulation to get original switch value"""),
    ("""      addr = backup2Switch(fd,values[i],normalvn,labelVarnode());""",
     """      addr = labelValue(fd,values[i]);"""),
])
