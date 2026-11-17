"""Candidate 12 (grm-hf5h.11): label a switch on a shifted index i<<c by i, masking i when its high
bits may be set.  Applied on top of candidate 10's jumptable.cc / jumptable.hh (LF or CRLF).

Exact when i's high bits are provably clear; otherwise switch(i & lowmask), exact because
(i<<c) == (i&lowmask)<<c; declined (offset labels kept) when the table is longer than lowmask+1
or a branch on the dominator path lets high-bit values of i reach the switch (ff1 9069's carry
picks a second table -- that case is grm-hf5h.19). Candidate 12 sha256 72a9a0fe...

usage: python -I tools/decompiler/apply-hf5h11.py <decompile cpp dir>
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
    ("""  Varnode *switchvn;			///< Unnormalized switch Varnode
  static bool isprune(Varnode *vn);""",
     """  Varnode *switchvn;			///< Unnormalized switch Varnode
  uintb switchMask;			///< Mask applied to \\b switchvn for the switch (0 = none), see findUnnormalized
  Varnode *shiftvn;			///< Output of an index shift findUnnormalized stepped back through (or null)
  mutable bool shiftRevert;		///< Label values did not reverse through the shift: switch on \\b shiftvn instead
  static bool isprune(Varnode *vn);"""),
    ("""  bool flowsOnlyToModel(Varnode *vn,PcodeOp *trailOp);	///< Check if the given Varnode flows to anything other than \\b this model
""",
     """  bool flowsOnlyToModel(Varnode *vn,PcodeOp *trailOp);	///< Check if the given Varnode flows to anything other than \\b this model
  int4 shiftStepAllowed(PcodeOp *shiftop,Varnode *invn,int4 pathPos,uintb lowmask) const;	///< Can a masked index replace a shifted one
  static bool dependsOn(Varnode *vn,Varnode *target,int4 depth);	///< Does \\b vn depend on \\b target within a few ops
  static bool evaluateOn(Varnode *vn,Varnode *target,uintb val,int4 depth,uintb &res);	///< Evaluate \\b vn as a function of \\b target
  bool guardsBoundBelow(Varnode *invn,uintb lowmask) const;	///< Does a select guard keep \\b invn within \\b lowmask
  Varnode *labelVarnode(void) const { return shiftRevert ? shiftvn : switchvn; }	///< Varnode the labels are computed for
  void checkShiftReversal(Funcdata *fd,const vector<uintb> &vals) const;	///< Revert the shift step if a value does not reverse
"""),
    ("""  JumpBasic(JumpTable *jt) : JumpModel(jt) { jrange = (JumpValuesRange *)0; }	///< Construct given a parent JumpTable""",
     """  JumpBasic(JumpTable *jt) : JumpModel(jt) { jrange = (JumpValuesRange *)0; switchMask = 0; shiftvn = (Varnode *)0; shiftRevert = false; }	///< Construct given a parent JumpTable"""),
])

edit(os.path.join(d, 'jumptable.cc'), [
    # findUnnormalized: masked / declined INT_LEFT step
    ("""  i = varnodeIndex;
  normalvn = pathMeld.getVarnode(i++);
  switchvn = normalvn;
  markModel(true);

  int4 countaddsub=0;
  int4 countleftright=0;""",
     """  i = varnodeIndex;
  normalvn = pathMeld.getVarnode(i++);
  switchvn = normalvn;
  switchMask = 0;
  shiftvn = (Varnode *)0;
  shiftRevert = false;
  markModel(true);

  int4 countaddsub=0;
  int4 countleftright=0;"""),
    ("""  while(i<pathMeld.numCommonVarnode()) {
    if (!flowsOnlyToModel(switchvn, normop)) break;	// Switch variable should only flow into model
    Varnode *testvn = pathMeld.getVarnode(i);
    if (!switchvn->isWritten()) break;
    normop = switchvn->getDef();""",
     """  while(i<pathMeld.numCommonVarnode()) {
    bool onlyModel = flowsOnlyToModel(switchvn, normop);	// Switch variable should only flow into model
    Varnode *testvn = pathMeld.getVarnode(i);
    if (!switchvn->isWritten()) break;
    // ...except across an index shift, handled below: its scaled copy is often kept for other reads
    // (a 6502 TAX/TAY of the doubled index that the case bodies go on indexing with).
    if (!onlyModel && switchvn->getDef()->code() != CPUI_INT_LEFT) break;
    normop = switchvn->getDef();"""),
    ("""    case CPUI_INT_LEFT:
      // An index scaled by a shift (i << c, e.g. a word table indexed by i*2) is labeled
      // by i, not by the byte offset.  backup2Switch reverses it through
      // OpBehaviorIntLeft::recoverInputBinary.
      countleftright += 1;
      if (countleftright > maxleftright) break;
      if (j != 0 || !normop->getIn(1)->isConstant()) break;
      if (normop->getIn(1)->getOffset() >= 8*normop->getOut()->getSize()) break;
      switchvn = testvn;
      break;""",
     """    case CPUI_INT_LEFT:
    {
      // An index scaled by a shift (i << c, e.g. a word table indexed by i*2) is labeled
      // by i, not by the byte offset.  backup2Switch reverses it through
      // OpBehaviorIntLeft::recoverInputBinary, which returns the preimage with the top c bits
      // clear.  That is exact only if i's top c bits are known zero; otherwise the switch is
      // on (i & lowmask), which equals the shifted value >> c, and is labeled the same way.
      countleftright += 1;
      if (countleftright > maxleftright) break;
      if (j != 0 || !normop->getIn(1)->isConstant()) break;
      int4 sz = normop->getOut()->getSize();
      if (normop->getIn(1)->getOffset() >= 8*sz) break;
      if (testvn->getSize() != sz) break;
      uintb lowmask = calc_mask(sz) >> normop->getIn(1)->getOffset();
      bool exact = ((testvn->getNZMask() & ~lowmask) == 0) || guardsBoundBelow(testvn,lowmask);
      if (!exact) {
	int4 res = shiftStepAllowed(normop,testvn,i,lowmask);
	if (res == 0) break;		// Declined: keep the shifted value (offset labels)
	if (res == 1)
	  switchMask = lowmask;
      }
      shiftvn = switchvn;
      switchvn = testvn;
      break;
    }"""),
    # helpers, inserted before buildLabels
    ("""void JumpBasic::buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const
""",
     """/// The values labels are built from belong to the model the table was first recovered with, whose
/// normalized Varnode can differ from this model's (e.g. the index before its shift).  If any of
/// them does not reverse through the shift findUnnormalized stepped back across, the step is
/// undone and the labels are computed for the shifted value, as without the step.
/// \\param fd is the function containing the switch
/// \\param vals are the values of the normalized switch variable to be labeled
void JumpBasic::checkShiftReversal(Funcdata *fd,const vector<uintb> &vals) const

{
  shiftRevert = false;
  if (shiftvn == (Varnode *)0) return;
  for(int4 k=0;k<vals.size();++k) {
    try {
      backup2Switch(fd,vals[k],normalvn,switchvn);
    } catch(EvaluationError &err) {
      shiftRevert = true;
      return;
    }
  }
}

/// \\param vn is the Varnode to test
/// \\param target is the Varnode being looked for
/// \\param depth is the number of defining ops still allowed to be followed
/// \\return \\b true if \\b target is \\b vn or an input to its defining ops within \\b depth levels
bool JumpBasic::dependsOn(Varnode *vn,Varnode *target,int4 depth)

{
  if (vn == target) return true;
  if (depth <= 0 || !vn->isWritten()) return false;
  PcodeOp *op = vn->getDef();
  if (op->code() == CPUI_MULTIEQUAL || op->code() == CPUI_INDIRECT) return false;
  for(int4 k=0;k<op->numInput();++k) {
    if (dependsOn(op->getIn(k),target,depth-1)) return true;
  }
  return false;
}

/// \\param invn is the input \\b i of an index shift
/// \\param lowmask is the mask of the bits of \\b i that survive the shift
/// \\return \\b true if a select guard reading \\b i only lets values within \\b lowmask reach the switch
/// (e.g. a 6502 BCS on the carry an ASL shifts out, branching away from the dispatch)
bool JumpBasic::guardsBoundBelow(Varnode *invn,uintb lowmask) const

{
  for(int4 g=0;g<selectguards.size();++g) {
    if (selectguards[g].getBranch() == (PcodeOp *)0) continue;
    PcodeOp *readOp = selectguards[g].getReadOp();
    bool reads = false;
    for(int4 s=0;s<readOp->numInput();++s) {
      if (readOp->getIn(s) == invn) { reads = true; break; }
    }
    if (!reads) continue;
    const CircleRange &rng(selectguards[g].getRange());
    if (rng.isEmpty() || rng.isFull()) continue;
    if (rng.getMin() <= rng.getMax() && rng.getMax() <= lowmask) return true;
  }
  return false;
}

/// \\param vn is the Varnode to evaluate
/// \\param target is the free input
/// \\param val is the value assigned to \\b target
/// \\param depth is the number of defining ops still allowed to be followed
/// \\param res will hold the value of \\b vn
/// \\return \\b true if \\b vn is computed from \\b target and constants alone (within \\b depth ops)
bool JumpBasic::evaluateOn(Varnode *vn,Varnode *target,uintb val,int4 depth,uintb &res)

{
  if (vn == target) { res = val; return true; }
  if (vn->isConstant()) { res = vn->getOffset(); return true; }
  if (depth <= 0 || !vn->isWritten()) return false;
  PcodeOp *op = vn->getDef();
  uintb in0,in1;
  try {
    if (op->getEvalType() == PcodeOp::unary) {
      if (!evaluateOn(op->getIn(0),target,val,depth-1,in0)) return false;
      res = op->getOpcode()->evaluateUnary(vn->getSize(),op->getIn(0)->getSize(),in0);
      return true;
    }
    if (op->getEvalType() == PcodeOp::binary) {
      if (!evaluateOn(op->getIn(0),target,val,depth-1,in0)) return false;
      if (!evaluateOn(op->getIn(1),target,val,depth-1,in1)) return false;
      res = op->getOpcode()->evaluateBinary(vn->getSize(),op->getIn(0)->getSize(),in0,in1);
      return true;
    }
  } catch(EvaluationError &err) {
    return false;
  }
  return false;
}

/// Decide how a shifted index (i << c) whose input may have its top c bits set is labeled.
/// The shifted value always equals (i & lowmask) << c, so switching on (i & lowmask) is exact,
/// but the step is declined (offset labels kept) when the discarded bits influence how control
/// reaches the switch: a select guard restricting anything but the shifted value or values
/// nearer the BRANCHIND, a table longer than the masked index can distinguish, or a CBRANCH on the
/// dominator path from the shift to the switch that lets values of \\b i with top bits set reach
/// the switch on a condition computed from \\b i (e.g. a 6502 BCC/BCS on the carry the ASL shifted
/// out, picking one of two tables: grm-hf5h.19).  A CBRANCH that instead sends every such value
/// away from the switch proves the top bits are zero, and \\b i itself is exact.
/// \\param shiftop is the INT_LEFT
/// \\param invn is the shifted input \\b i
/// \\param pathPos is the position of \\b invn in the PathMeld (values nearer the switch come first)
/// \\param lowmask is the mask of the bits of \\b i that survive the shift
/// \\return 0 to decline, 1 to switch on (i & lowmask), 2 to switch on \\b i (proven exact)
int4 JumpBasic::shiftStepAllowed(PcodeOp *shiftop,Varnode *invn,int4 pathPos,uintb lowmask) const

{
  if (jrange != (JumpValuesRange *)0 && jrange->getSize() > lowmask + 1) return 0;
  for(int4 g=0;g<selectguards.size();++g) {
    if (selectguards[g].getBranch() == (PcodeOp *)0) continue;
    PcodeOp *readOp = selectguards[g].getReadOp();
    bool nearSide = false;
    for(int4 k=0;k<pathPos && !nearSide;++k) {
      Varnode *pvn = pathMeld.getVarnode(k);
      for(int4 s=0;s<readOp->numInput();++s) {
	if (readOp->getIn(s) == pvn) { nearSide = true; break; }
      }
    }
    if (!nearSide) return 0;
  }
  PcodeOp *indop = jumptable->getIndirectOp();
  if (indop == (PcodeOp *)0) return 0;
  const FlowBlock *switchbl = indop->getParent();
  const FlowBlock *shiftbl = shiftop->getParent();
  const FlowBlock *bl = switchbl;
  bool provenLow = false;
  for(int4 count=0;;++count) {
    if (count >= 64) return 0;		// Hard bound on the dominator walk
    if (bl != switchbl) {
      PcodeOp *last = bl->lastOp();
      if (last != (PcodeOp *)0 && last->code() == CPUI_CBRANCH && dependsOn(last->getIn(1),invn,6)) {
	if (invn->getSize() != 1) return 0;	// Only small enough to check every value
	const BlockBasic *cbl = (const BlockBasic *)bl;
	bool trueSide = cbl->getTrueOut()->dominates(switchbl);
	bool falseSide = cbl->getFalseOut()->dominates(switchbl);
	if (trueSide == falseSide) return 0;
	uintb sideVal = (trueSide != last->isBooleanFlip()) ? 1 : 0;	// Condition value towards the switch
	bool highReaches = false;
	for(uintb v=0;v<=calc_mask(1);++v) {
	  uintb cond;
	  if (!evaluateOn(last->getIn(1),invn,v,6,cond)) return 0;
	  if ((v & ~lowmask) != 0 && ((cond != 0) ? 1 : 0) == sideVal) { highReaches = true; break; }
	}
	if (highReaches) return 0;	// The discarded bits pick the path (e.g. a second table)
	provenLow = true;
      }
    }
    if (bl == shiftbl) break;
    bl = bl->getImmedDom();
    if (bl == (const FlowBlock *)0) return 0;
  }
  return provenLow ? 2 : 1;
}

void JumpBasic::buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const
"""),
    # foldInNormalization: synthesize the mask
    ("""  // Set the BRANCHIND input to be the unnormalized switch variable, so
  // all the intervening code to calculate the final address is eliminated as dead.
  fd->opSetInput(indop,switchvn,0);
  return switchvn;""",
     """  // Set the BRANCHIND input to be the unnormalized switch variable, so
  // all the intervening code to calculate the final address is eliminated as dead.
  if (shiftRevert) {		// Labels were computed for the shifted value, see checkShiftReversal
    fd->opSetInput(indop,shiftvn,0);
    return shiftvn;
  }
  if (switchMask != 0) {	// The switch is on (switchvn & switchMask), see findUnnormalized
    PcodeOp *andop = fd->newOpBefore(indop,CPUI_INT_AND,switchvn,
				     fd->newConstant(switchvn->getSize(),switchMask));
    fd->opSetInput(indop,andop->getOut(),0);
    return andop->getOut();
  }
  fd->opSetInput(indop,switchvn,0);
  return switchvn;"""),
    # buildLabels: validate the shift step against the label values
    ("""  const JumpValuesRange *origrange = (( const JumpBasic *)orig)->getValueRange();

  bool notdone = origrange->initializeForReading();""",
     """  const JumpValuesRange *origrange = (( const JumpBasic *)orig)->getValueRange();

  if (shiftvn != (Varnode *)0) {
    vector<uintb> vals;
    bool more = origrange->initializeForReading();
    while(more && vals.size() < addresstable.size()) {
      if (origrange->isReversible())
	vals.push_back(origrange->getValue());
      more = origrange->next();
    }
    checkShiftReversal(fd,vals);
  }
  bool notdone = origrange->initializeForReading();"""),
    ("""	switchval = backup2Switch(fd,val,normalvn,switchvn);		// Do reverse emulation to get original switch value""",
     """	switchval = backup2Switch(fd,val,normalvn,labelVarnode());	// Do reverse emulation to get original switch value"""),
    ("""  for(uint4 i=0;i<values.size();++i) {
    try {
      addr = backup2Switch(fd,values[i],normalvn,switchvn);""",
     """  checkShiftReversal(fd,values);
  for(uint4 i=0;i<values.size();++i) {
    try {
      addr = backup2Switch(fd,values[i],normalvn,labelVarnode());"""),
    # JumpBasic2 / override: reset the mask on paths that do not run the base routine
    ("""void JumpBasic2::findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)

{
""",
     """void JumpBasic2::findUnnormalized(uint4 maxaddsub,uint4 maxleftright,uint4 maxext)

{
  switchMask = 0;
  shiftvn = (Varnode *)0;
  shiftRevert = false;
"""),
    ("""  if (istwoleaf) return;	// The switch variable is synthesized by foldInNormalization""",
     """  if (istwoleaf) { switchMask = 0; shiftvn = (Varnode *)0; shiftRevert = false; return; }	// The switch variable is synthesized by foldInNormalization"""),
])
