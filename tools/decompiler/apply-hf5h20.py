"""Candidate 14 (grm-hf5h.20): stacked on candidate 13 (tools/decompiler/apply-hf5h11.py, then
tools/decompiler/apply-hf5h11-c13.py).

ROOT CAUSE. JumpBasic::buildLabels labels the switch from the ORIGINAL model's value range (the one
the address table was recovered with, on the flow copy) but reverse-emulates each value from the
CURRENT model's normalized Varnode. findSmallestNormal tries to make the two agree by stopping at the
path Varnode whose range equals the original one, and when none does it silently picks another, so
the values are read in the wrong units. ff1 W8000_B14::9076 (LDA $16; ASL A; TAY; BCC; LDA
$90d3,Y; ...; JMP ($0016)): on the flow copy the BCC on the carry bounds A to [0,0x80), so A is the
normalized Varnode; in the final function that guard no longer reads A, A's range is full, and
A<<1 (range (full,2), the same 128 values) is chosen instead. The values 0..0x7f were then taken as
values of A<<1, so the odd ones do not reverse through the shift, candidate 12's checkShiftReversal
reverted to the shifted variable, and switch(A<<1) was labelled 0..0x7f -- half the real values.

FIX. When the original range differs from the current one but has the same size, enumerate the
current range instead, provided emulating the current model on each of its values reproduces the
recovered address table entry for entry. The labels are then values of the current switch variable
that reach the address they label, by construction; without that proof nothing changes. A range
with a default (non-reversible) extra value is left alone. With the values in the right units the
candidate 12/13 shift step applies as for any other site: at 9076 the BCC proves A < 0x80, so the
switch is on A, labelled 0..0x7f, exact.

usage: python -I tools/decompiler/apply-hf5h20.py <decompile cpp dir already patched by
       apply-hf5h11.py and apply-hf5h11-c13.py>   (candidate 14 sha256 see grm-hf5h.20)
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
    ("""  void checkShiftReversal(Funcdata *fd,const vector<uintb> &vals) const;	///< Revert the shift step if a value does not reverse
""",
     """  void checkShiftReversal(Funcdata *fd,const vector<uintb> &vals) const;	///< Revert the shift step if a value does not reverse
  bool currentRangeMatches(Funcdata *fd,const vector<Address> &addresstable,const JumpValuesRange *origrange) const;	///< Can labels come from \\b jrange
"""),
])

edit(os.path.join(d, 'jumptable.cc'), [
    ("""void JumpBasic::buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const

{
  uintb val,switchval;
  const JumpValuesRange *origrange = (( const JumpBasic *)orig)->getValueRange();
""",
     """/// The original model's values are values of ITS normalized Varnode, which findSmallestNormal
/// cannot always match in the current function (a guard bounding it on the flow copy may no longer
/// read it), so the current normalized Varnode can be in different units (e.g. the index after its
/// shift rather than before).  The current range can be used instead when it has as many values and
/// emulating the current model on each reproduces the recovered address table entry for entry.
/// \\param fd is the function containing the switch
/// \\param addresstable is the recovered address table
/// \\param origrange is the original model's value range
/// \\return \\b true if \\b jrange differs from \\b origrange and enumerates the table in its order
bool JumpBasic::currentRangeMatches(Funcdata *fd,const vector<Address> &addresstable,const JumpValuesRange *origrange) const

{
  if (jrange == (JumpValuesRange *)0 || origrange == jrange) return false;
  if (jrange->getRange() == origrange->getRange()) return false;
  if (dynamic_cast<const JumpValuesRangeDefault *>(jrange) != (const JumpValuesRangeDefault *)0) return false;
  if (dynamic_cast<const JumpValuesRangeDefault *>(origrange) != (const JumpValuesRangeDefault *)0) return false;
  if (jrange->getSize() != origrange->getSize() || jrange->getSize() != addresstable.size()) return false;
  if (addresstable.empty() || addresstable.size() > 0x10000) return false;	// Hard bound on the emulation
  EmulateFunction emul(fd);
  uintb mask = ~((uintb)0);
  int4 bit = fd->getArch()->funcptr_align;
  if (bit != 0)
    mask = (mask >> bit) << bit;
  AddrSpace *spc = addresstable[0].getSpace();
  uint4 k = 0;
  try {
    bool notdone = jrange->initializeForReading();
    while(notdone) {
      if (k >= addresstable.size()) return false;
      uintb addr = emul.emulatePath(jrange->getValue(),pathMeld,jrange->getStartOp(),jrange->getStartVarnode());
      addr = AddrSpace::addressToByte(addr,spc->getWordSize()) & mask;
      if (addresstable[k] != Address(spc,addr)) return false;
      k += 1;
      notdone = jrange->next();
    }
  } catch(LowlevelError &err) {
    return false;
  }
  return (k == addresstable.size());
}

void JumpBasic::buildLabels(Funcdata *fd,vector<Address> &addresstable,vector<uintb> &label,const JumpModel *orig) const

{
  uintb val,switchval;
  const JumpValuesRange *origrange = (( const JumpBasic *)orig)->getValueRange();
  if (currentRangeMatches(fd,addresstable,origrange))
    origrange = jrange;		// The original values are in another Varnode's units, see currentRangeMatches
"""),
])
