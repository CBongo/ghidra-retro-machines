#!/usr/bin/env python3
"""Hand-assembles the C64ForthAnalyzer regression PRG (bead grm-arbi.2).

Usage: mkforthtest.py <output-dir>

Writes forthtest.prg and forthtest.forth.json (the config the analyzer reads from the Program-Info
property "Retro Machines.Forth Config", set by SetProgramInfo.java as a -preScript) into
<output-dir>. No dependencies beyond Python 3.

A tiny headerless indirect-threaded Forth for the 6502 in the shape of Adventure Construction
Set's: IP=$7E, W=$81 (so "JMP $0080" is JMP (W) once $80 holds $6C). Loaded at $2000:

  NEXT (code), DOCOL, DOCON, DOVAR, DODOES, EXECVEC handlers
  code words : EXIT LIT BRANCH 0BRANCH (.") DUP DROP + EMIT
  constant FIVE, variable COUNTER, DODOES word ARRAY (does-thread: DUP + EXIT),
  EXECVEC vector table VEC (entries DUP DROP EXIT, run ends at the next word's DOCOL)
  colon words: DOUBLE, SHOW (forward 0BRANCH, EXIT mid-body), GREET (inline string), TWICE,
               MAIN (backward BRANCH), HIDDEN (unnamed, only referenced)
  a DECOY: the DOCOL value in a data table followed by non-words (must NOT become a word)
  a DECOY2: the DOCOL value as a LIT operand ahead of a valid-looking suffix (inner overlap)
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bankgen  # noqa: E402

BASE = 0x2000
IP, W = 0x7E, 0x81


class Img:
    def __init__(self, base):
        self.base = base
        self.b = bytearray()
        self.sym = {}
        self.fix = []

    def here(self):
        return self.base + len(self.b)

    def label(self, name):
        assert name not in self.sym, name
        self.sym[name] = self.here()

    def raw(self, *bs):
        self.b.extend(bs)

    def word(self, v):
        self.b.extend([v & 0xFF, (v >> 8) & 0xFF])

    def ref(self, name):  # 16-bit absolute reference to a label
        self.fix.append((len(self.b), name, "abs", 0))
        self.word(0)

    def rel(self, name):  # signed offset relative to this operand's own address
        self.fix.append((len(self.b), name, "rel", self.here()))
        self.word(0)

    def jmp(self, name):
        self.raw(0x4C)
        self.ref(name)

    def resolve(self):
        for off, name, kind, opaddr in self.fix:
            t = self.sym[name]
            v = t if kind == "abs" else (t - opaddr) & 0xFFFF
            self.b[off] = v & 0xFF
            self.b[off + 1] = v >> 8


def build():
    m = Img(BASE)
    ldy, lda_ip_y, sta_zp = 0xA0, 0xB1, 0x85

    # --- inner interpreter -------------------------------------------------
    m.label("NEXT")
    m.raw(ldy, 1, lda_ip_y, IP, sta_zp, W + 1, 0x88, lda_ip_y, IP, sta_zp, W)
    m.raw(0x18, 0xA5, IP, 0x69, 2, sta_zp, IP, 0x90, 2, 0xE6, IP + 1)
    m.raw(0x4C, 0x80, 0x00)                                   # JMP $0080 = JMP (W)

    m.label("DOCOL")                                          # push IP, IP = W+2
    m.raw(0xA5, IP + 1, 0x48, 0xA5, IP, 0x48)
    m.raw(0x18, 0xA5, W, 0x69, 2, sta_zp, IP, 0xA5, W + 1, 0x69, 0, sta_zp, IP + 1)
    m.jmp("NEXT")

    m.label("DOCON")                                          # push [W+2]
    m.raw(ldy, 2, lda_ip_y, W, 0xCA, 0xCA, 0x95, 0, 0xC8, lda_ip_y, W, 0x95, 1)
    m.jmp("NEXT")

    m.label("DOVAR")                                          # push W+2
    m.raw(0x18, 0xA5, W, 0x69, 2, 0xCA, 0xCA, 0x95, 0, 0xA5, W + 1, 0x69, 0, 0x95, 1)
    m.jmp("NEXT")

    m.label("DODOES")                                         # push W+4, enter [W+2]
    m.raw(0x18, 0xA5, W, 0x69, 4, 0xCA, 0xCA, 0x95, 0, 0xA5, W + 1, 0x69, 0, 0x95, 1)
    m.raw(0xA5, IP + 1, 0x48, 0xA5, IP, 0x48)
    m.raw(ldy, 2, lda_ip_y, W, sta_zp, IP, 0xC8, lda_ip_y, W, sta_zp, IP + 1)
    m.jmp("NEXT")

    # --- code words: CFA holds CFA+2 ---------------------------------------
    def code(name, *body_bytes, tail=True, ref=None):
        m.label(name)
        m.word(m.here() + 2)
        m.raw(*body_bytes)
        if ref:
            m.jmp(ref)
        if tail:
            m.jmp("NEXT")

    code("EXIT", 0x68, sta_zp, IP, 0x68, sta_zp, IP + 1)
    code("LIT", ldy, 0, lda_ip_y, IP, 0xCA, 0xCA, 0x95, 0, 0xC8, lda_ip_y, IP, 0x95, 1,
         0x18, 0xA5, IP, 0x69, 2, sta_zp, IP, 0x90, 2, 0xE6, IP + 1)
    m.label("BRANCH")
    m.word(m.here() + 2)
    m.raw(ldy, 0, lda_ip_y, IP, 0x18, 0x65, IP, 0x48, 0xC8, lda_ip_y, IP, 0x65, IP + 1,
          sta_zp, IP + 1, 0x68, sta_zp, IP)
    m.jmp("NEXT")
    m.label("0BRANCH")
    m.word(m.here() + 2)
    m.raw(0xE8, 0xE8, 0xB5, 0xFE, 0x15, 0xFF, 0xD0, 3)
    m.jmp("BRANCH_code")
    m.raw(0x18, 0xA5, IP, 0x69, 2, sta_zp, IP, 0x90, 2, 0xE6, IP + 1)
    m.jmp("NEXT")
    m.sym["BRANCH_code"] = m.sym["BRANCH"] + 2
    code("STRP", ldy, 0, lda_ip_y, IP, 0x38, 0x65, IP, sta_zp, IP, 0x90, 2, 0xE6, IP + 1)
    code("DUP", 0xB5, 0, 0xB4, 1, 0xCA, 0xCA, 0x95, 0, 0x94, 1)
    code("DROP", 0xE8, 0xE8)
    code("PLUS", 0x18, 0xB5, 0, 0x75, 2, 0x95, 2, 0xB5, 1, 0x75, 3, 0x95, 3, 0xE8, 0xE8)
    code("EMIT", 0xB5, 0, 0x20, 0xD2, 0xFF, 0xE8, 0xE8)

    # --- defining-word instances ------------------------------------------
    m.label("FIVE")
    m.ref("DOCON")
    m.word(5)
    m.label("COUNTER")
    m.ref("DOVAR")
    m.word(0)
    m.label("ARRAY")
    m.ref("DODOES")
    m.ref("ARRAY_does")
    m.word(0x0102)
    m.word(0x0304)
    m.label("ARRAY_does")                    # the does-thread is a bare thread (no CFA)
    for w in ("DUP", "PLUS", "EXIT"):
        m.ref(w)

    # --- colon words --------------------------------------------------------
    def colon(name, cells):
        m.label(name)
        m.ref("DOCOL")
        for c in cells:
            if c[0] == "w":
                m.ref(c[1])
            elif c[0] == "lit":
                m.word(c[1])
            elif c[0] == "rel":
                m.rel(c[1])
            elif c[0] == "L":
                m.label(c[1])
            elif c[0] == "str":
                m.raw(len(c[1]), *c[1].encode("ascii"))

    colon("DOUBLE", [("w", "DUP"), ("w", "PLUS"), ("w", "EXIT")])
    colon("SHOW", [("w", "DUP"), ("w", "0BRANCH"), ("rel", "SHOW_L1"),
                   ("w", "LIT"), ("lit", 3), ("w", "PLUS"), ("w", "EXIT"),   # EXIT mid-body
                   ("L", "SHOW_L1"), ("w", "EMIT"), ("w", "EXIT")])
    colon("GREET", [("w", "STRP"), ("str", "HI"), ("w", "EXIT")])
    colon("TWICE", [("w", "DOUBLE"), ("w", "DOUBLE"), ("w", "FIVE"), ("w", "COUNTER"),
                    ("w", "ARRAY"), ("w", "EXIT")])
    colon("HIDDEN", [("w", "GREET"), ("w", "DROP"), ("w", "EXIT")])
    colon("MAIN", [("L", "MAIN_L0"), ("w", "TWICE"), ("w", "SHOW"), ("w", "HIDDEN"),
                   ("w", "BRANCH"), ("rel", "MAIN_L0"), ("w", "EXIT")])
    # DECOY2: LIT operand equal to DOCOL, followed by cells that would walk as a thread
    colon("USELIT", [("w", "LIT"), ("L", "DECOY2")])
    m.ref("DOCOL")                            # the operand of LIT
    for w in ("DUP", "DROP", "EXIT"):
        m.ref(w)
    # fix up: USELIT is "LIT DOCOL DUP DROP EXIT" -> operand is a DOCOL value at DECOY2

    # --- DECOY: DOCOL value in a data table, then non-words -----------------
    m.label("DECOY")
    m.ref("DOCOL")
    m.word(0x1234)
    m.word(0x0000)
    m.raw(0x05, 0x06, 0x07, 0x08)
    m.label("EXECVEC")                                        # pop n, execute body cell n
    m.raw(0xB5, 0, 0x0A, 0x18, 0x69, 2, 0xA8, 0xE8, 0xE8, 0xB1, W, 0x48, 0xC8, 0xB1, W,
          sta_zp, W + 1, 0x68, sta_zp, W)
    m.raw(0x4C, 0x80, 0x00)

    # VEC: a vector table; its run ends at the DOCOL cell of VECUSER
    m.label("VEC")
    m.ref("EXECVEC")
    for w in ("DUP", "DROP", "EXIT"):
        m.ref(w)

    colon("VECUSER", [("w", "VEC"), ("w", "EXIT")])
    m.resolve()
    return m


def main():
    outdir = bankgen.outdir_arg(__file__)
    m = build()
    path = bankgen.write_prg(outdir, "forthtest.prg", BASE, bytes(m.b))
    s = m.sym
    cfg = {"forth": {
        "ip": IP, "w": W, "next": s["NEXT"], "docol": s["DOCOL"], "exit": [s["EXIT"]],
        "handlers": {str(s["DOCON"]): "DOCON", str(s["DOVAR"]): "DOVAR",
                     str(s["DODOES"]): "DODOES", str(s["EXECVEC"]): "EXECVEC"},
        "inline": {str(s["LIT"]): "lit16", str(s["BRANCH"]): "branch",
                   str(s["0BRANCH"]): "branch", str(s["STRP"]): "counted_string"},
        "names": {str(s[n]): {"name": nm} for n, nm in (
            ("EXIT", "EXIT"), ("LIT", "LIT"), ("BRANCH", "BRANCH"), ("0BRANCH", "0BRANCH"),
            ("STRP", '(.")'), ("DUP", "DUP"), ("DROP", "DROP"), ("PLUS", "+"),
            ("EMIT", "EMIT"), ("FIVE", "FIVE"), ("COUNTER", "COUNTER"), ("ARRAY", "ARRAY"), ("VEC", "VEC"),
            ("DOUBLE", "DOUBLE"), ("SHOW", "SHOW"), ("TWICE", "TWICE"), ("MAIN", "MAIN"))},
    }}
    cfg["forth"]["names"][str(s["DUP"])]["comment"] = "( n -- n n )"
    cpath = os.path.join(outdir, "forthtest.forth.json")
    with open(cpath, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f)
    print("wrote %s (%d bytes) and %s" % (path, 2 + len(m.b), cpath))
    for k in sorted(s, key=s.get):
        print("  $%04X %s" % (s[k], k))


if __name__ == "__main__":
    main()
