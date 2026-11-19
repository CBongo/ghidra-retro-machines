"""grm-hf5h.31 replay experiment: rewrite 658xx.sinc ADC/SBC (8- and 16-bit) to their BINARY arm only,
i.e. what a ctx_DF=0 decode-time constructor would emit. For WSL decomp_dbg replays only: compile the
result with the replay tree's own C++ sleigh (make sleigh_opt in the decompile cpp dir) so the .sla
format matches decomp_dbg. Never ship it: real decimal-mode code would decode wrong.

usage: python -I tools/decompiler/sinc-adcsbc-binary-only.py <in 658xx.sinc> <out 658xx.sinc>"""
import re
import sys

src = open(sys.argv[1], newline="").read().replace("\r\n", "\n")


def body(mn, w):
    reg, val, sign, top, rn, nz = (
        ("A", "PRIMARY_VAL8", "0x80", "0xFF", "result8:1", "flag8_NZ")
        if w == 8
        else ("C", "PRIMARY_VAL16", "0x8000", "0xFFFF", "result16:2", "flag16_NZ")
    )
    size = 1 if w == 8 else 2
    inv = "    data = ~data;\n" if mn == "SBC" else ""
    rname = rn.split(":")[0]
    return (
        "{\n"
        f"    local data:{size} = {val};\n{inv}"
        f"    local result:4 = zext({reg}) + zext(data) + zext(CF);\n"
        f"    VF = (~zext({reg} ^ data) & (zext({reg}) ^ result) & {sign}) != 0;\n"
        f"    CF = result s> {top};\n"
        f"    local {rn} = result:{size};\n"
        f"    {nz}({rname});\n"
        f"    {reg} = {rname};\n"
        "}\n"
    )


n = 0
for mn in ("ADC", "SBC"):
    for w in (8, 16):
        pat = re.compile(r"(:%s PRIMARY_VAL%d\s+is .*?\.\.\. & PRIMARY_VAL%d\n)\{\n.*?\n\}\n" % (mn, w, w), re.S)
        src, k = pat.subn(lambda m, mn=mn, w=w: m.group(1) + body(mn, w), src, count=1)
        n += k
assert n == 4, n
open(sys.argv[2], "w", newline="\n").write(src)
print("rewrote", n)
