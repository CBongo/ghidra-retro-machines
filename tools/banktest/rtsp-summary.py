"""Summarise a snes-rom-sweep.sh output dir of RtsTrickProbe runs.

    python -I tools/banktest/rtsp-summary.py <out-dir>

Reads <out>/sweep.tsv and each ROM's log, writes <out>/rtsp-sites.tsv (one row per kept window,
with a heuristic class) and <out>/rtsp-summary.txt (per-ROM counts and totals). A survey aid, not
a gate: the classes are regex guesses over Ghidra's instruction text.
"""
import csv
import os
import re
import sys

PUSHES = {"PHA", "PHX", "PHY", "PUSH"}
# An indexed operand: "0x1235,X" (65816) or "0x1235+Y" / "!0x1235+Y" (SPC700).
IDX = re.compile(r"(?:\[)?(?:!|\$)?(?:0x)?([0-9A-Fa-f]{1,6})\s*(?:,\s*[XY]\b|\+\s*[XY]\b)")


def load_mnemonic(mn, text):
    """True if this instruction reads memory through an index (not a store)."""
    if mn.startswith("LD") or mn in ("ADC", "SBC", "CMP", "AND", "ORA", "EOR"):
        return True
    if mn == "MOV":  # SPC700: destination first; the indexed operand is a source if after the comma
        return "," in text and IDX.search(text.split(",", 1)[1]) is not None
    return False


def classify(cpu, insns):
    mns = [i[0] for i in insns]
    if any(m in ("PEA", "PER") for m in mns):
        return "pea"
    pushes = sum(1 for m in mns if m in PUSHES)
    loads = []
    for mn, text in insns:
        if load_mnemonic(mn, text):
            m = IDX.search(text)
            if m:
                loads.append(int(m.group(1), 16))
    if pushes >= 2 and len(loads) >= 2:
        for a in loads:
            for b in loads:
                if a == b + 1:
                    return "table2push"
    if cpu == "65816" and pushes == 1 and len(loads) == 1:
        return "table1push"
    return "other"


def parse_log(path):
    """Yield dicts: sites (list), summaries (dict cpu->(returns,kept)), spc facts."""
    sites, summ, spc = [], {}, {"rawhits": None, "recovery": "", "blocks": ""}
    cur = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\r\n")
            k = line.find("> RTSP ")
            if k < 0:
                continue
            body = line[k + 2:]
            body = re.sub(r"\s*\(GhidraScript\)\s*$", "", body)
            m = re.match(r"RTSP site (\S+) (\S+) cpu=(\S+) incomingMidWindow=(.*)$", body)
            if m:
                cur = {"addr": m.group(1), "ret": m.group(2), "cpu": m.group(3),
                       "mid": m.group(4).strip(), "cj": "", "insns": []}
                sites.append(cur)
                continue
            m = re.match(r"RTSP\s+computedJump n=(\d+)", body)
            if m and cur is not None:
                cur["cj"] = m.group(1)
                continue
            m = re.match(r"RTSP summary cpu=(\S+) returns=(\d+) kept=(\d+)", body)
            if m:
                summ[m.group(1)] = (int(m.group(2)), int(m.group(3)))
                cur = None
                continue
            m = re.match(r"RTSP spc rawhits=(\d+)", body)
            if m:
                spc["rawhits"] = int(m.group(1))
                continue
            m = re.match(r"RTSP spc recovery (.*)$", body)
            if m:
                spc["recovery"] = m.group(1)
                continue
            m = re.match(r"RTSP spc blocks=(\d+)", body)
            if m:
                spc["blocks"] = m.group(1)
                continue
            m = re.match(r"RTSP\s{3}([0-9a-fA-F]+) ([0-9a-f?]+) (.*)$", body)
            if m and cur is not None:
                text = re.sub(r"\s*\[m=.*\]$", "", m.group(3)).strip()
                cur["insns"].append((text.split(" ", 1)[0].upper(), text))
    return sites, summ, spc


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    with open(os.path.join(out, "sweep.tsv"), encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t"))
    site_rows, lines = [], []
    totals = {"roms": 0, "ok": 0, "returns": 0, "kept": 0, "rawhits": 0}
    classes = {}
    lines.append("rom\tstatus\tcpu\treturns\tkept\tspc_rawhits\tspc_blocks\tspc_recovery")
    for r in rows:
        totals["roms"] += 1
        if r["status"] == "ok":
            totals["ok"] += 1
        log = os.path.join(out, r["log"])
        if not os.path.exists(log):
            lines.append("%s\t%s\t-\t-\t-\t-\t-\t-" % (r["file"], r["status"]))
            continue
        sites, summ, spc = parse_log(log)
        for s in sites:
            cls = classify(s["cpu"], s["insns"])
            classes[(s["cpu"], cls)] = classes.get((s["cpu"], cls), 0) + 1
            site_rows.append([r["file"], s["cpu"], s["addr"] + " " + s["ret"], s["mid"], s["cj"], cls,
                              " ; ".join(t for _, t in s["insns"])])
        if not summ:
            lines.append("%s\t%s\t-\t-\t-\t%s\t%s\t%s" % (r["file"], r["status"], spc["rawhits"] if spc["rawhits"] is not None else "-", spc["blocks"] or "-", spc["recovery"] or "-"))
        for cpu, (ret, kept) in summ.items():
            totals["returns"] += ret
            totals["kept"] += kept
            is_spc = cpu == "spc700"
            if is_spc and spc["rawhits"]:
                totals["rawhits"] += spc["rawhits"]
            lines.append("%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s" % (
                r["file"], r["status"], cpu, ret, kept,
                spc["rawhits"] if is_spc and spc["rawhits"] is not None else "-",
                spc["blocks"] if is_spc else "-", spc["recovery"] if is_spc else "-"))
    with open(os.path.join(out, "rtsp-sites.tsv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, delimiter="\t", lineterminator="\n")
        w.writerow(["rom", "cpu", "ret_addr", "incomingMidWindow", "computedJump_n", "class", "window"])
        w.writerows(site_rows)
    with open(os.path.join(out, "rtsp-summary.txt"), "w", encoding="utf-8", newline="") as fh:
        fh.write("\n".join(lines) + "\n\n")
        fh.write("totals: roms=%(roms)d ok=%(ok)d returns=%(returns)d kept=%(kept)d spc_rawhits=%(rawhits)d\n" % totals)
        for (cpu, cls), n in sorted(classes.items()):
            fh.write("class %s %s: %d\n" % (cpu, cls, n))
    print("wrote %s and %s (%d windows)" % (os.path.join(out, "rtsp-sites.tsv"), os.path.join(out, "rtsp-summary.txt"), len(site_rows)))


main()
