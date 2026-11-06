#!/usr/bin/env python3
"""Convert the ACS Forth label tables in forthhex.pl into acs-forth.yaml (bead grm-arbi.1).

Input : external/game-music-extraction/c64/acs/forthhex.pl (git submodule; owner's disassembler
        helper). Perl hashes %ops (global) and %ops_b %ops_f %ops_o %ops_r %ops_s, each
        `0xADDR => ['label text', "mode"]`, mode in imm/var/rel/doe/ics or absent.
Output: tools/forth/generated/acs-forth.yaml (deterministic: sorted by address / letter).

    python -I tools/forth/forthhex2desc.py            # (re)write the committed file
    python -I tools/forth/forthhex2desc.py --check    # exit 1 if the committed file is stale

Layout: `forth:` (hand-declared kernel facts incl. handlers and inline operand kinds, plus
`names:` from %ops), `members:` (keyed by FILE LETTER, each `{forth: {names:, inline:}}`;
`inline:` only when the member's table carries modes). forthhex.pl picks tables by the first letter of the file name
(b/o/r/s share; d/p; w; c; f; everything falls back to %ops); mapping letters to member content
is a later bead, so letters are emitted as-is. Only tables present in the .pl are emitted.

Heuristics (every one applied, in order):
 H1 Entries at 0x08F9, 0x0906, 0x0CA0 (labelled imm/var/doe) are code-field HANDLERS (DOCON,
    DOVAR, DODOES), not words: forthhex labelled them only because it dumped linearly through
    word headers. They are never emitted as names (any table), only under forth.handlers.
 H2 Mode imm -> inline lit16; rel -> inline branch; ics -> inline counted_string. `var` and `doe`
    outside the handler addresses are not expected; they are reported on stderr and given no
    inline entry. Hand-declared inline facts must agree with derived ones (else reported).
 H3 Operand-bearing labels get fixed Forth names: 'push $%04X' (imm) -> LIT, 'BRA ...' ->
    BRANCH, 'BEQ ...' -> 0BRANCH, 'LOOP ...' -> (LOOP), 'LOOP+ ...' -> (+LOOP). For other
    labels containing a printf directive, the text from the directive (and any preceding '$')
    onward is dropped, e.g. 'print inline ctstr ("%s")' -> 'print inline ctstr ('; trailing
    space/':' trimmed.
 H4 A label that is already a Forth-style symbol (one token, <= 32 chars, charset
    A-Z a-z 0-9 _ @ ! + - * / < > = ? . # ( ) [ ] : ; ,) is the name verbatim, no comment.
 H5 Any other label is prose: `name` is the (H3-stripped) label sanitized (runs of chars outside
    [A-Za-z0-9_.+-] become '_', edges trimmed, cut at a '_' boundary to <= 40 chars) and the
    ORIGINAL label text is kept verbatim in `comment`.
 H6 Names in one table must be unique: a sanitized name colliding with an earlier (lower-address)
    one in the same table gets a `_XXXX` address suffix. Verbatim (H4) duplicates such as two
    DUPs at different addresses are kept and reported.
 H7 Hand-declared names NEXT 0x08C4, DOCOL 0x08E2, PUSH 0x08BD are added to global names only
    if the address is not already named in %ops.
 H8 Perl quirks tolerated: stray '.' after an entry, escaped quotes (\\') in labels, '#' comments.
Duplicates/conflicts (same address, different text: within a table, or member vs global / member
vs member) go to stderr. A member entry with the same text as the global one is still emitted
(members stand alone); only a differing one is a conflict.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SUB = os.path.join(ROOT, "external", "game-music-extraction")
SRC = os.path.join(SUB, "c64", "acs", "forthhex.pl")
OUT = os.path.join(ROOT, "tools", "forth", "generated", "acs-forth.yaml")
SRC_REL = "external/game-music-extraction/c64/acs/forthhex.pl"

HANDLER_ADDRS = {0x08F9: "DOCON", 0x0906: "DOVAR", 0x0CA0: "DODOES"}
FIXED_NAMES = {"BRA": "BRANCH", "BEQ": "0BRANCH", "LOOP": "(LOOP)", "LOOP+": "(+LOOP)"}
MODE_KIND = {"imm": "lit16", "rel": "branch", "ics": "counted_string"}
HAND_INLINE = {0x08AA: "lit16", 0x0966: "branch", 0x097B: "branch", 0x0993: "branch",
               0x09B9: "branch", 0x45EE: "counted_string"}
HAND_NAMES = {0x08C4: "NEXT", 0x08E2: "DOCOL", 0x08BD: "PUSH"}

TABLE_RE = re.compile(r"^\s*%(ops(?:_([a-z]))?)\s*=\s*\(?", re.M)
ENTRY_RE = re.compile(
    r"0x([0-9a-fA-F]+)\s*=>\s*\[\s*'((?:[^'\\]|\\.)*)'\s*(?:,\s*\"(\w+)\")?\s*\]")
SYMBOL_RE = re.compile(r"^[A-Za-z0-9_@!+\-*/<>=?.#()\[\]:;,]{1,32}$")


def warn(msg):
    print("forthhex2desc: " + msg, file=sys.stderr)


def tname(letter):
    return "%ops_" + letter if letter else "%ops"


def parse(text):
    """Return {letter or '': {addr: (label, mode)}}; later duplicates win, as in Perl."""
    tables = {}
    # Only the initops sub holds tables; restrict to it so `%ops_b{...}` lookups above are skipped.
    start = text.index("sub initops")
    text = text[start:]
    starts = [(m.start(), m.group(2) or "") for m in TABLE_RE.finditer(text)]
    for i, (pos, letter) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        body = "\n".join(ln for ln in text[pos:end].splitlines() if not ln.lstrip().startswith("#"))
        tab = tables.setdefault(letter, {})
        for m in ENTRY_RE.finditer(body):
            addr = int(m.group(1), 16)
            ent = (m.group(2).replace("\\'", "'").replace("\\\\", "\\"), m.group(3))
            if addr in tab and tab[addr] != ent:
                warn("CONFLICT in %s: 0x%04X %r vs %r (last wins, as in Perl)"
                     % (tname(letter), addr, tab[addr], ent))
            elif addr in tab:
                warn("duplicate in %s: 0x%04X %r" % (tname(letter), addr, ent))
            tab[addr] = ent
        n_arrows = body.count("=>")
        n_parsed = len(ENTRY_RE.findall(body))
        if n_arrows != n_parsed:
            warn("%s: %d '=>' but %d parsed entries" % (tname(letter), n_arrows, n_parsed))
    return tables


def sanitize(s):
    t = re.sub(r"[^A-Za-z0-9_.+-]+", "_", s).strip("_")
    if len(t) > 40:
        t = t[:40]
        if "_" in t:
            t = t.rsplit("_", 1)[0]
    return t or "word"


def derive_name(label, mode):
    """Return (name, comment-or-None)."""
    first = label.split(" ", 1)[0]
    if mode == "imm" and label.startswith("push $%"):
        return "LIT", None
    if mode == "rel" and first in FIXED_NAMES:
        return FIXED_NAMES[first], None
    core = label
    m = re.search(r"\s*\$?%", label)
    if m:
        core = label[:m.start()].rstrip(" :") or label
    if core == label and SYMBOL_RE.match(core):
        return core, None
    return sanitize(core), label


def build_names(table, label_of, inline_out):
    names = {}
    used = {}
    for addr in sorted(table):
        label, mode = table[addr]
        if addr in HANDLER_ADDRS:
            continue
        if mode in MODE_KIND:
            inline_out[addr] = MODE_KIND[mode]
        elif mode:
            warn("%s: 0x%04X mode %r (%r) not handled; no inline entry"
                 % (label_of, addr, mode, label))
        name, comment = derive_name(label, mode)
        if name in used:
            if comment is None:
                warn("%s: duplicate verbatim name %s at 0x%04X and 0x%04X"
                     % (label_of, name, used[name], addr))
            else:
                name = "%s_%04X" % (name, addr)
        used.setdefault(name, addr)
        names[addr] = (name, comment)
    return names


def q(s):
    return json.dumps(s)


def emit_names(names, indent):
    pad = " " * indent
    out = []
    for addr in sorted(names):
        name, comment = names[addr]
        body = "name: " + q(name) + (", comment: " + q(comment) if comment else "")
        out.append("%s0x%04X: {%s}" % (pad, addr, body))
    return out


def generate(text, commit):
    tables = parse(text)
    glob = tables.get("", {})
    inline = {}
    gnames = build_names(glob, "%ops", inline)
    for a, n in HAND_NAMES.items():
        gnames.setdefault(a, (n, None))
    for a, k in inline.items():
        if a in HAND_INLINE and HAND_INLINE[a] != k:
            warn("inline conflict at 0x%04X: hand %s vs derived %s" % (a, HAND_INLINE[a], k))
        if a not in HAND_INLINE:
            warn("derived inline 0x%04X %s not in hand-declared set; included" % (a, k))
    inline.update(HAND_INLINE)

    members = {}
    letters = sorted(k for k in tables if k)
    for letter in letters:
        t = tables[letter]
        minline = {}
        members[letter] = (build_names(t, tname(letter), minline), minline)
        for a, ent in t.items():
            if a in glob and glob[a] != ent:
                warn("CONFLICT %s vs %%ops at 0x%04X: %r vs %r" % (tname(letter), a, ent, glob[a]))
        for l2 in letters:
            if l2 < letter:
                for a, ent in t.items():
                    if a in tables[l2] and tables[l2][a] != ent:
                        warn("CONFLICT %s vs %s at 0x%04X: %r vs %r"
                             % (tname(letter), tname(l2), a, ent, tables[l2][a]))

    L = ["# GENERATED by tools/forth/forthhex2desc.py -- do not edit.",
         "# Source: %s" % SRC_REL,
         "# Submodule external/game-music-extraction commit: %s" % commit,
         "forth:",
         "  ip: 0x007E",
         "  w: 0x0081",
         "  next: 0x08C4",
         "  docol: 0x08E2",
         "  exit: [0x0B2E]",
         "  handlers:",
         "    0x08F9: {role: DOCON}",
         "    0x0906: {role: DOVAR}",
         "    0x0914: {role: DOUSER, base: 0x0083}",
         "    0x0CA0: {role: DODOES}",
         "  inline:"]
    for a in sorted(inline):
        L.append("    0x%04X: %s" % (a, inline[a]))
    L.append("  names:")
    L += emit_names(gnames, 4)
    L.append("members:")
    for letter in sorted(members):
        mnames, minl = members[letter]
        L.append("  %s:" % letter)
        L.append("    forth:")
        if minl:
            L.append("      inline:")
            for a in sorted(minl):
                L.append("        0x%04X: %s" % (a, minl[a]))
        L.append("      names:")
        L += emit_names(mnames, 8)
    stats = "global names %d, inline %d, members %s" % (
        len(gnames), len(inline), {k: len(v[0]) for k, v in members.items()})
    return "\n".join(L) + "\n", stats


def submodule_commit():
    try:
        return subprocess.run(["git", "-C", SUB, "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv):
    if not os.path.isfile(SRC):
        print("submodule not checked out: run `git submodule update --init "
              "external/game-music-extraction`", file=sys.stderr)
        return 2
    with open(SRC, encoding="latin-1", newline="") as f:
        text = f.read().replace("\r\n", "\n")
    out, stats = generate(text, submodule_commit())
    if "--check" in argv:
        with open(OUT, encoding="utf-8", newline="") as f:
            cur = f.read().replace("\r\n", "\n")
        if cur != out:
            print("acs-forth.yaml is stale; rerun tools/forth/forthhex2desc.py", file=sys.stderr)
            return 1
        return 0
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    print("wrote %s (%s)" % (os.path.relpath(OUT, ROOT), stats))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
