#!/usr/bin/env python3
"""Extract an upstream issue/PR draft from a bead, ready to paste.

The bead is the master copy of every draft (it syncs with `bd dolt push`). The draft is the
LAST block of this shape found in the bead's description, design or notes, or in any of its
comments (oldest first, so a later comment supersedes an earlier draft):

    ---8<--- TITLE ---8<---
    One-line title
    ---8<--- BODY ---8<---
    Markdown body, one line per paragraph (GitHub issue bodies turn single newlines into
    line breaks, so do not hard-wrap it).
    ---8<--- END ---8<---

It writes docs/drafts/<bead>.md (gitignored -- a throwaway copy, regenerate it any time) as
the title, a blank line, then the body, and puts that same text on the clipboard: paste it into
the GitHub body field, then cut the first line into the title field.

Usage: python -I tools/upstream-draft.py <bead-id>
"""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

BLOCK = re.compile(
    r"^---8<--- TITLE ---8<---[ \t]*\n(?P<title>.*?)\n"
    r"^---8<--- BODY ---8<---[ \t]*\n(?P<body>.*?)\n"
    r"^---8<--- END ---8<---[ \t]*$",
    re.MULTILINE | re.DOTALL)


def bd_json(*args):
    out = subprocess.run(["bd", *args, "--json"], capture_output=True, text=True,
                         encoding="utf-8", check=True).stdout
    return json.loads(out or "null")


def find_draft(bead):
    """Returns (title, body, source) of the last draft block, or None."""
    issue = bd_json("show", bead)
    issue = issue[0] if isinstance(issue, list) else issue
    sources = [(field, issue.get(field) or "") for field in ("description", "design", "notes")]
    for comment in bd_json("comments", bead) or []:
        sources.append((f"comment {comment.get('created_at')}", comment.get("text") or ""))
    found = None
    for source, text in sources:
        for match in BLOCK.finditer(text.replace("\r\n", "\n")):
            found = (match.group("title"), match.group("body"), source)
    if found is None:
        return None
    title, body, source = found
    # A title wrapped over several lines is still one title.
    title = " ".join(line.strip() for line in title.splitlines() if line.strip())
    return title, body.strip("\n"), source


def set_clipboard(path):
    """Copies the file's text to the clipboard; returns a note on what happened."""
    if os.name == "nt":
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell:
            # Read from the file, not stdin: PowerShell decodes piped stdin with the console
            # code page and would mangle non-ASCII text.
            env = dict(os.environ, GRM_DRAFT_PATH=str(path))
            subprocess.run([shell, "-NoProfile", "-Command",
                            "Set-Clipboard -Value (Get-Content -Raw -Encoding UTF8 "
                            "-LiteralPath $env:GRM_DRAFT_PATH)"], env=env, check=True)
            return "copied to clipboard"
    for tool in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"]):
        if shutil.which(tool[0]):
            subprocess.run(tool, input=path.read_bytes(), check=True)
            return "copied to clipboard"
    return "NOT copied: no clipboard tool found (open the file instead)"


def main(argv):
    if len(argv) != 2 or argv[1].startswith("-"):
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    bead = argv[1]
    draft = find_draft(bead)
    if draft is None:
        print(f"{bead}: no '---8<--- TITLE/BODY/END ---8<---' draft block found",
              file=sys.stderr)
        return 1
    title, body, source = draft
    out = Path(__file__).resolve().parent.parent / "docs" / "drafts" / f"{bead}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"{title}\n\n{body}\n", encoding="utf-8", newline="\n")
    print(f"{bead}: draft from {source}")
    print(f"  title: {title}")
    print(f"  body:  {len(body)} chars")
    print(f"  file:  {out}")
    print(f"  {set_clipboard(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
