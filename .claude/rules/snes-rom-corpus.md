---
paths:
  - "src/main/java/**/Snes*"
  - "src/test/java/**/Snes*"
  - "tools/banktest/**"
---

# SNES ROM header corpus tier

<!-- Moved verbatim from CLAUDE.md (grm-yaat). Loaded only when a file matching the paths above is read. -->

**The SNES ROM header corpus survey (`snes-rom-corpus` chunk) is the fourth opt-in tier and, like
the `.dis` differential, REPORTS rather than gates.** It needs `GRM_SNES_ROM_DIR` — one or more
space-separated directories of cartridge images, indexed at depth 1 only, exactly as `GRM_ROM_DIR`
is read — and Assume-*skips* when unset. It runs `SnesRomHeader.parse` over every file there and
writes `build/snes-rom-corpus/roms.tsv` (per image, with sha256) and `summary.txt`. It asserts only
corpus-INDEPENDENT invariants — parse never throws on any file including the non-cartridges, an
image with a valid checksum/complement pair is always accepted, an accepted header is structurally
self-consistent, parse is deterministic — because the corpus is user-supplied and its distribution
differs per machine. **Never pin its counts and never add golden files over it**: on the reference
corpus 13 checksum-valid commercial cartridges disagree with `mapTypeMatchesLocation()` (5 of them
`UNKNOWN`, refused by the loader today), and those are bead `grm-9nxj.14`'s subject, not defects.
Reach for it occasionally after a change to `SnesRomHeader`'s detection or scoring, not per commit.
See docs/testing.md.
