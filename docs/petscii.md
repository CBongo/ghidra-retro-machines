# PETSCII display-string map (bead grm-1.4.1)

## Purpose

A data-driven, Java-callable PETSCII byte -> display-string API, built for the future C64
BASIC detokenizing analyzer (grm-odt.1) and PETSCII charset registration (parent bead
grm-1.4). Given a raw PETSCII byte (or run of bytes) from memory, `PetsciiMapper` returns a
readable ASCII string suitable for a listing, comment, or log line.

**Scope note:** this maps PETSCII byte values only -- what's in memory, what the keyboard
sends. VIC-II *screen codes* (what's POKEd into screen RAM, a different numbering scheme)
are explicitly out of scope and are not represented anywhere in this pipeline.

## Files

- `machines/generated/petscii.yaml` -- hand-maintained source of truth. Compact by design:
  the 256-byte table is expressed as a handful of rules (`named_controls`, `literals`,
  `identity_ranges`, `letter_range`) rather than 256 (or 512, one per variant) explicit
  entries -- see the file's own header for the full rationale and the frozen-convention
  provenance (exact VICE `petcat.c` commit verified against).
- `tools/gdtbuilder/src/main/java/gdtbuilder/PetsciiCompiler.java` -- build-time compiler
  (Gradle task `buildPetsciiMap`), YAML -> JSON. Unlike `MapCompiler`, this is a standalone
  small tool: `MapCompiler` hard-validates descriptor **schema 2** (physical spaces, banking
  state, windows...), none of which applies to PETSCII's much simpler byte-table schema, so
  reusing it would mean fighting its validation rather than being served by it.
- `data/petscii.map` -- generated JSON artifact (gitignored, never committed, like
  `data/machines/*.map`). Two fully-expanded 256-entry string tables, one per
  `PetsciiMapper.Variant`. The 256x2 duplication that the YAML avoids is deliberately
  present here: it's a generated artifact, and it keeps the runtime lookup a plain array
  index with no rule evaluation.
- `src/main/java/retromachines/PetsciiMapper.java` -- runtime API (flat `retromachines`
  package, no Ghidra-type dependencies beyond the one `load()` method).

## Frozen convention

The bracket-escape names are VICE petcat's own SHORT `ctrl1[]`/`ctrl2[]` name tables,
transcribed **verbatim, byte-for-byte** -- e.g. `{clr}`, `{down}`, `{rvon}`, `{f1}` -- plus
petcat's own `{$xx}` fallback (lowercase, 2 hex digits, `$`-prefixed) for every byte petcat
itself does not name. This is a frozen convention: golden test dumps will be built against
it, so renaming or reshaping any entry is a breaking change for every consumer.

Verified against the canonical VICE source -- the official GitHub mirror of the upstream
SourceForge VICE project:

- repo: <https://github.com/VICE-Team/svn-mirror>
- path: `vice/src/tools/petcat/petcat.c`
- commit: `dd98b495dd4b49612922fdba20ad71304361cd1f`

The `machines/generated/petscii.yaml` header repeats this provenance next to the actual
table so the two never drift silently.

### Corrections to the initial (scout-archived) table

The bead's scouted archive (pulled through a third-party mirror) had two classes of error,
both corrected after re-verifying against the canonical source above:

1. Most of `ctrl1[]`'s "filler" entries for otherwise-unnamed control bytes are **not**
   blank, as the archive claimed. Only byte `0x00` is truly blank; bytes like `0x01`
   ("CTRL-A"), `0x03` ("stop"), `0x0B` ("CTRL-K"), and `0x0C` ("CTRL-L") all have real
   petcat names that must round-trip through real petcat.
2. `ctrl2[]`'s function-key names are lowercase (`f1`, `f3`, ... `f8`), not uppercase
   (`F1`, `F3`, ...) as the archive had them.

### Not reused: petcat's `cbmkeys[]` table

petcat names bytes `0xA0`-`0xBF` via a separate `cbmkeys[]` table of **key-combo** names
(e.g. `SHIFT-K`, `CBM-I`) -- these describe the *keyboard gesture* that produces the byte on
real hardware, not the glyph shown on screen. Since `PetsciiMapper`'s job is describing
what's on screen, not what was typed, this project deliberately does not reuse those names.
The entire `0xA0`-`0xFF` graphics half of PETSCII (including the `0xC0`-`0xDF`/`0xE0`-`0xFE`
mirror ranges) falls through to the `{$xx}` hex fallback uniformly in both variants.

### ASCII/PETSCII divergence (the "handful" of transliterated bytes)

Six bytes in the nominally-ASCII-looking `0x40`-`0x5F` range needed a decision: three are
genuinely identical to their ASCII codepoint (`0x40` `@`, `0x5B` `[`, `0x5D` `]`); three
diverge and are transliterated (following petcat verbatim, since ASCII has no equivalent
glyph):

| byte | real PETSCII glyph | rendered as | note |
|------|---------------------|-------------|------|
| `0x5C` | £ (pound sign) | `\` | ASCII has no £; petcat's own transliteration |
| `0x5E` | up-arrow | `^` | ASCII-safe transliteration |
| `0x5F` | left-arrow | `_` | ASCII-safe transliteration |

### Variant model

`PetsciiMapper.Variant` has two values, `UNSHIFTED_GRAPHICS` and `SHIFTED_LOWERCASE`. By
design, **only one byte range differs between them**: `0x41`-`0x5A`, which shows uppercase
letters in `UNSHIFTED_GRAPHICS` and lowercase letters in `SHIFTED_LOWERCASE`. This mirrors
VICE petcat's own `_p_toascii()`, which has no shift-state parameter at all and always
treats `0x41`-`0x5A` as the "opposite case" range -- i.e. petcat's unconditional behavior is
exactly this project's `SHIFTED_LOWERCASE` interpretation, since virtually all real-world
BASIC listings live in the lowercase charset. Every other byte (including `0x61`-`0x7A`,
which *does* differ by shift state on real hardware -- graphics glyphs in one charset,
uppercase letters in the other) is treated uniformly across both variants in this v1 model
and falls to the `{$xx}` hex fallback, rather than trying to resolve that second ambiguity
without more context than a single byte provides.

### v1 has no Unicode

Output is ASCII-only bracket escapes. A `toDisplayUnicode()` that renders control codes and
graphics glyphs as real Unicode characters (PETSCII's box-drawing/graphics range has a
plausible target in the "Symbols for Legacy Computing" Unicode block) is a natural follow-up
but is out of scope here.

## Runtime API

```java
PetsciiMapper mapper = PetsciiMapper.load();
String s = mapper.toDisplayEscaped(0x12, PetsciiMapper.Variant.UNSHIFTED_GRAPHICS); // "{rvon}"
String line = mapper.toDisplayEscaped(byteArray, PetsciiMapper.Variant.SHIFTED_LOWERCASE);
```

`load()` requires a running Ghidra application (`Application.findDataFileInAnyModule`).
Tools that run outside a Ghidra runtime (e.g. the verifier below) use
`PetsciiMapper.loadFromMapFile(File)` instead, which parses `data/petscii.map` directly.

## Verification

`tools/petscii/PetsciiMapperVerify.java` (own Gradle source set `petsciiCheck`, own task
`verifyPetsciiMapper`, structured after `tools/bitalgebra/BitAlgebraEquivalence.java`)
exhaustively checks all 256 bytes x 2 variants: non-null/non-empty display strings, every
petcat-named byte matches the independently-transcribed reference table, every unnamed
non-printable byte renders exactly `{$xx}`, and printable bytes render the expected
character. Run with `gradle verifyPetsciiMapper`.

## For future consumers (grm-odt.1, Charset registration in grm-1.4)

- Call `PetsciiMapper.load()` once (it caches) rather than re-parsing `petscii.map` per use.
- The two `Variant` values are a genuine input you must supply -- there is no "auto-detect"
  from a byte stream; a BASIC detokenizer typically wants `SHIFTED_LOWERCASE` (the charset
  virtually all real-world listings actually use), but if the analyzer ever needs to render
  the *unshifted* charset (e.g. before a program's first `{swlc}`), pass
  `UNSHIFTED_GRAPHICS` explicitly.
- `toDisplayEscaped` never throws for any `int`/`byte` value (all 256 bytes are covered);
  the only failure mode is `load()`'s `IOException` if `petscii.map` is missing from the
  installed extension.
- Screen-code-to-PETSCII conversion is NOT provided here (out of scope, see above) --
  a consumer working from screen RAM needs its own screen-code -> PETSCII step first.
