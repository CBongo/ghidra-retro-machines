# Descriptor-driven CBM BASIC detokenizing analyzer (beads grm-odt.1, grm-1.6.1)

## Purpose

`C64BasicAnalyzer` retains its class name for analyzer-run and bookmark compatibility, but
recognizes any tokenized-CBM-BASIC PRG whose selected descriptor declares
`formats.prg.basic`. It walks the line-link chain, types the per-line link/line-number
fields, writes petcat-compatible detokenized comments, and marks a real machine-language
entry point from a `SYS <decimal>` line.

Two dependencies documented elsewhere: byte-to-text rendering goes through `PetsciiMapper`
(see [docs/petscii.md](petscii.md)), and each descriptor names its token enums as `kind:
enum` `types:` entries (see "Types: struct, flags, and enum kinds" in
[docs/SCHEMA.md](SCHEMA.md)).

## Files

- `src/main/java/retromachines/CbmBasicWalker.java` -- dialect-agnostic line-link chain
  walker, shared by the loader (cheap structural sniff) and the analyzer (full walk).
- `src/main/java/retromachines/BasicTokenLookup.java` -- the `(bytes consumed, name)`
  token-lookup interface.
- `src/main/java/retromachines/BasicDescriptorTokenLookup.java` -- primary and optional
  prefix-page enum lookup selected by the imported program's descriptor.
- `src/main/java/retromachines/C64BasicAnalyzer.java` -- the retained-name generic analyzer.
- `src/main/java/retromachines/C64PrgLoader.java` -- `looksLikeBasicStart` gate on the
  load-address function mark (see "Loader/analyzer split" below).
- `tools/banktest/mkbasictest.py`, `tools/banktest/expected/c64basictest.dump` -- fixture
  and golden dump, run by `tools/banktest/run-banktest.sh`.

## Loader/analyzer split

Prior to this bead, `C64PrgLoader` unconditionally labeled and `markAsFunction`'d the load
address for every PRG. For a BASIC-start PRG those bytes are the first line's link word,
not code. The fix is split:

- **The loader** runs `CbmBasicWalker.isBasicStart` (a cheap structural sniff over the raw
  PRG bytes, no descriptor/gdt access needed) and skips the load-address function mark when
  it looks like BASIC. It still creates the `entry` label and external entry point at the
  load address (harmless, and consistent with every other PRG) -- it just doesn't call
  `markAsFunction` there.
- **The analyzer** does the real work: walks the line chain, types/comments every line, and
  -- if it finds a `SYS <decimal>` line -- marks *that* address as a function and an
  external entry point instead.

This intentionally does **not** compare the load address against a hardcoded value such as
`$0801` (the `RAM_MAIN` region in `machines/c64.map` starts at `$0800`, one byte before the
conventional BASIC start, so even a region-start comparison would need an unmotivated `+1`
fudge). Instead, a well-formed line-link chain at whatever address the PRG loads *is* the
signal: `isBasicStart` returns true only if the first line parses cleanly (link matches the
address reached by scanning to that line's own `$00` terminator). This also doubles as a
false-positive guard: plain machine code that happens to contain an early `$00` byte can
produce a single bogus "line" by coincidence, but its bogus link essentially never lands
exactly on the terminator-scan address, so the first-line-clean requirement rejects it. (An
earlier draft accepted any walk that produced >= 1 line, including one ending at the
malformed-link stop condition on the very first line; this false-positived on the existing
`banktest*.prg` machine-code fixtures, which is what surfaced the need for the stricter
rule -- see the regression note in `CbmBasicWalker.isBasicStart`'s javadoc.)

## Token-enum consumption path

The selected map's `formats.prg.basic` object supplies the primary `token_enum`, optional
`prefix_enums` (`prefix` and `enum`), and PETSCII variant. The analyzer derives that map's
`.gdt` path, reopens the archive, and reads the named enum straight from its data type manager:

```java
DataType dt = gdtMgr.getDataType(CategoryPath.ROOT, descriptorTokenEnum);
```

The enum is **not** resolved into the program's own `DataTypeManager` -- it is only ever
queried for member names (`Enum.getName(int)`), never applied as a data type to a byte (see
"Data typing" below), so there is no need to pay for or pollute the program DTM with it.

`BasicTokenLookup.lookup(byte[] data, int offset)` returns a `Match(int bytesConsumed,
String name)` record rather than a plain `byte -> name` map. Ordinary tokens return
`(1, name)`; a configured prefix page such as BASIC 7 `$CE`/`$FE` returns `(2, name)`.
Every configured complete prefix pair consumes both bytes. If its page or selector is unknown,
the match has a null name and the analyzer renders both bytes as raw PETSCII without rescanning
the selector; a truncated prefix remains one raw byte. Missing configured prefix enums are
reported once in the analyzer log and their pairs also remain raw.

## Detokenizer state machine

One pass over each line's raw text bytes (`C64BasicAnalyzer.renderLine`), tracking three
booleans (`inQuotes`, `afterRem`, `afterData`):

- **Outside quotes, not past REM:** a byte `>= $80` is looked up as a token. A hit renders
  the keyword name; a miss (BASIC 2 leaves `$CC`-`$FF` unassigned) falls through to
  `PetsciiMapper`, rendered as that byte's escape (e.g. `$FF`, PETSCII pi, renders as
  `{$ff}` -- `PetsciiMapper` is deliberately ASCII-escape-only in v1, no Unicode glyphs, so
  this is consistent with every other unassigned/control byte, not a special case).
  `$22` toggles `inQuotes` (and, since it is `< $80`, also renders via `PetsciiMapper` as
  `"` through the normal fallthrough -- no special-cased output text is needed).
- **Inside quotes:** every byte renders via `PetsciiMapper`, regardless of value -- a
  control code or a byte that happens to equal a token value is always literal PETSCII
  inside a string; the real tokenizer never tokenizes string contents.
- **After a REM token:** every remaining byte to the terminator renders via `PetsciiMapper`,
  unconditionally (no token lookup, no quote-toggle check). This matches the real BASIC ROM
  cruncher, which stops tokenizing entirely once it emits the REM token -- a `"` inside a
  REM comment is just a raw quote character, not a quote-mode toggle.
- **After a DATA token:** item bytes are untokenized raw PETSCII until an unquoted `$3A`
  colon. Quote bytes are still tracked so a quoted colon stays in the item text. The separator
  itself is rendered raw, then normal token scanning resumes for the next statement.
- **Malformed line link:** per-line, if the link does not point exactly at the address
  reached by scanning to that line's own `$00` terminator, the walk stops (does not follow
  that link further) and the analyzer drops a `Warning` bookmark at the offending line
  naming the mismatch. The line already parsed up to its own terminator is still typed and
  commented -- only the *rest of the chain* is abandoned, not the whole result.
- **No auto-spacing.** Unlike some naive detokenizers, this renderer does not insert spaces
  around tokens. Real BASIC 2 preserves exactly the literal PETSCII bytes that were present
  when the line was tokenized (typing `10FORI=1TO10` keeps no spaces; typing `10 FOR I=1 TO
  10` keeps exactly those spaces as literal `$20` bytes in the stream) -- so the fixture's
  hand-tokenized lines include literal `$20` bytes wherever a space should appear in the
  rendered listing, matching what a real user's typed-with-spaces line would tokenize to.

## SYS detection

The same per-line pass detects the first `SYS` token (regardless of which line it's on) and
looks for a decimal-literal argument: optional leading `$20` (space) bytes, then one or more
`$30`-`$39` digit bytes, then optional spaces followed only by end-of-line or a `$3A`
statement separator. The value must be in the 16-bit address range `0` through `65535`
(including zero). A valid literal address marks a function and external entry point there
(`CreateFunctionCmd`, matching `BoardBankAnalyzer`'s own pattern for marking overlay-retargeted
call targets) and drops a `PLATE` comment ("SYS target from BASIC line N"). An expression,
variable, trailing non-space byte, or out-of-range value drops a `Note` bookmark instead and
marks nothing. Only the first SYS occurrence in the whole program is acted on; further `SYS`
lines are rendered normally but not inspected.

## Comment placement and data typing

- **Link/line-number words:** each gets `WordDataType` plus a short EOL comment (`"line
  link"` / `"line number"`) identifying the field. This is the one place raw hex bytes in
  the listing benefit from a label -- there's no other way to tell a link word from a line
  number word by eye.
- **Detokenized text:** a single `PRE` comment at the line's start address (the link word),
  formatted exactly like a petcat listing line: `"<line number> <rendered text>"`. Example
  (from the fixture, `tools/banktest/mkbasictest.py`):

  ```
  10 FOR I=1 TO 10
  0801  10 08 0a 00 81 20 49 b2 31 20 a4 20 31 30 00     ....... I.1 . 10.
  20 PRINT"{clr}HI{$a0}"
  0810  1c 08 14 00 99 22 93 48 49 a0 22 00              ......".HI.".
  ```

  (The second line of each pair is illustrative of what the undefined-byte region looks
  like in a real Ghidra listing; the `PRE` comment is what actually ships.)
- **Tokenized text bytes themselves are left undefined** -- no byte-array data type is
  applied. The `PRE` comment already carries the full meaning of those bytes in the most
  readable form available (real BASIC text); typing them as a byte array would duplicate
  that information less readably (a raw hex dump sitting next to a comment that already
  says what it means) and would block any more specific future typing of the same bytes
  (e.g. per-opcode structuring for a hypothetical BASIC compiler-analysis pass).

## PETSCII variant

The selected map's `formats.prg.basic.petscii_variant` chooses either
`unshifted_graphics` (the stock C64 uppercase + graphics set) or `shifted_lowercase`. If
omitted, it defaults to `unshifted_graphics` for C64-compatible behavior.

## Known limitations / deferred work

- **Line-number monotonicity** is not validated or reported. A program with out-of-order
  line numbers still detokenizes and types correctly; only the *link* chain's structural
  validity is checked.
- **Dialect coverage** is descriptor-defined: a map only opts in when it supplies the
  required BASIC enums and `formats.prg.basic` metadata. Supporting a new dialect is normally
  descriptor/GDT work rather than an analyzer-code change.
- **SYS argument scope** is a 16-bit bare decimal literal, optionally surrounded by spaces
  before a line end or statement colon. `SYS (2064)`, `SYS 2064+1`, `SYS 65536`, and similar
  real-world patterns are not recognized (they fall into the `Note`-bookmark path).
- **Empty-program edge case:** a PRG whose first two bytes happen to be `$00 $00` is
  trivially treated as an empty BASIC program (`isBasicStart` returns true) even though
  this is indistinguishable from two null bytes at the start of real machine code. This is
  a low-probability collision (real 6502 code essentially never starts with `BRK; BRK`) and
  is accepted as a known limitation rather than special-cased further.
