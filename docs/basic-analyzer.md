# C64 BASIC detokenizing analyzer (bead grm-odt.1)

## Purpose

`C64BasicAnalyzer` recognizes a tokenized-BASIC-start C64 PRG, walks the line-link chain,
types the per-line link/line-number fields, writes petcat-compatible detokenized comments,
and marks the real machine-language entry point (from a `SYS <decimal>` line) instead of
the load address that `C64PrgLoader` marks for every other PRG.

Two dependencies documented elsewhere: byte-to-text rendering goes through `PetsciiMapper`
(see [docs/petscii.md](petscii.md)), and the `BASIC_V2_TOKEN` table it reads is a `kind:
enum` `types:` entry (see "Types: struct, flags, and enum kinds" in
[docs/SCHEMA.md](SCHEMA.md)).

## Files

- `src/main/java/retromachines/C64BasicWalker.java` -- dialect-agnostic line-link chain
  walker, shared by the loader (cheap structural sniff) and the analyzer (full walk).
- `src/main/java/retromachines/BasicTokenLookup.java` -- the `(bytes consumed, name)`
  token-lookup interface (dialect seam for future BASIC 7 two-byte prefix tokens).
- `src/main/java/retromachines/BasicV2TokenLookup.java` -- BASIC V2 implementation, reading
  the `BASIC_V2_TOKEN` enum directly out of `machines/c64.gdt` (compiled from
  `machines/generated/basic-tokens.yaml`) -- no transcribed token table of its own.
- `src/main/java/retromachines/C64BasicAnalyzer.java` -- the analyzer.
- `src/main/java/retromachines/C64PrgLoader.java` -- `looksLikeBasicStart` gate on the
  load-address function mark (see "Loader/analyzer split" below).
- `tools/banktest/mkbasictest.py`, `tools/banktest/expected/c64basictest.dump` -- fixture
  and golden dump, run by `tools/banktest/run-banktest.sh`.

## Loader/analyzer split

Prior to this bead, `C64PrgLoader` unconditionally labeled and `markAsFunction`'d the load
address for every PRG. For a BASIC-start PRG those bytes are the first line's link word,
not code. The fix is split:

- **The loader** runs `C64BasicWalker.isBasicStart` (a cheap structural sniff over the raw
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
rule -- see the regression note in `C64BasicWalker.isBasicStart`'s javadoc.)

## Token-enum consumption path

`BASIC_V2_TOKEN` is a `kind: enum` entry in `machines/c64.yaml`'s `types:` list, compiled
into `machines/c64.gdt` by `GdtBuilder` from `machines/generated/basic-tokens.yaml`. The
analyzer reopens the archive with `DescriptorSupport.openGdt("machines/c64.gdt")` (the same
helper the loader uses, but a fresh call -- the loader's own `FileDataTypeManager` is closed
in its `finally` block before the analyzer ever runs) and reads the enum straight from the
archive's data type manager:

```java
DataType dt = gdtMgr.getDataType(CategoryPath.ROOT, "BASIC_V2_TOKEN");
```

The enum is **not** resolved into the program's own `DataTypeManager` -- it is only ever
queried for member names (`Enum.getName(int)`), never applied as a data type to a byte (see
"Data typing" below), so there is no need to pay for or pollute the program DTM with it.

`BasicTokenLookup.lookup(byte[] data, int offset)` returns a `Match(int bytesConsumed,
String name)` record rather than a plain `byte -> name` map. For BASIC 2 this is always
`(1, name)`. The shape exists for BASIC 7 (C128), whose `$CE`/`$FE` prefix bytes select a
second-byte table (not implemented here -- see `machines/generated/basic-tokens.yaml`'s
header for the planned `lists: [basic2-base, basic7-...]` composition and the future
`BASIC_V7_TOKEN_FE`-style per-prefix enum): a BASIC 7 lookup implementation would return
`(2, name)` for a recognized prefix pair, and the analyzer's per-line scan loop (which
already advances `i` by `m.bytesConsumed()`, not a hardcoded `1`) needs no change to consume
it.

## Detokenizer state machine

One pass over each line's raw text bytes (`C64BasicAnalyzer.renderLine`), tracking two
booleans (`inQuotes`, `afterRem`):

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
- **DATA gets no special treatment.** The task brief for this bead assumed DATA argument
  text is stored raw. That is not how the real BASIC 2 tokenizer works: DATA statement text
  is tokenized exactly like any other text outside quotes -- this is the well-known "`DATA
  GOTO` silently tokenizes GOTO" C64 gotcha, which VICE's petcat (the detokenization
  reference this bead targets compatibility with) reproduces faithfully. So there is no
  DATA-specific branch here; the general outside-quotes rule already does the right thing,
  and a colon following DATA text needs no special casing either -- it is just PETSCII
  `$3A`, never a token, rendered like any other byte `< $80`. The fixture's line 40
  (`DATA 1,2:PRINT 3`) demonstrates the colon continuation re-tokenizing `PRINT` normally.
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
`$30`-`$39` digit bytes, parsed as a base-10 value. A literal address marks a function and
external entry point there (`CreateFunctionCmd`, matching `BoardBankAnalyzer`'s own pattern
for marking overlay-retargeted call targets) and drops a `PLATE` comment ("SYS target from
BASIC line N"). A non-literal argument (an expression, a variable, anything that isn't
straight decimal digits) drops a `Note` bookmark instead and marks nothing -- explicitly out
of scope per the bead. Only the first SYS occurrence in the whole program is acted on;
further `SYS` lines are rendered normally but not inspected.

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

All text renders via `PetsciiMapper.Variant.UNSHIFTED_GRAPHICS` -- the character set a
stock C64 boots into (uppercase + graphics mode). This is hardcoded for v1; a per-program
override (for programs that POKE the shift flag or issue a shift-to-lowercase control code
before printing) is not implemented.

## Known limitations / deferred work

- **Line-number monotonicity** is not validated or reported. A program with out-of-order
  line numbers still detokenizes and types correctly; only the *link* chain's structural
  validity is checked.
- **BASIC 4/7 dialects** (disk-command keyword fork above `$CB`; BASIC 7's two-byte
  `$CE`/`$FE` prefix tokens) are not implemented. The token-lookup interface and the
  `basic-tokens.yaml` `lists:` composition model are already shaped for this (see
  "Token-enum consumption path" above); adding a dialect means a new `BasicTokenLookup`
  implementation plus a new enum type entry in the relevant machine YAML, with no change to
  `C64BasicWalker` or the analyzer's per-line loop. Tracked as follow-on work under
  grm-1.6.1.
- **SYS argument scope** is a bare decimal literal only, matching the bead's stated scope.
  `SYS (2064)`, `SYS PEEK(43)*256+PEEK(44)`, and similar real-world patterns are not
  recognized (they fall into the non-literal `Note`-bookmark path).
- **Empty-program edge case:** a PRG whose first two bytes happen to be `$00 $00` is
  trivially treated as an empty BASIC program (`isBasicStart` returns true) even though
  this is indistinguishable from two null bytes at the start of real machine code. This is
  a low-probability collision (real 6502 code essentially never starts with `BRK; BRK`) and
  is accepted as a known limitation rather than special-cased further.
