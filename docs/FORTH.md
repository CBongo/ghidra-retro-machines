# Forth threaded-code support (grm-arbi)

# Forth config format (shared contract for grm-arbi.1 / .2 / .3)

YAML (hex ints written 0x...; the same structure is accepted as JSON). One `forth:` mapping:

```yaml
forth:
  ip: 0x7E            # zero-page low byte of IP (IP+1 = high)
  w: 0x81             # zero-page low byte of W
  next: 0x08C4        # NEXT entry (label only)
  docol: 0x08E2       # code-field VALUE that marks a colon word
  exit: [0x0B2E]      # CFAs that end a colon body
  handlers:           # code-field VALUE -> role
    0x08F9: DOCON     # body: one 16-bit constant
    0x0906: DOVAR     # body: data (unknown length; type 2 bytes)
    0x0914: {role: DOUSER, base: 0x83}   # body: 16-bit offset added to word at zp `base`
    0x0CA0: DODOES    # body: [does-thread address][data...]
    0x1872: EXECVEC   # vector table: pops n, executes body cell n; body = a run of word cells
    # a handler value may also be written {role: DOCON} -- accept both forms
  inline:             # CFA -> inline operand following the cell in a thread
    0x08AA: lit16
    0x0966: branch    # signed 16-bit offset; target = operand address + offset
    0x097B: branch
    0x0993: branch
    0x09B9: branch
    0x45EE: counted_string   # 1 count byte then count bytes
  names:              # CFA -> name, optional comment (names MAY repeat across addresses)
    0x0B2E: {name: EXIT}
    0x0C02: {name: DUP, comment: "( n -- n n )"}
```

Per-member overrides (overlays sharing addresses) use the same shape, nested as
`members: {<key>: {forth: {names: ..., inline: ...}}}`; member names take precedence over global.

Model: ITC on 6502. A word's CFA holds the address of machine code. Code word: [CFA] == CFA+2.
Colon word: [CFA] == docol; body = cells from CFA+2, each a CFA, until an `exit` cell (continue
past it if a forward branch targets beyond). Handler words: [CFA] == a `handlers` key.

## Implementation notes (grm-arbi.2)

- `ForthConfig` parses the compiled JSON form (also accepted wrapped as `{"forth": {...}}`).
  Integers may be numbers or strings (`"0x08C4"`, `"$08C4"`); map keys are strings, `0x`/`$`
  prefixed values are hex and bare digits are decimal. `inline` also accepts `cell16` (a data
  cell typed like a literal); values may be `{role:..}` / `{mode:..}` objects.
- `C64ForthAnalyzer` takes the config from the program's C64 game descriptor (grm-arbi.3):
  game-level `forth` with the member's `forth` (`names`, `inline`) merged over it, member wins
  (`ForthConfig.merge`). A JSON config in the Program-Info string property
  `Retro Machines.Forth Config` overrides the descriptor when present; with neither it does
  nothing. The ACS descriptor is generated: `machines/games/acs.yaml` by
  `tools/forth/forthhex2desc.py`.
- EXECVEC words (grm-arbi.3): the table length is not encoded in the image. The body is the run
  of cells from CFA+2 that are valid thread targets (same rule as a colon-body cell: declared name,
  EXIT or inline word, in-memory word, valid colon word, EXTERNAL named word). It stops at the
  first invalid cell, at a cell holding the DOCOL or any handler value (the next word's code
  field), or at the address of a declared name. An EXIT value is a legal entry. A vector needs at
  least one entry or it is not a word (threads referencing it are rejected). Cells are typed as
  pointers with `COMPUTED_CALL` references; the plate reads `VECTOR: NAME  w0 w1 w2 ...`.
- `ForthThreads` (pure) discovers words: every address holding the `docol` value is a colon
  candidate and is accepted only if its body walks cleanly to an `exit` (continuing past an
  `exit` while a forward branch targets beyond). Handler words and code words are accepted
  only when named/declared or referenced from an accepted thread. A candidate lying inside an
  accepted word's body loses. Rejections are logged and bookmarked (category `ForthAnalyzer`).
- Listing effects: label per CFA (`name`, punctuation mapped, else `FORTH_xxxx`), code field and
  thread cells as 16-bit pointers, inline operands as word / short / Pascal string, functions
  at code-word entries, NEXT and handler entries, a plate comment `[Forth] : NAME  ... ; `.
- Reference types: thread cell -> CFA is `COMPUTED_CALL` (NEXT dispatches through a computed
  pointer and the word returns via EXIT, so xrefs and call trees read as calls); CFA -> its
  code/handler and branch operand -> target are `COMPUTED_JUMP` (no return); DODOES word ->
  does-thread is `COMPUTED_CALL`.
- Rendering: `: NAME  DUP 0BRANCH L1 LIT $0003 L1: + ; ` -- branch targets that land on a cell
  of the same body become `Ln:` markers (numbered by address); the final exit prints as `;`.
