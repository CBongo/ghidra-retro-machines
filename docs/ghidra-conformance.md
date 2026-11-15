# Ghidra conformance: contribution rules and coding standards

Two upstream documents govern work that touches Ghidra:

- `CONTRIBUTING.md` -- how a pull request must be shaped
- `GhidraDocs/GhidraCodingStandards.md` -- code style (Ver 2.0, 2026-11-04; Markdown since GP-7469)

Both live on Ghidra's `master` and change over time; **re-read them before drafting an upstream
change**, and update this file when they move. This file was written against them on 2026-11-14.

**Scope, per the owner (2026-11-14):**

| Code | Status |
|---|---|
| Changes to the Ghidra codebase itself (upstream PRs, decompiler C++, Ghidra Java) | **Required** -- follow every rule below as far as possible |
| This extension's own code (`src/`, `ghidra_scripts/`, `tools/`) | **Recommended** -- a guideline for code you write or edit from now on; never a retrofit sweep |

Do not change an outstanding upstream PR to match these rules unless the owner or a reviewer asks.

## Part 1 -- Upstream PRs (required)

These apply to every draft kept on a bead (see `AGENTS.md`, "Upstream drafts") and to the branch
the owner pushes.

- **One PR per independent change, smallest reasonable diff.** No renames, repackaging,
  refactors, reindents or find-and-replace sweeps beyond what the fix needs -- not even
  "obviously better" ones. Small enough to review, but not so minimal it is hard to read.
- **No jar or third-party library updates** (file an issue asking instead), and **no
  self-generated binary files**.
- **One squashed commit** that briefly describes the change. To update a branch, rebase onto
  `master` and force-push; never merge `master` into it.
- **No title or commit-message line may begin with `#`** (it is lost when squashing).
- **Issue numbers go in the body as `Fixes #N`, never in the title.** Do not file an issue that
  duplicates a PR -- the PR body carries the full bug description.
- **Bug fixes from real-world use are the preferred kind.** For anything larger than a contained
  bug fix, open the dialogue first -- an issue, or a comment on an existing one asking whether
  the direction is wanted -- before drafting the PR. Unsolicited feature PRs start at low
  priority.
- **AI-assisted work gets extra scrutiny**, for correctness and for the legal terms
  (inbound=outbound Apache-2.0). Never include an Architecture Decision Record. Include unit
  tests only when they add coverage to an EXISTING test file and belong there; otherwise keep
  datatests and unit tests on the bead and offer them if a reviewer asks.
- **It must build in Ghidra's development environment**, ideally the full build -- not only in
  `decomp_test_dbg`.
- **Format to the shipped Eclipse profiles**: `eclipse/GhidraEclipseFormatter.xml` for Java,
  `eclipse/GhidraCDTFormatter.xml` for the decompiler's C++ (in `$GRM_GHIDRA_SRC/eclipse/`). Where
  a formatter cannot be run, match the touched file's own style exactly; never reformat lines the
  change does not touch.
- **Java changes follow Part 2 in full.** Decompiler C++ is not covered by the coding-standards
  document: follow the surrounding file (its Doxygen comment style, naming and brace layout).
- **Review vocabulary:** reviewers mark comments MUST (required), SHOULD (suggested; discuss),
  COULD (optional). When relaying review feedback to the owner, keep that distinction.
- Be patient and constructive; a polite update request after a reasonable wait is fine. Never
  post anything yourself -- the owner posts (`AGENTS.md`, "Anything needing the user's identity").

## Part 2 -- Coding standards

Required for Java going into Ghidra; recommended for new and edited code in this extension.
Any rule may be broken with a short comment saying why the code is better for it.

**Formatting** (mostly what the Eclipse profile does)
- 100 columns per line; indent with tabs, a tab counting as 4; continuation lines indented one tab.
- Braces always, even where optional; K&R placement; an empty block holds a comment saying why.
- `//@formatter:off` / `//@formatter:on` around hand-formatted code; never an empty `//` to defeat
  the formatter.
- One variable per declaration. A space around binary operators, after `//`, and after `for`'s
  semicolons.

**Naming**
- No abbreviations in class, method, field, parameter or long-lived local names, except well-known
  ones (URL, HTML) and the `Utils` suffix; an acronym capitalizes only its first letter (`fooUrl`).
- Classes are nouns; subclasses prepend to the base name (`DumpTruck` extends `Truck`); interface
  `Foo` with `AbstractFoo` / `DefaultFoo` / `{Descriptive}Foo` implementations.
- Methods are verbs: `get`/`set` for attributes, `is`/`has`/`can`/`should` for booleans, `find` for
  lookups; name a method by what it returns, or by what it does if void.
- Variables are named for their type or role (`Button openButton`); collections are plurals
  (`dogs`, not `dogList`); name length grows with scope.
- Constants `UPPER_SNAKE`; enum values upper case; generic types `T`, `K,V`, `R` or `RowT`.
- Test classes end in `Test`; test doubles are `Dummy`/`Spy`/`Mock`/`Fake` + name.

**Structure**
- File order: header, package, imports, class Javadoc, class, static fields, instance fields,
  static factories, constructors, methods, private classes. Overloads sit together.
- Modifier order: access, `abstract`, `static`, `final`, `transient`, `volatile`, `default`,
  `synchronized`, `native`, `strictfp`.
- Declare locals where first needed, initialized at declaration.

**Javadoc and comments**
- Javadoc on every non-private class, interface, record and method, except `@Override` methods
  and JUnit test methods.
- Open with a summary fragment, capitalized and punctuated as a sentence ("Sets the level.", not
  "This method sets the level."). Separate paragraphs with a line holding only `<p>`.
- Block tags never empty, ordered `@param @return @throws @see @deprecated`, with no trailing
  period unless another sentence follows. Use `{@link}` for method references.
- Comments explain why, not what, and are not pseudo-code; prefer a well-named method to a block
  comment, and rewrite tricky code rather than commenting it. (For this extension, a bead id as a
  pointer is fine; long investigation history belongs in the bead and the commit message.)

**Complexity**
- Methods do one thing in about 30 lines and read in about 30 seconds.
- Complexity (1 + each non-guard return, `if`/`else if`/`case`/`default`, loop, `break`,
  `continue`, `&&`/`||`/`?`, `catch`/`finally`/`throw`): 0-5 fine, 6-10 simplify, 11+ unacceptable.
- Nesting 2 or less is good, 5 or more is unacceptable. Parameters: 3 or fewer is good, 6+ means
  redesign; avoid several parameters of one type, booleans above all.
- Keep each method at one level of abstraction.

**Miscellaneous**
- `@Override` on every override and interface implementation.
- No `var`; no `Pair`/`Triple` tuples (return a record); immutable fields `final`; fields never
  public; no shadowing.
- try-with-resources wherever possible; parameterize generic types; `isEmpty()`, not `size() == 0`.
- Never an empty catch; an "impossible" exception throws `AssertException` saying so.
- Do not mutate parameters. No magic numbers other than 0 and 1 -- name them as constants
  (in this extension, a one-off ISA encoding or hardware address named in an adjacent comment is
  an accepted exception).
- Unit tests: one result per test (consider splitting past 2-3 asserts), each under a second.

## This extension today

Measured 2026-11-14 over `src/main/java` and `src/test/java` (386 files, ~140k lines): tabs,
braces, `@Override`, no tuples and no empty catch already conform. Outside the standard: 1172
lines over 100 columns in 216 files, 66 uses of `var`, about 140 methods over 60 lines. Leave
existing code alone unless you are already editing it. Automated checks for the added rules are
tracked in beads (see `bd search "style check"`).
