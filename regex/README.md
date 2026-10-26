<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# regex — regular expressions for loft

Inline regular expressions over an engine of the library's own, in C99
(`c/regex.c`): the Rust `regex` crate's syntax and leftmost-first semantics —
groups, named groups, alternation, greedy and lazy quantifiers, classes, `\d
\w \s` and `\p{L}` over Unicode, `^ $ \b`, `(?i)` — matched by backtracking
with a step bound, so a pathological pattern ends in a miss rather than running
away.  loft builds the engine with `cc` as the package's `[c] shim`; no Rust
crate and no rustc, one source for the interpreter, `--native` and the C
backend.

Deliberately minimal — this is the **small-script** text tool (log
scanning, CLI fields, quick extraction).  You pass the pattern inline;
there is no compile step and no handle to manage.  Compiled patterns are
cached in a thread-local table, so repeated calls with the same pattern
are cheap.

> Structured parsing — grammars, ASTs, recursion — is **not** this
> library's job.  That belongs to the match-pattern parser framework.

## Install

```sh
loft install regex
```

## API

| Call | Returns | Notes |
|---|---|---|
| `input.matches(pattern: text) -> boolean` | `true` if `pattern` matches anywhere in `input` | invalid pattern → `false` (never raises) |
| `input.search(pattern: text) -> integer?` | byte offset of the first match | `null` when there is no match / invalid pattern |
| `input.capture(pattern: text) -> Match?` | the first match with its capture groups | `null` on a miss; `m.group(1)`, `m.named("x")`, `m.text`, `m.start`, `m.end` |
| `input.capture_all(pattern: text) -> vector<Match>` | every non-overlapping match, in order | empty on a miss; an empty match advances one character |
| `input.replace_on(pattern: text, template: text, limit = 0) -> text` | the text with its matches replaced | `$1`, `${name}`, `$0`, `$$` in the template; `limit` 0 is every match |
| `input.split_on(pattern: text) -> iterator<text>` | the pieces between matches, lazily | no match → one piece, the whole text |
| `m.group(i: integer) -> text?` | group `i` (1-based; 0 is the whole match) | `null` for a group that did not take part, or on a null `m` |
| `m.named(name: text) -> text?` | the `(?<name>…)` group | `null` for an unknown name, or on a null `m` |

```loft
pub struct Group { pub text: text?, pub start: integer, pub end: integer }
pub struct Match { pub text: text, pub start: integer, pub end: integer,
                   pub groups: vector<Group>, pub names: vector<text> }
```

**Every offset is a byte offset on a code-point boundary**: the engine matches by
character, so a span never cuts a character.  Slice with it (`input[m.start..m.end]`)
and compare it against `size()`, never `len()`.  A `Match` holds no copy of the
subject: its texts are slices of it, built in the shape under which the compiler keeps
them views of the subject on `--native` (@PLN192 in the loft repository).

**A pattern that does not compile answers a miss** (`false`, `null`, the input
unchanged) and, the first time it is used, logs one warning naming the pattern and the
parser's message — the stdlib's channel for an unguarded `÷ 0`.

0.5.0 made `search` honest (`integer?`) and removed the superseded `regex_find` /
`regex_split` spellings; 0.4.0 removed the free functions `regex::find` and
`regex::split`, whose bare calls the stdlib's `text` methods of the same names took.
Write `input.search(pattern)` and `input.split_on(pattern)`.

## Usage

```loft
use regex;

fn main() {
    if "order #123".matches("[0-9]+") {
        print("digits start at {"order #123".search("[0-9]+")}\n");  // 7
    }
}
```

No compile call needed — the first use of a pattern compiles it, every
later use of the same pattern is a cache hit.

## Not here, on purpose

A `Regex` handle (the pattern cache makes a compile step a worse API); a `replace`
with a callback (a closure cannot cross a placed library — walk `capture_all` and build
the result from the subject's spans, four lines, `@RGX-007`); a lazy `iterator<Match>`
(`capture_all` answers a vector); lookaround and backreferences (the engine is
linear-time by construction).  The plan: `doc/claude/plans/192-regex-captures-as-spans.md`
in the loft repository.

## Worked examples

The contracts a signature cannot state are demonstrated by running tests
(@PLN141): [tests/worked-examples.loft](tests/worked-examples.loft) —
`@RGX-001` the spelling decides which library you called (a bare
`find(pattern, input)` compiles and reaches the **stdlib** method, answering
something else), `@RGX-002` `search` answers a BYTE offset and a typed null on a
miss, `@RGX-003` a broken pattern reports a miss rather than an error, `@RGX-004`
`split_on` yields the gaps — including empty ones — and never yields zero pieces,
`@RGX-005` a group that did not take part is null and not `""`, `@RGX-006` every
offset is a byte on a code-point boundary, `@RGX-007` the walk idiom replaces a
callback, `@RGX-008` a replacement template is not a format string.

## Provenance

Up to 0.5 a native crate `loft_regex` wrapped the Rust `regex` crate; since
0.6.0 the engine is `c/regex.c`, a backtracking matcher with the crate's
semantics (measured against the crate on this suite), bound by `#c`
declarations and built by loft itself.  The replacement template (`$1`,
`${name}`, `$$`) is expanded in loft.  Built directly in `loft-libs-core`
rather than extracted from the monorepo.
