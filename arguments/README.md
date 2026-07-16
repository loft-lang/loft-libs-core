<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# arguments — GNU-style CLI argument parsing for loft

Declare options against an `Args`, call `parse(argv)`, then query the results.
Supports the GNU `getopt_long` surface and renders a GNU-format `--help` screen
generated automatically from the declared options.

## Install

```sh
loft install arguments
```

## Usage

```loft
use arguments;

fn main() {
    a = arguments::create("greet", "1.0", "Greet someone.");
    a.set_usage("[NAME...]");
    a.flag("v", "verbose", "explain what is being done");
    a.option("o", "output", "FILE", "write the greeting to FILE");
    a.enable_help();                       // opt-in: wires --help / --version

    if !a.parse(argv()) {                  // argv() = the process arguments
        println(a.error_msg());
        println(a.try_help());
        return;
    }
    if a.wants_help()    { print(a.help());          return; }
    if a.wants_version() { println(a.version_text()); return; }

    for name in a.positionals {
        line = "hello {name}";
        if a.has("verbose") { line += " (verbose)"; }
        println(line);
    }
}
```

## Supported syntax

- **Long options:** `--name`, `--name=value`, `--name value`.
- **Short options:** `-n`, `-n value`, `-nvalue` (glued), `-abc` (bundled flags),
  `-vo value` (bundled flag + value option).
- **Prefix abbreviation:** `--verb` resolves to `--verbose` when unambiguous;
  an ambiguous prefix is a reported error.
- **`--`** ends option parsing — everything after is positional.
- **`-`** is a positional (the stdin convention).
- **Interspersed** options and positionals (GNU permutation): options are still
  recognised after the first positional.

## API

| Function | Purpose |
|---|---|
| `create(name, version, description) -> Args` | Start a parser. |
| `flag(short, long, desc)` | A boolean flag. |
| `option(short, long, metavar, desc)` | An option that takes a value. |
| `required(short, long, metavar, desc)` | A value option that must be present. |
| `optional(short, long, metavar, desc)` | Optional-argument option (`--x` or `--x=v`). |
| `set_usage(synopsis)` / `set_bug_address(addr)` / `set_epilog(text)` | Help text. |
| `enable_help()` | Opt-in: register `--help` / `--version`. |
| `parse(argv) -> boolean` | Parse; `false` on error (see `error_msg()`). |
| `has(long) -> boolean` | Was the option given? |
| `get(long) -> text?` | Its value, or null when unset. |
| `get_or(long, fallback) -> text` | Value, or `fallback` when unset. |
| `get_int(long) -> integer?` | Value parsed as an integer, or null. |
| `positionals` | The positional arguments (`vector<text>`). |
| `ok()` / `error_msg()` | Parse status and the error message. |
| `wants_help()` / `wants_version()` | Set after `enable_help()` when requested. |
| `version_text()` / `try_help()` / `help()` | Rendered strings. |

A value option's value must not itself look like an option: give it as
`--opt=value`, or as `--opt value` where `value` does not begin with `-`
(otherwise the value is a *required-argument* error). This is stricter than
GNU's "grab the next word literally", and avoids the classic footgun of a
missing filename silently swallowing the following flag.

## Implementation note

The parsing core is written with loft's cursor / match-PEG engine (@PLN35): each
`argv` element is lexed into a token against the option table, then a cursor
`match` drives the token stream — the `[ NeedVal, Pos ]` versus `[ NeedVal ]`
sequence is what decides whether an option consumes the following word. It
therefore requires a loft build that ships the cursor-match feature.

## Provenance

Extracted from the loft monorepo's `lib/arguments/` 2026-05-24 (plan-12 Phase
3.5a). Rebuilt on the cursor/match-PEG engine and extended to the full GNU
option surface + auto-generated `--help` in 2026-07.
