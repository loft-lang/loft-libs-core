<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# script — what a script reaches for, on demand

The helpers a script needs that the standard library keeps out of itself: each is loft over
primitives the runtime already answers, and each hangs off `text`, so a script writes
`dir.walk(".loft")` and names no library — the method is the trigger that loads it.

| Call | Answers | Notes |
|---|---|---|
| `dir.walk(suffix = "", links = true)` | `iterator<text>` | every file below `dir`, recursively, one at a time as a `for` loop asks: each directory's files in name order, then its subdirectories, depth first — nothing listed before the loop reaches it, nothing sorted.  A link to a directory is never entered; a link to a file is given unless `links: false`.  `suffix` keeps the names ending with it |
| `dir.walk_sorted(suffix = "", links = true)` | `vector<text>` | the same files as one vector in path order — the whole tree listed first, then sorted.  `walk_sorted(suffix, links: false)` is the `walk` of 0.2 and before |
| `src.copy_to(dst)` | `boolean` | the bytes of `src` written to `dst` as they are; false when `src` cannot be read or the write fails, and nothing written |
| `pattern.glob()` | `vector<text>` | the paths in one directory matching the last component: `*` any run, `?` one character, the directory part literal; name order.  A name starting with `.` matches only a pattern starting with `.` |
| `glob_match(pattern, name)` | `boolean` | the match alone, for a name already in hand |
| `set(words)` | `sorted<Word[key]>` | a set of texts: each once, in key order — a keyed collection over the one-field `Word`, with every lookup, removal and prefix range such a collection has; `set([])` is empty.  The builder: `script::set(words)` always, bare once builder triggers load a library |
| `s.put(w)` | | `w` in the set, once |
| `s.has(w)` | `boolean` | membership |
| `a.minus(b)` | `vector<text>` | the texts of `a` not in `b`, in key order |
| `s.words()` | `vector<text>` | the texts, in key order |

## Install

```sh
loft install script
```

Nothing more: a `use script;` is never written.  `script::walk(dir)` is the spelling that
always works.

**0.4 renames the walk.**  `walk` is now the lazy one; the sorted vector it used to answer is
`walk_sorted`.  A caller that indexes the result, adds it to a vector or relies on its order
moves to `walk_sorted(suffix, links: false)`, which gives exactly the 0.2 answer.

## Why these, and why here

Three ports of repository scripts to loft each wrote the same recursive walk by hand, copied
a file as `write_bytes(dst, read_bytes(src) ?? [])`, and spelled a shell's `default/*.loft` as
a listing and a filter (@PLN179 findings 004, 005, 008).  A primitive only the runtime can
answer belongs in the standard library; anything expressible in loft over such primitives
belongs in a library that loads on demand — this one.
