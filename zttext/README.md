<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# zttext — a text engine for loft

One content substrate — an append-only buffer plus a piece sequence — with a
pluggable per-surface layout behind an API layer of ports (`Measurer`,
`StyleResolver`, `Layout`, `RenderSink`, `InteractionMap`).  "Switch the surface"
means swap the layout bundle; the content core is unchanged.

Pure Tier-1 loft with **measurement injected**, so behaviour is identical on the
interpreter, `--native`, `--native-wasm` and in the browser by construction.

## Install

```sh
loft install zttext
```

## Layers

| Layer | Types + entry points |
|---|---|
| Content core | `Doc`, `Piece`, `Run` · `doc_from_text`, `materialise`, `doc_len`, `insert_text`, `delete_range`, `set_style`, `slice_runs`, `char_styles` |
| Transactions | `Op` (`Ins` / `Del` / `Sty`), `Txn` · `txn_of`, `apply`, `invert` |
| Style + measure ports | `Style` · `default_style`, `default_resolver`, `mono_measure`, `run_height` |
| Layout | `Box`, `BoxSet`, `LaidLine`, `Layout` · `flow_layout`, `flow_layout_full`, `line_assignment`, `boxset_height`, `render_commands` |
| Interaction | `box_at`, `anchor_at`, `caret_at`, `sel`, `sel_rects`, `word_at`, `line_boxes` |

## Four things to know before you call it

- **An edit is a value you have to keep.** `insert_text` / `delete_range` /
  `set_style` return a NEW `Doc` and leave the one you passed alone.  Writing
  `insert_text(d, 0, "x", 0);` as a statement compiles, runs, and throws the
  result away — the symptom is an editor where typing does nothing.
- **Offsets are CHARACTER positions, never bytes.**  The buffer is a
  `vector<character>`, so a range lands on character boundaries by construction —
  the multi-byte truncation trap is designed out rather than guarded against.
- **A delete does not shrink the buffer.** The buffer is append-only; a delete
  rewrites the piece sequence.  That is not a leak, it is what undo restores from.
- **Undo is inverted against the state BEFORE the edit.**  `invert(pre, txn)`
  needs the pre-state because the inverse of a deletion is an insertion of what
  was there.  It restores per-character styles, not only text.

## Worked examples

Those four are demonstrated by running tests (@PLN141):
[tests/worked-examples.loft](tests/worked-examples.loft) — `@ZTX-001` an edit is
a value, `@ZTX-002` character offsets and the append-only buffer, `@ZTX-003` undo
against the pre-state, `@ZTX-004` layout is portable because measurement is an
argument.

## Design

`doc/EDITOR_DESIGN.md` (direction) → `doc/ZTTEXT_NOTATION.md` (the formal model,
invariants I1–I9) → `doc/ZTTEXT_PLAN.md` (the M0–M5 build plan).
