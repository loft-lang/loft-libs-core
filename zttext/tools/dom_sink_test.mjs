// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Headless test for the reference DOM RenderSink (dom_sink.mjs) — the parse + spec half, which is
// the only logic (mount() is trivial createElement glue). Fed the SAME golden render_commands the
// loft test asserts (test_render_commands_golden), so the JS sink and the loft engine agree on the
// protocol by construction.  Run: node dom_sink_test.mjs
import { parseRenderCommands, renderToSpecs } from './dom_sink.mjs';

let fails = 0;
const eq = (got, want, msg) => {
  const a = JSON.stringify(got), b = JSON.stringify(want);
  if (a !== b) { console.error(`FAIL ${msg}\n  got  ${a}\n  want ${b}`); fails++; }
};

// The golden from lib/zttext test_render_commands_golden (doc "the quick brown fox\njumps over", w=8).
const GOLDEN =
  "LINE|0.00|1.00|8.00|0\nLINE|1.00|1.00|8.00|0\nLINE|2.00|1.00|8.00|0\n" +
  "LINE|3.00|1.00|8.00|1\nLINE|4.00|1.00|8.00|0\nLINE|5.00|1.00|8.00|1\n" +
  "BOX|0.00|0.00|3.00|1.00|0|the\nBOX|0.00|1.00|5.00|1.00|0|quick\nBOX|0.00|2.00|5.00|1.00|0|brown\n" +
  "BOX|0.00|3.00|3.00|1.00|0|fox\nBOX|0.00|4.00|5.00|1.00|0|jumps\nBOX|0.00|5.00|4.00|1.00|0|over\n";

const { lines, boxes } = parseRenderCommands(GOLDEN);
eq(lines.length, 6, "6 laid lines parsed");
eq(boxes.length, 6, "6 boxes parsed");
eq(lines[3], { y: 3, h: 1, right: 8, paraEnd: true }, "line 3 is a paragraph end");
eq(boxes[0], { x: 0, y: 0, w: 3, h: 1, style: 0, text: "the" }, "first box is 'the' at (0,0) w=3");
eq(boxes[5], { x: 0, y: 5, w: 4, h: 1, style: 0, text: "over" }, "last box is 'over' at (0,5) w=4");

// specs are 1:1 by default; scale multiplies through.
const specs = renderToSpecs(GOLDEN);
eq(specs.length, 6, "6 specs (one per box)");
eq(specs[0], { left: 0, top: 0, width: 3, height: 1, text: "the", style: 0 }, "spec 0 positions 'the'");
const scaled = renderToSpecs(GOLDEN, { scaleX: 2, scaleY: 10 });
eq(scaled[1], { left: 0, top: 10, width: 10, height: 10, text: "quick", style: 0 }, "scale multiplies geometry, not text");

// edge case: a BOX whose text contains a literal '|' must round-trip (rejoined, not truncated).
const piped = parseRenderCommands("BOX|1.00|2.00|3.00|1.00|0|a|b\n");
eq(piped.boxes[0].text, "a|b", "a '|' inside box text survives (rejoined)");
// a space box (its text is a single space) survives too.
const spaced = parseRenderCommands("BOX|0.00|0.00|1.00|1.00|0| \n");
eq(spaced.boxes[0].text, " ", "a space box keeps its space");

if (fails) { console.error(`dom_sink: ${fails} FAILED`); process.exit(1); }
console.log("dom_sink: OK — render_commands parse + specs (incl. '|'-in-text and space boxes) match the golden");
