#!/usr/bin/env node
// F13 parity + F14/F15 pump gate — the SAME plugin, the SAME frames, three ways.
//
//   native            loft src/main.loft < frames        (the reference)
//   browser, whole    one wasm instance, all frames       -> F13
//   browser, split    a FRESH instance per chunk          -> F14/F15
//
// The split run is the platform axis made concrete. The platform may background, throttle or
// DISCARD the page between any two pumps, so the browser may hand the next batch to an instance
// that has no memory of the last one. If the plugin carried anything across frames, the split run
// would diverge — and it would diverge quietly, because both runs return plausible frames.
//
// The frames are CHAINED (each apply_op carries the state the previous step produced), which is
// what makes splitting meaningful: with independent frames the split test would pass trivially.
//
// This drives the wasm DIRECTLY (the tools/wasm_debug_client.mjs pattern) rather than through a
// browser: the host boundary is the same fixed `loft_io` import set either way, and the plugin
// touches no DOM — it is pure compute over a byte channel, which is the design.
//
// Usage: node parity_check.mjs <main.html> <frames.txt> <native-replies.txt>
import fs from 'node:fs';

const [htmlPath, framesPath, nativePath] = process.argv.slice(2);
if (!htmlPath || !framesPath || !nativePath) {
  console.error('usage: parity_check.mjs <main.html> <frames.txt> <native-replies.txt>');
  process.exit(2);
}

const html = fs.readFileSync(htmlPath, 'latin1');
const b64 = html.match(/[A-Za-z0-9+/]{500,}={0,2}/);
if (!b64) { console.error('no embedded wasm found in ' + htmlPath); process.exit(2); }
const wasmBytes = Buffer.from(b64[0], 'base64');
const module = new WebAssembly.Module(wasmBytes);

const enc = new TextEncoder(), dec = new TextDecoder();
const frames = fs.readFileSync(framesPath, 'utf8').split('\n').filter(s => s.length > 0);

// Run one batch in a FRESH instance and return its replies. host_input() pops all pending input as
// one text on native (stdin to EOF), so a batch is seeded as one newline-joined message — feeding
// frames one-per-pop would be a different input shape and not a parity test.
function pump(batch) {
  const inQ = [enc.encode(batch.join('\n'))];
  const outputs = [];
  let mem = null;
  const io = {
    loft_host_print: (p, l) => { process.stderr.write(dec.decode(new Uint8Array(mem.buffer, p, l))); },
    loft_host_input_len: () => (inQ.length ? inQ[0].length : 0),
    loft_host_input_copy: (p) => { const b = inQ.shift(); if (b) new Uint8Array(mem.buffer, p, b.length).set(b); },
    loft_host_output: (p, l) => { outputs.push(dec.decode(new Uint8Array(mem.buffer, p, l))); },
    loft_host_time_now_ms: () => Date.now(),
    loft_host_time_ticks_us: () => Math.trunc(performance.now() * 1000),
  };
  // an import this build declares but never calls resolves to a no-op, so a newly-added one cannot
  // LinkError a harness that does not exercise it
  const stubs = new Proxy({ loft_io: new Proxy(io, { get: (t, k) => (k in t ? t[k] : () => 0) }) },
                          { get: (t, k) => (k in t ? t[k] : new Proxy({}, { get: () => () => 0 })) });
  const inst = new WebAssembly.Instance(module, stubs);
  mem = inst.exports.memory;
  inst.exports.loft_start();
  return outputs;
}

function chunk(xs, n) {
  const out = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
}

function report(label, got, want) {
  if (got === want) return true;
  console.error(`FAIL — ${label} disagrees with the native run\n`);
  const b = got.split('\n'), n = want.split('\n');
  console.error(`  native  replies: ${n.length}`);
  console.error(`  ${label} replies: ${b.length}`);
  for (let i = 0; i < Math.max(b.length, n.length); i++) {
    if (b[i] !== n[i]) console.error(`  frame ${i + 1}:\n    native : ${n[i] ?? '(none)'}\n    got    : ${b[i] ?? '(none)'}`);
  }
  return false;
}

const native = fs.readFileSync(nativePath, 'utf8').trim();
let ok = true;

ok = report('browser (one instance)', pump(frames).join('\n').trim(), native) && ok;

// F14/F15: a fresh instance per chunk — the page was discarded between pumps
for (const size of [1, 3]) {
  const replies = chunk(frames, size).flatMap(pump).join('\n').trim();
  ok = report(`browser (fresh instance per ${size}-frame pump)`, replies, native) && ok;
}

if (!ok) process.exit(1);
console.log(`F13 PASS — ${frames.length} frames, byte-identical on native and browser`);
console.log(`F14/F15 PASS — identical again with a FRESH instance per pump (1- and 3-frame chunks):`);
console.log(`              the plugin carries nothing across pumps, so a discarded page is a`);
console.log(`              scheduling event, not a correctness one`);
