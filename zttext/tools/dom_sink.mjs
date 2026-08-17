// SPDX-License-Identifier: LGPL-3.0-or-later
//
// The reference DOM RenderSink for lib/zttext — the browser backend of the engine port
// R : 𝔅 → target. It turns the engine's paint commands (render_commands: LINE|/BOX| lines) into
// positioned DOM. loft owns EVERY coordinate (§8.22) — this only positions boxes it is handed, and
// measures nothing and lays out nothing, which is exactly what makes screen == PDF == native. The
// engine's box set is byte-identical across interpret/native/native-wasm/browser (loft test +
// parity.sh), so painting it is the only browser-specific step, and it is this ~30 lines.
//
// The parse + spec half is headless-testable (dom_sink_test.mjs); `mount` is the thin browser glue.

// render_commands text -> { lines:[{y,h,right,paraEnd}], boxes:[{x,y,w,h,style,text}] }
export function parseRenderCommands(text) {
  const lines = [], boxes = [];
  for (const raw of text.split('\n')) {
    if (!raw) continue;
    const f = raw.split('|');
    if (f[0] === 'LINE') {
      lines.push({ y: +f[1], h: +f[2], right: +f[3], paraEnd: f[4] === '1' });
    } else if (f[0] === 'BOX') {
      // BOX|x|y|w|h|style|text — text is LAST and may contain '|' (e.g. a literal pipe), so rejoin.
      boxes.push({ x: +f[1], y: +f[2], w: +f[3], h: +f[4], style: +f[5], text: f.slice(6).join('|') });
    }
    // unknown verbs (a future SCALE|/IMAGE|) are ignored, so an older sink survives a newer engine
  }
  return { lines, boxes };
}

// The absolutely-positioned box specs (data — no DOM, so this is what the headless test asserts).
// scale is 1:1 by default (a pixel IS an engine coordinate, D2), overridable for HiDPI/zoom.
export function renderToSpecs(commands, { scaleX = 1, scaleY = 1 } = {}) {
  return parseRenderCommands(commands).boxes.map(b => ({
    left: b.x * scaleX, top: b.y * scaleY, width: b.w * scaleX, height: b.h * scaleY,
    text: b.text, style: b.style,
  }));
}

// Mount into a container (browser): one absolutely-positioned <span> per glyph-box. The host owns
// only the font-face + colours; the geometry is the engine's. Returns the container.
export function mount(container, commands, opts = {}) {
  container.style.position = 'relative';
  container.replaceChildren();
  for (const s of renderToSpecs(commands, opts)) {
    const el = document.createElement('span');
    el.textContent = s.text;
    el.style.cssText =
      `position:absolute;left:${s.left}px;top:${s.top}px;width:${s.width}px;` +
      `height:${s.height}px;white-space:pre;`;
    if (s.style) el.dataset.style = String(s.style);
    container.appendChild(el);
  }
  return container;
}
