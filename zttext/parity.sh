#!/usr/bin/env bash
# The --html leg of the zttext parity gate — the DOM RenderSink's cross-target proof. Lay out a
# fixed document and emit the sink's paint commands (render_commands) on NATIVE and in the BROWSER
# wasm, and require them byte-identical. loft test already proves interpret == native == native-wasm
# for the box set; this adds the browser (--html) target the DOM sink unlocks.
#
#   ./parity.sh [--rebuild]      # --rebuild recompiles the --html artifact (~minutes)
#
# Uses tools/parity_check.mjs (drives the wasm directly, one instance + a fresh instance per pump).
# The layout is stateless, so the split run is trivially identical.
set -euo pipefail
cd "$(dirname "$0")"
W="${TMPDIR:-/tmp}/zttext-parity"; mkdir -p "$W"
printf 'render\n' > "$W/trigger.txt"

# 1. native: the sink's commands to stderr.
#
# ⚠ FILTER stderr to the sink protocol.  `host_output` shares stderr with the compiler's
# diagnostics, so an unfiltered capture counts every `advice[...]` line as a paint command and
# the comparison below comes out red for a reason that has nothing to do with the engine: on
# the loft this migrated against, 62 lines of `advice[avoidable-copy]` turned 98 real commands
# into "160 paint commands" and the gate reported FAIL against a browser that had emitted the
# correct 98.  The browser side never sees those lines — the JS host receives only what the
# sink writes — so the two sides were never comparable without this.
loft src/main.loft < "$W/trigger.txt" 2> "$W/native.raw"
grep -E '^(LINE\||BOX\|)' "$W/native.raw" > "$W/native.txt" || true
echo "native: $(wc -l < "$W/native.txt") paint commands"
if [ ! -s "$W/native.txt" ]; then
  echo "FAIL — the native run emitted no paint commands at all; the harness would compare nothing" >&2
  sed -n '1,20p' "$W/native.raw" >&2
  exit 1
fi

# 2. browser: build once unless asked to rebuild
if [ "${1:-}" = "--rebuild" ] || [ ! -f src/.loft/main.html ]; then
  echo "building --html (minutes) …"
  LOFT_TIMEOUT=900 loft --html src/main.loft >/dev/null 2>&1
fi

# 3. compare native vs browser, byte-for-byte
node tools/parity_check.mjs src/.loft/main.html "$W/trigger.txt" "$W/native.txt"
