#!/usr/bin/env python3
"""
Build blueteam-trainer.html from blueteam-trainer.jsx + data/techniques.json.

Two inputs are merged into one self-contained HTML:
  1. The JSX source (UI logic and component code)
  2. The techniques data (full Atomic Red Team library + curated overlay)

The data is embedded as window.__BTT_TECHNIQUES__ so the JSX can read it
without a runtime fetch — keeps the platform fully offline-capable.

Usage:
    python3 build-html.py             # standard build
    python3 build-html.py --no-data   # skip data embedding (for early dev)

Run via the orchestrator instead, normally:
    ./build.sh
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

base = Path(__file__).resolve().parent
jsx_path = base / "blueteam-trainer.jsx"
out_path = base / "blueteam-trainer.html"
data_path = base / "data" / "techniques.json"
vite_copy = base / "vite-project" / "src" / "BlueTeamTrainer.jsx"


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--no-data",
        action="store_true",
        help="Build without embedding techniques.json (for very early dev)",
    )
    args = parser.parse_args()

    if not jsx_path.exists():
        print(f"Error: {jsx_path} not found", file=sys.stderr)
        return 1

    src = jsx_path.read_text(encoding="utf-8")

    # Replace the React import line with a destructuring assignment from
    # window.React. Babel Standalone runs in the browser and React is loaded
    # via the UMD bundle, not as an ES module — so the `import` syntax does
    # not apply here.
    src = re.sub(
        r'^import\s+(?:React,\s*)?\{[^}]*\}\s+from\s+"react";\s*$',
        "const { useState, useCallback, useRef, useEffect, useMemo } = React;",
        src,
        count=1,
        flags=re.MULTILINE,
    )

    # Convert `export default function` to a plain function declaration so we
    # can render it directly with React.createElement at the bottom of the HTML.
    src = src.replace(
        "export default function BlueTeamTrainer()",
        "function BlueTeamTrainer()",
    )

    # Embed techniques.json as window.__BTT_TECHNIQUES__ if available.
    # Falls back to an empty array if --no-data or the file is missing,
    # which lets the UI render an empty-state without crashing.
    if args.no_data:
        techniques_payload = {"_meta": {"merged_total": 0}, "techniques": []}
        print("  ⚠ Skipping data embed (--no-data)")
    elif data_path.exists():
        techniques_payload = json.loads(data_path.read_text(encoding="utf-8"))
        meta = techniques_payload.get("_meta", {})
        print(
            f"  ✓ Embedded {meta.get('merged_total', 0)} techniques "
            f"({meta.get('curated_count', 0)} curated)"
        )
    else:
        techniques_payload = {"_meta": {"merged_total": 0}, "techniques": []}
        print(
            f"  ⚠ {data_path.relative_to(base)} not found — embedding empty data.\n"
            "    Run tools/import-atomics.py + tools/build-techniques.py first."
        )

    # Serialise to a compact JSON literal. We escape `</script>` defensively
    # so the embedded blob can never break out of the surrounding script tag.
    techniques_json = json.dumps(techniques_payload, separators=(",", ":"))
    techniques_json = techniques_json.replace("</", "<\\/")

    template = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Blue Team Trainer</title>
  <!--
    THIS FILE IS GENERATED. Do not edit by hand.
    Source: blueteam-trainer.jsx + data/techniques.json
    Regenerate with: ./build.sh   (or just ./build-html.sh for UI-only changes)
  -->
  <style>
    html, body, #root { margin: 0; padding: 0; height: 100%; width: 100%; background: #0d1117; overflow: hidden; }
    body { font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace; color: #e6edf3; }
    #boot-screen { position: fixed; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px; background: #0d1117; color: #00d97e; font-family: 'JetBrains Mono', monospace; font-size: 13px; letter-spacing: 1.5px; }
    #boot-screen .spinner { width: 36px; height: 36px; border: 2px solid rgba(0, 217, 126, 0.18); border-top-color: #00d97e; border-radius: 50%; animation: spin 0.8s linear infinite; }
    #boot-error { max-width: 640px; padding: 20px 24px; background: rgba(248, 81, 73, 0.08); border: 1px solid rgba(248, 81, 73, 0.4); border-radius: 8px; color: #f85149; font-size: 12px; line-height: 1.6; display: none; text-align: left; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div id="boot-screen">
    <div class="spinner"></div>
    <div>INITIALISING BLUE TEAM TRAINER</div>
    <div id="boot-error"></div>
  </div>
  <div id="root"></div>

  <script>
    // Embedded technique library — all 330+ techniques, ~1700 atomic tests.
    // The JSX reads this via window.__BTT_TECHNIQUES__ so the platform stays
    // fully offline-capable.
    window.__BTT_TECHNIQUES__ = __TECHNIQUES_JSON__;
  </script>

  <script src="vendor/react.production.min.js"></script>
  <script src="vendor/react-dom.production.min.js"></script>
  <script src="vendor/babel.min.js"></script>

  <script>
    window.addEventListener('error', function (ev) {
      var box = document.getElementById('boot-error');
      if (!box) return;
      box.style.display = 'block';
      box.textContent = 'Boot error: ' + (ev.message || ev.error || 'unknown') +
        '\\n\\nMake sure the ./vendor/ folder is alongside this HTML file ' +
        'and contains react.production.min.js, react-dom.production.min.js, and babel.min.js.';
    });
  </script>

  <script type="text/babel" data-type="module" data-presets="env,react">
__COMPONENT_BODY__

    const rootEl = document.getElementById('root');
    const bootEl = document.getElementById('boot-screen');
    if (bootEl) bootEl.remove();
    const root = ReactDOM.createRoot(rootEl);
    root.render(React.createElement(BlueTeamTrainer));
  </script>
</body>
</html>
"""

    html = template.replace("__TECHNIQUES_JSON__", techniques_json)
    html = html.replace("__COMPONENT_BODY__", src)
    out_path.write_text(html, encoding="utf-8")

    size_kb = out_path.stat().st_size / 1024
    print(f"  ✓ Wrote {out_path.name} ({size_kb:,.1f} KB)")

    # Sync the Vite project copy too, so contributors who edit the top-level
    # JSX do not end up with a stale Vite copy.
    if vite_copy.exists():
        vite_copy.write_text(jsx_path.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"  ✓ Synced {vite_copy.relative_to(base)}")

    print("")
    print("Done. Commit blueteam-trainer.jsx AND blueteam-trainer.html together.")
    print("data/techniques.json is .gitignore'd — regenerate locally via ./build.sh.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
