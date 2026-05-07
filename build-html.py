#!/usr/bin/env python3
"""
Build blueteam-trainer.html from blueteam-trainer.jsx + styles.css + data/techniques.json.

Three inputs are merged into one self-contained HTML:
  1. The JSX source (UI logic and component code)
  2. The CSS stylesheet (design system)
  3. The techniques data (full Atomic Red Team library + curated overlay)

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
css_path = base / "styles.css"
out_path = base / "blueteam-trainer.html"
data_path = base / "data" / "techniques.json"
vite_copy = base / "vite-project" / "src" / "BlueTeamTrainer.jsx"


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

    # ---------- CSS ----------
    if css_path.exists():
        css_content = css_path.read_text(encoding="utf-8")
        print(f"  ✓ Embedded styles.css ({len(css_content):,} bytes)")
    else:
        css_content = "/* styles.css not found — UI will be unstyled */"
        print(f"  ⚠ {css_path.relative_to(base)} not found — embedding placeholder")

    # ---------- React import ----------
    src = re.sub(
        r'^import\s+(?:React,\s*)?\{[^}]*\}\s+from\s+"react";\s*$',
        "const { useState, useCallback, useRef, useEffect, useMemo } = React;",
        src,
        count=1,
        flags=re.MULTILINE,
    )

    src = src.replace(
        "export default function BlueTeamTrainer()",
        "function BlueTeamTrainer()",
    )

    # ---------- techniques.json ----------
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
    Source: blueteam-trainer.jsx + styles.css + data/techniques.json
    Regenerate with: ./build.sh   (or just ./build-html.sh for UI-only changes)
  -->
  <style>
__STYLES__
  </style>
</head>
<body>
  <div id="boot-screen" class="boot-screen">
    <div class="boot-screen-name">BLUE TEAM TRAINER<span class="boot-cursor"></span></div>
    <div class="boot-screen-status">INITIALISING…</div>
    <div id="boot-error" class="boot-error"></div>
  </div>
  <div id="root"></div>

  <script>
    // Embedded technique library — full Atomic Red Team + curated overlay.
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

    html = template.replace("__STYLES__", css_content)
    html = html.replace("__TECHNIQUES_JSON__", techniques_json)
    html = html.replace("__COMPONENT_BODY__", src)
    out_path.write_text(html, encoding="utf-8")

    size_kb = out_path.stat().st_size / 1024
    print(f"  ✓ Wrote {out_path.name} ({size_kb:,.1f} KB)")

    if vite_copy.exists():
        vite_copy.write_text(jsx_path.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"  ✓ Synced {vite_copy.relative_to(base)}")

    print("")
    print("Done. Commit blueteam-trainer.jsx, styles.css AND blueteam-trainer.html together.")
    print("data/techniques.json is .gitignore'd — regenerate locally via ./build.sh.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
