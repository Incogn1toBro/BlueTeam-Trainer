#!/usr/bin/env python3
"""
build-techniques.py — merge upstream Atomic Red Team data with the
hand-curated overlay to produce the final techniques.json the JSX consumes.

Input:
    data/atomics-generated.json  (from import-atomics.py — auto-overwritten)
    data/curation.json           (hand-maintained — never auto-overwritten)

Output:
    data/techniques.json         (consumed by the JSX/HTML at build time)

The merge is non-destructive:
    - For curated techniques (currently 19), curation.json wins on tactic
      and provides huntPack content.
    - For non-curated techniques, the upstream tactic from MITRE STIX is used
      and huntPack is empty (UI shows "no curated hunt pack yet").
    - Atomic test data (names, descriptions, platforms, connectivity) always
      comes from upstream — curation.json never overrides it.

Usage:
    python tools/build-techniques.py
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("build-techniques")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--generated", default="data/atomics-generated.json")
    parser.add_argument("--curation", default="data/curation.json")
    parser.add_argument("--output", default="data/techniques.json")
    args = parser.parse_args()

    gen_path = Path(args.generated).resolve()
    cur_path = Path(args.curation).resolve()
    out_path = Path(args.output).resolve()

    if not gen_path.exists():
        log.error("Missing %s — run tools/import-atomics.py first", gen_path)
        return 1

    generated = json.loads(gen_path.read_text())
    curation = (
        json.loads(cur_path.read_text())
        if cur_path.exists()
        else {"techniques": {}}
    )

    cur_techniques = curation.get("techniques", {})
    aliases = curation.get("_aliases", {})  # {curated_id: actual_upstream_id}

    # Apply aliases so curation entries follow techniques that MITRE has
    # renumbered. Example: "T1070.001": "T1070" if the subtechnique was
    # rolled back into the parent.
    if aliases:
        for old_id, new_id in aliases.items():
            if old_id in cur_techniques and new_id not in cur_techniques:
                cur_techniques[new_id] = cur_techniques.pop(old_id)
                log.info("Aliased curation %s → %s", old_id, new_id)

    log.info("Loaded %d upstream techniques and %d curated overlays",
             len(generated["techniques"]), len(cur_techniques))

    merged: list[dict] = []
    curated_count = 0
    for t in generated["techniques"]:
        tid = t["id"]
        cur = cur_techniques.get(tid)

        # Tactic: prefer curation, fall back to generated
        if cur and "tactic" in cur:
            tactic = cur["tactic"]
        else:
            tactic = t.get("tactic", "TA0002")

        # Hunt pack: only present if curated
        hunt_pack = cur.get("huntPack") if cur else None

        merged_entry = {
            "id": tid,
            "name": t["name"],
            "tactic": tactic,
            "tactics": t.get("tactics", []),
            "atomicTests": t["atomicTests"],
            "curated": bool(cur),
        }
        if hunt_pack:
            merged_entry["huntPack"] = hunt_pack
            curated_count += 1
        merged.append(merged_entry)

    # Sort: curated techniques first (so they're easy to find in the UI),
    # then by ID. The UI can re-sort as it likes.
    merged.sort(key=lambda t: (not t["curated"], t["id"]))

    # Audit: warn about curation entries that don't match an upstream technique
    upstream_ids = {t["id"] for t in generated["techniques"]}
    orphan_curations = sorted(set(cur_techniques.keys()) - upstream_ids)
    if orphan_curations:
        log.warning("Curation entries with no upstream match: %s",
                    ", ".join(orphan_curations))

    out: dict = {
        "_meta": {
            **generated.get("_meta", {}),
            "curated_count": curated_count,
            "merged_total": len(merged),
        },
        "techniques": merged,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))

    log.info("✓ Wrote %s", out_path)
    log.info("  %d techniques total (%d curated with hunt packs, %d list-only)",
             len(merged), curated_count, len(merged) - curated_count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
