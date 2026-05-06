#!/usr/bin/env python3
"""
import-atomics.py — pull every Atomic Red Team test from upstream and
generate a clean JSON snapshot for the Blue Team Trainer to consume.

Usage:
    python tools/import-atomics.py [--no-pull] [--cache-dir .cache]

What it does:
    1. Clones (or pulls) redcanaryco/atomic-red-team into .cache/
    2. Fetches the current MITRE ATT&CK Enterprise STIX bundle for the
       technique to tactic mapping
    3. Walks every T*/T*.yaml under atomics/ and extracts test data
    4. Runs heuristics for connectivity (offline / staged / online)
    5. Writes data/atomics-generated.json

What it does NOT do:
    - Touch your data/curation.json (your hand-curated overlay)
    - Modify the JSX directly — that's build-techniques.py's job
    - Make any guesses about hunt packs

Re-running is safe and idempotent. The output JSON is fully replaced each
time with whatever the upstream currently says.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any, Optional

# Optional dependency. We fall back to a hand-rolled YAML reader if
# pyyaml isn't available — keeps the contributor experience zero-install
# for read-only metadata.
try:
    import yaml  # type: ignore
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

ATOMIC_REPO = "https://github.com/redcanaryco/atomic-red-team.git"
MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("import-atomics")


# ---------------------------------------------------------------------------
# Tactic mapping — fetched at runtime from MITRE
# ---------------------------------------------------------------------------

# Stable tactic ID → human display name. MITRE has 14 tactics on the
# Enterprise matrix and they don't change often, so this is safe to hardcode.
TACTIC_NAMES: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# MITRE uses string tactic shortnames in STIX; map them to TA-codes.
TACTIC_SHORTNAME_TO_ID: dict[str, str] = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


def fetch_mitre_tactic_map() -> dict[str, list[str]]:
    """Return {technique_id: [tactic_id, ...]} from MITRE's STIX bundle.

    The same technique can belong to multiple tactics (Process Injection
    is both Defense Evasion and Privilege Escalation, etc.) so values are
    lists. Falls back to a small hardcoded map if the network call fails.
    """
    log.info("Fetching MITRE ATT&CK technique → tactic mapping...")
    try:
        with urllib.request.urlopen(MITRE_STIX_URL, timeout=30) as response:
            stix = json.loads(response.read())
    except Exception as e:
        log.warning("  Could not reach MITRE STIX (%s); using minimal fallback map", e)
        return _fallback_tactic_map()

    mapping: dict[str, list[str]] = {}
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        # Find the T-id from external_references
        tid: Optional[str] = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
                break
        if not tid or not tid.startswith("T"):
            continue

        # kill_chain_phases gives us the tactic shortnames
        tactic_ids: list[str] = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            shortname = phase.get("phase_name", "")
            tid_tactic = TACTIC_SHORTNAME_TO_ID.get(shortname)
            if tid_tactic and tid_tactic not in tactic_ids:
                tactic_ids.append(tid_tactic)

        if tactic_ids:
            mapping[tid] = tactic_ids

    log.info("  Loaded %d technique → tactic mappings", len(mapping))
    return mapping


def _fallback_tactic_map() -> dict[str, list[str]]:
    """Tiny last-resort tactic map for the techniques that ship with the
    curated hunt packs, so the script works fully offline if needed."""
    return {
        "T1566.001": ["TA0001"],
        "T1059.001": ["TA0002"],
        "T1059.003": ["TA0002"],
        "T1547.001": ["TA0003", "TA0004"],
        "T1053.005": ["TA0002", "TA0003", "TA0004"],
        "T1543.003": ["TA0003", "TA0004"],
        "T1548.002": ["TA0004", "TA0005"],
        "T1070.001": ["TA0005"],
        "T1055.001": ["TA0004", "TA0005"],
        "T1003.001": ["TA0006"],
        "T1558.003": ["TA0006"],
        "T1082": ["TA0007"],
        "T1016": ["TA0007"],
        "T1069.002": ["TA0007"],
        "T1021.001": ["TA0008"],
        "T1021.002": ["TA0008"],
        "T1071.001": ["TA0011"],
        "T1048.003": ["TA0010"],
        "T1486": ["TA0040"],
    }


# ---------------------------------------------------------------------------
# YAML loading — handles missing pyyaml
# ---------------------------------------------------------------------------


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file. Falls back to a minimal parser if pyyaml is missing."""
    text = path.read_text(encoding="utf-8")
    if HAVE_YAML:
        try:
            return yaml.safe_load(text) or {}
        except yaml.YAMLError as e:
            log.warning("  YAML parse error in %s: %s", path.name, e)
            return {}
    return _minimal_yaml_parse(text)


def _minimal_yaml_parse(text: str) -> dict[str, Any]:
    """Bare-minimum YAML reader for the fields we need. Intentionally
    limited — covers the fields atomic-red-team uses, not the full spec.

    Used only when pyyaml isn't installed. Strongly recommended to install
    pyyaml: `pip install pyyaml`.
    """
    log.warning("  Using minimal YAML reader (install pyyaml for full support)")
    out: dict[str, Any] = {"atomic_tests": []}
    current_test: dict[str, Any] = {}
    in_tests = False
    in_description = False
    description_lines: list[str] = []
    description_indent = 0

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        if line.startswith("attack_technique:"):
            out["attack_technique"] = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("display_name:"):
            out["display_name"] = line.split(":", 1)[1].strip().strip("'\"")
        elif line.startswith("atomic_tests:"):
            in_tests = True
        elif in_tests and line.lstrip().startswith("- name:"):
            if current_test:
                if in_description:
                    current_test["description"] = "\n".join(description_lines).strip()
                out["atomic_tests"].append(current_test)
            current_test = {"name": line.split("name:", 1)[1].strip().strip("'\"")}
            in_description = False
            description_lines = []
        elif in_tests and current_test:
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            if in_description:
                if indent <= description_indent:
                    current_test["description"] = "\n".join(description_lines).strip()
                    in_description = False
                    description_lines = []
                else:
                    description_lines.append(stripped)
                    continue
            if stripped.startswith("description:"):
                rest = stripped.split(":", 1)[1].strip()
                if rest in ("|", ">"):
                    in_description = True
                    description_indent = indent
                    description_lines = []
                else:
                    current_test["description"] = rest.strip("'\"")
            elif stripped.startswith("- windows") or stripped.startswith("- macos") or stripped.startswith("- linux") or stripped.startswith("- containers"):
                current_test.setdefault("supported_platforms", []).append(stripped[2:].strip())
            elif stripped.startswith("auto_generated_guid:"):
                current_test["auto_generated_guid"] = stripped.split(":", 1)[1].strip()

    if current_test:
        if in_description:
            current_test["description"] = "\n".join(description_lines).strip()
        out["atomic_tests"].append(current_test)
    return out


# ---------------------------------------------------------------------------
# Connectivity heuristics
# ---------------------------------------------------------------------------

# Patterns that suggest the test makes a runtime network call.
# Conservative — false positives cost users an unnecessary "online" badge,
# but false negatives mean the test silently fails on isolated victims.
NETWORK_PATTERNS = [
    r"Invoke-WebRequest",
    r"\biwr\b",
    r"DownloadString",
    r"DownloadFile",
    r"WebClient",
    r"curl\s",
    r"\bwget\b",
    r"BitsTransfer",
    r"Start-BitsTransfer",
    r"http[s]?://(?!localhost|127\.|\$|#\{)",
]

# Some tests download once via a get_prereq_command then run offline.
# We detect that pattern so we can label them "staged" rather than "online".
PREREQ_PATTERNS = [
    r"get_prereq_command",
    r"Invoke-AtomicTest.*-GetPrereqs",
]


def classify_connectivity(test: dict[str, Any]) -> tuple[bool, bool]:
    """Return (offline_capable, prereq_stage) flags for a single test.

    offline_capable=True: works on a network-isolated victim
    prereq_stage=True:    needs internet at first, then runs offline after
                          payloads are staged
    """
    # Concatenate every executor command + cleanup + dependency for analysis
    parts: list[str] = []
    executor = test.get("executor") or {}
    if isinstance(executor, dict):
        parts.append(executor.get("command", "") or "")
        parts.append(executor.get("cleanup_command", "") or "")
    for dep in test.get("dependencies", []) or []:
        if isinstance(dep, dict):
            parts.append(dep.get("get_prereq_command", "") or "")
            parts.append(dep.get("prereq_command", "") or "")
    blob = "\n".join(parts)

    runtime_network = any(re.search(p, blob, flags=re.IGNORECASE) for p in NETWORK_PATTERNS)
    has_prereqs = bool(test.get("dependencies")) or any(
        re.search(p, blob, flags=re.IGNORECASE) for p in PREREQ_PATTERNS
    )

    # If the only network calls are inside dependencies/get_prereq_command,
    # the test itself can run offline once payloads are staged.
    executor_command = ""
    if isinstance(executor, dict):
        executor_command = executor.get("command", "") or ""
    executor_has_network = any(re.search(p, executor_command, flags=re.IGNORECASE) for p in NETWORK_PATTERNS)

    if executor_has_network:
        # The test itself reaches out at runtime
        return (False, False)
    if has_prereqs and runtime_network:
        # Network only in prereqs — staged
        return (False, True)
    # Default: assume offline-capable
    return (True, False)


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------


def ensure_repo(cache_dir: Path, no_pull: bool = False) -> Path:
    """Clone or update atomic-red-team. Returns the atomics/ folder path."""
    repo_dir = cache_dir / "atomic-red-team"
    if repo_dir.exists():
        if no_pull:
            log.info("Using existing checkout at %s (--no-pull)", repo_dir)
        else:
            log.info("Updating atomic-red-team checkout...")
            subprocess.run(
                ["git", "-C", str(repo_dir), "pull", "--quiet"],
                check=False,
            )
    else:
        log.info("Cloning atomic-red-team into %s ...", repo_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", ATOMIC_REPO, str(repo_dir)],
            check=True,
        )
    atomics_dir = repo_dir / "atomics"
    if not atomics_dir.exists():
        log.error("Expected atomics/ folder at %s", atomics_dir)
        sys.exit(1)
    return atomics_dir


def parse_technique(yaml_path: Path, tactic_map: dict[str, list[str]]) -> Optional[dict[str, Any]]:
    """Parse one T-id YAML into our normalised structure."""
    data = load_yaml(yaml_path)
    technique_id = data.get("attack_technique")
    name = data.get("display_name")
    tests = data.get("atomic_tests", [])
    if not technique_id or not tests:
        return None

    # Use the upstream display_name verbatim. Earlier versions stripped
    # everything before the first colon to remove "Phishing: ..." style
    # prefixes, but that destroys legitimate names like "Scheduled Task/Job:
    # At" or "OS Credential Dumping: LSASS Memory". Treating the field as
    # canonical keeps us aligned with whatever Atomic Red Team and MITRE
    # publish.
    name = (name or technique_id).strip()

    parsed_tests: list[dict[str, Any]] = []
    for i, test in enumerate(tests, start=1):
        if not isinstance(test, dict):
            continue
        offline, staged = classify_connectivity(test)
        platforms = test.get("supported_platforms") or []
        # Normalise platform names
        platforms = [p.strip().lower() for p in platforms if isinstance(p, str)]
        parsed_tests.append({
            "id": f"{technique_id}-{i}",
            "name": (test.get("name") or f"Test {i}").strip(),
            "description": _clean_description(test.get("description") or ""),
            "supportedPlatforms": platforms,
            "offlineCapable": offline,
            "prereqStage": staged,
            "hasPrereqs": bool(test.get("dependencies")),
        })

    if not parsed_tests:
        return None

    tactics = tactic_map.get(technique_id, [])
    primary_tactic = tactics[0] if tactics else "TA0002"  # fall back to Execution

    return {
        "id": technique_id,
        "name": name,
        "tactic": primary_tactic,
        "tactics": tactics,
        "atomicTests": parsed_tests,
    }


def _clean_description(text: str) -> str:
    """Trim and collapse a multi-line description to a single paragraph."""
    lines = [line.strip() for line in text.splitlines()]
    return " ".join(line for line in lines if line)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--cache-dir", default=".cache",
        help="Where to clone atomic-red-team (default: .cache/)",
    )
    parser.add_argument(
        "--output", default="data/atomics-generated.json",
        help="Path to write generated JSON (default: data/atomics-generated.json)",
    )
    parser.add_argument(
        "--no-pull", action="store_true",
        help="Skip git pull on existing checkout (useful for offline runs)",
    )
    args = parser.parse_args()

    cache_dir = Path(args.cache_dir).resolve()
    output_path = Path(args.output).resolve()

    atomics_dir = ensure_repo(cache_dir, no_pull=args.no_pull)
    tactic_map = fetch_mitre_tactic_map()

    log.info("Walking atomics folder at %s ...", atomics_dir)
    technique_dirs = sorted(d for d in atomics_dir.iterdir() if d.is_dir() and d.name.startswith("T"))
    log.info("  Found %d technique folders", len(technique_dirs))

    techniques: list[dict[str, Any]] = []
    skipped: list[tuple[str, str]] = []
    for d in technique_dirs:
        yaml_files = list(d.glob("T*.yaml"))
        if not yaml_files:
            skipped.append((d.name, "no T*.yaml"))
            continue
        if len(yaml_files) > 1:
            log.warning("  %s has multiple YAMLs; using %s", d.name, yaml_files[0].name)
        result = parse_technique(yaml_files[0], tactic_map)
        if not result:
            skipped.append((d.name, "no atomic_tests or missing fields"))
            continue
        techniques.append(result)

    techniques.sort(key=lambda t: t["id"])
    total_tests = sum(len(t["atomicTests"]) for t in techniques)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({
        "_meta": {
            "source": "redcanaryco/atomic-red-team",
            "tactic_source": "mitre/cti enterprise-attack",
            "tactics": TACTIC_NAMES,
            "technique_count": len(techniques),
            "test_count": total_tests,
        },
        "techniques": techniques,
    }, indent=2, sort_keys=False))

    log.info("")
    log.info("✓ Wrote %s", output_path)
    log.info("  %d techniques, %d tests", len(techniques), total_tests)
    if skipped:
        log.info("  Skipped %d folders (%s)", len(skipped), ", ".join(f"{n}: {r}" for n, r in skipped[:3]))
        if len(skipped) > 3:
            log.info("    ...and %d more", len(skipped) - 3)
    return 0


if __name__ == "__main__":
    sys.exit(main())
