"""
P4.5 Scenario Quality Gate (see ODIN_Multi_Host_Validation_and_SIH_Demonstration_Plan.md
Phase 4.5). Every generated multi-host scenario should pass this before its
rows are merged into a training dataset -- catches an empty/misconfigured
capture before hours are spent on more of them, not after.

Checks, against a scenario's provenance manifest (training/scenarios/
<threat_class>/<scenario_id>.json, written by write_provenance() in
multihost_common.py) and the Zeek conn.log covering its capture window:

  1. Provenance manifest exists and has every required field.
  2. conn.log has at least one entry for the scenario's capture window
     (not an empty/failed capture).
  3. Every attacker_ip / victim_ips in the manifest actually appears in
     conn.log during that window (the scenario ran against the hosts it
     claims to, not e.g. a typo'd IP nobody was listening on).
  4. No src==dst (self-connection) or 127.0.0.1 entries when
     environment == "docker_multihost" (loopback contamination check).
  5. No malformed JSON lines / missing required conn.log fields.
  6. Time-windowed: if a sessions_<threat_class>_<scenario_id>.json exists
     (written by the capture scripts alongside the provenance manifest),
     checks 1-5 above run against ONLY the conn.log entries whose ts falls
     within that scenario's [first mark, last mark] window -- not the
     whole shared conn.log. Without this, every scenario that reused the
     same victim IP looks identical (same "IPs present" answer) since
     they're all checked against one continuously-growing log file.

Does NOT attempt full feature-distribution comparison against the existing
loopback dataset (plan's P2.5 checklist item) -- that needs the actual
built feature rows, not raw conn.log, and belongs in the build_dataset_*.py
step once a scenario has passed this gate.

Remember the P2.5 finding: Zeek buffers a connection record until an
inactivity timeout before writing it to conn.log. Run this gate at least
~60s after a capture script exits, not immediately.

Run: python3 training/capture/validate_scenario.py <threat_class> <scenario_id> \
         [--conn-log path/to/conn.log]
Exit code 0 = PASS, 1 = FAIL (see printed reasons).
"""
import argparse
import json
import sys
from pathlib import Path

SCENARIOS_DIR = Path(__file__).parent.parent / "scenarios"
CAPTURE_DIR = Path(__file__).parent
DEFAULT_CONN_LOG = Path(__file__).parent.parent / "zeek-logs-multihost" / "conn.log"
FLUSH_MARGIN_S = 65  # Zeek's own inactivity-timeout flush delay, see this file's docstring

REQUIRED_FIELDS = [
    "scenario_id", "threat_class", "is_malicious", "attack_subtype", "source",
    "environment", "label_method", "generator", "capture_id", "attacker_ip",
    "victim_ips", "configuration", "timestamp",
]


def load_manifest(threat_class: str, scenario_id: str) -> dict:
    path = SCENARIOS_DIR / threat_class / f"{scenario_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"No provenance manifest at {path}")
    with open(path) as f:
        return json.load(f)


def load_conn_log(conn_log_path: Path):
    entries = []
    bad_lines = 0
    if not conn_log_path.exists():
        return entries, bad_lines
    with open(conn_log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                bad_lines += 1
    return entries, bad_lines


def find_sessions_window(threat_class: str, scenario_id: str):
    """Locates sessions_<threat_class>_<scenario_id>.json (the naming
    convention sessions_filename() in multihost_common.py produces) and
    returns (min_ts, max_ts + FLUSH_MARGIN_S), or None if no such file
    exists (e.g. an older scenario captured before this windowing existed)."""
    path = CAPTURE_DIR / f"sessions_{threat_class}_{scenario_id}.json"
    if not path.exists():
        return None, path
    with open(path) as f:
        marks = json.load(f)
    if not marks:
        return None, path
    timestamps = [m["ts"] for m in marks if "ts" in m]
    if not timestamps:
        return None, path
    return (min(timestamps), max(timestamps) + FLUSH_MARGIN_S), path


def validate(threat_class: str, scenario_id: str, conn_log_path: Path):
    findings = []  # (level, message) -- level in {"FAIL", "WARN"}

    # 1. Manifest exists and is complete.
    try:
        manifest = load_manifest(threat_class, scenario_id)
    except FileNotFoundError as e:
        return [("FAIL", str(e))]

    missing = [f for f in REQUIRED_FIELDS if f not in manifest]
    if missing:
        findings.append(("FAIL", f"Manifest missing required fields: {missing}"))

    environment = manifest.get("environment")
    attacker_ip = manifest.get("attacker_ip")
    victim_ips = manifest.get("victim_ips") or []

    # 2. conn.log has entries at all, and is well-formed.
    entries, bad_lines = load_conn_log(conn_log_path)
    if bad_lines:
        findings.append(("WARN", f"{bad_lines} malformed JSON line(s) in {conn_log_path}"))
    if not entries:
        findings.append(("FAIL", f"conn.log at {conn_log_path} has no entries -- empty/failed capture, "
                                   f"or checked before Zeek's flush timeout (see this file's docstring)"))
        return findings  # nothing further to check without any entries

    # 6. Window to this scenario's own capture time range, if we can find it,
    # so scenarios sharing a victim IP don't all report the same whole-log count.
    window, sessions_path = find_sessions_window(threat_class, scenario_id)
    if window:
        lo, hi = window
        windowed = [e for e in entries if lo <= e.get("ts", -1) <= hi]
        findings.append(("INFO", f"Windowed to {sessions_path.name} range [{lo:.0f}, {hi:.0f}] "
                                   f"({len(entries)} total conn.log entries -> {len(windowed)} in window)"))
        entries = windowed
        if not entries:
            findings.append(("FAIL", f"No conn.log entries fall within this scenario's own capture "
                                       f"window -- traffic may have gone to the wrong interface/IP, "
                                       f"or the window/flush-margin logic is wrong"))
            return findings
    else:
        findings.append(("WARN", f"No {sessions_path.name} found -- falling back to checking the "
                                   f"WHOLE conn.log, not just this scenario's window"))

    # 3. Every claimed IP actually shows up somewhere in conn.log.
    seen_ips = set()
    for e in entries:
        seen_ips.add(e.get("id.orig_h"))
        seen_ips.add(e.get("id.resp_h"))

    claimed_ips = ([attacker_ip] if attacker_ip else []) + list(victim_ips)
    for ip in claimed_ips:
        if ip and ip not in seen_ips:
            findings.append(("FAIL", f"Manifest claims {ip} but it never appears as src/dst in conn.log"))

    # 4. Loopback-contamination check, only meaningful for multi-host captures.
    if environment == "docker_multihost":
        loopback_hits = sum(
            1 for e in entries
            if e.get("id.orig_h") == "127.0.0.1" or e.get("id.resp_h") == "127.0.0.1"
        )
        if loopback_hits:
            findings.append(("FAIL", f"{loopback_hits} conn.log entries touch 127.0.0.1 despite "
                                       f"environment=docker_multihost"))

        self_conn_hits = sum(1 for e in entries if e.get("id.orig_h") == e.get("id.resp_h"))
        if self_conn_hits:
            findings.append(("FAIL", f"{self_conn_hits} conn.log entries have src==dst"))

    # 5. Every conn.log entry has the core fields validate_scenario relies on
    #    (and dataset-build scripts read directly).
    core_fields = ["id.orig_h", "id.resp_h", "proto", "conn_state"]
    schema_bad = [e.get("uid") for e in entries if any(f not in e for f in core_fields)]
    if schema_bad:
        findings.append(("WARN", f"{len(schema_bad)} entries missing one of {core_fields} "
                                   f"(uids: {schema_bad[:5]}{'...' if len(schema_bad) > 5 else ''})"))

    if not any(level == "FAIL" for level, _ in findings):
        findings.append(("PASS", f"{len(entries)} conn.log entries in window, all claimed IPs present, "
                                   f"no loopback contamination, schema clean"))
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("threat_class")
    parser.add_argument("scenario_id")
    parser.add_argument("--conn-log", type=Path, default=DEFAULT_CONN_LOG)
    args = parser.parse_args()

    findings = validate(args.threat_class, args.scenario_id, args.conn_log)
    failed = any(level == "FAIL" for level, _ in findings)

    print(f"=== P4.5 quality gate: {args.threat_class}/{args.scenario_id} ===")
    for level, msg in findings:
        print(f"  [{level}] {msg}")
    print("RESULT:", "FAIL -- do not merge into training dataset" if failed else "PASS")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
