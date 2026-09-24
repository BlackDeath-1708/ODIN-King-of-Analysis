"""
Shared CLI/provenance plumbing for the P4 multi-host parameterization of
capture_ddos.py / capture_recon.py / capture_c2.py / capture_ddos_udp_spoof.py
/ capture_exfil.py (see ODIN_Multi_Host_Validation_and_SIH_Demonstration_Plan.md
Phase 4 / Phase 4.5 / Phase 9).

Kept as one small shared module instead of duplicating the same argparse
block five times (DRY) -- each capture script imports add_multihost_args()
and write_provenance() and stays otherwise unchanged. Every default matches
the script's existing loopback behavior exactly, so running any of these
scripts with zero CLI args is byte-for-byte the same as before this change.
"""
import argparse
import json
import time
from pathlib import Path

SCENARIOS_DIR = Path(__file__).parent.parent / "scenarios"


def add_multihost_args(parser: argparse.ArgumentParser, default_victim_ip: str = "127.0.0.1"):
    """Adds the P4 CLI surface. Defaults preserve existing loopback behavior."""
    parser.add_argument("--attacker-ip", default=None,
                         help="Attacker container/host IP, for provenance only -- "
                              "these scripts run FROM the attacker, so this never "
                              "changes what they connect to.")
    parser.add_argument("--victim-ip", default=default_victim_ip,
                         help=f"Single target IP (default: {default_victim_ip}, the "
                              "original loopback behavior).")
    parser.add_argument("--victim-ips", default=None,
                         help="Comma-separated multiple target IPs, for fan-out "
                              "scenarios (e.g. recon_multi_02/03). Overrides "
                              "--victim-ip when given.")
    parser.add_argument("--duration-cap", type=float, default=None,
                         help="Optional overall wall-clock cap in seconds. The "
                              "per-session randomized durations already in this "
                              "script are unchanged; this just stops the pair "
                              "loop early once the cap is hit, rather than "
                              "replacing the existing volume/timing model.")
    parser.add_argument("--scenario-id", default=None,
                         help="Tags the output sessions file (sessions_<name>_"
                              "<scenario-id>.json instead of sessions_<name>.json) "
                              "and, if given, writes a provenance manifest to "
                              "training/scenarios/<threat_class>/<scenario-id>.json.")
    return parser


def resolve_victim_ips(args) -> list:
    if args.victim_ips:
        return [ip.strip() for ip in args.victim_ips.split(",") if ip.strip()]
    return [args.victim_ip]


def sessions_filename(default_name: str, scenario_id) -> str:
    """default_name e.g. 'sessions_recon.json' -> 'sessions_recon_recon_multi_04.json'
    when a scenario id is given, else unchanged (backward compatible)."""
    if not scenario_id:
        return default_name
    stem = default_name.rsplit(".json", 1)[0]
    return f"{stem}_{scenario_id}.json"


def write_provenance(
    *,
    scenario_id: str,
    threat_class: str,
    attack_subtype,
    source: str,
    environment: str,
    label_method: str,
    generator: str,
    attacker_ip,
    victim_ips: list,
    configuration: dict,
    capture_id=None,
    split=None,
):
    """Writes training/scenarios/<threat_class>/<scenario_id>.json, matching
    the existing manifest schema in training/scenarios/README.md, plus the
    plan's new environment/attacker_ip/victim_ips/capture_id/timestamp
    fields (see plan.md Phase 9's provenance note on why `source` stays
    'real' rather than forking to a new value for multi-host captures).

    split (optional, added P9): "train" | "validation" | "unseen_test" --
    plan §12's "document the split choice in provenance metadata so it's
    auditable later" requirement. Omitted (no key written) when not given,
    so every existing call site is unaffected; the 19 P5-P8 scenarios had
    this backfilled by a one-off script since they predate this parameter.
    """
    out_dir = SCENARIOS_DIR / threat_class
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "scenario_id": scenario_id,
        "threat_class": threat_class,
        "is_malicious": attack_subtype is not None,
        "attack_subtype": attack_subtype,
        "source": source,
        "environment": environment,
        "label_method": label_method,
        "generator": generator,
        "capture_id": capture_id or f"{scenario_id}_{int(time.time())}",
        "attacker_ip": attacker_ip,
        "victim_ips": victim_ips,
        "configuration": configuration,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if split is not None:
        manifest["split"] = split
    out_path = out_dir / f"{scenario_id}.json"
    with open(out_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"  provenance: {out_path}")
    return out_path
