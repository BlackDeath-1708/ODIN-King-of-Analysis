"""
Standardized alert export: STIX 2.1 and CEF, for air-gapped SOC/SIEM/TIP
integration (PS 26145's "standardized alert schema" requirement -- the
internal schema in detectors/base.py already has every field the PS
literally lists, but nothing exports it in a format a real SOC's tooling
actually ingests).

Purely additive: takes the *existing* internal alert dict unchanged.
Zero changes to detectors/base.py, any detector, or the correlator.

KEY CONSTRAINT: `evidence` is NOT uniform across detectors -- a list[str]
for ddos/recon/c2 (human-readable report lines), a flat dict for
dga/exfil/tls, and a dict with a nested list for the correlator's
MULTI_VECTOR alerts (`{'pattern', 'contributing_alerts': [...], ...}`).
Both exporters below serialize `evidence` as-is (JSON-encode it) rather
than type-branching on list-vs-dict -- simpler and correct for all three
shapes without per-detector special-casing.

No stix2 library dependency: STIX 2.1 Indicator/Sighting objects are
simple enough to hand-roll correctly with stdlib uuid/datetime, and this
avoids an unverified-for-this-repo's-Python-3.14.4-venv new dependency
(the same reasoning that led the Tier-2 CNN work to check torch's wheel
availability before committing to it -- here, skipping the dependency
question entirely is simpler still). CEF has no widely-used library
either way.
"""
import json
import uuid
from datetime import datetime, timezone

# STIX 2.1 confidence is 0-100; internal confidence is hard-capped at 0.99
# with no lower clamp (see base.py's alert()), so this scale-up is safe.
_STIX_LABELS = {
    "ddos": "denial-of-service", "recon": "reconnaissance", "c2": "command-and-control",
    "dga": "malicious-activity", "tls": "malicious-activity", "exfil": "exfiltration",
    "MULTI_VECTOR": "multi-vector-attack",  # kept as its own literal label, not lowercased,
                                             # matching app.py's get_stats() precedent of
                                             # treating MULTI_VECTOR as its own key, not
                                             # normalized to the other six's lowercase.
}

_CEF_SEVERITY = {"CRITICAL": 9, "HIGH": 7, "MEDIUM": 4}
_CEF_SEVERITY_DEFAULT = 5  # defensive: ddos/exfil/dga all compute severity dynamically,
                           # not just from fixed literals, so a future value is plausible.


def _stix_pattern(alert: dict) -> str:
    clauses = [f"[ipv4-addr:value = '{alert.get('src_ip', '')}']"]
    dst_ip = alert.get("dst_ip")
    if dst_ip:
        clauses.append(f"[ipv4-addr:value = '{dst_ip}']")
    dst_port = alert.get("dst_port")
    if dst_port is not None:
        clauses.append(f"[network-traffic:dst_port = {int(dst_port)}]")
    return " AND ".join(clauses)


def to_stix_indicator(alert: dict) -> dict:
    """One internal alert -> one STIX 2.1 `indicator` SDO."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    threat_class = alert.get("threat_class", "")
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": alert.get("threat_label", threat_class),
        "pattern": _stix_pattern(alert),
        "pattern_type": "stix",
        "valid_from": now,
        "labels": [_STIX_LABELS.get(threat_class, "malicious-activity"), threat_class],
        "confidence": round(float(alert.get("confidence", 0)) * 100),
        # No native STIX slot for these -- STIX 2.1 explicitly allows
        # custom properties with an `x_` prefix, so nothing is dropped.
        "x_odin_flow_id": alert.get("flow_id"),
        "x_odin_detector": alert.get("detector"),
        "x_odin_severity": alert.get("severity"),
        "x_odin_calibrated": alert.get("calibrated", False),
        "x_odin_event_ts": alert.get("event_ts"),
        "x_odin_evidence": alert.get("evidence"),
    }


def to_stix_bundle(alerts: list) -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [to_stix_indicator(a) for a in alerts],
    }


def _cef_escape_header(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_extension_value(value: str) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
    )


def to_cef_line(alert: dict) -> str:
    """One internal alert -> one CEF:0 syslog line."""
    threat_class = alert.get("threat_class", "unknown")
    threat_label = alert.get("threat_label", threat_class)
    severity = _CEF_SEVERITY.get(alert.get("severity"), _CEF_SEVERITY_DEFAULT)

    header = "|".join([
        "CEF:0",
        _cef_escape_header("ODIN"),
        _cef_escape_header("ThreatDetectionPipeline"),
        _cef_escape_header("1.0"),
        _cef_escape_header(threat_class),
        _cef_escape_header(threat_label),
        str(severity),
    ])

    # Evidence is JSON-encoded first (so its own internal structure -- list
    # or dict, arbitrarily nested -- round-trips losslessly), THEN
    # CEF-escaped on top: JSON's own `"`-escaping doesn't cover CEF's
    # `=`/`|` extension-value delimiters, so both passes are required, in
    # this order.
    evidence_json = json.dumps(alert.get("evidence"), default=str)
    extensions = {
        "src": alert.get("src_ip", ""),
        "dst": alert.get("dst_ip", ""),
        "dpt": alert.get("dst_port"),
        "rt": alert.get("timestamp", ""),
        "cn1": round(float(alert.get("confidence", 0)) * 100),
        "cn1Label": "confidencePercent",
        "cs1": evidence_json,
        "cs1Label": "evidence",
        "cs2": alert.get("flow_id", ""),
        "cs2Label": "flowId",
    }
    extension_str = " ".join(
        f"{k}={_cef_escape_extension_value(v)}" for k, v in extensions.items() if v is not None
    )
    return f"{header}|{extension_str}"


def to_cef_lines(alerts: list) -> list:
    return [to_cef_line(a) for a in alerts]
