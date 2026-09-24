"""
Forensic chain-of-custody for alerts.json.

PS 26145's own rationale for the whole one-way-diode architecture is that it
"preserves a clean chain of custody for forensic use" -- but until now
nothing in this repo actually made that provable. alerts.json was a plain
append-only file: nothing stopped an entry from being edited after the fact,
and nothing let an analyst prove it hadn't been.

This module hash-chains every alert record the same way a blockchain/ledger
does: each record's hash covers its own content PLUS the previous record's
hash, so changing, deleting, reordering, or inserting any past record breaks
every hash from that point forward. append_chain_fields() is called once per
alert as it's written (see stream_consumer.py's write_alert());
verify_chain() independently recomputes the whole chain from genesis and is
exposed at GET /api/alerts/verify (see app.py) -- click-to-verify, and a live
"tamper with the file, watch it turn red" demo.

Deliberately STATELESS (re-reads the file's own tail on every call) rather
than keeping an in-memory last-hash: alerts.json is written by
stream_consumer.py but can be reset by app.py's POST /api/clear from a
separate process, so any in-memory chain state here would go stale the
moment a clear happened in the other process. Re-reading a few hundred bytes
off the end of the file before every alert is cheap at this system's demo
throughput and stays correct across restarts and clears with no
cross-process coordination needed.
"""
import hashlib
import json
from pathlib import Path

GENESIS_HASH = "0" * 64
CHAIN_FIELDS = ("seq", "prev_hash", "record_hash")


def _content_hash(content: dict, prev_hash: str) -> str:
    # sort_keys makes this independent of dict insertion order (Python
    # preserves insertion order, but a future refactor of a detector's
    # alert()-building code could reorder keys without meaning to break
    # every previously-written hash).
    canonical = json.dumps(content, sort_keys=True, default=str)
    return hashlib.sha256(f"{canonical}|{prev_hash}".encode("utf-8")).hexdigest()


def _strip_chain_fields(record: dict) -> dict:
    return {k: v for k, v in record.items() if k not in CHAIN_FIELDS}


def _read_last_record(alerts_file: Path) -> tuple:
    """(last_seq, last_hash) from the last well-formed line in alerts_file,
    or (-1, GENESIS_HASH) if the file is empty, missing, or every line is
    unparseable."""
    try:
        text = alerts_file.read_text().strip()
    except OSError:
        return -1, GENESIS_HASH
    if not text:
        return -1, GENESIS_HASH
    for line in reversed(text.splitlines()):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        return record.get("seq", -1), record.get("record_hash", GENESIS_HASH)
    return -1, GENESIS_HASH


def append_chain_fields(alert: dict, alerts_file: Path) -> dict:
    """Attaches seq/prev_hash/record_hash to `alert` (mutated in place and
    returned), chaining onto whatever the last record in alerts_file
    currently is. Call this BEFORE writing `alert` to the file -- it does
    not write anything itself."""
    last_seq, prev_hash = _read_last_record(alerts_file)
    content = _strip_chain_fields(alert)
    record_hash = _content_hash(content, prev_hash)
    alert["seq"] = last_seq + 1
    alert["prev_hash"] = prev_hash
    alert["record_hash"] = record_hash
    return alert


def verify_chain(alerts_file: Path) -> dict:
    """Independently recomputes the hash chain over the entire alerts_file
    from genesis -- the actual forensic-integrity check, not just a replay
    of whatever the writer last believed. Returns
    {valid, total_lines, verified, broken_at, detail}."""
    try:
        text = alerts_file.read_text().strip()
    except OSError:
        return {"valid": True, "total_lines": 0, "verified": 0, "broken_at": None,
                "detail": "Alert log not found -- nothing to verify yet."}
    if not text:
        return {"valid": True, "total_lines": 0, "verified": 0, "broken_at": None,
                "detail": "Alert log is empty -- nothing to verify yet."}

    lines = text.splitlines()
    expected_prev = GENESIS_HASH
    verified = 0

    for i, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return {"valid": False, "total_lines": len(lines), "verified": verified, "broken_at": i,
                    "detail": f"Line {i} is not valid JSON -- the log file is corrupted or was truncated."}

        seq = record.get("seq")
        prev_hash = record.get("prev_hash")
        record_hash = record.get("record_hash")
        if seq is None or prev_hash is None or record_hash is None:
            return {"valid": False, "total_lines": len(lines), "verified": verified,
                    "broken_at": seq if seq is not None else i,
                    "detail": (f"Record at line {i} has no chain fields -- either written before "
                               f"forensic chaining was enabled, or those fields were stripped.")}

        if prev_hash != expected_prev:
            return {"valid": False, "total_lines": len(lines), "verified": verified, "broken_at": seq,
                    "detail": (f"Record #{seq}'s prev_hash does not match the previous record's hash -- "
                               f"a record was inserted, deleted, or reordered.")}

        recomputed = _content_hash(_strip_chain_fields(record), prev_hash)
        if recomputed != record_hash:
            return {"valid": False, "total_lines": len(lines), "verified": verified, "broken_at": seq,
                    "detail": (f"Record #{seq}'s content hash does not match its stored hash -- "
                               f"this alert's fields were modified after it was written.")}

        verified += 1
        expected_prev = record_hash

    return {"valid": True, "total_lines": len(lines), "verified": verified, "broken_at": None,
            "detail": f"All {verified} alert record(s) verified intact from genesis -- no tampering detected."}
