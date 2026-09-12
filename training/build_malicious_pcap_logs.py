"""
Offline Zeek processing for real malicious pcaps (Track A dataset prep for
the Tier-2 seq-CNN -- see backend/detectors/tier2_model.py).

Deliberately a fresh, disposable `docker run` per pcap, NOT the same
docker-exec-into-the-live-container pattern backend/app.py's /api/replay
uses -- that execs into zeek_monitor, which is simultaneously mid-flight
capturing `-i lo` for the live demo; reusing it here would contend with
that process. Mounts the exact same zeek/local.zeek + zeek/scripts as
docker-compose.yml's zeek service, so pkt_seq.log (zeek/scripts/pkt_seq.zeek,
already @load'd by local.zeek) comes out identically to how the live
pipeline produces it -- same reason train-time and serve-time feature code
paths are kept identical everywhere else in this repo.

Run: python3 training/build_malicious_pcap_logs.py
Reads: training/malicious_pcaps_raw/*.pcap
Writes: training/zeek-logs-tls-malicious/<pcap_stem>/{conn,ssl,quic,pkt_seq,...}.log
"""
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
RAW_DIR = REPO_ROOT / "training" / "malicious_pcaps_raw"
OUT_DIR = REPO_ROOT / "training" / "zeek-logs-tls-malicious"
ZEEK_SITE = REPO_ROOT / "zeek"


def process_pcap(pcap: Path) -> None:
    out = OUT_DIR / pcap.stem
    out.mkdir(parents=True, exist_ok=True)
    if (out / "conn.log").exists():
        print(f"Skipping {pcap.name} (already processed at {out})")
        return

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{ZEEK_SITE / 'local.zeek'}:/usr/local/zeek/share/zeek/site/local.zeek:ro",
        "-v", f"{ZEEK_SITE / 'scripts'}:/usr/local/zeek/share/zeek/site/scripts:ro",
        "-v", f"{RAW_DIR}:/pcaps:ro",
        "-v", f"{out}:/out",
        "-w", "/out",
        "zeek/zeek:latest",
        "zeek", "-C", "-r", f"/pcaps/{pcap.name}",
        "/usr/local/zeek/share/zeek/site/local.zeek",
    ]
    print(f"Processing {pcap.name} -> {out}")
    subprocess.run(cmd, check=True)


def main() -> None:
    pcaps = sorted(RAW_DIR.glob("*.pcap"))
    if not pcaps:
        print(f"No pcaps found in {RAW_DIR} -- nothing to process")
        return
    for pcap in pcaps:
        process_pcap(pcap)


if __name__ == "__main__":
    main()
