"""
Download JA3 blacklist from SSL Abuse and save offline. Run ONCE before
starting the detector -- never called at runtime, fully compliant with the
one-way constraint.
Source: https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
Output: backend/data/ja3_blacklist.json
Format: {"<md5_hash>": {"family": "<Malware_type>", "severity": "high"}, ...}
"""
import csv
import json
import urllib.request
from pathlib import Path

URL = 'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv'
OUTPUT = Path(__file__).parent.parent / "backend" / "data" / "ja3_blacklist.json"


def download():
    """The feed's actual data header ("ja3_md5,Firstseen,Lastseen,Listingreason")
    is itself commented out (starts with '#'), same as the decorative banner
    lines above it -- so it must be captured explicitly before filtering out
    every other '#'-prefixed line, or DictReader silently gets zero rows."""
    result = {}
    try:
        with urllib.request.urlopen(URL, timeout=10) as resp:
            lines = resp.read().decode('utf-8').splitlines()

        header = None
        data_lines = []
        for line in lines:
            stripped = line.lstrip('#').strip()
            if header is None and stripped.lower().startswith('ja3_md5'):
                header = stripped
                continue
            if line.startswith('#') or not line.strip():
                continue
            data_lines.append(line)

        if header:
            reader = csv.DictReader(data_lines, fieldnames=header.split(','))
            for row in reader:
                h = (row.get('ja3_md5') or '').strip()
                if h:
                    result[h] = {
                        'family': (row.get('Listingreason') or 'Unknown').strip(),
                        'severity': 'high',
                    }
    except Exception as e:
        print(f"[ja3] download failed ({e}) -- writing an empty blacklist; "
              f"the flow-stats ML path still works without it")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"Saved {len(result)} JA3 entries to {OUTPUT}")


if __name__ == '__main__':
    download()
