#!/bin/bash
# Synthetic traffic generator for prototype validation -- this is a
# controlled demo input, not a production attack-simulation tool.
#
# --max-rate caps this at 15 packets/sec. Without it, -T4 completes 1000
# ports fast enough to *also* exceed the DDoS detector's packet-rate
# threshold (>200 conns/10s), so a single scan fires both RECON and DDoS
# alerts together -- technically correct (the burst really is anomalous
# by both measures) but confusing for a live demo meant to show one
# attack -> one alert. Capping the rate keeps this a clean recon-only
# signal while still comfortably clearing the recon port-count threshold.
echo "[+] Starting port scan on 127.0.0.1..."
sudo nmap -sS -p 1-1000 --max-rate 15 127.0.0.1
echo "[+] Port scan complete."
