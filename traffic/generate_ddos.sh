#!/bin/bash
# Synthetic traffic generator for prototype validation -- a controlled
# demo input, not a production attack-simulation environment.
#
# NOTE: --flood sends as fast as the CPU allows (tens/hundreds of thousands
# of pps). Against 127.0.0.1, both "attacker" and "victim" are the same
# kernel, so that traffic competes with your own desktop for CPU and can
# hang the whole machine. The ddos detector only needs >200 conns/10s
# (20 pps) to fire, so we rate-limit to ~500pps -- ~25x the threshold,
# nowhere near enough to overload the system.
echo "[+] Starting rate-limited SYN flood to 127.0.0.1:8080 for 15 seconds..."
sudo timeout 15 nice -n 19 hping3 -S -i u2000 --rand-source -p 8080 127.0.0.1
echo "[+] SYN flood stopped."
