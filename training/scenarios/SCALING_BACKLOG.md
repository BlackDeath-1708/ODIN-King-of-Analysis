# Scenario Scaling Backlog

Dataset-plan Step 5 (scale by scenario diversity, not raw rows). This is the
concrete next-scenarios list, not just the abstract rule — each entry below is
a real, currently-missing behavioral variant, identified by actually looking at
what's already captured (see `README.md`'s inventory), sized to be quick and
safe to add later without repeating the 2026-09-13 conn.log-truncation incident
(`docs/DATASET_STRUCTURE.md` §4).

**Rule for adding any of these**: write the manifest in the relevant
`training/scenarios/<threat_class>/` directory *first*, then capture — and if the
capture reuses an existing shared container, it must run inside that container's
*current* continuous session, never after a fresh restart (Zeek truncates
`conn.log` on container start, doesn't resume appending across one).

## Recon — horizontal scanning (real gap, not yet covered)

Current `recon_port_scan` scans many ports on **one** target (127.0.0.1) — this
is vertical scanning only. Horizontal scanning (one port, many hosts) has never
been captured, so `unique_hosts`/host-fanout has near-zero real variance in the
current dataset — a real risk called out in the original dataset plan.

**How to add it cheaply**: Linux loopback supports multiple addresses on `lo`
without any extra hardware (`ip addr add 127.0.0.2/8 dev lo`, etc. — no root
setcap needed beyond what recon capture already has). Scan a fixed port across
5-10 such addresses per session instead of a port range on one address. New
scenario: `recon_horizontal_scan`. Estimated capture time: similar to the
existing ~56min port_scan phase, since it reuses the same benign/session pacing.

## C2 — multi-destination beaconing (real gap, not yet covered)

Every current C2 scenario targets a single fixed (host, port) for its whole
session (`capture_c2.py`'s own design choice, made to isolate the timing-only
signal). Real multi-destination C2 (round-robin or failover across several
controllers) is unrepresented. New scenario: `c2_multi_destination` — same
timing generator, but rotates through 2-3 fixed ports per session instead of
one. Low risk since it reuses `capture_c2.py`'s existing structure; the real
cost is time (C2 captures are the slowest, ~85min/65-pair campaign).

## DDoS — true reflection/amplification port targeting

Checked before writing this down (`capture_ddos_udp_spoof.py`): `ddos_udp_flood`
targets real reflection-associated ports (53, 123) but is a **direct**, non-
spoofed flood; `ddos_spoofed_source` genuinely spoofs the source IP but targets
a private, non-amplification port pool (19140-19169), not 53/123/1900. So
*neither* current scenario is actually "spoofed-source traffic hitting a real
amplification port" — that combination (what a real reflection/amplification
attack looks like) doesn't exist in the dataset yet, and there's no way to
relabel existing rows into it at build time; it needs a new capture:
`spoofed_flood()` pointed at `REFLECTION_PORTS` instead of `SPOOFED_PORTS`. New
scenario: `ddos_udp_reflection`. Cheap once captured (same generator, one port
pool changed) — the cost is capture time, not code.

## Exfil / DGA / TLS — no backlog item

- **Exfil**: already has 4 real + 4 synthetic scenarios spanning bulk/low-slow/
  covert-ICMP/DNS-tunnel shapes — reasonably covered for now.
- **DGA**: 11 scenarios across 9 published algorithm families already —
  diversifying further means adding more published families, not a structural
  gap.
- **TLS**: intentionally not scaled further — see the real-evidence ceiling in
  `docs/DATASET_STRUCTURE.md` §3. Adding synthetic volume here would work
  against the plan's own honesty principle, not toward it.

## Benign diversity — recon/c2 still owe the addition ddos already has

`ddos_benign_http_baseline` exists; `recon`/`c2` don't have the equivalent yet
(deferred 2026-09-13, see incident note). Adding it now means re-running their
full captures (~56min recon, ~85min c2) since it can no longer be safely bolted
on after the fact without redoing the whole thing — do this as part of, not
separate from, their next full recapture.
