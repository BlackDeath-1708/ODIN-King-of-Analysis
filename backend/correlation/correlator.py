"""
Cross-Threat Correlation Engine

Ingests alerts (the dicts Detector.alert() produces) from all six detectors.
Tracks per-source alert history. Emits a MULTI_VECTOR correlated alert when a
known pattern is detected -- in addition to, never instead of, the individual
alerts that triggered it.

Patterns (priority order, highest first):
  KILL_CHAIN  : recon + c2 + exfil within 600s -> confidence 0.97
  C2_EXFIL    : c2 + exfil within 600s          -> confidence 0.92
  DGA_C2      : dga + c2 within 120s            -> confidence 0.88
  RECON_DDOS  : recon + ddos within 300s        -> confidence 0.85

History is keyed on each alert's `event_ts` (the underlying Zeek event's own
clock, threaded through by Detector.alert() -- see base.py), not wall-clock
ingest time. This matters specifically because of how this project's PCAP
replay demo works: replay makes Zeek reprocess a pcap offline and drain the
resulting log lines through Kafka essentially back-to-back, so wall-clock
ingest time for a whole multi-stage attack pcap collapses into a few
real-time seconds -- every pattern's window would trivially "look" satisfied
regardless of how far apart the events actually were in the pcap's own
timeline. `ddos.py`'s cooldown and AdaptiveEntropyBaseline hit this same
class of bug already and fixed it by keying on event time; correlation needs
the same fix for the same reason.
"""

import uuid
from collections import defaultdict
from datetime import datetime, timezone

CORRELATION_WINDOW = 600  # seconds -- the outer prune bound; each pattern also has its own window
MAX_CONTRIBUTING_ALERTS = 20  # see _make_correlated's docstring -- bounds a real memory-growth bug


class CorrelationEngine:
    PATTERNS = [
        # (pattern_name, required_threat_classes, window_seconds, confidence, severity)
        ('KILL_CHAIN', {'recon', 'c2', 'exfil'}, 600, 0.97, 'CRITICAL'),
        ('C2_EXFIL',   {'c2', 'exfil'},          600, 0.92, 'CRITICAL'),
        ('DGA_C2',     {'dga', 'c2'},            120, 0.88, 'HIGH'),
        ('RECON_DDOS', {'recon', 'ddos'},        300, 0.85, 'HIGH'),
    ]

    def __init__(self):
        self._history: dict = defaultdict(list)  # {src_ip: [(event_ts, threat_class, alert_dict), ...]}
        # {(src_ip, pattern_name): (last_fired_event_ts, frozenset(identities of alerts used))}
        self._fired: dict = {}

    @staticmethod
    def _alert_identity(alert: dict):
        """A stable per-alert identity for dedup -- flow_id when the detector set one
        (all six do), else a (event_ts, threat_class) fallback so two literally
        distinct alerts are never mistaken for the same one."""
        flow_id = alert.get('flow_id')
        return flow_id if flow_id else (alert.get('event_ts'), alert.get('threat_class'))

    def _sweep(self, now: float):
        """Drop anything older than the outer window, for every tracked source --
        not just the one that triggered this ingest() call -- so a source that goes
        idle after alerting is eventually forgotten instead of leaking forever."""
        cutoff = now - CORRELATION_WINDOW
        for src_ip in list(self._history.keys()):
            kept = [(ts, tc, al) for ts, tc, al in self._history[src_ip] if ts > cutoff]
            if kept:
                self._history[src_ip] = kept
            else:
                del self._history[src_ip]
        for key in [k for k, (ts, _) in self._fired.items() if ts <= cutoff]:
            del self._fired[key]

    def ingest(self, alert: dict) -> dict | None:
        src = alert.get('src_ip', '')
        tc = alert.get('threat_class', '')
        now = alert.get('event_ts')
        if not src or not tc or tc == 'MULTI_VECTOR' or now is None:
            return None

        self._history[src].append((now, tc, alert))
        self._sweep(now)

        classes_present = {tc for _, tc, _ in self._history[src]}

        for pattern_name, required, window, confidence, severity in self.PATTERNS:
            if not required.issubset(classes_present):
                continue
            cutoff = now - window
            contributing_records = [
                (ts, tc, al) for ts, tc, al in self._history[src] if ts > cutoff and tc in required
            ]
            classes_in_window = {tc for _, tc, _ in contributing_records}
            if not required.issubset(classes_in_window):
                continue  # pattern's own window, not just the outer 600s prune

            # Dedup on WHICH alerts contributed, not just when we last fired: a
            # flat time-based cooldown can reuse a stale alert to "re-earn" a
            # different pattern and end up silently suppressing a second,
            # genuinely distinct attack chain from the same source. Only
            # suppress when every alert contributing this time already
            # contributed to this pattern's last firing -- i.e. nothing new.
            current_identities = frozenset(self._alert_identity(al) for _, _, al in contributing_records)
            previous = self._fired.get((src, pattern_name))
            if previous is not None and current_identities.issubset(previous[1]):
                continue
            self._fired[(src, pattern_name)] = (now, current_identities)

            return self._make_correlated(src, pattern_name, confidence, severity, window, contributing_records)

        return None

    def _make_correlated(self, src_ip, pattern, confidence, severity, window, records) -> dict:
        # A sustained burst from one source (e.g. many exfil-shaped flows in
        # a short window) can produce hundreds of `records` here, and this
        # method fires once per new contributing alert (see ingest()'s
        # dedup, which only suppresses when nothing NEW contributed -- so a
        # flood of distinct flows never gets suppressed by design). Without
        # a cap, evidence.contributing_alerts grows ~1+2+...+N across N
        # firings (quadratic in the burst size) -- confirmed directly: a
        # 25s/300-conn/s benchmark run produced ~405,000 embedded entries
        # across ~900 correlated alerts, bloating alerts.json enough to
        # OOM-kill the Flask process reading it back. Keeping only the most
        # recent MAX_CONTRIBUTING_ALERTS bounds every single correlated
        # alert's size regardless of burst length, without changing which
        # alerts are used for the re-fire dedup above (that still sees the
        # full `records`) -- only the evidence payload shown to a human
        # reviewer is trimmed.
        records = sorted(records, key=lambda r: r[0])[-MAX_CONTRIBUTING_ALERTS:]
        contributing = [
            {'threat_class': tc, 'event_ts': ts, 'confidence': al.get('confidence')}
            for ts, tc, al in records
        ]
        latest_record = max(records, key=lambda r: r[0])
        latest_alert = latest_record[2]
        return {
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'event_ts': latest_record[0],
            'flow_id': str(uuid.uuid4()),
            'src_ip': src_ip,
            'src_port': None,
            'dst_ip': latest_alert.get('dst_ip', ''),
            'dst_port': latest_alert.get('dst_port'),
            'threat_class': 'MULTI_VECTOR',
            'threat_label': f'Multi-Vector Attack ({pattern})',
            'severity': severity,
            'confidence': confidence,
            'calibrated': False,
            'evidence': {
                'pattern': pattern,
                'contributing_alerts': contributing,
                'correlation_window_seconds': window,
            },
            'detector': 'correlator',
            'window_seconds': window,
        }
