"""
Cross-Threat Correlation Engine

Ingests alerts (the dicts Detector.alert() produces) from all six detectors.
Tracks per-source alert history. Two layers, checked in order:

1. Curated patterns -- emits a MULTI_VECTOR alert when a known kill-chain
   shape is detected (priority order, highest first):
     KILL_CHAIN  : recon + c2 + exfil within 600s -> confidence 0.97
     C2_EXFIL    : c2 + exfil within 600s          -> confidence 0.92
     DGA_C2      : dga + c2 within 120s            -> confidence 0.88
     RECON_DDOS  : recon + ddos within 300s        -> confidence 0.85
2. Adaptive statistical layer (ODIN plan Phase C, see baseline.py) -- if no
   curated pattern matched, emits a MULTI_VECTOR_ANOMALY alert when >=2
   distinct threat classes co-occur from one source far more often than
   their own independently-observed background rates would predict by
   chance. Self-calibrates from this deployment's own traffic instead of a
   fixed list, so a genuinely novel multi-vector combination isn't invisible
   just because nobody named it above.

Either layer emits its correlated alert IN ADDITION TO, never instead of,
the individual alerts that triggered it.

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

import math
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from .baseline import AlertRateBaseline

# 900, not 600: must be >= AlertRateBaseline.WINDOW_MAX_SECONDS (900) so the
# adaptive statistical layer's own window never exceeds this outer prune
# bound -- otherwise _sweep() could forget history/dedup state the adaptive
# layer still considers "in window", reintroducing duplicate anomaly
# alerts. Each named pattern below still uses its own (smaller) window.
CORRELATION_WINDOW = 900
MAX_CONTRIBUTING_ALERTS = 20  # see _make_correlated's docstring -- bounds a real memory-growth bug
ANOMALY_MIN_CLASSES = 2       # a "multi-vector" anomaly needs at least 2 distinct threat classes
# -log(joint independent probability) threshold to flag a co-occurrence as
# surprising -- exp(-3.0) ~= 0.05, i.e. this combination would be expected
# under 5% of the time if these classes fired independently at their own
# observed background rates. A conventional significance-testing cutoff,
# not an arbitrarily tuned number.
ANOMALY_SCORE_THRESHOLD = 3.0


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
        # Adaptive statistical layer (ODIN plan Phase C) -- see baseline.py.
        self._baseline = AlertRateBaseline()

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
        if not src or not tc or tc in ('MULTI_VECTOR', 'MULTI_VECTOR_ANOMALY') or now is None:
            return None

        self._baseline.update(tc, now)
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
                continue  # pattern's own window, not just the outer prune bound

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

        # No curated pattern matched -- fall through to the adaptive
        # statistical layer (ODIN plan Phase C), which catches multi-vector
        # combinations nobody enumerated above.
        return self._check_adaptive_anomaly(src, now, classes_present)

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

    def _check_adaptive_anomaly(self, src_ip: str, now: float, classes_present: set) -> dict | None:
        """The statistical layer: flags a source whose recent alerts span
        >=2 distinct threat classes that -- given how often each class
        fires on its own, per self._baseline -- would rarely co-occur by
        chance. Generalizes beyond the 4 named PATTERNS above without
        needing a labeled multi-stage-attack corpus (see baseline.py's
        module docstring for why)."""
        if len(classes_present) < ANOMALY_MIN_CLASSES:
            return None

        window = self._baseline.adaptive_window_seconds()
        cutoff = now - window
        contributing_records = [(ts, tc, al) for ts, tc, al in self._history[src_ip] if ts > cutoff]
        classes_in_window = {tc for _, tc, _ in contributing_records}
        if len(classes_in_window) < ANOMALY_MIN_CLASSES:
            return None

        # Joint probability under an independence assumption: how likely is
        # it that ALL these classes would land in this window by chance,
        # given each one's own observed background rate? Low joint
        # probability (high -log score) means the co-occurrence itself is
        # the surprising signal, not any single alert's own confidence.
        probs_by_class = {
            tc: max(self._baseline.probability_in_window(tc, window), 1e-6) for tc in classes_in_window
        }
        score = -sum(math.log(p) for p in probs_by_class.values())
        if score < ANOMALY_SCORE_THRESHOLD:
            return None

        # Same "only suppress when nothing new contributed" dedup as the
        # named patterns above, keyed on the specific class combination so
        # a source cycling through different surprising combinations isn't
        # silently collapsed into a single alert.
        key = (src_ip, 'ADAPTIVE', frozenset(classes_in_window))
        current_identities = frozenset(
            self._alert_identity(al) for _, tc, al in contributing_records if tc in classes_in_window
        )
        previous = self._fired.get(key)
        if previous is not None and current_identities.issubset(previous[1]):
            return None
        self._fired[key] = (now, current_identities)

        confidence = min(0.99, 1 - math.exp(-score))
        severity = 'CRITICAL' if len(classes_in_window) >= 3 else 'HIGH'
        return self._make_adaptive_anomaly(
            src_ip, classes_in_window, confidence, severity, window, contributing_records, probs_by_class, score,
        )

    def _make_adaptive_anomaly(self, src_ip, classes_in_window, confidence, severity, window,
                                records, probs_by_class, score) -> dict:
        # Only the records from the surprising classes belong in the
        # evidence trail -- contributing_records may include other classes
        # from _history that fell inside the window but weren't part of
        # what triggered this (rare, but possible if classes_present grew
        # since the window was computed).
        records = [r for r in records if r[1] in classes_in_window]
        records = sorted(records, key=lambda r: r[0])[-MAX_CONTRIBUTING_ALERTS:]
        contributing = [
            {'threat_class': tc, 'event_ts': ts, 'confidence': al.get('confidence')}
            for ts, tc, al in records
        ]
        latest_record = max(records, key=lambda r: r[0])
        latest_alert = latest_record[2]
        classes_sorted = sorted(classes_in_window)
        return {
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'event_ts': latest_record[0],
            'flow_id': str(uuid.uuid4()),
            'src_ip': src_ip,
            'src_port': None,
            'dst_ip': latest_alert.get('dst_ip', ''),
            'dst_port': latest_alert.get('dst_port'),
            'threat_class': 'MULTI_VECTOR_ANOMALY',
            'threat_label': f"Multi-Vector Anomaly ({'+'.join(classes_sorted)})",
            'severity': severity,
            'confidence': confidence,
            'calibrated': False,
            'evidence': {
                'classes': classes_sorted,
                'contributing_alerts': contributing,
                'correlation_window_seconds': round(window, 1),
                'surprise_score': round(score, 4),
                'baseline_probabilities': {tc: round(p, 4) for tc, p in probs_by_class.items()},
                'explanation': (
                    'Statistically adaptive layer: no curated pattern matched, but these classes '
                    'co-occurred from the same source far more often than their own independent '
                    'background rates would predict by chance.'
                ),
            },
            'detector': 'correlator',
            'window_seconds': round(window, 1),
        }
