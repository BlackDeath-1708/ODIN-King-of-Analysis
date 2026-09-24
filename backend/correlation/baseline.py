"""
Adaptive alert-rate baseline for the correlation engine's statistical layer
(ODIN plan Phase C).

correlator.py's 4 named patterns (KILL_CHAIN, C2_EXFIL, DGA_C2, RECON_DDOS)
are curated, high-confidence kill-chain shapes -- but real, or exercise,
multi-stage attacks aren't limited to those 4 exact combinations. This
module gives the correlator a second, self-calibrating signal: instead of
a fixed list, it tracks how often each threat_class actually fires in the
traffic this deployment has observed, so the correlator can ask "how
surprising is it that these classes fired together, given how often each
one fires on its own?" -- without needing a labeled multi-stage-attack
training set, which doesn't exist for this project (training/scenarios/
only has single-threat-class captures).

Modeled as an independent Poisson process per threat_class: if a class
fires on average once every `mean_gap` seconds, the probability of at
least one such alert landing in a window of length W is
1 - exp(-W/mean_gap). A class no one has seen alert on yet defaults to
"not rare" (probability 1.0) rather than an assumed rate -- an unknown
class contributes nothing to a surprise score, so the adaptive layer only
ever flags combinations of classes it has enough history to judge, never
guesses about one it hasn't seen.
"""
import math
from collections import defaultdict

MIN_OBSERVATIONS = 3        # per-class inter-arrival samples needed before trusting its rate
EWMA_ALPHA = 0.2            # smoothing factor -- recent tempo weighted over old history
DEFAULT_WINDOW_SECONDS = 300  # used only until enough global samples exist to adapt
WINDOW_MULTIPLIER = 3       # adaptive window = this many mean global inter-alert gaps
WINDOW_MIN_SECONDS = 60
WINDOW_MAX_SECONDS = 900


class AlertRateBaseline:
    def __init__(self):
        self._last_ts: dict = {}       # threat_class -> ts of its last-seen alert
        self._mean_gap: dict = defaultdict(lambda: None)  # threat_class -> EWMA inter-arrival gap (s)
        self._count: dict = defaultdict(int)  # threat_class -> observations folded into _mean_gap

        # Global (any class, any source) tempo -- drives the adaptive window,
        # independent of per-class rates above.
        self._last_global_ts = None
        self._global_mean_gap = None
        self._global_count = 0

    def update(self, threat_class: str, event_ts: float) -> None:
        """Call once per alert ingested, in event_ts order (matching
        CorrelationEngine.ingest()'s own event-time keying -- see
        correlator.py's module docstring for why wall-clock time would be
        wrong under PCAP replay)."""
        last = self._last_ts.get(threat_class)
        if last is not None and event_ts > last:
            gap = event_ts - last
            prev = self._mean_gap[threat_class]
            self._mean_gap[threat_class] = gap if prev is None else (EWMA_ALPHA * gap + (1 - EWMA_ALPHA) * prev)
            self._count[threat_class] += 1
        if last is None or event_ts > last:
            self._last_ts[threat_class] = event_ts

        if self._last_global_ts is not None and event_ts > self._last_global_ts:
            gap = event_ts - self._last_global_ts
            self._global_mean_gap = gap if self._global_mean_gap is None else (
                EWMA_ALPHA * gap + (1 - EWMA_ALPHA) * self._global_mean_gap
            )
            self._global_count += 1
        if self._last_global_ts is None or event_ts > self._last_global_ts:
            self._last_global_ts = event_ts

    def probability_in_window(self, threat_class: str, window_seconds: float) -> float:
        """P(>=1 alert of this class in a window of this length), under the
        Poisson-process assumption above. Returns 1.0 (i.e. "not rare,
        contributes no surprise") when there isn't yet enough history for
        this class to trust a rate estimate -- a cold-start class should
        never itself manufacture an anomaly."""
        count = self._count[threat_class]
        mean_gap = self._mean_gap[threat_class]
        if count < MIN_OBSERVATIONS or not mean_gap or mean_gap <= 0:
            return 1.0
        rate_per_sec = 1.0 / mean_gap
        return 1.0 - math.exp(-rate_per_sec * window_seconds)

    def adaptive_window_seconds(self) -> float:
        """A correlation window sized to this deployment's own observed
        alert tempo -- 3x the mean global inter-alert gap, clamped to a
        sane [60s, 900s] range, instead of a magic-number window that's
        either too tight for slow/quiet traffic or absurdly loose for a
        fast PCAP replay. Falls back to a fixed default until enough
        global samples exist to adapt."""
        if self._global_count < MIN_OBSERVATIONS or not self._global_mean_gap:
            return DEFAULT_WINDOW_SECONDS
        window = self._global_mean_gap * WINDOW_MULTIPLIER
        return max(WINDOW_MIN_SECONDS, min(WINDOW_MAX_SECONDS, window))
