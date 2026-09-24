import { useState } from 'react'

// Displays alerts and lets one be expanded to show its evidence.
// No data fetching, no application state — only which row is expanded.
//
// Contract note: the backend's actual alert shape (backend/detectors/base.py
// Detector.alert()) sends `severity` as the string enum below and `evidence`
// as an array of pre-formatted sentences — not a numeric severity or a
// structured evidence object. This component renders exactly that shape;
// it does not guess at alternate encodings.

const THREAT_META = {
  ddos: { label: 'DDoS / SYN Flood', accent: 'var(--threat-ddos)' },
  recon: { label: 'Recon / Port Scan', accent: 'var(--threat-recon)' },
  c2: { label: 'C2 Beaconing', accent: 'var(--threat-c2)' },
  dga: { label: 'DGA / DNS Tunnelling', accent: 'var(--threat-dga)' },
  tls: { label: 'TLS Malware (JA3)', accent: 'var(--threat-tls)' },
  exfil: { label: 'Data Exfiltration', accent: 'var(--threat-exfil)' },
  MULTI_VECTOR: { label: 'Multi-Vector', accent: 'var(--threat-multi-vector)' },
  MULTI_VECTOR_ANOMALY: { label: 'Multi-Vector Anomaly', accent: 'var(--threat-multi-vector)' },
}

const SEVERITY_META = {
  CRITICAL: { label: 'CRITICAL', color: 'var(--severity-critical)' },
  HIGH: { label: 'HIGH', color: 'var(--severity-high)' },
  MEDIUM: { label: 'MEDIUM', color: 'var(--severity-medium)' },
  LOW: { label: 'LOW', color: 'var(--severity-low)' },
}

const UNKNOWN_THREAT = { label: 'UNKNOWN', accent: 'var(--threat-unknown)' }
const UNKNOWN_SEVERITY = { label: 'UNKNOWN', color: 'var(--severity-unknown)' }

// Every value backend/detectors/base.py's alert() can put in
// `detection_method` (see that file's docstring for the full list). `warn:
// true` marks the cases worth calling out visually -- a rule fallback that
// fired because the ML model either isn't loaded at all, or because this
// specific input fell outside the model's validated range (c2.py's
// MODEL_MAX_OBSERVATIONS/MODEL_MAX_MEAN_INTERVAL -- see that module's
// docstring) rather than the model extrapolating past what it was ever
// shown to be safe on.
const DETECTION_METHOD_META = {
  ml: { label: 'ML', title: 'Trained classifier prediction' },
  rule_based: { label: 'Rule', title: 'Rule-based detection — no ML model involved on this path' },
  rule_fallback_no_model: {
    label: 'Rule (fallback)', warn: true,
    title: 'ML model unavailable — using the fixed-threshold fallback rule instead',
  },
  rule_fallback_out_of_range: {
    label: 'Rule (out-of-range)', warn: true,
    title: "This input falls outside the model's validated range — using the fixed-threshold "
      + 'fallback rule instead of trusting the model to extrapolate',
  },
  ja3_blacklist: { label: 'JA3 Blacklist', title: 'Matched a known-malicious JA3 TLS fingerprint' },
  ja4_blacklist: { label: 'JA4 Blacklist', title: 'Matched a known-malicious JA4 TLS fingerprint' },
  flow_stats_ml: { label: 'ML (Tier 1)', title: 'Flow-statistics classifier (Tier 1)' },
  'flow_stats_ml+tier2_seq_cnn': {
    label: 'ML (Tier 1→2)',
    title: "Tier 1's confidence landed in the ambiguous band — escalated to the Tier 2 "
      + 'packet-sequence CNN, which made the final call',
  },
  ml_rule_confirmed: { label: 'ML + Rule', title: 'ML confidence backed by a matching rule-based exfil pattern' },
  ml_only: { label: 'ML only', title: 'No rule-based pattern matched — held to a higher confidence bar' },
}

function getDetectionMethodMeta(method) {
  return DETECTION_METHOD_META[method] || null
}

// Fields worth surfacing in the expanded "Technical Details" grid, in
// display order. Only rendered when present/non-null on the alert —
// nothing invented. Source IP is already visible in the collapsed row
// above; it's repeated here too so the details grid reads as the complete
// technical record on its own.
const DETAIL_FIELDS = [
  ['threat_label', 'Threat Label'],
  ['detector', 'Detector'],
  ['src_ip', 'Source IP'],
  ['src_port', 'Source Port'],
  ['dst_ip', 'Destination IP'],
  ['dst_port', 'Destination Port'],
  ['window_seconds', 'Window'],
  ['flow_id', 'Flow ID'],
  ['seq', 'Chain Sequence #'],
  ['record_hash', 'Chain Record Hash'],
]

// window_seconds reads better with a unit suffix; record_hash is a 64-hex
// digest -- truncated for a scannable row (full value is what's actually
// hashed/exported, this is display-only). Every other detail field is
// displayed as-is.
function formatDetailValue(key, value) {
  if (key === 'window_seconds') return `${value}s`
  if (key === 'record_hash' && typeof value === 'string' && value.length > 16) {
    return `${value.slice(0, 12)}…${value.slice(-4)}`
  }
  return String(value)
}

function getThreatMeta(threatClass) {
  return THREAT_META[threatClass] || UNKNOWN_THREAT
}

function getSeverityMeta(severity) {
  return SEVERITY_META[severity] || UNKNOWN_SEVERITY
}

function formatConfidence(confidence) {
  if (typeof confidence !== 'number' || Number.isNaN(confidence)) return 'N/A'
  return `${Math.round(confidence * 100)}%`
}

function formatTimestamp(timestamp) {
  if (!timestamp) return 'N/A'
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return String(timestamp)
  return date.toLocaleString()
}

// A nested object/array value (e.g. MULTI_VECTOR's contributing_alerts)
// stringifies unreadably via String() -- "[object Object]" -- without ever
// telling the reader anything. JSON.stringify at least shows real content;
// this is formatting, not parsing apart or interpreting the value.
function formatEvidenceValue(value) {
  if (value === null || value === undefined) return 'N/A'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

// Evidence's primary contract is an array of ready-to-read sentences.
// A bare string is handled as a single-item list. An object is accepted
// only defensively (never assumed) and rendered as its own entries — never
// parsed apart or embellished with a fabricated explanation.
function normalizeEvidence(evidence) {
  if (Array.isArray(evidence)) {
    return evidence.filter((item) => item !== null && item !== undefined && item !== '')
  }
  if (typeof evidence === 'string') {
    return evidence.trim() ? [evidence] : []
  }
  if (evidence && typeof evidence === 'object') {
    return Object.entries(evidence).map(([key, value]) => `${key}: ${formatEvidenceValue(value)}`)
  }
  return []
}

function AlertFeed({
  alerts,
  subtitle,
  emptyTitle = 'MONITORING ACTIVE',
  emptySubtitle = 'No threats detected',
}) {
  const [expandedAlert, setExpandedAlert] = useState(null)
  const safeAlerts = Array.isArray(alerts) ? alerts : []

  const toggleExpanded = (alert) => {
    setExpandedAlert((prev) => (prev === alert ? null : alert))
  }

  return (
    <div className="panel alert-feed">
      <div className="panel-header">
        <div className="alert-feed__heading">
          <span className="panel-title">Live Alert Feed</span>
          {subtitle && <span className="panel-subtitle">{subtitle}</span>}
        </div>
        <span className="alert-feed__count">
          {safeAlerts.length} {safeAlerts.length === 1 ? 'ALERT' : 'ALERTS'}
        </span>
      </div>

      {safeAlerts.length === 0 ? (
        <div className="alert-feed__empty">
          <div className="alert-feed__empty-title">{emptyTitle}</div>
          <div className="alert-feed__empty-subtitle">{emptySubtitle}</div>
        </div>
      ) : (
        <ul className="alert-feed__list">
          {safeAlerts.map((alert, i) => {
            if (!alert || typeof alert !== 'object') return null

            const threatMeta = getThreatMeta(alert.threat_class)
            const severityMeta = getSeverityMeta(alert.severity)
            const methodMeta = getDetectionMethodMeta(alert.detection_method)
            const isExpanded = expandedAlert === alert
            const evidenceLines = normalizeEvidence(alert.evidence)
            const contributions = Array.isArray(alert.feature_contributions) ? alert.feature_contributions : []
            const details = DETAIL_FIELDS.filter(
              ([key]) => alert[key] !== null && alert[key] !== undefined && alert[key] !== '',
            )

            return (
              <li
                key={`${alert.flow_id ?? alert.timestamp ?? 'unknown'}-${i}`}
                className="alert-feed__row"
                style={{ borderLeftColor: threatMeta.accent }}
              >
                <button
                  type="button"
                  className="alert-feed__summary"
                  onClick={() => toggleExpanded(alert)}
                >
                  <span className="badge" style={{ color: threatMeta.accent }}>
                    {threatMeta.label}
                  </span>
                  {alert.threat_class === 'MULTI_VECTOR' && (
                    <span className="kill-chain-badge">⚡ {alert.evidence?.pattern}</span>
                  )}
                  {alert.threat_class === 'MULTI_VECTOR_ANOMALY' && (
                    <span className="kill-chain-badge">⚡ {(alert.evidence?.classes || []).join('+')}</span>
                  )}
                  <span className="alert-feed__src-ip">{alert.src_ip || 'N/A'}</span>
                  <span className="badge" style={{ color: severityMeta.color }}>
                    {severityMeta.label}
                  </span>
                  {methodMeta && (
                    <span
                      className="badge"
                      style={{ color: methodMeta.warn ? 'var(--status-warning)' : 'var(--accent)' }}
                      title={methodMeta.title}
                    >
                      {methodMeta.warn ? '⚠ ' : ''}{methodMeta.label}
                    </span>
                  )}
                  <span className="alert-feed__confidence">
                    {formatConfidence(alert.confidence)}
                    {alert.calibrated && (
                      <span
                        className="alert-feed__calibrated-label"
                        title="Platt-calibrated — reflects empirical precision, not raw model output."
                      >
                        (calibrated)
                      </span>
                    )}
                  </span>
                  <span className="alert-feed__timestamp">{formatTimestamp(alert.timestamp)}</span>
                </button>

                {isExpanded && (
                  <div className="alert-feed__evidence">
                    <div className="alert-feed__evidence-title">Evidence</div>
                    {evidenceLines.length > 0 ? (
                      <ul className="evidence-list">
                        {evidenceLines.map((line, idx) => (
                          <li key={idx} className="evidence-list__item">
                            {line}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="alert-feed__no-evidence">No evidence available</div>
                    )}

                    {contributions.length > 0 && (
                      <>
                        <div className="alert-feed__evidence-title alert-feed__evidence-title--details">
                          Why Flagged — Model Feature Breakdown
                        </div>
                        <p className="feature-contributions__note">
                          This alert&rsquo;s observed feature values, ranked by how much each feature
                          mattered to the trained classifier overall (global importance from the model
                          itself — not a per-alert SHAP attribution).
                        </p>
                        <div className="feature-contributions">
                          {contributions.map((c) => (
                            <div key={c.feature} className="feature-contributions__row">
                              <span className="feature-contributions__name">{c.feature}</span>
                              <span className="feature-contributions__bar-track">
                                <span
                                  className="feature-contributions__bar-fill"
                                  style={{ width: `${Math.round(Math.min(c.importance, 1) * 100)}%` }}
                                />
                              </span>
                              <span className="feature-contributions__importance">
                                {Math.round(c.importance * 100)}%
                              </span>
                              <span className="feature-contributions__value">{formatEvidenceValue(c.value)}</span>
                            </div>
                          ))}
                        </div>
                      </>
                    )}

                    {details.length > 0 && (
                      <>
                        <div className="alert-feed__evidence-title alert-feed__evidence-title--details">
                          Technical Details
                        </div>
                        <div className="evidence-grid">
                          {details.map(([key, label]) => (
                            <div key={key} className="evidence-row">
                              <span className="evidence-key">{label}</span>
                              <span className="evidence-value">
                                {formatDetailValue(key, alert[key])}
                              </span>
                            </div>
                          ))}
                        </div>
                      </>
                    )}
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

export default AlertFeed
