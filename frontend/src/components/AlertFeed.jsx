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
}

const SEVERITY_META = {
  CRITICAL: { label: 'CRITICAL', color: 'var(--severity-critical)' },
  HIGH: { label: 'HIGH', color: 'var(--severity-high)' },
  MEDIUM: { label: 'MEDIUM', color: 'var(--severity-medium)' },
  LOW: { label: 'LOW', color: 'var(--severity-low)' },
}

const UNKNOWN_THREAT = { label: 'UNKNOWN', accent: 'var(--threat-unknown)' }
const UNKNOWN_SEVERITY = { label: 'UNKNOWN', color: 'var(--severity-unknown)' }

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
]

// window_seconds reads better with a unit suffix; every other detail field
// is displayed as-is.
function formatDetailValue(key, value) {
  if (key === 'window_seconds') return `${value}s`
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
            const isExpanded = expandedAlert === alert
            const evidenceLines = normalizeEvidence(alert.evidence)
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
                  <span className="alert-feed__src-ip">{alert.src_ip || 'N/A'}</span>
                  <span className="badge" style={{ color: severityMeta.color }}>
                    {severityMeta.label}
                  </span>
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
