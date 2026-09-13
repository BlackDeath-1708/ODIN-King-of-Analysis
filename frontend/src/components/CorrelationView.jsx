// Visualizes backend/correlation/correlator.py's output: a MULTI_VECTOR
// alert's evidence carries {pattern, contributing_alerts, correlation_window_seconds}
// (see correlator.py:_make_correlated) -- this renders that real payload,
// never a simulated kill chain. PATTERN_INFO below is static reference
// text describing what correlator.py's own PATTERNS list already encodes
// (threat classes + window + confidence), shown so an incident's meaning
// is legible without reading the source; it is not fetched from the
// backend since correlator.py has no endpoint exposing its pattern table,
// only its resulting alerts.

const PATTERN_INFO = {
  KILL_CHAIN: {
    label: 'Kill Chain',
    sequence: ['recon', 'c2', 'exfil'],
    window: 600,
    confidence: 0.97,
    description: 'Reconnaissance followed by C2 beaconing followed by data exfiltration from the same source — the full attack lifecycle.',
  },
  C2_EXFIL: {
    label: 'C2 → Exfiltration',
    sequence: ['c2', 'exfil'],
    window: 600,
    confidence: 0.92,
    description: 'An established C2 channel followed by outbound data exfiltration — a compromised host shipping data out.',
  },
  DGA_C2: {
    label: 'DGA → C2',
    sequence: ['dga', 'c2'],
    window: 120,
    confidence: 0.88,
    description: 'A DGA/DNS-tunnel resolution immediately followed by C2 beaconing — domain-generation-driven C2 rendezvous.',
  },
  RECON_DDOS: {
    label: 'Recon → DDoS',
    sequence: ['recon', 'ddos'],
    window: 300,
    confidence: 0.85,
    description: 'Port/host scanning followed by a volumetric flood from the same source — reconnaissance preceding an attack.',
  },
}

const THREAT_ACCENTS = {
  ddos: 'var(--threat-ddos)',
  recon: 'var(--threat-recon)',
  c2: 'var(--threat-c2)',
  dga: 'var(--threat-dga)',
  tls: 'var(--threat-tls)',
  exfil: 'var(--threat-exfil)',
}

const SEVERITY_COLORS = {
  CRITICAL: 'var(--severity-critical)',
  HIGH: 'var(--severity-high)',
  MEDIUM: 'var(--severity-medium)',
  LOW: 'var(--severity-low)',
}

export function PatternSummaryCards({ incidents }) {
  const counts = {}
  for (const alert of incidents) {
    const p = alert.evidence?.pattern
    if (p) counts[p] = (counts[p] || 0) + 1
  }

  return (
    <div className="correlation-pattern-grid">
      {Object.entries(PATTERN_INFO).map(([key, info]) => (
        <div key={key} className="panel correlation-pattern-card">
          <div className="correlation-pattern-card__header">
            <span className="correlation-pattern-card__label">{info.label}</span>
            <span className="correlation-pattern-card__count">{counts[key] || 0}</span>
          </div>
          <div className="correlation-pattern-card__sequence">
            {info.sequence.map((tc, i) => (
              <span key={tc} className="correlation-pattern-card__step">
                <span
                  className="correlation-pattern-card__step-dot"
                  style={{ background: THREAT_ACCENTS[tc] || 'var(--text-tertiary)' }}
                />
                {tc}
                {i < info.sequence.length - 1 && <span className="correlation-pattern-card__arrow">→</span>}
              </span>
            ))}
          </div>
          <p className="correlation-pattern-card__desc">{info.description}</p>
          <p className="correlation-pattern-card__meta">
            Window: {info.window}s · Confidence: {Math.round(info.confidence * 100)}%
          </p>
        </div>
      ))}
    </div>
  )
}

function relativeOffset(baseTs, ts) {
  const diff = ts - baseTs
  if (diff < 1) return 'origin'
  if (diff < 60) return `+${diff.toFixed(0)}s`
  return `+${(diff / 60).toFixed(1)}m`
}

function IncidentRow({ incident }) {
  const contributing = incident.evidence?.contributing_alerts || []
  const sorted = [...contributing].sort((a, b) => a.event_ts - b.event_ts)
  const baseTs = sorted.length > 0 ? sorted[0].event_ts : incident.event_ts
  const info = PATTERN_INFO[incident.evidence?.pattern]

  return (
    <div className="panel correlation-incident">
      <div className="correlation-incident__header">
        <span className="kill-chain-badge">⚡ {info?.label || incident.evidence?.pattern}</span>
        <span className="correlation-incident__src">{incident.src_ip}</span>
        <span className="badge" style={{ color: SEVERITY_COLORS[incident.severity] || 'var(--severity-unknown)' }}>
          {incident.severity}
        </span>
        <span className="correlation-incident__confidence">
          {Math.round((incident.confidence || 0) * 100)}% confidence
        </span>
        <span className="correlation-incident__time">{new Date(incident.timestamp).toLocaleString()}</span>
      </div>
      <div className="correlation-incident__sequence">
        {sorted.map((step, i) => (
          <div key={i} className="correlation-incident__step">
            <span
              className="correlation-pattern-card__step-dot"
              style={{ background: THREAT_ACCENTS[step.threat_class] || 'var(--text-tertiary)' }}
            />
            <span className="correlation-incident__step-class">{step.threat_class}</span>
            <span className="correlation-incident__step-offset">{relativeOffset(baseTs, step.event_ts)}</span>
            <span className="correlation-incident__step-conf">
              {step.confidence != null ? `${Math.round(step.confidence * 100)}%` : '—'}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

export function IncidentList({ incidents }) {
  if (incidents.length === 0) {
    return (
      <div className="panel">
        <p className="alert-feed__empty-subtitle">
          No multi-vector incidents correlated yet. Trigger a multi-stage attack (e.g. the Threat Analysis
          page&rsquo;s replay buttons for recon, then C2, then exfil from the same source) to see one appear
          here in real time.
        </p>
      </div>
    )
  }

  const sorted = [...incidents].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
  return (
    <div className="correlation-incident-list">
      {sorted.map((incident) => (
        <IncidentRow key={incident.flow_id} incident={incident} />
      ))}
    </div>
  )
}
