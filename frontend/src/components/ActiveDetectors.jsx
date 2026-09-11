import { useEffect, useState } from 'react'

// Scope statement — all six detectors this prototype implements
// (backend/detectors/{ddos,recon,c2,dga,tls_malware,exfil}.py). `live`
// (from GET /api/detector_status, polled below) reflects whether each
// one's model actually loaded just now — not hardcoded, not derived from
// alert counts (a detector can be healthy with zero alerts).
const DETECTORS = [
  {
    key: 'ddos',
    label: 'DDoS / SYN Flood',
    accent: 'var(--threat-ddos)',
    description: 'Detects high-rate traffic patterns associated with SYN flood activity.',
  },
  {
    key: 'recon',
    label: 'Recon / Port Scan',
    accent: 'var(--threat-recon)',
    description: 'Detects scanning and reconnaissance patterns across ports and hosts.',
  },
  {
    key: 'c2',
    label: 'C2 Beaconing',
    accent: 'var(--threat-c2)',
    description:
      'Detects periodic communication patterns associated with command-and-control activity.',
  },
  {
    key: 'dga',
    label: 'DGA / DNS Tunnelling',
    accent: 'var(--threat-dga)',
    description: 'Detects algorithmically generated domains and encoded-payload DNS tunnels.',
  },
  {
    key: 'tls',
    label: 'TLS Malware (JA3)',
    accent: 'var(--threat-tls)',
    description: 'Detects malicious TLS sessions via JA3 fingerprint blacklist and flow statistics.',
  },
  {
    key: 'exfil',
    label: 'Data Exfiltration',
    accent: 'var(--threat-exfil)',
    description: 'Detects asymmetric-volume uploads, ICMP covert channels, and DNS exfiltration.',
  },
]

// green = model loaded and ready, orange = model file missing, red = model
// present but failed to load, grey = status not yet fetched (initial render).
const STATUS_COLOR = {
  ok: 'var(--status-live)',
  model_missing: 'var(--status-warning)',
  error: 'var(--status-offline)',
}

function useDetectorStatus() {
  const [status, setStatus] = useState({})
  useEffect(() => {
    fetch('/api/detector_status')
      .then((r) => r.json())
      .then(setStatus)
      .catch(() => {})
  }, [])
  return status
}

function StatusDot({ entry }) {
  const color = entry ? STATUS_COLOR[entry.status] ?? 'var(--text-tertiary)' : 'var(--text-tertiary)'
  const title = entry
    ? `${entry.status}${entry.status === 'ok' ? ` (${entry.calibrated ? 'calibrated' : 'base'} model, F1 ${entry.f1})` : ''}`
    : 'checking…'
  return <span className="active-detectors__status-dot" style={{ background: color }} title={title} />
}

function ActiveDetectors({ compact = false }) {
  const status = useDetectorStatus()

  if (compact) {
    return (
      <div className="active-detectors">
        <ul className="active-detectors__list">
          {DETECTORS.map((d) => (
            <li key={d.key} className="active-detectors__item" style={{ color: d.accent }}>
              <StatusDot entry={status[d.key]} /> {d.label}
            </li>
          ))}
        </ul>
        <span className="active-detectors__caption">6 active prototype detectors</span>
      </div>
    )
  }

  return (
    <div className="active-detectors">
      <div className="panel-title">Active Prototype Detectors</div>
      <p className="panel-subtitle active-detectors__subtitle">
        Detection capabilities currently enabled in this prototype
      </p>

      <ul className="active-detectors__detail-list">
        {DETECTORS.map((d) => (
          <li key={d.key} className="active-detectors__detail-item">
            <StatusDot entry={status[d.key]} />
            <span
              className="active-detectors__detail-accent"
              style={{ background: d.accent }}
              aria-hidden="true"
            />
            <div>
              <div className="active-detectors__detail-label" style={{ color: d.accent }}>
                {d.label}
                {status[d.key]?.status === 'ok' && (
                  <span className="active-detectors__f1"> — F1 {status[d.key].f1}</span>
                )}
              </div>
              <div className="active-detectors__detail-description">{d.description}</div>
            </div>
          </li>
        ))}
      </ul>

      <span className="active-detectors__caption">6 active prototype detectors</span>
    </div>
  )
}

export default ActiveDetectors
