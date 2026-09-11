import { useState } from 'react'
import AlertFeed from '../components/AlertFeed'
import DetectorMetrics from '../components/DetectorMetrics'

// Evidence signals listed here are the fields the corresponding detector
// already emits in `alert.evidence` per the fixed API contract — nothing
// invented, no telemetry beyond what the backend provides.
const THREAT_DEFINITIONS = {
  ddos: {
    label: 'DDoS / SYN Flood',
    accent: 'var(--threat-ddos)',
    summary:
      'Flags a surge of connections arriving from many distinct source addresses within a short window, or many long-lived low-byte connections held open at once (slow HTTP exhaustion).',
    signals: [
      'Packet rate over a 10-second window',
      'Number of unique source IPs',
      'Source IP entropy versus a configured threshold',
      'Rule-based slow-exhaustion path: many long-duration, low-byte connections to one destination over a 5-minute window — catches Slowloris-style attacks the rate-based path is too fast to see',
    ],
    replayAvailable: true,
  },
  recon: {
    label: 'Recon / Port Scan',
    accent: 'var(--threat-recon)',
    summary:
      'Flags a single source probing an unusually large number of destination ports or hosts.',
    signals: [
      'Unique destination ports contacted',
      'Unique destination hosts contacted',
      'Comparison against a configured port threshold',
    ],
    replayAvailable: true,
  },
  c2: {
    label: 'C2 Beaconing',
    accent: 'var(--threat-c2)',
    summary:
      'Flags recurring connections to the same destination with unusually regular timing.',
    signals: [
      'Mean interval and standard deviation between connections',
      'Coefficient of variation versus a configured threshold',
      'Number of observed connections',
    ],
    replayAvailable: true,
  },
  dga: {
    label: 'DGA / DNS Tunnelling',
    accent: 'var(--threat-dga)',
    summary:
      'Flags algorithmically-generated DNS query names and DNS-tunnelling patterns (long queries with a high answer-to-query byte ratio).',
    signals: [
      'Shannon entropy and character-trigram log-probability of the query name',
      'Word-boundary score (fraction decomposable into real English words) — separates dictionary-style DGA from random',
      'Query length, numeric ratio, and known-TLD check',
      'Rule-based tunnel path: long TXT/NULL queries with a high byte-ratio in either direction (large answer relative to query, or large query relative to answer — validated against a real iodine tunnel)',
    ],
    replayAvailable: true,
  },
  tls: {
    label: 'TLS/QUIC Malware',
    accent: 'var(--threat-tls)',
    summary:
      'Flags malware communicating over encrypted TLS or QUIC sessions, from metadata alone — no payload decryption.',
    signals: [
      'JA3/JA4 fingerprint match against an offline threat-intel blacklist',
      'Flow byte ratio, total bytes, and bytes/sec (flow-stats ML path)',
      'Session duration',
      'Packet-size and inter-arrival-time sequence (mean/std of the first ~12 packets) — catches regular-cadence beacon traffic that byte volume alone looks benign',
      'Protocol indicator (TLS vs QUIC) — the model is trained on real captured traffic from both, not just TLS',
    ],
    replayAvailable: true,
  },
  exfil: {
    label: 'Data Exfiltration',
    accent: 'var(--threat-exfil)',
    summary:
      'Flags asymmetric flow-volume anomalies — unusually large or one-sided outbound transfers, including covert ICMP/DNS channels.',
    signals: [
      'Outbound-to-inbound byte ratio',
      'Rule-based pattern pre-filter: ICMP covert channel, DNS exfil, high-volume upload, or sustained upload',
      'Total bytes transferred and flow duration',
    ],
    replayAvailable: true,
  },
}

// Threat-class-focused view of the active prototype detectors. Reuses
// AlertFeed for the selected class's alerts instead of duplicating rendering.
function ThreatAnalysisPage({ stats, alerts }) {
  const [selected, setSelected] = useState('ddos')
  const [replayState, setReplayState] = useState({ status: 'idle' })

  const definition = THREAT_DEFINITIONS[selected]
  const safeAlerts = Array.isArray(alerts) ? alerts : []
  const relatedAlerts = safeAlerts.filter((alert) => alert && alert.threat_class === selected)
  const count = stats?.[selected] ?? 0

  // Replays a pre-recorded pcap for the selected threat through the same
  // live pipeline real traffic uses (see backend/app.py's /api/replay) --
  // a reliable, on-demand way to trigger a specific detection for a demo,
  // instead of depending on manually timed traffic generator scripts.
  const runReplay = () => {
    setReplayState({ status: 'running' })
    fetch(`/api/replay/${selected}`, { method: 'POST' })
      .then((r) => r.json().then((body) => ({ ok: r.ok, body })))
      .then(({ ok, body }) => {
        if (!ok) throw new Error(body.message || 'replay failed')
        setReplayState({ status: 'done', events: body.events_injected })
      })
      .catch((err) => setReplayState({ status: 'error', message: err.message }))
  }

  return (
    <div className="page">
      <div className="page-intro">
        <h1 className="page-intro__title">Threat Analysis</h1>
        <p className="page-intro__subtitle">Analyze active detector classes</p>
      </div>

      <div className="threat-tabs" role="tablist" aria-label="Threat class">
        {Object.entries(THREAT_DEFINITIONS).map(([key, def]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={selected === key}
            className={`pill-toggle ${selected === key ? 'is-active' : ''}`}
            style={{ '--tab-accent': def.accent }}
            onClick={() => {
              setSelected(key)
              setReplayState({ status: 'idle' })
            }}
          >
            {def.label}
          </button>
        ))}
      </div>

      <div className="panel threat-detail">
        <div className="threat-detail__header">
          <span className="threat-detail__label" style={{ color: definition.accent }}>
            {definition.label}
          </span>
          <span className="threat-detail__count">{count} DETECTED</span>
        </div>
        <p className="threat-detail__summary">{definition.summary}</p>

        <div className="threat-detail__replay">
          {definition.replayAvailable ? (
            <>
              <button
                type="button"
                className="btn"
                onClick={runReplay}
                disabled={replayState.status === 'running'}
              >
                {replayState.status === 'running' ? 'Replaying…' : `Replay ${definition.label} Traffic`}
              </button>
              {replayState.status === 'done' && (
                <span className="threat-detail__replay-note is-ok">
                  Injected {replayState.events} events from a recorded pcap into the live pipeline.
                </span>
              )}
              {replayState.status === 'error' && (
                <span className="threat-detail__replay-note is-error">
                  Replay failed: {replayState.message}
                </span>
              )}
            </>
          ) : (
            <span className="threat-detail__replay-note">{definition.replayNote}</span>
          )}
        </div>
        <div className="threat-detail__signals">
          <span className="threat-detail__signals-title">
            Evidence signals used by this detector
          </span>
          <ul>
            {definition.signals.map((signal) => (
              <li key={signal}>{signal}</li>
            ))}
          </ul>
        </div>
      </div>

      <div className="panel">
        <DetectorMetrics detectorKey={selected} label={definition.label} />
      </div>

      <AlertFeed alerts={relatedAlerts} />
    </div>
  )
}

export default ThreatAnalysisPage
