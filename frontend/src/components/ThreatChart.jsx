// Displays threat distribution only — no data fetching, no state ownership.
const THREAT_CATEGORIES = [
  { key: 'ddos', label: 'DDoS / SYN Flood', accent: 'var(--threat-ddos)' },
  { key: 'recon', label: 'Recon / Port Scan', accent: 'var(--threat-recon)' },
  { key: 'c2', label: 'C2 Beaconing', accent: 'var(--threat-c2)' },
  { key: 'dga', label: 'DGA / DNS Tunnelling', accent: 'var(--threat-dga)' },
  { key: 'tls', label: 'TLS Malware (JA3)', accent: 'var(--threat-tls)' },
  { key: 'exfil', label: 'Data Exfiltration', accent: 'var(--threat-exfil)' },
]

function ThreatChart({ stats, subtitle }) {
  const counts = THREAT_CATEGORIES.map((category) => ({
    ...category,
    count: stats[category.key] ?? 0,
  }))

  const sum = counts.reduce((acc, c) => acc + c.count, 0)
  const maxCount = Math.max(...counts.map((c) => c.count), 0)

  return (
    <div className="panel threat-chart">
      <div className="threat-chart__header">
        <div className="panel-title">Threat Distribution</div>
        {subtitle && <div className="panel-subtitle">{subtitle}</div>}
      </div>

      {sum === 0 ? (
        <div className="threat-chart__empty">No threats detected</div>
      ) : (
        <div className="threat-chart__rows">
          {counts.map((category) => {
            const barWidth = maxCount > 0 ? (category.count / maxCount) * 100 : 0
            const percent = sum > 0 ? Math.round((category.count / sum) * 100) : null

            return (
              <div key={category.key} className="threat-chart__row">
                <div className="threat-chart__row-header">
                  <span className="threat-chart__row-label">{category.label}</span>
                  <span className="threat-chart__row-count" style={{ color: category.accent }}>
                    {category.count}
                    {percent !== null ? ` · ${percent}%` : ''}
                  </span>
                </div>
                <div className="threat-chart__track">
                  <div
                    className="threat-chart__fill"
                    style={{ width: `${barWidth}%`, background: category.accent }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default ThreatChart
