import { useState } from 'react'
import AlertFeed from '../components/AlertFeed'

// All filtering below is client-side over the alerts already delivered via
// SSE/GET (App.jsx owns fetching, SSE, dedup, and the reconciliation poll —
// none of that is touched here). This page only narrows what it hands to
// AlertFeed, which continues to own all row/evidence/details rendering.

const THREAT_FILTERS = [
  { value: 'all', label: 'All' },
  { value: 'ddos', label: 'DDoS', accent: 'var(--threat-ddos)' },
  { value: 'recon', label: 'Recon', accent: 'var(--threat-recon)' },
  { value: 'c2', label: 'C2', accent: 'var(--threat-c2)' },
  { value: 'dga', label: 'DGA', accent: 'var(--threat-dga)' },
  { value: 'tls', label: 'TLS', accent: 'var(--threat-tls)' },
  { value: 'exfil', label: 'Exfil', accent: 'var(--threat-exfil)' },
  { value: 'MULTI_VECTOR', label: 'Multi-Vector', accent: 'var(--threat-multi-vector)' },
]

// Keyed by the backend's actual severity strings — never numeric, never guessed.
const SEVERITY_FILTERS = [
  { value: 'all', label: 'All' },
  { value: 'CRITICAL', label: 'Critical', accent: 'var(--severity-critical)' },
  { value: 'HIGH', label: 'High', accent: 'var(--severity-high)' },
  { value: 'MEDIUM', label: 'Medium', accent: 'var(--severity-medium)' },
  { value: 'LOW', label: 'Low', accent: 'var(--severity-low)' },
]

function AlertsPage({ alerts, stats }) {
  const [search, setSearch] = useState('')
  const [threatFilter, setThreatFilter] = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')

  const safeAlerts = Array.isArray(alerts) ? alerts : []
  const term = search.trim().toLowerCase()
  const filtersActive = threatFilter !== 'all' || severityFilter !== 'all' || term !== ''

  const filteredAlerts = safeAlerts.filter((alert) => {
    if (!alert) return false
    if (threatFilter !== 'all' && alert.threat_class !== threatFilter) return false
    if (severityFilter !== 'all' && alert.severity !== severityFilter) return false
    if (term && !String(alert.src_ip || '').toLowerCase().includes(term)) return false
    return true
  })

  // Real values only, from App's own `stats` state (the backend's actual
  // aggregate counts) — distinct from the "loaded alerts" count below,
  // which reflects only the bounded client-side array.
  const summaryCards = [
    { key: 'total', label: 'Total', value: stats?.total ?? 0 },
    { key: 'ddos', label: 'DDoS', value: stats?.ddos ?? 0, accent: 'var(--threat-ddos)' },
    { key: 'recon', label: 'Recon', value: stats?.recon ?? 0, accent: 'var(--threat-recon)' },
    { key: 'c2', label: 'C2', value: stats?.c2 ?? 0, accent: 'var(--threat-c2)' },
    { key: 'dga', label: 'DGA', value: stats?.dga ?? 0, accent: 'var(--threat-dga)' },
    { key: 'tls', label: 'TLS', value: stats?.tls ?? 0, accent: 'var(--threat-tls)' },
    { key: 'exfil', label: 'Exfil', value: stats?.exfil ?? 0, accent: 'var(--threat-exfil)' },
  ]

  // Distinguishes "no filtered results" from "no alerts exist" — the latter
  // falls through to AlertFeed's own default empty state unchanged.
  const noMatches = filtersActive && filteredAlerts.length === 0 && safeAlerts.length > 0

  return (
    <div className="page">
      <div className="page-intro">
        <h1 className="page-intro__title">Alerts</h1>
        <p className="page-intro__subtitle">Review and investigate detected network threats</p>
        <p className="overview-header__context">
          Evidence-backed detections from the monitoring pipeline
        </p>
      </div>

      <div className="alerts-summary">
        {summaryCards.map((card) => (
          <div key={card.key} className="alerts-summary__card">
            <span
              className="alerts-summary__value"
              style={card.accent ? { color: card.accent } : undefined}
            >
              {card.value}
            </span>
            <span className="alerts-summary__label">{card.label}</span>
          </div>
        ))}
      </div>

      <div className="alerts-toolbar">
        <input
          type="text"
          className="alerts-toolbar__search"
          placeholder="Filter by source IP"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          aria-label="Filter alerts by source IP"
        />

        <div className="alerts-toolbar__filter-groups">
          <div className="alerts-toolbar__filter-group">
            <span className="alerts-toolbar__group-label">Threat</span>
            <div
              className="alerts-toolbar__filters"
              role="group"
              aria-label="Filter by threat class"
            >
              {THREAT_FILTERS.map((filter) => (
                <button
                  key={filter.value}
                  type="button"
                  className={`pill-toggle ${threatFilter === filter.value ? 'is-active' : ''}`}
                  aria-pressed={threatFilter === filter.value}
                  style={filter.accent ? { '--tab-accent': filter.accent } : undefined}
                  onClick={() => setThreatFilter(filter.value)}
                >
                  {filter.label}
                </button>
              ))}
            </div>
          </div>

          <div className="alerts-toolbar__filter-group">
            <span className="alerts-toolbar__group-label">Severity</span>
            <div
              className="alerts-toolbar__filters"
              role="group"
              aria-label="Filter by severity"
            >
              {SEVERITY_FILTERS.map((filter) => (
                <button
                  key={filter.value}
                  type="button"
                  className={`pill-toggle ${severityFilter === filter.value ? 'is-active' : ''}`}
                  aria-pressed={severityFilter === filter.value}
                  style={filter.accent ? { '--tab-accent': filter.accent } : undefined}
                  onClick={() => setSeverityFilter(filter.value)}
                >
                  {filter.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <AlertFeed
        alerts={filteredAlerts}
        subtitle={
          filtersActive
            ? `${filteredAlerts.length} of ${safeAlerts.length} loaded alerts`
            : undefined
        }
        emptyTitle={noMatches ? 'NO ALERTS MATCH THE CURRENT FILTERS' : undefined}
        emptySubtitle={noMatches ? 'Try adjusting or clearing the filters above.' : undefined}
      />
    </div>
  )
}

export default AlertsPage
