import { PatternSummaryCards, IncidentList } from '../components/CorrelationView'

// Dedicated view of backend/correlation/correlator.py's output: alerts
// with threat_class === 'MULTI_VECTOR' (curated pattern) or
// 'MULTI_VECTOR_ANOMALY' (adaptive statistical layer, ODIN plan Phase C)
// are second, separate alerts the correlator emits alongside (never
// instead of) the individual detector alerts that triggered them (see
// correlator.py's own module docstring). This page never fabricates an
// incident -- an empty `incidents` list renders an honest empty state,
// not a placeholder kill chain.
const CORRELATED_THREAT_CLASSES = new Set(['MULTI_VECTOR', 'MULTI_VECTOR_ANOMALY'])

function CorrelationPage({ alerts }) {
  const safeAlerts = Array.isArray(alerts) ? alerts : []
  const incidents = safeAlerts.filter((a) => CORRELATED_THREAT_CLASSES.has(a?.threat_class))

  return (
    <div className="page">
      <div className="page-intro">
        <h1 className="page-intro__title">Correlation &amp; Kill Chain</h1>
        <p className="page-intro__subtitle">Multi-stage attacks detected across threat classes</p>
        <p className="overview-header__context">
          {incidents.length} correlated incident{incidents.length === 1 ? '' : 's'} in the currently-loaded
          feed
        </p>
      </div>

      <PatternSummaryCards incidents={incidents} />

      <div className="panel-title" style={{ marginTop: 'var(--space-5)' }}>
        Correlated Incidents
      </div>
      <IncidentList incidents={incidents} />
    </div>
  )
}

export default CorrelationPage
