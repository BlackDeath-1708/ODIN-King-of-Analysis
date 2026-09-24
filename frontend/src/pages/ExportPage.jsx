import ExportPanel from '../components/ExportPanel'

// Standardized export (STIX/CEF/CSV/JSON, see ExportPanel.jsx) plus an
// auto-generated incident summary built entirely from the currently-loaded
// `alerts`/`stats` — every number here is a real count derived on render,
// never a fabricated placeholder. "Print Report" uses the browser's own
// print dialog (no PDF library needed) with a print stylesheet that hides
// chrome/nav and keeps only this page's content.
function ExportPage({ alerts, stats }) {
  const safeAlerts = Array.isArray(alerts) ? alerts : []

  const bySeverity = {}
  const byThreatClass = {}
  for (const alert of safeAlerts) {
    if (alert.severity) bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1
    if (alert.threat_class) byThreatClass[alert.threat_class] = (byThreatClass[alert.threat_class] || 0) + 1
  }

  const topAlerts = [...safeAlerts]
    .filter((a) => a.severity === 'CRITICAL' || a.severity === 'HIGH')
    .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
    .slice(0, 5)

  const generatedAt = new Date().toLocaleString()

  return (
    <div className="page">
      <div className="page-intro no-print">
        <h1 className="page-intro__title">Export &amp; Reports</h1>
        <p className="page-intro__subtitle">Standardized export and an auto-generated incident summary</p>
      </div>

      <div className="no-print">
        <ExportPanel alerts={safeAlerts} />
      </div>

      <div className="panel export-report">
        <div className="export-report__header">
          <div>
            <div className="panel-title">Incident Summary Report</div>
            <p className="panel-subtitle">Generated {generatedAt} from {safeAlerts.length} loaded alerts</p>
          </div>
          <button type="button" className="btn no-print" onClick={() => window.print()}>
            Print Report
          </button>
        </div>

        <div className="export-report__section">
          <h3 className="export-report__section-title">Totals</h3>
          <div className="alerts-summary">
            <div className="alerts-summary__card">
              <span className="alerts-summary__value">{stats?.total ?? safeAlerts.length}</span>
              <span className="alerts-summary__label">Total Alerts</span>
            </div>
            {Object.entries(byThreatClass).map(([tc, count]) => (
              <div key={tc} className="alerts-summary__card">
                <span className="alerts-summary__value" style={{ color: `var(--threat-${tc.toLowerCase()})` }}>
                  {count}
                </span>
                <span className="alerts-summary__label">{tc}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="export-report__section">
          <h3 className="export-report__section-title">By Severity</h3>
          {Object.keys(bySeverity).length === 0 ? (
            <p className="detector-metrics__empty">No alerts loaded.</p>
          ) : (
            <ul className="export-report__list">
              {Object.entries(bySeverity).map(([sev, count]) => (
                <li key={sev}>
                  <strong>{sev}</strong>: {count}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="export-report__section">
          <h3 className="export-report__section-title">Top Critical / High Severity Findings</h3>
          {topAlerts.length === 0 ? (
            <p className="detector-metrics__empty">No critical or high-severity alerts in the loaded feed.</p>
          ) : (
            <table className="detector-metrics__confusion-table export-report__table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Threat</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                  <th>Source</th>
                  <th>Destination</th>
                </tr>
              </thead>
              <tbody>
                {topAlerts.map((a, i) => (
                  <tr key={`${a.flow_id}-${i}`}>
                    <td>{new Date(a.timestamp).toLocaleTimeString()}</td>
                    <td>{a.threat_label || a.threat_class}</td>
                    <td>{a.severity}</td>
                    <td>{a.confidence != null ? `${Math.round(a.confidence * 100)}%` : '—'}</td>
                    <td>{a.src_ip}</td>
                    <td>{a.dst_ip}{a.dst_port ? `:${a.dst_port}` : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <p className="export-report__disclaimer">
          Generated client-side from the monitoring dashboard&rsquo;s currently-loaded alert feed. This is
          not a substitute for the full STIX/CEF export above for formal SOC/SIEM ingestion.
        </p>
      </div>
    </div>
  )
}

export default ExportPage
