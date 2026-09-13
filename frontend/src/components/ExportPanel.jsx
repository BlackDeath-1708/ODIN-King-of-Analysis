import { useState } from 'react'

// Client-side triggers for the standardized alert-export endpoints
// (PS 26145's "standardized alert schema" requirement -- see
// backend/alert_export.py): GET /api/alerts/stix (STIX 2.1 Bundle) and
// GET /api/alerts/cef (CEF syslog lines) are already live on the backend
// but had no UI trigger before this page. CSV/JSON export below is purely
// client-side, over whatever `alerts` is already loaded -- no new
// endpoint, since the data is already in the browser.

async function downloadFromEndpoint(url, filename) {
  const res = await fetch(url)
  const blob = await res.blob()
  const objectUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = objectUrl
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(objectUrl)
}

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType })
  const objectUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = objectUrl
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(objectUrl)
}

const CSV_COLUMNS = [
  'timestamp', 'flow_id', 'threat_class', 'threat_label', 'severity',
  'confidence', 'calibrated', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'detector',
]

function toCsv(alerts) {
  const escape = (v) => {
    const s = v === null || v === undefined ? '' : String(v)
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const header = CSV_COLUMNS.join(',')
  const rows = alerts.map((a) => CSV_COLUMNS.map((col) => escape(a[col])).join(','))
  return [header, ...rows].join('\n')
}

function ExportPanel({ alerts }) {
  const [status, setStatus] = useState(null)
  const safeAlerts = Array.isArray(alerts) ? alerts : []

  const withStatus = async (label, fn) => {
    setStatus(`Preparing ${label}…`)
    try {
      await fn()
      setStatus(`${label} downloaded.`)
    } catch {
      setStatus(`${label} failed — check the API connection.`)
    }
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-')

  return (
    <div className="panel export-panel">
      <div className="panel-title">Standardized Alert Export</div>
      <p className="panel-subtitle">
        PS 26145&rsquo;s standardized-alert-schema requirement — export the currently-loaded
        {' '}{safeAlerts.length} alert{safeAlerts.length === 1 ? '' : 's'} for downstream SOC/SIEM/TIP
        ingestion
      </p>

      <div className="export-panel__grid">
        <div className="export-panel__option">
          <div className="export-panel__option-title">STIX 2.1 Bundle</div>
          <p className="export-panel__option-desc">
            Indicator/Sighting objects, for TIP ingestion (air-gapped compatible).
          </p>
          <button
            type="button"
            className="btn"
            onClick={() => withStatus('STIX bundle', () =>
              downloadFromEndpoint('/api/alerts/stix', `odin-alerts-${stamp}.stix.json`))}
          >
            Download STIX Bundle
          </button>
        </div>

        <div className="export-panel__option">
          <div className="export-panel__option-title">CEF Syslog Lines</div>
          <p className="export-panel__option-desc">
            ArcSight Common Event Format, one line per alert, for SIEM ingestion.
          </p>
          <button
            type="button"
            className="btn"
            onClick={() => withStatus('CEF log', () =>
              downloadFromEndpoint('/api/alerts/cef', `odin-alerts-${stamp}.cef.log`))}
          >
            Download CEF Log
          </button>
        </div>

        <div className="export-panel__option">
          <div className="export-panel__option-title">CSV</div>
          <p className="export-panel__option-desc">
            Flat spreadsheet of the currently-loaded alerts — timestamp, flow, class, severity, confidence.
          </p>
          <button
            type="button"
            className="btn"
            disabled={safeAlerts.length === 0}
            onClick={() => withStatus('CSV', () =>
              downloadBlob(toCsv(safeAlerts), `odin-alerts-${stamp}.csv`, 'text/csv'))}
          >
            Download CSV
          </button>
        </div>

        <div className="export-panel__option">
          <div className="export-panel__option-title">Raw JSON</div>
          <p className="export-panel__option-desc">
            The full alert objects exactly as received, evidence field included.
          </p>
          <button
            type="button"
            className="btn"
            disabled={safeAlerts.length === 0}
            onClick={() => withStatus('JSON', () =>
              downloadBlob(JSON.stringify(safeAlerts, null, 2), `odin-alerts-${stamp}.json`, 'application/json'))}
          >
            Download JSON
          </button>
        </div>
      </div>

      {status && <p className="export-panel__status">{status}</p>}
    </div>
  )
}

export default ExportPanel
