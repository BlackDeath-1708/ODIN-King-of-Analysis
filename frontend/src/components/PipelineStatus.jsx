import { useEffect, useState } from 'react'

// Live consumer of GET /api/pipeline-status only. This component performs
// no health logic of its own — it renders exactly what the backend reports
// (real file-mtime/socket checks in backend/app.py:pipeline_status()) and
// nothing else. If the endpoint is unreachable, that is shown explicitly;
// it never falls back to assuming everything is online.

const POLL_INTERVAL_MS = 7000

// Each row maps to one field the backend actually returns. `diode` is
// intentionally excluded from this list and handled separately below: it is
// the one row the backend itself labels "simulated," so it must never be
// rendered as a green/red online dot.
const ROWS = [
  { key: 'zeek', label: 'Zeek NSM' },
  { key: 'kafka', label: 'Kafka Event Stream' },
  { key: 'kafka_producer', label: 'Kafka Producer (Zeek → Kafka)' },
  { key: 'stream_detector', label: 'Stream Processor / Detection Engine' },
  { key: 'alert_engine', label: 'Alert Engine' },
]

function PipelineStatus() {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    let cancelled = false

    const poll = () => {
      fetch('/api/pipeline-status')
        .then((r) => {
          if (!r.ok) throw new Error(`HTTP ${r.status}`)
          return r.json()
        })
        .then((data) => {
          if (cancelled) return
          setStatus(data)
          setError(false)
        })
        .catch(() => {
          if (cancelled) return
          setError(true)
        })
    }

    poll()
    const id = setInterval(poll, POLL_INTERVAL_MS)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  if (error || !status) {
    return (
      <div className="panel pipeline-status">
        <div className="panel-title">Hybrid 1 Pipeline — Live Status</div>
        <div className="pipeline-status__unavailable">
          <div className="pipeline-status__unavailable-title">PIPELINE STATUS UNAVAILABLE</div>
          <div className="pipeline-status__unavailable-body">
            Unable to retrieve component health.
          </div>
        </div>
      </div>
    )
  }

  const diode = status.diode || {}

  return (
    <div className="panel pipeline-status">
      <div className="panel-title">Hybrid 1 Pipeline — Live Status</div>

      <div className="pipeline-status__rows">
        <div className="pipeline-status__row">
          <span className="pipeline-status__row-left">
            <span className="badge pipeline-status__simulated">
              {String(diode.status || 'unknown').toUpperCase()}
            </span>
            <span className="pipeline-status__label">Passive Input</span>
          </span>
          <span className="pipeline-status__note">{diode.detail || ''}</span>
        </div>

        {ROWS.map(({ key, label }) => {
          const online = status[key] === true
          return (
            <div
              key={key}
              className={`pipeline-status__row ${online ? 'is-online' : 'is-offline'}`}
            >
              <span className="pipeline-status__row-left">
                <span className="status-dot" />
                <span className="pipeline-status__label">{label}</span>
              </span>
              <span className="pipeline-status__value">{online ? 'ONLINE' : 'OFFLINE'}</span>
            </div>
          )
        })}

        <div className="pipeline-status__row is-online">
          <span className="pipeline-status__row-left">
            <span className="status-dot" />
            <span className="pipeline-status__label">Dashboard</span>
          </span>
          <span className="pipeline-status__value">ONLINE</span>
        </div>
      </div>

      <div className="pipeline-status__footer">
        <div className="pipeline-status__footer-row">
          <span>Read-Only Ingest</span>
          <span className="pipeline-status__footer-value">
            {status.read_only_ingest ? 'ENABLED' : 'DISABLED'}
          </span>
        </div>
        <div className="pipeline-status__footer-row">
          <span>Return Path</span>
          <span className="pipeline-status__footer-value">{String(status.return_path ?? 'N/A')}</span>
        </div>
      </div>
    </div>
  )
}

export default PipelineStatus
