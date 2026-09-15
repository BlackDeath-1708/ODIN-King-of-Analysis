// Hand-rolled inline-SVG bar chart of alert volume over time, bucketed by
// threat class per bucket (stacked) -- same no-charting-library convention
// as ThreatDonut.jsx/ThroughputSparkline.jsx. Pure presentational: buckets
// whatever `alerts` it's handed (already-loaded client-side array, the
// same one AlertFeed renders) into N equal time windows spanning oldest to
// newest, so this reflects the visible feed's own time range rather than
// assuming a fixed wall-clock window.
const BUCKET_COUNT = 16
const HEIGHT = 64

const THREAT_ACCENTS = {
  ddos: 'var(--threat-ddos)',
  recon: 'var(--threat-recon)',
  c2: 'var(--threat-c2)',
  dga: 'var(--threat-dga)',
  tls: 'var(--threat-tls)',
  exfil: 'var(--threat-exfil)',
  MULTI_VECTOR: 'var(--threat-multi-vector)',
  MULTI_VECTOR_ANOMALY: 'var(--threat-multi-vector)',
}
const THREAT_ORDER = ['ddos', 'recon', 'c2', 'dga', 'tls', 'exfil', 'MULTI_VECTOR', 'MULTI_VECTOR_ANOMALY']

function bucketize(alerts) {
  const timed = alerts
    .map((a) => ({ alert: a, ts: a?.timestamp ? new Date(a.timestamp).getTime() : NaN }))
    .filter((a) => !Number.isNaN(a.ts))
    .sort((a, b) => a.ts - b.ts)

  if (timed.length === 0) return { buckets: [], maxTotal: 0, start: null, end: null }

  const start = timed[0].ts
  const end = timed[timed.length - 1].ts
  const span = Math.max(end - start, 1)
  const buckets = Array.from({ length: BUCKET_COUNT }, () => ({}))

  for (const { alert, ts } of timed) {
    const idx = Math.min(BUCKET_COUNT - 1, Math.floor(((ts - start) / span) * BUCKET_COUNT))
    const cls = THREAT_ACCENTS[alert.threat_class] ? alert.threat_class : 'other'
    buckets[idx][cls] = (buckets[idx][cls] ?? 0) + 1
  }

  const maxTotal = Math.max(
    ...buckets.map((b) => Object.values(b).reduce((sum, n) => sum + n, 0)),
    1
  )

  return { buckets, maxTotal, start, end }
}

function AlertsTimeline({ alerts }) {
  const safeAlerts = Array.isArray(alerts) ? alerts : []
  const { buckets, maxTotal, start, end } = bucketize(safeAlerts)

  if (buckets.length === 0) {
    return (
      <div className="panel alerts-timeline">
        <div className="panel-title">Alerts Over Time</div>
        <div className="threat-chart__empty">No alerts yet</div>
      </div>
    )
  }

  const fmt = (ms) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

  return (
    <div className="panel alerts-timeline">
      <div className="panel-title">Alerts Over Time</div>
      <p className="panel-subtitle alerts-timeline__subtitle">
        Volume by threat class across the currently-loaded alert feed
      </p>
      <div className="alerts-timeline__chart" style={{ height: HEIGHT }}>
        {buckets.map((bucket, i) => {
          const entries = THREAT_ORDER.filter((k) => bucket[k]).map((k) => [k, bucket[k]])
          const total = entries.reduce((sum, [, n]) => sum + n, 0)
          const barHeight = total > 0 ? (total / maxTotal) * HEIGHT : 0
          return (
            <div
              key={i}
              className="alerts-timeline__bar-slot"
              title={total > 0 ? `${total} alert${total === 1 ? '' : 's'}` : undefined}
            >
              <div className="alerts-timeline__bar" style={{ height: `${barHeight}px` }}>
                {entries.map(([cls, n]) => (
                  <div
                    key={cls}
                    className="alerts-timeline__segment"
                    style={{
                      height: `${(n / total) * 100}%`,
                      background: THREAT_ACCENTS[cls] ?? 'var(--text-tertiary)',
                    }}
                  />
                ))}
              </div>
            </div>
          )
        })}
      </div>
      <div className="alerts-timeline__axis">
        <span>{fmt(start)}</span>
        <span>{fmt(end)}</span>
      </div>
    </div>
  )
}

export default AlertsTimeline
