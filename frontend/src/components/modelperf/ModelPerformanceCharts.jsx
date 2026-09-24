import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts'

// Cross-detector comparison charts for ModelPerformancePage.jsx, built
// entirely from GET /api/model_metrics (per-detector held-out precision/
// recall/F1/FPR/FNR/confusion-matrix from training/metrics_utils.py, plus
// inference latency from scripts/benchmark_throughput.py). DetectorMetrics.jsx
// already shows one detector's numbers in depth on the Threat Analysis page;
// this is the side-by-side view across all six.

const DETECTOR_LABELS = {
  ddos: 'DDoS',
  recon: 'Recon',
  c2: 'C2',
  dga: 'DGA',
  tls: 'TLS',
  exfil: 'Exfil',
  tls_tier2: 'TLS (Tier-2)',
}

const THREAT_ACCENTS = {
  ddos: 'var(--threat-ddos)',
  recon: 'var(--threat-recon)',
  c2: 'var(--threat-c2)',
  dga: 'var(--threat-dga)',
  tls: 'var(--threat-tls)',
  exfil: 'var(--threat-exfil)',
  tls_tier2: 'var(--threat-tls)',
}

const TOOLTIP_STYLE = {
  background: 'var(--bg-elevated)',
  border: '1px solid var(--border-strong)',
  borderRadius: 'var(--radius-sm)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-sm)',
}

// Primary six only, in PS 26145's own (a)-(f) order -- tls_tier2 is a
// second model for the same threat class, not a 7th independent detector,
// so it's shown separately rather than crowding this cross-detector view.
const PRIMARY_ORDER = ['ddos', 'recon', 'c2', 'dga', 'tls', 'exfil']

function pct(v) {
  return v == null ? null : Math.round(v * 1000) / 10 // one decimal, as a percent
}

export function MetricsBarChart({ detectors }) {
  const data = PRIMARY_ORDER.filter((k) => detectors[k]).map((key) => ({
    name: DETECTOR_LABELS[key] || key,
    Precision: pct(detectors[key].precision),
    Recall: pct(detectors[key].recall),
    F1: pct(detectors[key].f1),
  }))

  if (data.length === 0) return <div className="analytics-chart__empty">No model metrics available yet</div>

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} margin={{ left: -16, right: 8, top: 4, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis dataKey="name" tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
        <YAxis unit="%" domain={[0, 100]} tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'var(--bg-inset)' }} />
        <Legend wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)' }} />
        <Bar dataKey="Precision" fill="var(--accent)" radius={[4, 4, 0, 0]} />
        <Bar dataKey="Recall" fill="var(--status-live)" radius={[4, 4, 0, 0]} />
        <Bar dataKey="F1" fill="var(--severity-medium)" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function FalseRateChart({ detectors }) {
  const data = PRIMARY_ORDER.filter((k) => detectors[k]).map((key) => ({
    name: DETECTOR_LABELS[key] || key,
    'False Positive Rate': pct(detectors[key].false_positive_rate),
    'False Negative Rate': pct(detectors[key].false_negative_rate),
  }))

  if (data.length === 0) return <div className="analytics-chart__empty">No model metrics available yet</div>

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ left: -16, right: 8, top: 4, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis dataKey="name" tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
        <YAxis unit="%" tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'var(--bg-inset)' }} />
        <Legend wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)' }} />
        <Bar dataKey="False Positive Rate" fill="var(--severity-high)" radius={[4, 4, 0, 0]} />
        <Bar dataKey="False Negative Rate" fill="var(--severity-critical)" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function MetricsRadar({ detectors }) {
  const keys = PRIMARY_ORDER.filter((k) => detectors[k])
  if (keys.length === 0) return <div className="analytics-chart__empty">No model metrics available yet</div>

  const axes = ['precision', 'recall', 'f1']
  const data = axes.map((axis) => {
    const row = { axis: axis === 'f1' ? 'F1' : axis[0].toUpperCase() + axis.slice(1) }
    for (const key of keys) row[DETECTOR_LABELS[key] || key] = pct(detectors[key][axis])
    return row
  })

  return (
    <ResponsiveContainer width="100%" height={280}>
      <RadarChart data={data} outerRadius="70%">
        <PolarGrid stroke="var(--border)" />
        <PolarAngleAxis dataKey="axis" tick={{ fill: 'var(--text-secondary)', fontSize: 12 }} />
        <PolarRadiusAxis domain={[0, 100]} tick={{ fill: 'var(--text-tertiary)', fontSize: 9 }} />
        {keys.map((key) => (
          <Radar
            key={key}
            name={DETECTOR_LABELS[key] || key}
            dataKey={DETECTOR_LABELS[key] || key}
            stroke={THREAT_ACCENTS[key]}
            fill={THREAT_ACCENTS[key]}
            fillOpacity={0.12}
          />
        ))}
        <Legend wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)' }} />
        <Tooltip contentStyle={TOOLTIP_STYLE} />
      </RadarChart>
    </ResponsiveContainer>
  )
}

export function LatencyChart({ detectors }) {
  const data = Object.keys(detectors)
    .filter((k) => detectors[k].inference_latency_ms != null)
    .map((key) => ({
      name: DETECTOR_LABELS[key] || key,
      latency: Math.round(detectors[key].inference_latency_ms * 10) / 10,
    }))
    .sort((a, b) => b.latency - a.latency)

  if (data.length === 0) {
    return (
      <div className="analytics-chart__empty">
        No latency benchmark yet — run <code>scripts/benchmark_throughput.py</code>
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 32)}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 24, top: 4, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
        <XAxis type="number" unit="ms" tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
        <YAxis type="category" dataKey="name" width={90} tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'var(--bg-inset)' }} />
        <Bar dataKey="latency" fill="var(--threat-c2)" radius={[0, 4, 4, 0]} name="Median latency (ms)" />
      </BarChart>
    </ResponsiveContainer>
  )
}

export { DETECTOR_LABELS, PRIMARY_ORDER }
