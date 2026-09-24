import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  PieChart,
  Pie,
  Legend,
} from 'recharts'

// Five real-data visualizations for AnalyticsPage.jsx, all derived
// client-side from the same `alerts` array App.jsx already loads (no new
// backend endpoint needed) -- deliberately distinct dimensions from the
// existing Overview/Alerts-page views (threat-class distribution and
// alerts-over-time already exist as ThreatChart/ThreatDonut and
// AlertsTimeline): source IP concentration, severity mix, confidence
// calibration spread, targeted ports, and hour-of-day activity pattern.
// Every chart renders an honest empty state instead of a fabricated
// placeholder when `alerts` is empty.

const SEVERITY_COLORS = {
  CRITICAL: 'var(--severity-critical)',
  HIGH: 'var(--severity-high)',
  MEDIUM: 'var(--severity-medium)',
  LOW: 'var(--severity-low)',
}

const TOOLTIP_STYLE = {
  background: 'var(--bg-elevated)',
  border: '1px solid var(--border-strong)',
  borderRadius: 'var(--radius-sm)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-sm)',
}

function EmptyChart({ label }) {
  return <div className="analytics-chart__empty">{label}</div>
}

function tallyBy(alerts, keyFn) {
  const counts = new Map()
  for (const alert of alerts) {
    const key = keyFn(alert)
    if (key === null || key === undefined || key === '') continue
    counts.set(key, (counts.get(key) || 0) + 1)
  }
  return counts
}

export function TopSourceIPs({ alerts }) {
  const counts = tallyBy(alerts, (a) => a.src_ip)
  const data = [...counts.entries()]
    .map(([src_ip, count]) => ({ src_ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8)

  if (data.length === 0) return <EmptyChart label="No source IPs observed yet" />

  return (
    <ResponsiveContainer width="100%" height={Math.max(160, data.length * 34)}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
        <XAxis type="number" allowDecimals={false} tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
        <YAxis
          type="category"
          dataKey="src_ip"
          width={110}
          tick={{ fill: 'var(--text-secondary)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
        />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'var(--bg-inset)' }} />
        <Bar dataKey="count" fill="var(--accent)" radius={[0, 4, 4, 0]} name="Alerts" />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function SeverityBreakdown({ alerts }) {
  const counts = tallyBy(alerts, (a) => a.severity)
  const data = [...counts.entries()].map(([severity, value]) => ({ severity, value }))

  if (data.length === 0) return <EmptyChart label="No severities recorded yet" />

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="severity"
          innerRadius={50}
          outerRadius={80}
          paddingAngle={2}
        >
          {data.map((entry) => (
            <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] || 'var(--text-tertiary)'} />
          ))}
        </Pie>
        <Legend
          verticalAlign="bottom"
          height={28}
          wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)' }}
        />
        <Tooltip contentStyle={TOOLTIP_STYLE} />
      </PieChart>
    </ResponsiveContainer>
  )
}

const CONFIDENCE_BUCKETS = 10

export function ConfidenceHistogram({ alerts }) {
  const withConfidence = alerts.filter((a) => typeof a.confidence === 'number')
  if (withConfidence.length === 0) return <EmptyChart label="No confidence scores recorded yet" />

  const buckets = Array.from({ length: CONFIDENCE_BUCKETS }, (_, i) => ({
    range: `${i * 10}-${i * 10 + 10}%`,
    count: 0,
  }))
  for (const alert of withConfidence) {
    const idx = Math.min(CONFIDENCE_BUCKETS - 1, Math.floor(alert.confidence * CONFIDENCE_BUCKETS))
    buckets[idx].count += 1
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={buckets} margin={{ left: -16, right: 8, top: 4, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis dataKey="range" tick={{ fill: 'var(--text-tertiary)', fontSize: 10 }} interval={1} />
        <YAxis allowDecimals={false} tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'var(--bg-inset)' }} />
        <Bar dataKey="count" fill="var(--threat-c2)" radius={[4, 4, 0, 0]} name="Alerts" />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function TargetedPorts({ alerts }) {
  const counts = tallyBy(alerts, (a) => a.dst_port)
  const data = [...counts.entries()]
    .map(([port, count]) => ({ port: String(port), count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8)

  if (data.length === 0) return <EmptyChart label="No destination ports recorded yet" />

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ left: -16, right: 8, top: 4, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis dataKey="port" tick={{ fill: 'var(--text-tertiary)', fontSize: 11, fontFamily: 'var(--font-mono)' }} />
        <YAxis allowDecimals={false} tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'var(--bg-inset)' }} />
        <Bar dataKey="count" fill="var(--threat-recon)" radius={[4, 4, 0, 0]} name="Flows" />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function ActivityByHour({ alerts }) {
  const timed = alerts.filter((a) => a.timestamp)
  if (timed.length === 0) return <EmptyChart label="No timestamped alerts yet" />

  const hours = Array.from({ length: 24 }, (_, h) => ({ hour: h, count: 0 }))
  for (const alert of timed) {
    const d = new Date(alert.timestamp)
    if (Number.isNaN(d.getTime())) continue
    hours[d.getHours()].count += 1
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={hours} margin={{ left: -16, right: 8, top: 4, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis
          dataKey="hour"
          tickFormatter={(h) => `${h}:00`}
          tick={{ fill: 'var(--text-tertiary)', fontSize: 10 }}
          interval={2}
        />
        <YAxis allowDecimals={false} tick={{ fill: 'var(--text-tertiary)', fontSize: 11 }} />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          cursor={{ fill: 'var(--bg-inset)' }}
          labelFormatter={(h) => `${h}:00 - ${h}:59 (browser local time)`}
        />
        <Bar dataKey="count" fill="var(--threat-tls)" radius={[4, 4, 0, 0]} name="Alerts" />
      </BarChart>
    </ResponsiveContainer>
  )
}
