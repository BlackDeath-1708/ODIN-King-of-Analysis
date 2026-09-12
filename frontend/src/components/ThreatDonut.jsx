// Hand-rolled inline-SVG donut chart -- no charting library, matching this
// project's existing convention (see ThroughputSparkline.jsx's own
// comment): a handful of small visuals here don't justify a new
// dependency. Pure presentational: takes the same {key, label, accent,
// count} shape ThreatChart.jsx already computes, draws nothing else.
const SIZE = 120
const STROKE = 16
const RADIUS = (SIZE - STROKE) / 2
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

function ThreatDonut({ categories, total }) {
  if (total === 0) {
    return null
  }

  const segments = categories
    .filter((c) => c.count > 0)
    .reduce((acc, c) => {
      const cumulative = acc.length > 0 ? acc[acc.length - 1].cumulative : 0
      const arcLength = (c.count / total) * CIRCUMFERENCE
      return [...acc, { ...c, arcLength, offset: -cumulative, cumulative: cumulative + arcLength }]
    }, [])

  return (
    <div className="threat-donut">
      <svg
        className="threat-donut__svg"
        width={SIZE}
        height={SIZE}
        viewBox={`0 0 ${SIZE} ${SIZE}`}
        role="img"
        aria-label={`Threat distribution donut chart, ${total} total alerts`}
      >
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          stroke="var(--border)"
          strokeWidth={STROKE}
        />
        <g transform={`rotate(-90 ${SIZE / 2} ${SIZE / 2})`}>
          {segments.map((segment) => (
            <circle
              key={segment.key}
              cx={SIZE / 2}
              cy={SIZE / 2}
              r={RADIUS}
              fill="none"
              stroke={segment.accent}
              strokeWidth={STROKE}
              strokeDasharray={`${segment.arcLength} ${CIRCUMFERENCE - segment.arcLength}`}
              strokeDashoffset={segment.offset}
              strokeLinecap={segments.length > 1 ? 'butt' : 'round'}
            />
          ))}
        </g>
      </svg>
      <div className="threat-donut__center">
        <span className="threat-donut__center-value">{total}</span>
        <span className="threat-donut__center-label">alerts</span>
      </div>
    </div>
  )
}

export default ThreatDonut
