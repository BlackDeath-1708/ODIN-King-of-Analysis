import { useEffect, useRef, useState } from 'react'

// A glanceable trend line, not the main visual — no axes, no labels, no
// external chart library (this project hand-rolls its visualizations, see
// ThreatChart.jsx). Keeps the last MAX_SAMPLES readings of whatever
// `value` App.jsx is already polling from /api/throughput every 2s; this
// component owns only the rolling history, not the fetch itself.
//
// Samples on its own fixed interval (via a ref, not a `value`-keyed effect)
// rather than only when `value` changes -- a flat/idle throughput (e.g. no
// live pipeline running) is a real, meaningful reading and must still show
// as a flat line, not an empty chart forever waiting for its first change.
const MAX_SAMPLES = 60
const SAMPLE_INTERVAL_MS = 2000
const WIDTH = 120
const HEIGHT = 28

function ThroughputSparkline({ value }) {
  const [samples, setSamples] = useState([])
  const latestValue = useRef(value)
  latestValue.current = value

  useEffect(() => {
    const id = setInterval(() => {
      const v = latestValue.current
      setSamples((prev) => [...prev, typeof v === 'number' && !Number.isNaN(v) ? v : 0].slice(-MAX_SAMPLES))
    }, SAMPLE_INTERVAL_MS)
    return () => clearInterval(id)
  }, [])

  if (samples.length < 2) return null

  const max = Math.max(...samples, 1)
  const points = samples
    .map((v, i) => {
      const x = (i / (samples.length - 1)) * WIDTH
      const y = HEIGHT - (v / max) * HEIGHT
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')

  return (
    <svg
      className="throughput-sparkline"
      width={WIDTH}
      height={HEIGHT}
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={`Throughput trend, last ${samples.length} samples`}
    >
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  )
}

export default ThroughputSparkline
