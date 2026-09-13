import { useMemo, useState } from 'react'

// Hand-rolled inline-SVG node-link diagram -- matching this project's
// existing no-charting-library convention for bespoke visuals (see
// ThreatDonut.jsx/AlertsTimeline.jsx) rather than pulling in a graph
// library for one diagram. Renders real src_ip -> dst_ip pairs from the
// currently-loaded `alerts` array: source nodes on the left, destination
// nodes on the right, link color = that pair's most common threat class,
// link width = how many alerts share the pair. Two-column bipartite
// layout (not a physics-based force graph) is a deliberate choice: it's
// deterministic and legible at the alert volumes this prototype handles,
// with no simulation warm-up or layout jitter between renders.

const THREAT_ACCENTS = {
  ddos: 'var(--threat-ddos)',
  recon: 'var(--threat-recon)',
  c2: 'var(--threat-c2)',
  dga: 'var(--threat-dga)',
  tls: 'var(--threat-tls)',
  exfil: 'var(--threat-exfil)',
  MULTI_VECTOR: 'var(--threat-multi-vector)',
}

const MAX_SOURCES = 10
const MAX_DESTS = 10
const ROW_HEIGHT = 28
const COL_X = { src: 95, dst: 405 }
const WIDTH = 500

function buildGraph(alerts) {
  const linkMap = new Map() // "src|dst" -> { src, dst, count, classes: Map }
  for (const alert of alerts) {
    const src = alert.src_ip
    const dst = alert.dst_ip
    if (!src || !dst) continue
    const key = `${src}|${dst}`
    if (!linkMap.has(key)) linkMap.set(key, { src, dst, count: 0, classes: new Map() })
    const link = linkMap.get(key)
    link.count += 1
    const tc = alert.threat_class || 'unknown'
    link.classes.set(tc, (link.classes.get(tc) || 0) + 1)
  }

  const links = [...linkMap.values()].map((link) => {
    const [dominant] = [...link.classes.entries()].sort((a, b) => b[1] - a[1])[0]
    return { ...link, dominant }
  })

  const srcCounts = new Map()
  const dstCounts = new Map()
  for (const link of links) {
    srcCounts.set(link.src, (srcCounts.get(link.src) || 0) + link.count)
    dstCounts.set(link.dst, (dstCounts.get(link.dst) || 0) + link.count)
  }

  const sources = [...srcCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_SOURCES).map(([ip]) => ip)
  const dests = [...dstCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_DESTS).map(([ip]) => ip)
  const sourceSet = new Set(sources)
  const destSet = new Set(dests)

  const visibleLinks = links.filter((l) => sourceSet.has(l.src) && destSet.has(l.dst))
  const maxCount = Math.max(...visibleLinks.map((l) => l.count), 1)

  return { sources, dests, links: visibleLinks, maxCount }
}

function NetworkFlowMap({ alerts }) {
  const [hoveredIp, setHoveredIp] = useState(null)
  const { sources, dests, links, maxCount } = useMemo(() => buildGraph(alerts), [alerts])

  if (sources.length === 0 || dests.length === 0) {
    return <div className="analytics-chart__empty">No source/destination pairs observed yet</div>
  }

  const height = Math.max(sources.length, dests.length) * ROW_HEIGHT + 24
  const srcY = (i) => 16 + i * ROW_HEIGHT
  const dstY = (i) => 16 + i * ROW_HEIGHT

  return (
    <div className="network-flow-map">
      <svg
        width="100%"
        viewBox={`0 0 ${WIDTH} ${height}`}
        role="img"
        aria-label="Network flow map: source IPs to destination IPs by threat class"
      >
        {links.map((link, i) => {
          const si = sources.indexOf(link.src)
          const di = dests.indexOf(link.dst)
          const dimmed = hoveredIp && hoveredIp !== link.src && hoveredIp !== link.dst
          const y1 = srcY(si)
          const y2 = dstY(di)
          const midX = (COL_X.src + COL_X.dst) / 2
          return (
            <path
              key={`${link.src}|${link.dst}|${i}`}
              d={`M ${COL_X.src + 8} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${COL_X.dst - 8} ${y2}`}
              fill="none"
              stroke={THREAT_ACCENTS[link.dominant] || 'var(--text-tertiary)'}
              strokeWidth={1 + (link.count / maxCount) * 4}
              strokeOpacity={dimmed ? 0.08 : 0.55}
            >
              <title>
                {link.src} → {link.dst}: {link.count} alert{link.count === 1 ? '' : 's'} (mostly {link.dominant})
              </title>
            </path>
          )
        })}

        {sources.map((ip, i) => (
          <g
            key={ip}
            transform={`translate(${COL_X.src}, ${srcY(i)})`}
            onMouseEnter={() => setHoveredIp(ip)}
            onMouseLeave={() => setHoveredIp(null)}
            style={{ cursor: 'default' }}
          >
            <circle r="4" fill="var(--accent)" opacity={hoveredIp && hoveredIp !== ip ? 0.3 : 1} />
            <text x="-10" dy="4" textAnchor="end" className="network-flow-map__label">
              {ip}
            </text>
          </g>
        ))}

        {dests.map((ip, i) => (
          <g
            key={ip}
            transform={`translate(${COL_X.dst}, ${dstY(i)})`}
            onMouseEnter={() => setHoveredIp(ip)}
            onMouseLeave={() => setHoveredIp(null)}
            style={{ cursor: 'default' }}
          >
            <circle r="4" fill="var(--text-tertiary)" opacity={hoveredIp && hoveredIp !== ip ? 0.3 : 1} />
            <text x="10" dy="4" textAnchor="start" className="network-flow-map__label">
              {ip}
            </text>
          </g>
        ))}
      </svg>
      <div className="network-flow-map__legend">
        {Object.entries(THREAT_ACCENTS).map(([cls, color]) => (
          <span key={cls} className="network-flow-map__legend-item">
            <span className="network-flow-map__legend-dot" style={{ background: color }} />
            {cls}
          </span>
        ))}
      </div>
    </div>
  )
}

export default NetworkFlowMap
