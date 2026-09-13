import { useEffect, useState } from 'react'
import Sidebar from './components/Sidebar'
import OverviewPage from './pages/OverviewPage'
import AlertsPage from './pages/AlertsPage'
import AnalyticsPage from './pages/AnalyticsPage'
import CorrelationPage from './pages/CorrelationPage'
import ThreatAnalysisPage from './pages/ThreatAnalysisPage'
import ModelPerformancePage from './pages/ModelPerformancePage'
import ExportPage from './pages/ExportPage'
import ArchitecturePage from './pages/ArchitecturePage'
import './App.css'

const MAX_ALERTS = 200
const THEME_STORAGE_KEY = 'ntro-theme'
// Conservative safety-net interval: SSE is the primary, fast delivery path
// for new alerts. This reconciliation poll exists only to recover from a
// silently stalled EventSource (one that never fires `onerror`) and to
// dedupe/settle state against the server's own record — not to drive
// normal updates, so it stays well below SSE's push cadence.
const RECONCILE_INTERVAL_MS = 10000

function getInitialTheme() {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY)
    if (stored === 'dark' || stored === 'light') return stored
  } catch {
    // localStorage unavailable (private mode, disabled storage, etc.) — fall through
  }
  return 'dark'
}

function App() {
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({})
  const [throughput, setThroughput] = useState({})
  const [connected, setConnected] = useState(false)
  const [activePage, setActivePage] = useState('overview')
  const [theme, setTheme] = useState(getInitialTheme)

  // Theme is purely a presentation concern — persisted for convenience,
  // but unrelated to alerts/stats/connection state or any API call.
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme)
    } catch {
      // persistence is a nice-to-have, not required for the theme to work
    }
  }, [theme])

  // 1 & 2. Initial load: existing alerts + stats
  useEffect(() => {
    fetch('/api/alerts')
      .then((r) => r.json())
      .then((data) => setAlerts([...data].reverse().slice(0, MAX_ALERTS)))
      .catch(console.error)

    fetch('/api/stats')
      .then((r) => r.json())
      .then(setStats)
      .catch(console.error)
  }, [])

  // 3 & 4. Live alert stream via SSE + connection status.
  // De-duplicates by flow_id before prepending: an SSE reconnect can
  // redeliver an alert already present from the initial load or a prior
  // message, and the backend's own alert schema already gives us a stable
  // id for exactly this purpose. An alert missing flow_id is never matched
  // against anything (it can't cause a false dedup) and is always added.
  useEffect(() => {
    const es = new EventSource('/api/stream')

    es.onopen = () => setConnected(true)

    es.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'connected') return

      setAlerts((prev) => {
        if (data.flow_id && prev.some((a) => a.flow_id && a.flow_id === data.flow_id)) {
          return prev
        }
        return [data, ...prev].slice(0, MAX_ALERTS)
      })

      setStats((prev) => ({
        ...prev,
        total: (prev.total || 0) + 1,
        [data.threat_class]: (prev[data.threat_class] || 0) + 1,
      }))
    }

    es.onerror = () => setConnected(false)

    return () => es.close()
  }, [])

  // 5. Reconciliation safety net (see RECONCILE_INTERVAL_MS above). Replaces
  // local alerts/stats wholesale from the server's own record, so it can
  // only correct drift/duplicates/missed SSE messages, never introduce them.
  // A successful poll also recovers `connected` in case the EventSource
  // stalled without ever firing `onerror`; a failed poll is left for the
  // next tick rather than forcing an offline flap from one bad request.
  useEffect(() => {
    const id = setInterval(() => {
      Promise.all([
        fetch('/api/alerts').then((r) => r.json()),
        fetch('/api/stats').then((r) => r.json()),
      ])
        .then(([alertsData, statsData]) => {
          setAlerts([...alertsData].reverse().slice(0, MAX_ALERTS))
          setStats(statsData)
          setConnected(true)
        })
        .catch(() => {
          // Leave `connected` as-is; SSE's own onerror is authoritative for
          // flipping to offline, so a single failed poll doesn't flap it.
        })
    }, RECONCILE_INTERVAL_MS)

    return () => clearInterval(id)
  }, [])

  // Throughput deserves its own faster poll, separate from the 10s
  // alerts/stats reconciliation above: it's a live "is this pipeline doing
  // something right now" indicator (driven by stream_consumer.py's own
  // rolling window, see backend/app.py's /api/throughput), most useful
  // when it visibly reacts within a couple seconds of pressing a replay
  // button -- 10s would make it feel unresponsive for that purpose.
  const THROUGHPUT_INTERVAL_MS = 2000
  useEffect(() => {
    const poll = () => {
      fetch('/api/throughput')
        .then((r) => r.json())
        .then(setThroughput)
        .catch(() => {})
    }
    poll()
    const id = setInterval(poll, THROUGHPUT_INTERVAL_MS)
    return () => clearInterval(id)
  }, [])

  // 5. Reset demo
  const resetDemo = () => {
    fetch('/api/clear', { method: 'POST' })
      .then((r) => r.json())
      .then(() => {
        setAlerts([])
        return fetch('/api/stats').then((r) => r.json()).then(setStats)
      })
      .catch(console.error)
  }

  const renderPage = () => {
    switch (activePage) {
      case 'alerts':
        return <AlertsPage alerts={alerts} stats={stats} />
      case 'analytics':
        return <AnalyticsPage alerts={alerts} />
      case 'correlation':
        return <CorrelationPage alerts={alerts} />
      case 'threat-analysis':
        return <ThreatAnalysisPage stats={stats} alerts={alerts} />
      case 'model-performance':
        return <ModelPerformancePage />
      case 'export':
        return <ExportPage alerts={alerts} stats={stats} />
      case 'architecture':
        return <ArchitecturePage />
      case 'overview':
      default:
        return (
          <OverviewPage
            stats={stats}
            throughput={throughput}
            connected={connected}
            alerts={alerts}
            onNavigate={setActivePage}
          />
        )
    }
  }

  return (
    <div className="shell">
      <header className="shell-topbar">
        <div className="shell-topbar__brand-block">
          <span className="shell-topbar__brand">NTRO MONITOR</span>
          <span className="shell-topbar__tagline">Unidirectional threat monitoring</span>
        </div>
        <div className="shell-topbar__meta">
          <span className={`shell-topbar__status ${connected ? 'is-live' : 'is-offline'}`}>
            <span className="status-dot" />
            {connected ? 'LIVE' : 'OFFLINE'}
          </span>
          <span className="shell-topbar__enclave">Monitoring Enclave</span>
          <div className="theme-toggle" role="group" aria-label="Theme">
            <button
              type="button"
              className={`pill-toggle ${theme === 'dark' ? 'is-active' : ''}`}
              onClick={() => setTheme('dark')}
            >
              Dark
            </button>
            <button
              type="button"
              className={`pill-toggle ${theme === 'light' ? 'is-active' : ''}`}
              onClick={() => setTheme('light')}
            >
              Light
            </button>
          </div>
          <button type="button" className="btn" onClick={resetDemo}>
            Reset Demo
          </button>
        </div>
      </header>

      <div className="shell-body">
        <Sidebar activePage={activePage} onNavigate={setActivePage} />
        <main className="shell-main">{renderPage()}</main>
      </div>

      <footer className="shell-footer">
        LIVE/OFFLINE reflects the browser&rsquo;s connection to the monitoring API — not the
        physical data-diode link itself.
      </footer>
    </div>
  )
}

export default App
