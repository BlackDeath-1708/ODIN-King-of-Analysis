import StatusBar from '../components/StatusBar'
import ThreatChart from '../components/ThreatChart'
import AlertsTimeline from '../components/AlertsTimeline'
import AlertFeed from '../components/AlertFeed'
import HybridPipeline from '../components/HybridPipeline'
import ActiveDetectors from '../components/ActiveDetectors'

// Answers "what is happening right now" — headline stats, threat
// distribution, and the live feed, in one screen. Connection status has
// exactly one authoritative home: the global topbar (see App.jsx).
function OverviewPage({ stats, throughput, connected, alerts, onNavigate }) {
  return (
    <div className="page">
      <div className="page-intro">
        <h1 className="page-intro__title">Overview</h1>
        <p className="page-intro__subtitle">Operational monitoring summary</p>
        <p className="overview-header__context">
          Passive, read-only observation of unidirectional IP traffic
        </p>
      </div>

      {!connected && (
        <p className="overview-offline-note">
          Live detection events are unavailable while the monitoring stream is disconnected.
        </p>
      )}

      <StatusBar stats={stats} throughput={throughput} />

      <AlertsTimeline alerts={alerts} />

      <div className="overview-grid">
        <div className="overview-grid__left">
          <div className="overview-grid__block">
            <ThreatChart stats={stats} subtitle="Active prototype detector distribution" />
            <button
              type="button"
              className="text-link"
              onClick={() => onNavigate('threat-analysis')}
            >
              View threat analysis →
            </button>
          </div>

          <div className="overview-grid__block">
            <div className="panel context-panel">
              <HybridPipeline compact />
              <ActiveDetectors compact />
              <div className="context-panel__footer">
                <button
                  type="button"
                  className="text-link"
                  onClick={() => onNavigate('architecture')}
                >
                  View architecture →
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="overview-grid__feed">
          <AlertFeed
            alerts={alerts}
            subtitle="Evidence-backed detections received from the monitoring pipeline"
          />
          <button type="button" className="text-link" onClick={() => onNavigate('alerts')}>
            View all alerts →
          </button>
        </div>
      </div>
    </div>
  )
}

export default OverviewPage
