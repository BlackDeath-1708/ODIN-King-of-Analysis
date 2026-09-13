import {
  TopSourceIPs,
  SeverityBreakdown,
  ConfidenceHistogram,
  TargetedPorts,
  ActivityByHour,
} from '../components/analytics/AnalyticsCharts'
import NetworkFlowMap from '../components/NetworkFlowMap'

// Deeper analytics over the currently-loaded alert feed -- deliberately
// distinct dimensions from Overview (threat-class distribution, alerts
// over time) and Alerts (search/filter/investigate one alert at a time):
// source concentration, severity mix, confidence spread, targeted ports,
// time-of-day pattern, and a source->destination flow map. All client-
// side derived from the same `alerts` array, no new backend endpoint.
function AnalyticsPage({ alerts }) {
  const safeAlerts = Array.isArray(alerts) ? alerts : []

  return (
    <div className="page">
      <div className="page-intro">
        <h1 className="page-intro__title">Analytics</h1>
        <p className="page-intro__subtitle">
          Deeper patterns across the currently-loaded alert feed
        </p>
        <p className="overview-header__context">
          {safeAlerts.length} alert{safeAlerts.length === 1 ? '' : 's'} in view — client-side analysis, no
          new server aggregation
        </p>
      </div>

      <div className="analytics-grid">
        <div className="panel analytics-grid__span2">
          <div className="panel-title">Network Flow Map</div>
          <p className="panel-subtitle">
            Top source IPs (left) to top destination IPs (right) — line color is the pair&rsquo;s dominant
            threat class, thickness is alert volume
          </p>
          <NetworkFlowMap alerts={safeAlerts} />
        </div>

        <div className="panel">
          <div className="panel-title">Top Attack Sources</div>
          <p className="panel-subtitle">Source IPs ranked by alert count</p>
          <TopSourceIPs alerts={safeAlerts} />
        </div>

        <div className="panel">
          <div className="panel-title">Severity Mix</div>
          <p className="panel-subtitle">Distribution across the four severity levels</p>
          <SeverityBreakdown alerts={safeAlerts} />
        </div>

        <div className="panel">
          <div className="panel-title">Confidence Distribution</div>
          <p className="panel-subtitle">How confident the pipeline is across all alerts</p>
          <ConfidenceHistogram alerts={safeAlerts} />
        </div>

        <div className="panel">
          <div className="panel-title">Most-Targeted Ports</div>
          <p className="panel-subtitle">Destination ports appearing most often in alerts</p>
          <TargetedPorts alerts={safeAlerts} />
        </div>

        <div className="panel analytics-grid__span2">
          <div className="panel-title">Activity by Hour of Day</div>
          <p className="panel-subtitle">
            When alerts occur, bucketed by hour (browser&rsquo;s local time zone)
          </p>
          <ActivityByHour alerts={safeAlerts} />
        </div>
      </div>
    </div>
  )
}

export default AnalyticsPage
