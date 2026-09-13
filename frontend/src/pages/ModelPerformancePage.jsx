import { useModelMetrics, useDetectorStatus } from '../hooks/useApiPolling'
import {
  MetricsBarChart,
  FalseRateChart,
  MetricsRadar,
  LatencyChart,
  DETECTOR_LABELS,
  PRIMARY_ORDER,
} from '../components/modelperf/ModelPerformanceCharts'

// Cross-detector view: every number here comes from GET /api/model_metrics
// (training/metrics_utils.py's held-out evaluation, refreshed only when a
// train_*.py script re-runs) and GET /api/detector_status (real load
// status, not a hardcoded "online"). DetectorMetrics.jsx already covers
// one detector in depth per Threat Analysis page; this page is the
// side-by-side comparison plus calibration/load status across all six.
function ModelPerformancePage() {
  const metrics = useModelMetrics()
  const status = useDetectorStatus()

  const detectors = metrics?.detectors || {}
  const hasMetrics = Object.keys(detectors).length > 0

  return (
    <div className="page">
      <div className="page-intro">
        <h1 className="page-intro__title">Model Performance</h1>
        <p className="page-intro__subtitle">Cross-detector evaluation, calibration, and latency</p>
        <p className="overview-header__context">
          Every number below is read from a held-out test set or a live load check — never asserted
        </p>
      </div>

      <div className="model-perf-status-row">
        {PRIMARY_ORDER.map((key) => {
          const s = status?.[key]
          const ok = s?.status === 'ok'
          return (
            <div key={key} className="model-perf-status-card">
              <span
                className="active-detectors__status-dot"
                style={{ background: ok ? 'var(--status-live)' : 'var(--status-offline)' }}
              />
              <div>
                <div className="model-perf-status-card__name">{DETECTOR_LABELS[key]}</div>
                <div className="model-perf-status-card__meta">
                  {s ? (
                    <>
                      {ok ? (s.calibrated ? 'Calibrated' : 'Uncalibrated') : s.status}
                      {' · F1 '}
                      {s.f1}
                    </>
                  ) : (
                    'Loading…'
                  )}
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {!hasMetrics ? (
        <div className="panel">
          <p className="detector-metrics__empty">
            No held-out metrics found yet — run any <code>training/train_*.py</code> script to generate
            <code>docs/metrics/&lt;detector&gt;.json</code>.
          </p>
        </div>
      ) : (
        <div className="analytics-grid">
          <div className="panel analytics-grid__span2">
            <div className="panel-title">Precision / Recall / F1 by Detector</div>
            <p className="panel-subtitle">Held-out test set, per detector</p>
            <MetricsBarChart detectors={detectors} />
          </div>

          <div className="panel">
            <div className="panel-title">Detector Comparison</div>
            <p className="panel-subtitle">Precision, recall, and F1 on one radar</p>
            <MetricsRadar detectors={detectors} />
          </div>

          <div className="panel">
            <div className="panel-title">False Positive / Negative Rate</div>
            <p className="panel-subtitle">Lower is better on both</p>
            <FalseRateChart detectors={detectors} />
          </div>

          <div className="panel analytics-grid__span2">
            <div className="panel-title">Inference Latency</div>
            <p className="panel-subtitle">Median time for one detector call to fire, per detector</p>
            <LatencyChart detectors={detectors} />
          </div>
        </div>
      )}

      {metrics?.throughput?.sustained_flows_per_sec != null && (
        <div className="panel">
          <div className="panel-title">Pipeline Throughput</div>
          <p className="detector-metrics__throughput" style={{ margin: 0 }}>
            {metrics.throughput.sustained_flows_per_sec} flows/sec sustained
            {metrics.throughput.hardware ? ` on ${metrics.throughput.hardware}` : ''} —{' '}
            {metrics.throughput.measurement_scope || 'see docs/benchmark_results.json for exact scope'}
          </p>
        </div>
      )}
    </div>
  )
}

export default ModelPerformancePage
