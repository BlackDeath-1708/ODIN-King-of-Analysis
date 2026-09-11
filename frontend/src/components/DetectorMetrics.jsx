import { useEffect, useState } from 'react'

// Precision/recall/F1/false-positive-rate/false-negative-rate/confusion
// matrix, computed from each detector's own held-out test set by
// training/metrics_utils.py (persisted per-detector at docs/metrics/
// <name>.json when that detector's train_*.py script runs), merged with
// per-detector inference latency and the pipeline's own sustained-
// throughput measurement (scripts/benchmark_throughput.py) by
// GET /api/model_metrics. Exists so "how many false positives do you
// generate" has an immediate, sourced number instead of requiring a dig
// through ML_MODELS.md's prose.
function useModelMetrics() {
  const [data, setData] = useState(null)
  useEffect(() => {
    fetch('/api/model_metrics')
      .then((r) => r.json())
      .then(setData)
      .catch(() => {})
  }, [])
  return data
}

const RATE_ROWS = [
  { key: 'precision', label: 'Precision' },
  { key: 'recall', label: 'Recall' },
  { key: 'f1', label: 'F1' },
  { key: 'false_positive_rate', label: 'False Positive Rate' },
  { key: 'false_negative_rate', label: 'False Negative Rate' },
]

function formatPct(value) {
  return value === null || value === undefined ? '—' : `${(value * 100).toFixed(2)}%`
}

function DetectorMetrics({ detectorKey, label }) {
  const data = useModelMetrics()

  if (!data) {
    return null
  }

  const metrics = data.detectors?.[detectorKey]

  if (!metrics) {
    return (
      <div className="detector-metrics">
        <span className="detector-metrics__title">Model Evaluation Metrics</span>
        <p className="detector-metrics__empty">
          No held-out metrics file found for this detector yet — run{' '}
          <code>training/train_{detectorKey}.py</code> (or the matching training script) to generate one.
        </p>
      </div>
    )
  }

  const cm = metrics.confusion_matrix

  return (
    <div className="detector-metrics">
      <span className="detector-metrics__title">
        Model Evaluation Metrics
        <span className="detector-metrics__source">
          {' '}
          — held-out test set, {metrics.test_set_size} rows, grouped by {metrics.grouping}
        </span>
      </span>

      <div className="detector-metrics__grid">
        {RATE_ROWS.map(({ key, label: rowLabel }) => (
          <div className="detector-metrics__stat" key={key}>
            <span className="detector-metrics__stat-label">{rowLabel}</span>
            <span className="detector-metrics__stat-value">{formatPct(metrics[key])}</span>
          </div>
        ))}
        <div className="detector-metrics__stat">
          <span className="detector-metrics__stat-label">Inference Latency</span>
          <span className="detector-metrics__stat-value">
            {metrics.inference_latency_ms != null ? `${metrics.inference_latency_ms.toFixed(1)}ms` : '—'}
          </span>
        </div>
      </div>

      <div className="detector-metrics__confusion">
        <span className="detector-metrics__confusion-title">Confusion Matrix</span>
        <table className="detector-metrics__confusion-table">
          <thead>
            <tr>
              <th aria-hidden="true" />
              <th>Predicted benign</th>
              <th>Predicted {label}</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th>Actual benign</th>
              <td>{cm.tn}</td>
              <td className="is-fp">{cm.fp}</td>
            </tr>
            <tr>
              <th>Actual {label}</th>
              <td className="is-fn">{cm.fn}</td>
              <td>{cm.tp}</td>
            </tr>
          </tbody>
        </table>
      </div>

      {data.throughput?.sustained_flows_per_sec != null && (
        <p className="detector-metrics__throughput">
          Pipeline sustained throughput: {data.throughput.sustained_flows_per_sec} flows/sec (Python
          detection-loop measurement, not a Kafka-broker round-trip — see{' '}
          <code>docs/benchmark_results.json</code>).
        </p>
      )}

      {metrics.notes && <p className="detector-metrics__notes">{metrics.notes}</p>}
    </div>
  )
}

export default DetectorMetrics
