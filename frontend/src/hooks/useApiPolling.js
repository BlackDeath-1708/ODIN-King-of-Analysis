import { useEffect, useState } from 'react'

// Shared fetch-once hooks for endpoints that don't change fast enough to
// need SSE/polling (unlike alerts/stats/throughput, which App.jsx owns) --
// model metrics and detector status only change when a model is retrained
// or the process restarts, so a single fetch on mount is enough. Consumed
// by DetectorMetrics.jsx (existing, per-detector deep dive) and the new
// ModelPerformancePage.jsx (cross-detector comparison).

export function useModelMetrics() {
  const [data, setData] = useState(null)
  useEffect(() => {
    fetch('/api/model_metrics')
      .then((r) => r.json())
      .then(setData)
      .catch(() => {})
  }, [])
  return data
}

export function useDetectorStatus() {
  const [data, setData] = useState(null)
  useEffect(() => {
    fetch('/api/detector_status')
      .then((r) => r.json())
      .then(setData)
      .catch(() => {})
  }, [])
  return data
}
