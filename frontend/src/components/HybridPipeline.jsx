// Architecture / data-flow view only. The backend exposes no per-component
// health telemetry as a single "is the pipeline healthy" flag — so nodes
// here are never labeled ONLINE / HEALTHY / RUNNING, only named and
// described as stages. Real, live per-component status lives only in
// PipelineStatus.jsx, driven by GET /api/pipeline-status.
import { STAGES } from '../data/pipelineStages'

// compact:        vertical dot+label flow only (Overview's left column, and
//                 nested inside the Architecture page's overview diagram).
// showProperties: whether to render the Read-Only Ingest / Return Path /
//                 Observation footer. Default true preserves this
//                 component's existing behavior everywhere it was already
//                 in use; the Architecture page's redesign explicitly
//                 opts out where that footer would otherwise repeat the
//                 page's own dedicated security-boundary section.
function HybridPipeline({ compact = false, showProperties = true }) {
  return (
    <div className="hybrid-pipeline">
      {!compact && <div className="panel-title">Hybrid 1 Detection Pipeline</div>}

      {compact ? (
        // Compact architectural summary only — a vertical stepped flow,
        // not a live health readout. Dots are decorative (.step-dot),
        // never ONLINE/OFFLINE.
        <div className="stepped-flow">
          {STAGES.map((stage, i) => (
            <div key={stage.name} className="stepped-flow__step">
              <div className="stepped-flow__step-row">
                <span className="step-dot" aria-hidden="true" />
                <span className="stepped-flow__step-label">{stage.name}</span>
              </div>
              {i < STAGES.length - 1 && (
                <div className="stepped-flow__step-arrow">↓</div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="pipeline">
          {STAGES.map((stage, i) => (
            <div className="pipeline__stage" key={stage.name}>
              <div className="panel pipeline__box">
                <div className="pipeline__title">
                  <span className="pipeline__number">{String(i + 1).padStart(2, '0')}</span>
                  <span className="step-dot" aria-hidden="true" />
                  {stage.name}
                </div>
                <div className="pipeline__note">{stage.description}</div>
                {stage.fullDesign && (
                  <div className="pipeline__full-design">
                    <span className="pipeline__full-design-label">Full design:</span> {stage.fullDesign}
                  </div>
                )}
              </div>
              {i < STAGES.length - 1 && <div className="pipeline__arrow">↓</div>}
            </div>
          ))}
        </div>
      )}

      {showProperties && (
        <div className="hybrid-pipeline__properties">
          <span className="hybrid-pipeline__property">
            <span className="hybrid-pipeline__property-label">Read-Only Ingest</span>
            <span className="hybrid-pipeline__property-value">Enabled</span>
          </span>
          <span className="hybrid-pipeline__property">
            <span className="hybrid-pipeline__property-label">Return Path</span>
            <span className="hybrid-pipeline__property-value">None</span>
          </span>
          <span className="hybrid-pipeline__property">
            <span className="hybrid-pipeline__property-label">Observation</span>
            <span className="hybrid-pipeline__property-value">One-Way</span>
          </span>
        </div>
      )}
    </div>
  )
}

export default HybridPipeline
