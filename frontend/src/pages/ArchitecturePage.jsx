import HybridPipeline from '../components/HybridPipeline'
import ThreatCoverageMatrix from '../components/ThreatCoverageMatrix'
import PipelineStatus from '../components/PipelineStatus'
import { STAGES } from '../data/pipelineStages'

// Why the architecture combines an NSM front-end with a streaming
// back-end, rather than using either alone -- the "Hybrid" in Hybrid 1.
// Each row states one family's specific weakness and what the other
// family contributes to resolve it; this is the actual design reasoning,
// not a marketing pitch.
const HYBRID_RATIONALE = [
  {
    title: 'NSM front-end (Zeek) alone',
    body: 'Protocol-aware, security-proven, produces the structured fields (dns.log, ssl.log, conn.log) every detector needs. But it has no native ML inference path and no horizontal scaling — a single Zeek process is the throughput ceiling.',
  },
  {
    title: 'Streaming back-end (Kafka + a stream processor) alone',
    body: 'Horizontally scalable, decouples ingest rate from processing rate, natively suited to the windowed statistics detection needs (rates, fan-out, timing). But it cannot parse a TLS ClientHello or a DNS query from raw packets — it needs an upstream protocol parser or it has nothing to compute features from.',
  },
  {
    title: 'Combined',
    body: 'Zeek\'s structured log output becomes Kafka\'s streaming input. Neither family\'s weakness is present in the combination: protocol parsing is solved once (by Zeek, not reimplemented), and windowed feature computation scales independently of Zeek\'s own throughput ceiling.',
  },
]

// Three architectural properties, not runtime metrics — matched to the
// software's actual, verifiable behavior (no return path exists in the
// code; physical isolation is a deployment concern handled by the diode).
const SECURITY_PRINCIPLES = [
  { title: 'ONE-WAY', body: 'No return path to the production network.' },
  { title: 'READ-ONLY', body: 'Monitoring observes traffic without modifying or blocking it.' },
  {
    title: 'ISOLATED',
    body: 'Detection and visualization operate inside the monitoring environment.',
  },
]

const SYSTEM_NOTES = [
  'Physical isolation is a deployment property, enforced by the hardware data diode — not by this software.',
  'This dashboard reflects the software/API state of the monitoring pipeline, not the physical network.',
  'The browser cannot independently verify the physical health of the data diode itself.',
  'The current implementation is a prototype built for SIH 2026, not a production deployment.',
  'All six threat classes named in the problem statement have a real detector implemented and trained entirely inside this repo; DDoS/recon/C2 are real captured traffic, TLS/exfil are majority-real with a synthetic malicious-class top-up, DGA is synthetic reproducing 9 published algorithm families — see the Threat Coverage matrix below.',
]

// Actual on-the-wire/on-disk representation at each stage, as implemented:
// Zeek writes JSON conn.log lines; kafka_producer.py tails and republishes
// them verbatim onto the "zeek-conn" topic; stream_consumer.py normalizes
// them before handing them to the detectors; alerts are appended to
// alerts.json as JSON lines and read back by the API.
const DATA_FLOW_STEPS = [
  'Network Packets',
  'Zeek JSON Logs (conn.log)',
  'Kafka Events (zeek-conn topic)',
  'Normalized Events',
  'Detection',
  'Alerts (JSON)',
  'Dashboard',
]

// Attaches a small "is this a design description or a live reading"
// disambiguator to a section — used only where that distinction is the
// point (never sprinkled everywhere, or it stops meaning anything).
function SectionLabel({ eyebrow, caption }) {
  return (
    <div className="section-label">
      <span className="section-label__eyebrow">{eyebrow}</span>
      <span className="section-label__caption">{caption}</span>
    </div>
  )
}

function ArchitecturePage() {
  return (
    <div className="page">
      <div className="page-intro">
        <h1 className="page-intro__title">System Architecture</h1>
        <p className="page-intro__subtitle">
          End-to-end architecture of the NTRO unidirectional threat monitoring system
        </p>
        <p className="overview-header__context">
          Passive network observation → security analytics → evidence-backed detection
        </p>
      </div>

      {/* SECTION 1 — Architecture overview: the page's visual centerpiece. */}
      <div className="panel arch-overview">
        <div className="panel-title">Architecture Overview</div>

        <div className="arch-overview__flow">
          <div className="arch-overview__layer">
            <div className="arch-overview__layer-title">Production Network</div>
            <div className="arch-overview__layer-note">Network / OT assets being observed</div>
          </div>

          <div className="arch-overview__connector">
            <span className="arch-overview__connector-arrow" aria-hidden="true">
              ↓
            </span>
            <span className="arch-overview__connector-label">Mirrored / passive traffic</span>
          </div>

          <div className="arch-overview__layer arch-overview__layer--boundary">
            <span className="badge arch-overview__boundary-tag">Security Boundary</span>
            <div className="arch-overview__layer-title">Hardware Data Diode / Passive Tap</div>
            <div className="arch-overview__layer-note">
              Physically enforces one-way data flow — nothing can be sent back in.
            </div>
          </div>

          <div className="arch-overview__connector">
            <span className="arch-overview__connector-arrow" aria-hidden="true">
              ↓
            </span>
          </div>

          <div className="arch-overview__enclave">
            <div className="arch-overview__enclave-title">Monitoring Enclave</div>
            <HybridPipeline compact showProperties={false} />
          </div>
        </div>
      </div>

      {/* SECTION 1b — Why "Hybrid": the design reasoning behind combining an
          NSM front-end with a streaming back-end, not just a components list. */}
      <div className="panel why-hybrid">
        <SectionLabel eyebrow="Architecture" caption="Why the system is designed this way" />
        <div className="panel-title">Why "Hybrid" — NSM + Streaming</div>
        <div className="why-hybrid__grid">
          {HYBRID_RATIONALE.map((item) => (
            <div key={item.title} className="why-hybrid__item">
              <div className="why-hybrid__item-title">{item.title}</div>
              <p className="why-hybrid__item-body">{item.body}</p>
            </div>
          ))}
        </div>
      </div>

      {/* SECTION 2 + 3 — One-way security boundary | Hybrid 1 pipeline (detailed) */}
      <div className="architecture-grid">
        <div className="panel security-boundary">
          <SectionLabel eyebrow="Architecture" caption="How the system is designed" />
          <div className="panel-title">One-Way Security Boundary</div>

          <div className="security-boundary__flow">
            <span className="security-boundary__node">Production Network</span>
            <span className="security-boundary__arrow" aria-hidden="true">
              ↓
            </span>
            <span className="security-boundary__node">Monitoring Enclave</span>
          </div>

          <div className="security-boundary__rows">
            <div className="security-boundary__row">
              <span className="security-boundary__row-label">Read-Only Ingest</span>
              <span className="security-boundary__row-value is-enabled">Enabled</span>
            </div>
            <div className="security-boundary__row">
              <span className="security-boundary__row-label">Return Path</span>
              <span className="security-boundary__row-value is-none">None</span>
            </div>
          </div>

          <p className="security-boundary__note">
            The monitoring system observes mirrored traffic without providing any active
            return path into the production network. This one-way property is enforced by the
            hardware data diode in the deployment architecture — not by this browser or
            application code.
          </p>
        </div>

        <div className="panel architecture-section">
          <SectionLabel eyebrow="Architecture" caption="How the system is designed" />
          <HybridPipeline showProperties={false} />
        </div>
      </div>

      {/* SECTION 4 + 6 — Component responsibilities | Live pipeline status */}
      <div className="architecture-grid">
        <div className="panel architecture-section">
          <SectionLabel eyebrow="Architecture" caption="How the system is designed" />
          <div className="panel-title">Component Responsibilities</div>
          <div className="responsibility-grid">
            {STAGES.map((stage) => (
              <div key={stage.name} className="responsibility-grid__item">
                <div className="responsibility-grid__name">{stage.name}</div>
                <div className="responsibility-grid__role">{stage.responsibility}</div>
                {stage.fullDesign && (
                  <div className="responsibility-grid__full-design">{stage.fullDesign}</div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div>
          <SectionLabel
            eyebrow="Runtime Status"
            caption="What the monitoring backend currently reports"
          />
          <PipelineStatus />
        </div>
      </div>

      {/* SECTION 5 + 7 — Threat coverage (all six PS classes) | Data flow */}
      <div className="architecture-grid">
        <div className="panel architecture-section">
          <ThreatCoverageMatrix />
        </div>

        <div className="panel data-flow">
          <div className="panel-title">Data Flow</div>
          <p className="panel-subtitle data-flow__subtitle">
            Actual event representation as data moves through the pipeline
          </p>
          <div className="stepped-flow">
            {DATA_FLOW_STEPS.map((step, i) => (
              <div key={step} className="stepped-flow__step">
                <div className="stepped-flow__step-row">
                  <span className="step-dot" aria-hidden="true" />
                  <span className="stepped-flow__step-label">{step}</span>
                </div>
                {i < DATA_FLOW_STEPS.length - 1 && (
                  <div className="stepped-flow__step-arrow">↓</div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* SECTION 8 — Security principles */}
      <div className="section-heading">Security Principles</div>
      <div className="principles">
        {SECURITY_PRINCIPLES.map((principle) => (
          <div className="panel principles__card" key={principle.title}>
            <div className="principles__title">{principle.title}</div>
            <p className="principles__body">{principle.body}</p>
          </div>
        ))}
      </div>

      {/* SECTION 9 — System notes: deliberately understated, not a panel. */}
      <div className="system-notes">
        <div className="system-notes__title">System Notes</div>
        <ul className="system-notes__list">
          {SYSTEM_NOTES.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}

export default ArchitecturePage
