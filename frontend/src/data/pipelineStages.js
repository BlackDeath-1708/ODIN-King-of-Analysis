// Single source of truth for Hybrid 1 pipeline stage metadata — read by
// HybridPipeline.jsx (the stage-by-stage diagram) and ArchitecturePage.jsx
// (the component-responsibility grid), so the two views can never drift
// out of sync with each other.
//
// `fullDesign` names the full Hybrid 1 architecture's own component for
// this layer (per the NTRO Problem 26145 architectural analysis this
// project is built from) where it differs from what's actually running.
// Omitted when this prototype's implementation already IS the full-design
// choice (Kafka, the alert schema) rather than a stand-in for it.
export const STAGES = [
  {
    name: 'Passive Input',
    description: 'Receives mirrored network traffic through TAP/SPAN infrastructure.',
    responsibility: 'Traffic acquisition',
    fullDesign: 'Hardware data diode + hybrid flow-record/selective-raw-capture acquisition. This prototype simulates the diode boundary in software (loopback capture) rather than a physical device.',
  },
  {
    name: 'Zeek',
    description: 'Transforms network traffic into structured security metadata.',
    responsibility: 'Network metadata generation',
    fullDesign: 'Zeek (as implemented) + optional Suricata for a high-throughput volumetric path — not added here, since prototype-scale traffic doesn’t need it.',
  },
  {
    name: 'Kafka',
    description: 'Provides event streaming between network monitoring and processing.',
    responsibility: 'Event transport',
  },
  {
    name: 'Stream Processor',
    description: 'Consumes events and prepares them for detection.',
    responsibility: 'Event processing',
    fullDesign: 'Apache Flink, for stateful, horizontally-scalable windowing. This prototype uses a single-process Python Kafka consumer with the same plugin-style Detector interface, so it can be swapped for a real Flink job later without changing detector logic.',
  },
  {
    name: 'Detection Engine',
    description: 'Runs the active prototype threat detectors.',
    responsibility: 'Threat detection',
    fullDesign: 'Six specialist models, one per PS-required threat class, all implemented and trained inside this repo — see the Threat Coverage matrix below for each one\'s real-vs-synthetic training data breakdown.',
  },
  {
    name: 'Alert Engine',
    description: 'Produces evidence-backed alerts with severity and confidence.',
    responsibility: 'Alert generation',
  },
  {
    name: 'Storage',
    description: 'Persists alerts for historical query and dashboard replay.',
    responsibility: 'Alert persistence',
    fullDesign: 'Time-series database (TimescaleDB/InfluxDB-class) + an immutable raw-log archive for forensic chain of custody. This prototype uses a single append-only JSON-lines file (alerts.json) — durable enough for a demo, not for production retention or concurrent multi-writer access.',
  },
  {
    name: 'Dashboard',
    description: 'Presents alerts, statistics, evidence and pipeline state.',
    responsibility: 'Visualization',
    fullDesign: 'Same concept as an off-the-shelf framework (Grafana/Kibana-class); implemented here as a purpose-built React dashboard instead, for full control over the evidence/replay UX.',
  },
]
