import { THREAT_MATRIX } from '../data/threatMatrix'

// Architecture-page-only view of all six problem-statement-required threat
// classes (the Overview/ActiveDetectors component deliberately shows only
// the three actually running -- this component is the one place the full
// six-class target design is shown, and it's equally deliberate about
// distinguishing "implemented and validated" from "designed, not built"
// for each of them. Nothing here claims a detector exists where it doesn't.
function ThreatCoverageMatrix() {
  const implementedCount = THREAT_MATRIX.filter((t) => t.status === 'implemented').length
  const allImplemented = implementedCount === THREAT_MATRIX.length

  return (
    <div className="threat-coverage">
      <div className="panel-title">Threat Coverage — Full Design vs. Implemented</div>
      <p className="panel-subtitle threat-coverage__subtitle">
        All six threat classes named in the problem statement, and this prototype's actual
        coverage of each — {implementedCount} of {THREAT_MATRIX.length} implemented and
        ML-validated{allImplemented
          ? '. All six are trained inside this repo. DDoS/recon/C2 are real captured traffic; TLS/exfil are majority-real blended with a synthetic malicious-class top-up; DGA is synthetic, reproducing 9 published DGA algorithm families — see each row.'
          : ', the rest architecturally designed but not yet built.'}
      </p>

      <ul className="threat-coverage__list">
        {THREAT_MATRIX.map((t) => (
          <li key={t.key} className="threat-coverage__row">
            <div className="threat-coverage__row-top">
              <span className="threat-coverage__accent" style={{ background: t.accent }} aria-hidden="true" />
              <span className="threat-coverage__label" style={{ color: t.accent }}>{t.label}</span>
              <span
                className={`badge threat-coverage__status threat-coverage__status--${t.status}`}
              >
                {t.status === 'implemented' ? 'IMPLEMENTED' : 'DESIGNED'}
              </span>
            </div>
            <div className="threat-coverage__approach">{t.approach}</div>
            <div className="threat-coverage__detail">{t.detail}</div>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default ThreatCoverageMatrix
