// The six threat classes named by the problem statement (NTRO Problem
// 26145), and this prototype's actual coverage of each -- not an
// aspirational list. All six now have a real detector running end-to-end
// in backend/detectors/ (see ../../ML_MODELS.md for the numbers). As of
// 2026-09-12, ALL SIX are trained entirely inside this repo (training/) --
// the three (ddos/recon/c2) originally trained in a sibling exploration
// repo (recon-ml-poc/) have been fully retrained here on larger, real
// datasets. The distinction that matters now is training-data provenance,
// not location or built-vs-not: ddos/recon/c2 are real captured traffic
// (hping3/nmap/beacon-emulator); tls/exfil are majority-real (real HTTPS
// requests / real asymmetric transfers) blended with a synthetic
// malicious-class top-up (no ethical real-malware-traffic source exists);
// dga is synthetic but reproduces 9 published DGA algorithm families'
// real characteristic shapes rather than one generic generator -- see
// each `detail` field and ML_MODELS.md's "Phase 2 detectors" /
// "Real-traffic retraining" sections for the full honest breakdown.
export const THREAT_MATRIX = [
  {
    key: 'ddos',
    label: 'Volumetric / Protocol DDoS',
    accent: 'var(--threat-ddos)',
    approach: 'Flow-level rate and source-IP entropy statistics',
    status: 'implemented',
    detail: 'RandomForestClassifier, GroupKFold-validated on 29,844 real rows covering SYN floods, UDP floods, and spoofed-source floods (F1 1.000 vs. 0.912 for the original fixed-rate threshold). backend/detectors/ddos.py.',
  },
  {
    key: 'c2',
    label: 'Botnet C2 Beaconing',
    accent: 'var(--threat-c2)',
    approach: 'Periodicity and inter-arrival interval analysis',
    status: 'implemented',
    detail: 'RandomForestClassifier, range-gated to its validated input region (F1 0.994 vs. 0.875 for the original CV-threshold rule), validated on 16,262 real beacon-emulator rows. backend/detectors/c2.py.',
  },
  {
    key: 'recon',
    label: 'Reconnaissance / Port Scanning',
    accent: 'var(--threat-recon)',
    approach: 'Fan-out patterns (unique ports/hosts) from a single source',
    status: 'implemented',
    detail: 'RandomForestClassifier, GroupKFold-validated on 17,674 real nmap-scan rows (F1 1.000 vs. 0.983 for the original fixed-threshold rule). backend/detectors/recon.py.',
  },
  {
    key: 'dga',
    label: 'DGA Domains / DNS Tunnelling',
    accent: 'var(--threat-dga)',
    approach: 'Entropy / n-gram / word-boundary analysis of DNS query names, plus a rule-based DNS tunnel path',
    status: 'implemented',
    detail: 'RandomForestClassifier (F1 0.99 on 19,000 synthetic rows reproducing 9 published DGA algorithm families -- Conficker, Cryptolocker, Suppobox, etc. -- rather than one generic generator; still no real-malware-capture validation set). backend/detectors/dga.py.',
  },
  {
    key: 'tls',
    label: 'Malware in Encrypted Sessions (TLS/QUIC)',
    accent: 'var(--threat-tls)',
    approach: 'JA3/JA4 fingerprint blacklist lookup + flow-stats ML (no decryption)',
    status: 'implemented',
    detail: 'JA3 blacklist (97 real entries from sslbl.abuse.ch) + JA4 blacklist (wired up, ships empty -- no public JA4 feed exists yet) + a RandomForestClassifier on flow statistics, trained on 19,060 rows (9,530 REAL benign HTTPS flows + synthetic malicious), F1 0.9996. Also covers QUIC metadata (real SNI extraction, no decryption). backend/detectors/tls_malware.py.',
  },
  {
    key: 'exfil',
    label: 'Data Exfiltration',
    accent: 'var(--threat-exfil)',
    approach: 'Rule-based pattern pre-filter (ICMP covert, DNS exfil, high-volume/sustained upload) plus flow-volume ML',
    status: 'implemented',
    detail: 'RandomForestClassifier trained on 15,501 rows (7,001 REAL: real asymmetric HTTP transfers, real ICMP pings, real DNS bursts to public resolvers + synthetic top-up), F1 1.000. backend/detectors/exfil.py.',
  },
]
