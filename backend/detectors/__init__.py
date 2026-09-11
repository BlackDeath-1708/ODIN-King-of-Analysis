from .ddos import DDoSDetector
from .recon import ReconDetector
from .c2 import C2Detector
from .dga import DGADetector
from .tls_malware import TLSMalwareDetector
from .exfil import ExfilDetector

ACTIVE_DETECTORS = [
    DDoSDetector, ReconDetector, C2Detector,
    DGADetector, TLSMalwareDetector, ExfilDetector,
]
