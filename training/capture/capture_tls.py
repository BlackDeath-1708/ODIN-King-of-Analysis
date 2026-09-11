"""
Real benign TLS/HTTPS traffic capture for the TLS-malware flow-stats
classifier, run against the isolated zeek_ml_capture_tls container
(docker-compose-tls.yml in this directory) -- watches the real egress
interface, not loopback, since real HTTPS traffic to real internet domains
never touches `lo`. Separate container/log dir from every other capture in
this project (including the live demo's zeek_monitor).

Why this exists: tls_malware.py's flow-stats ML path uses only
orig_bytes/resp_bytes/duration (see backend/stream_consumer.py's
SSLByteEnricher for why those aren't natively on ssl.log rows and had to be
joined from conn.log -- a real bug found and fixed in this same session).
The original benign class for this detector was 100% synthetic. This
script generates the REAL half: actual HTTPS GET requests to a large set
of real, diverse domains, so the benign class's byte/duration distribution
comes from genuine internet traffic instead of a hand-picked numeric range
-- closing the same "non-overlapping synthetic ranges make classification
artificially easy" caveat ML_MODELS.md already flags for this detector.

The malicious class has no ethical real-world source (no real malware C2
traffic can be captured here) and stays synthetic in build_dataset_tls.py
-- documented plainly, not hidden.

High concurrency (ThreadPoolExecutor) since each request is I/O-bound
(network RTT + TLS handshake), not CPU-bound -- makes thousands of real
requests finish in a few minutes instead of a sequential hour+.

Run: python3 training/capture/capture_tls.py
"""
import random
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

# A deliberately broad, diverse set of real, well-known HTTPS domains
# (news, tech, government, education, e-commerce, reference, social) so the
# benign class's response-size/duration distribution reflects genuinely
# varied real-world traffic, not one or two sites' fixed page sizes.
REAL_DOMAINS = [
    "www.wikipedia.org", "en.wikipedia.org", "www.python.org", "www.mozilla.org",
    "www.github.com", "www.gitlab.com", "www.stackoverflow.com", "www.reddit.com",
    "www.bbc.com", "www.nytimes.com", "www.theguardian.com", "www.reuters.com",
    "www.npr.org", "www.cnn.com", "www.aljazeera.com", "www.apnews.com",
    "www.nasa.gov", "www.nist.gov", "www.usa.gov", "www.who.int",
    "www.un.org", "www.europa.eu", "www.gov.uk", "www.india.gov.in",
    "www.mit.edu", "www.stanford.edu", "www.harvard.edu", "www.ox.ac.uk",
    "www.cam.ac.uk", "www.iitb.ac.in", "www.iisc.ac.in",
    "www.amazon.com", "www.ebay.com", "www.etsy.com", "www.walmart.com",
    "www.wikipedia.org", "www.archive.org", "www.gutenberg.org",
    "www.w3.org", "www.ietf.org", "www.icann.org", "www.iso.org",
    "www.cloudflare.com", "www.digitalocean.com", "www.linode.com",
    "www.debian.org", "www.ubuntu.com", "www.kernel.org", "www.gnu.org",
    "www.apache.org", "www.nginx.org", "www.docker.com", "www.kubernetes.io",
    "www.rust-lang.org", "www.golang.org", "nodejs.org", "www.php.net",
    "www.ruby-lang.org", "www.java.com", "www.oracle.com", "www.ibm.com",
    "www.microsoft.com", "www.apple.com", "www.google.com", "www.bing.com",
    "duckduckgo.com", "www.mozilla.org", "www.wikimedia.org",
    "www.coursera.org", "www.edx.org", "www.khanacademy.org", "www.udemy.com",
    "www.researchgate.net", "www.arxiv.org", "www.ncbi.nlm.nih.gov",
    "www.who.int", "www.cdc.gov", "www.nih.gov", "www.fda.gov",
    "www.weather.gov", "www.noaa.gov", "www.usgs.gov", "www.epa.gov",
    "www.imdb.com", "www.rottentomatoes.com", "www.goodreads.com",
    "www.espn.com", "www.skysports.com", "www.olympics.com", "www.fifa.com",
    "www.weforum.org", "www.imf.org", "www.worldbank.org", "www.oecd.org",
    "www.redhat.com", "www.suse.com", "www.canonical.com", "www.freebsd.org",
    "www.mozilla.com", "www.eff.org", "www.torproject.org", "www.letsencrypt.org",
    "www.digicert.com", "www.cloudflare.com", "www.fastly.com", "www.akamai.com",
    "www.salesforce.com", "www.sap.com", "www.adobe.com", "www.autodesk.com",
    "www.intel.com", "www.amd.com", "www.nvidia.com", "www.arm.com",
    "www.cisco.com", "www.juniper.net", "www.vmware.com", "www.citrix.com",
    "www.mongodb.com", "www.postgresql.org", "www.mysql.com", "www.redis.io",
    "www.elastic.co", "www.grafana.com", "www.datadoghq.com", "www.newrelic.com",
]
N_PER_DOMAIN = 40
CURL_TIMEOUT = 6
MAX_WORKERS = 40

random.seed(11)


def fetch(domain: str) -> None:
    try:
        subprocess.run(
            ["curl", "-sk", "-m", str(CURL_TIMEOUT), "-o", "/dev/null", f"https://{domain}/"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=CURL_TIMEOUT + 2,
        )
    except Exception:
        pass


def main():
    tasks = REAL_DOMAINS * N_PER_DOMAIN
    random.shuffle(tasks)
    print(f"Firing {len(tasks)} real HTTPS requests across {len(REAL_DOMAINS)} domains "
          f"({MAX_WORKERS} concurrent workers)...")

    t0 = time.time()
    done = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for _ in pool.map(fetch, tasks):
            done += 1
            if done % 500 == 0:
                print(f"[{time.time() - t0:6.0f}s] {done}/{len(tasks)} requests done")

    print(f"\nDone in {time.time() - t0:.0f}s. {len(tasks)} real HTTPS requests fired.")


if __name__ == "__main__":
    main()
