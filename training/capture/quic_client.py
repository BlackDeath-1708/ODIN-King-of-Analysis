"""
Minimal real QUIC client, used by capture_quic.py to generate real QUIC
sessions for the encrypted-session malware detector's QUIC coverage
(PS 26145 (d): "Detection from TLS/QUIC metadata alone"). Not part of the
runtime detection pipeline -- training/capture tooling only.

Uses aioquic directly (pip install aioquic) since this environment's curl
build has no HTTP/3 support (`curl --http3` fails: "installed libcurl
version does not support this" -- checked directly). Only performs the
QUIC handshake itself (no HTTP/3 request layer needed) -- aioquic's
`connect()` completes the full handshake before the context manager body
runs, which alone is enough to give Zeek's quic.log a real Initial packet
(with real SNI) and conn.log a real multi-packet, real-duration UDP flow.
A short sleep after connecting lets a few keepalive/ack packets exchange
so the flow isn't a single-packet stub.
"""
import asyncio
import ssl

from aioquic.asyncio import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration


async def fetch_one(host: str, port: int = 443) -> None:
    config = QuicConfiguration(alpn_protocols=H3_ALPN, is_client=True, server_name=host)
    config.verify_mode = ssl.CERT_NONE  # training capture only, never used for real validation
    async with connect(host, port, configuration=config) as protocol:
        await protocol.ping()
        await asyncio.sleep(0.3)


async def main(host: str, port: int = 443) -> None:
    try:
        await asyncio.wait_for(fetch_one(host, port), timeout=8)
    except Exception:
        pass  # training capture: a failed/timed-out attempt just yields one fewer real sample


if __name__ == "__main__":
    import sys
    asyncio.run(main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 443))
