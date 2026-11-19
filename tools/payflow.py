#!/usr/bin/env python3
"""payflow.py — the payment partner "PayFlow": calls ZT Bank's webhook from the internet, no VPN.

  python3 tools/payflow.py --to ZTB-ALICE-01 --amount 12.50 [--description "Order 42"]

Every request: mTLS with the partner's certificate (the bank's server is checked by its SPIFFE ID,
not by host name: the partner dials whatever address publishes the API), and headers
  X-ZT-Timestamp: <unix seconds>   X-ZT-Nonce: <random, once>   X-ZT-Signature: v1=<hex>
where the signature is HMAC-SHA256(secret, "<timestamp>.<nonce>.<body>").

Attack modes, to see the bank refuse them:
  --replay          send the very same signed request twice (captured traffic played again)
  --skew SECONDS    sign with a timestamp SECONDS away from now (stale or future)
  --tamper          change the amount after signing (man in the middle)
  --wrong-secret    sign with a secret that is not the partner's
Defaults read the i5's files (build/, ansible/.secrets); on another machine pass every path.
Standard library only.
"""
import argparse
import hashlib
import hmac
import http.client
import json
import secrets
import ssl
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRUST_DOMAIN = "spiffe://cloud.local"


def signature(secret: bytes, timestamp: str, nonce: str, body: bytes) -> str:
    return hmac.new(secret, f"{timestamp}.{nonce}.".encode() + body, hashlib.sha256).hexdigest()


def signed(secret: bytes, payment: dict, ts: int | None = None, nonce: str | None = None):
    """-> (body bytes, headers) ready to send."""
    body = json.dumps(payment, separators=(",", ":")).encode()
    ts = str(int(time.time()) if ts is None else ts)
    nonce = nonce or secrets.token_urlsafe(24)
    return body, {"Content-Type": "application/json", "X-ZT-Timestamp": ts, "X-ZT-Nonce": nonce,
                  "X-ZT-Signature": "v1=" + signature(secret, ts, nonce, body)}


def context(cert, key, ca):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.check_hostname = False          # identity is checked below, by SPIFFE ID (chain still verified)
    c.load_verify_locations(ca)
    c.load_cert_chain(cert, key)
    return c


def send(host, port, ctx, body, headers, path="/webhook", expect=f"{TRUST_DOMAIN}/frontend", timeout=20):
    """-> (status, parsed body). Raises if the server is not the bank's frontend."""
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
    try:
        conn.connect()
        ids = [v for k, v in conn.sock.getpeercert().get("subjectAltName", ()) if k == "URI"]
        if ids != [expect]:
            raise ssl.SSLError(f"server is {ids}, expected {expect}: not sending anything")
        conn.request("POST", path, body=body, headers=headers)
        r = conn.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw.decode(errors="replace")
    finally:
        conn.close()


def default_url():
    """From the i5: the gateway's published address (build/host/host.json)."""
    try:
        h = json.loads((ROOT / "build/host/host.json").read_text())
        return "https://" + next(d["to"] for d in h["dnat"] if d["flow"] == "partner-webhook") + "/webhook"
    except (OSError, StopIteration, KeyError, ValueError):
        return None


def main(argv=None):
    sec = ROOT / "ansible/.secrets"
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=default_url(), help="https://HOST:PORT/webhook (i7: https://cloud-i5.local:8444/webhook)")
    ap.add_argument("--partner", default="payflow")
    ap.add_argument("--cert"), ap.add_argument("--key"), ap.add_argument("--secret-file")
    ap.add_argument("--ca", default=str(ROOT / "build/pki/root_ca.crt"))
    ap.add_argument("--to", required=True)
    ap.add_argument("--amount", required=True)
    ap.add_argument("--reference", default=None, help="the partner's payment id (default: new one)")
    ap.add_argument("--description", default="")
    ap.add_argument("--replay", action="store_true")
    ap.add_argument("--skew", type=int, default=0)
    ap.add_argument("--tamper", action="store_true")
    ap.add_argument("--wrong-secret", action="store_true")
    a = ap.parse_args(argv)
    if not a.url:
        ap.error("--url is required here")
    cn = f"partner-{a.partner}"
    cert = a.cert or str(sec / "pki" / cn / "client.crt")
    key = a.key or str(sec / "pki" / cn / "client.key")
    secret = bytes.fromhex(Path(a.secret_file or sec / "partners" / f"{a.partner}.key").read_text().strip())
    if a.wrong_secret:
        secret = secrets.token_bytes(32)
    u = a.url.split("://", 1)[-1]
    hostport, _, path = u.partition("/")
    host, _, port = hostport.rpartition(":")
    payment = {"reference": a.reference or f"PF-{secrets.token_hex(6).upper()}", "to": a.to,
               "amount": a.amount, "description": a.description}
    body, headers = signed(secret, payment, ts=int(time.time()) + a.skew)
    if a.tamper:
        body = body.replace(f'"amount":"{a.amount}"'.encode(), b'"amount":"4999.00"')
    ctx = context(cert, key, a.ca)
    rounds = 2 if a.replay else 1
    worst = 0
    for i in range(rounds):
        status, out = send(host, int(port), ctx, body, headers, "/" + path)
        print(json.dumps({"attempt": i + 1, "status": status, "response": out}))
        worst = max(worst, status)
    return 0 if worst < 400 else 1


if __name__ == "__main__":
    sys.exit(main())
