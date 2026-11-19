#!/usr/bin/env python3
"""zt-bot.py — the monthly statements bot. Runs INSIDE its network namespace (zt-bot), whose only
way out is its own WireGuard peer, with its own short-lived (1h) certificate:

  sudo ip netns exec zt-bot python3 tools/zt-bot.py --cert C --key K --ca ROOT --url URL --out DIR

Fetches GET /api/statements?month=YYYY-MM from the frontend (server checked by SPIFFE ID and IP),
writes DIR/statements-YYYY-MM.json with a SHA-256 of the content. On 429 (rate limit) it waits the
Retry-After the bank sent, once. Exit code: 0 ok, 1 refused, 2 unreachable. Standard library only.
"""
import argparse
import hashlib
import http.client
import json
import ssl
import sys
import time
from pathlib import Path

EXPECT = "spiffe://cloud.local/frontend"


def fetch(host, port, ctx, path):
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=20)
    try:
        conn.connect()
        ids = [v for k, v in conn.sock.getpeercert().get("subjectAltName", ()) if k == "URI"]
        if ids != [EXPECT]:
            raise ssl.SSLError(f"server is {ids}, expected {EXPECT}")
        conn.request("GET", path, headers={"Accept": "application/json"})
        r = conn.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    finally:
        conn.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--url", required=True, help="https://10.20.0.10:8443/")
    ap.add_argument("--month", default=time.strftime("%Y-%m"))
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)          # chain + IP SAN checked
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(a.ca)
    try:
        ctx.load_cert_chain(a.cert, a.key)
    except (OSError, ssl.SSLError) as e:
        print(f"zt-bot: cannot load the bot's certificate: {e}", file=sys.stderr)
        return 1
    hostport = a.url.split("://", 1)[1].strip("/")
    host, _, port = hostport.rpartition(":")
    path = f"/api/statements?month={a.month}"
    try:
        for attempt in (1, 2):
            status, headers, body = fetch(host, int(port), ctx, path)
            if status == 429 and attempt == 1:
                wait = min(int(headers.get("Retry-After", "5")), 60)
                print(f"zt-bot: rate-limited, retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            break
    except (OSError, ssl.SSLError) as e:
        print(f"zt-bot: bank unreachable: {e}", file=sys.stderr)
        return 2
    if status != 200:
        print(f"zt-bot: refused ({status}): {body[:300].decode(errors='replace')}", file=sys.stderr)
        return 1
    data = json.loads(body)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    f = out / f"statements-{a.month}.json"
    f.write_text(json.dumps({"fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "month": a.month,
                             "sha256": hashlib.sha256(body).hexdigest(), **data}, indent=2) + "\n")
    print(f"zt-bot: {len(data['statements'])} statements for {a.month} -> {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
