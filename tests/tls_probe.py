#!/usr/bin/env python3
"""tls_probe.py — one HTTPS request with (or without) a client certificate; prints JSON.

    python3 tls_probe.py --url https://10.20.0.10:8443/chain?marker=x --ca root.crt \
        [--cert c.crt --key c.key] [--tls12]

Output: {"ok": bool, "stage": "connect|handshake|response", "status": int|null,
         "tls": "TLSv1.3"|null, "server_ids": [...], "body": {...}|str|null, "error": str|null}
A refusal by the server shows up as stage=handshake/response with an error, or status 403.
Stdlib only: it runs on the cloud host, inside the test peer's netns, and on the VMs.
"""
import argparse
import http.client
import json
import ssl
import sys
from urllib.parse import urlparse


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--tls12", action="store_true", help="offer TLS 1.2 ONLY (must be refused)")
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--data", help="request body (JSON text)")
    ap.add_argument("--header", action="append", default=[], help="extra request header 'Name: value'")
    a = ap.parse_args()
    u = urlparse(a.url)
    out = {"ok": False, "stage": "connect", "status": None, "tls": None, "server_ids": [],
           "body": None, "error": None}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if a.tls12:
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(a.ca)
    if a.cert:
        ctx.load_cert_chain(a.cert, a.key)
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=a.timeout)
    try:
        out["stage"] = "handshake"
        conn.connect()
        out["tls"] = conn.sock.version()
        pc = conn.sock.getpeercert()
        out["server_ids"] = [v for k, v in pc.get("subjectAltName", ()) if k == "URI"]
        out["server_serial"] = pc.get("serialNumber")
        # TLS 1.3: the server checks our certificate AFTER our Finished, so a refusal arrives
        # as an alert on the first read, i.e. here.
        out["stage"] = "response"
        body = a.data.encode() if a.data is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        for h in a.header:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
        conn.request(a.method, u.path + ("?" + u.query if u.query else ""), body=body, headers=headers)
        r = conn.getresponse()
        out["status"] = r.status
        out["headers"] = {k: v for k, v in r.getheaders()}
        raw = r.read().decode(errors="replace")
        try:
            out["body"] = json.loads(raw)
        except ValueError:
            out["body"] = raw
        out["ok"] = r.status == 200
    except Exception as e:   # noqa: BLE001 — every failure is a verdict here
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        conn.close()
    print(json.dumps(out))


if __name__ == "__main__":
    sys.exit(main())
