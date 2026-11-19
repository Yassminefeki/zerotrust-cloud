#!/usr/bin/env python3
"""burst_probe.py — bursts for the stage 12 limits; run inside a peer's netns, prints JSON.

  https: N sequential HTTPS GETs with a client certificate, `interval` seconds apart
         -> {"statuses": [...], "retry_after": [...]}       (the frontend's rate limit per identity)
  tcp:   N TCP connects started together, each with a short timeout, nothing sent
         -> {"connected": n, "failed": n}                     (the gateway's connection limit per peer)
"""
import argparse
import http.client
import json
import socket
import ssl
import threading
import time
from urllib.parse import urlparse


def https(a):
    u = urlparse(a.url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(a.ca)
    ctx.load_cert_chain(a.cert, a.key)
    statuses, retry = [], []
    for _ in range(a.n):
        c = http.client.HTTPSConnection(u.hostname, u.port, context=ctx, timeout=10)
        try:
            c.request("GET", u.path or "/")
            r = c.getresponse()
            r.read()
            statuses.append(r.status)
            retry.append(r.getheader("Retry-After"))
        except OSError as e:
            statuses.append(f"error: {e}")
            retry.append(None)
        finally:
            c.close()
        time.sleep(a.interval)
    return {"statuses": statuses, "retry_after": retry}


def tcp(a):
    u = urlparse(a.url)
    ok, bad, lock = [0], [0], threading.Lock()

    def one():
        s = socket.socket()
        s.settimeout(a.timeout)
        try:
            s.connect((u.hostname, u.port))
            with lock:
                ok[0] += 1
        except OSError:
            with lock:
                bad[0] += 1
        finally:
            s.close()
    threads = [threading.Thread(target=one) for _ in range(a.n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return {"connected": ok[0], "failed": bad[0]}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["https", "tcp"])
    ap.add_argument("--url", required=True)
    ap.add_argument("--n", type=int, default=25)
    ap.add_argument("--interval", type=float, default=0.3)
    ap.add_argument("--timeout", type=float, default=0.8)
    ap.add_argument("--cert"), ap.add_argument("--key"), ap.add_argument("--ca")
    a = ap.parse_args()
    print(json.dumps(https(a) if a.mode == "https" else tcp(a)))
