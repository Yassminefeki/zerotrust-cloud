"""Full TCP connect scan of one address (stdlib only): which of the 65535 ports answer?

Run from where the attacker stands: inside a network namespace (`ip netns exec zt-peer`), from the
cloud host's own namespace (= outside, like the Wi-Fi), or on the remote client.

    python3 port_scan.py 10.20.0.10                 # every TCP port
    python3 port_scan.py 10.20.0.10 --ports 1-1024,8443

Prints JSON: {"host", "scanned", "open": [ports], "refused": n, "silent": n, "seconds"}
  open    = handshake completed (something listens AND every firewall let it through)
  refused = RST: the path is open but nothing listens (a firewall that drops never answers)
  silent  = no answer: dropped (the zero-trust default)
"""
import argparse
import asyncio
import json
import resource
import time


def parse_ports(spec):
    out = set()
    for part in spec.split(","):
        a, _, b = part.partition("-")
        out.update(range(int(a), int(b or a) + 1))
    return sorted(p for p in out if 0 < p < 65536)


async def scan(host, ports, timeout, workers):
    verdict = {}
    queue = asyncio.Queue()
    for p in ports:
        queue.put_nowait(p)

    async def one(port):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            w.close()
            return "open"
        except ConnectionRefusedError:
            return "refused"
        except (asyncio.TimeoutError, TimeoutError):
            return "silent"
        except OSError as e:
            if e.errno == 24:    # out of file descriptors: never report that as "silent"
                raise
            return "silent"      # unreachable / no route: nothing answered either

    async def worker():
        while not queue.empty():
            p = queue.get_nowait()
            verdict[p] = await one(p)

    await asyncio.gather(*(worker() for _ in range(workers)))
    return verdict


def raise_nofile(cap=8192):
    """As many parallel sockets as the system lets us (a scan runs out of file descriptors at 1024
    and would then report open ports as silent). Returns the usable limit."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = min(cap, hard if hard != resource.RLIM_INFINITY else cap)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, want), hard))
        return max(soft, want)
    except (ValueError, OSError):
        return soft


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--ports", default="1-65535")
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--workers", type=int, default=0, help="parallel connections (default: from ulimit -n)")
    a = ap.parse_args()
    workers = a.workers or max(64, min(4000, raise_nofile() - 64))
    ports = parse_ports(a.ports)
    t0 = time.time()
    v = asyncio.run(scan(a.host, ports, a.timeout, workers))
    print(json.dumps({"host": a.host, "scanned": len(ports),
                      "open": sorted(p for p, s in v.items() if s == "open"),
                      "refused": sum(s == "refused" for s in v.values()),
                      "silent": sum(s == "silent" for s in v.values()),
                      "seconds": round(time.time() - t0, 1)}))


if __name__ == "__main__":
    main()
