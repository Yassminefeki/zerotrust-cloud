"""TCP reachability probes, run FROM a source (a VM over SSH, or the i5 itself).

Verdicts, as seen by the kernel of the source:
  open     - TCP handshake completed (a service is listening and the path is allowed)
  refused  - RST received: the path is ALLOWED by every firewall, nothing listens yet
  timeout  - no answer: dropped by a firewall (default-drop never answers)
  err:<n>  - local error, e.g. 101/113 = no route (VMs are never routed), 1 = blocked on output
So `reachable = open | refused`, `blocked = timeout | err:*`.
"""
import json
import shlex
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 2.0

# Same logic, shipped as a one-liner to the VMs (they have python3, nothing else to install).
REMOTE = r'''
import json,socket,sys
from concurrent.futures import ThreadPoolExecutor
T=float(sys.argv[2])
def p(t):
    s=socket.socket(); s.settimeout(T)
    try:
        s.connect((t[0],t[1])); return "open"
    except ConnectionRefusedError: return "refused"
    except socket.timeout: return "timeout"
    except OSError as e: return "err:%d" % e.errno
    finally: s.close()
with ThreadPoolExecutor(32) as ex: print(json.dumps(list(ex.map(p,json.loads(sys.argv[1])))))
'''


def is_reachable(verdict: str) -> bool:
    return verdict in ("open", "refused")


def probe_local(targets, timeout=TIMEOUT):
    """targets: [(ip, port)] -> [verdict]"""
    def p(t):
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect(t)
            return "open"
        except ConnectionRefusedError:
            return "refused"
        except socket.timeout:
            return "timeout"
        except OSError as e:
            return f"err:{e.errno}"
        finally:
            s.close()
    with ThreadPoolExecutor(32) as ex:
        return list(ex.map(p, targets))


def probe_from(host, targets, timeout=TIMEOUT):
    """Run the probe on a testinfra host (no root needed)."""
    if not targets:
        return []
    cmd = f"python3 -c {shlex.quote(REMOTE)} {shlex.quote(json.dumps(targets))} {timeout}"
    out = host.check_output(cmd)
    return json.loads(out)
