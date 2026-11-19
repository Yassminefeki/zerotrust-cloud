"""Stage 8a — nobody can sniff the traffic. Run with `make test-8` (on the i5, sudo).

tcpdump runs on EVERY libvirt bridge of the policy (virbr-zt-*) while a request carrying a
random marker crosses the whole chain: tunnel -> frontend -> service-a -> service-b -> database
(the database echoes the marker back). The marker must appear in NO capture.
Two guards keep the test honest:
  * a control marker sent in clear (UDP) on the mgmt bridge MUST be found: the capture works;
  * each hop's traffic MUST be present in the captures: the encrypted packets were really seen.
"""
import subprocess
import time
import uuid

import pytest

from ztlib import BUILD, run
from ztlive import VMs, ensure_peer, frontend_url, mtls, probe_tunnel, peer_creds

pytestmark = pytest.mark.final

CAPTURE_SECONDS = 15


@pytest.fixture(scope="module")
def capture(policy):
    ensure_peer()
    tp = peer_creds()
    bridges = {n: s["bridge"] for n, s in policy["networks"].items() if "bridge" in s}
    marker = f"ZT-SECRET-{uuid.uuid4().hex}"
    control = f"ZT-CONTROL-{uuid.uuid4().hex}"
    d = run(["mktemp", "-d", "/tmp/zt-cap-XXXXXX"], sudo=True, check=True).stdout.strip()   # root-only
    procs = []
    for net, br in bridges.items():
        procs.append(subprocess.Popen(
            ["sudo", "-n", "timeout", str(CAPTURE_SECONDS), "tcpdump", "-Z", "root", "-i", br, "-U", "-s", "0",
             "-w", f"{d}/{net}.pcap"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
    time.sleep(3)                      # tcpdump is listening
    result = probe_tunnel(frontend_url(f"/chain?marker={marker}"), *tp)
    ca_ip = policy["nodes"]["ca"]["interfaces"]["mgmt"]
    # clear-text control on mgmt (to the CA's discard port: dropped by its firewall, but on the wire)
    run(["python3", "-c", "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
         "s.sendto(sys.argv[1].encode(),(sys.argv[2],9))", control, ca_ip], check=True)
    for p in procs:
        p.wait(timeout=CAPTURE_SECONDS + 10)
    raw = {}
    for net in bridges:     # binary pcap, read as root (tcpdump wrote it as root)
        raw[net] = subprocess.run(["sudo", "-n", "cat", f"{d}/{net}.pcap"],
                                  capture_output=True, timeout=30, check=True).stdout
    run(["rm", "-rf", d], sudo=True)
    return {"marker": marker, "control": control, "result": result, "raw": raw, "bridges": bridges}


def _count(pcap_bytes, flt):
    """Packets matching a tcpdump filter in a capture held in memory."""
    r = subprocess.run(["tcpdump", "-nn", "-r", "-", flt], input=pcap_bytes, capture_output=True, timeout=30)
    return len([l for l in r.stdout.decode(errors="replace").splitlines() if l.strip()])


def test_the_request_went_through(capture):
    r = capture["result"]
    assert r["ok"], r
    db = r["body"]["next"]["next"]["next"]
    assert db["marker"] == capture["marker"], "the marker crossed every hop and the database"


def test_capture_works_control_marker_seen(capture):
    assert capture["control"].encode() in capture["raw"]["mgmt"], \
        "the clear-text control packet was not captured: the capture itself is broken"


@pytest.mark.parametrize("net,flt", [
    ("wan", "udp port 51820"),        # WireGuard, i5 <-> gateway
    ("dmz", "tcp port 8443"),         # gateway -> frontend
    ("app", "tcp port 9443"),         # frontend -> service-a -> service-b
    ("data", "tcp port 5432"),        # service-b -> database
])
def test_each_hop_was_captured(capture, net, flt):
    assert _count(capture["raw"][net], flt) > 0, f"no '{flt}' packet captured on {capture['bridges'][net]}"


def test_marker_never_in_clear(capture):
    leaks = [capture["bridges"][n] for n, data in capture["raw"].items() if capture["marker"].encode() in data]
    assert leaks == [], f"marker visible in clear text on {leaks}"


def test_every_hop_is_tls13(capture):
    hop, versions = capture["result"]["body"], []
    while hop:
        versions.append((hop["node"], hop["tls"]))
        hop = hop.get("next")
    assert all(v == "TLSv1.3" for _, v in versions), versions
    assert len(versions) == 4


@pytest.fixture(scope="module")
def vm():
    return VMs()


@pytest.mark.parametrize("caller,callee", [("frontend", "service-a"), ("service-a", "service-b")])
def test_tls12_refused_by_inner_services(vm, caller, callee):
    """Asked for TLS 1.2 only, from the VM the firewall lets through: no handshake."""
    listen = next(iter(mtls(callee)["serves"].values()))["listen"]
    out = vm(caller).run(f"openssl s_client -connect {listen} -tls1_2 </dev/null")
    assert out.rc != 0 or "Cipher is (NONE)" in out.stdout, out.stdout[-400:]


def test_tls12_refused_by_postgres(vm):
    db = next(n for n in ("database",) if (BUILD / "nodes" / n / "pg_hba.conf").exists())
    listen = next(iter(mtls(db)["serves"].values()))["listen"]
    caller = next(n for n in ("service-b",))
    out = vm(caller).run(f"openssl s_client -starttls postgres -connect {listen} -tls1_2 </dev/null")
    assert out.rc != 0 or "Cipher is (NONE)" in out.stdout, out.stdout[-400:]
    ok = vm(caller).run(f"openssl s_client -starttls postgres -connect {listen} -tls1_3 </dev/null")
    assert "TLSv1.3" in ok.stdout, ok.stdout[-400:]
