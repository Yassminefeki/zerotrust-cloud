#!/usr/bin/env python3
"""Stage 13 — security audit report: who did what, what was refused, and the state of the trust.

    tools/zt-audit.py [--since "24 hours ago"]        (make audit [SINCE="2 hours ago"])

Collected over SSH (build/ssh_config) from the VMs, read-only:
  * zt-mtls journals of every service: requests per identity, every refusal with its reason
    (route, identity, cross-site, revoked, rate limit, TLS handshake), next-hop failures;
  * nftables drop logs of every VM (zt-drop-*): who knocked where;
  * the bank's audit table and ledger (PostgreSQL, as the postgres superuser on the database VM);
  * step-ca's journal: certificates issued, renewed, revoked; the CRL each service enforces;
  * certificate expiry of every VM and every actor (cloud host);
  * the attack report (make attacks) and the remote client's report, when present.
Writes build/reports/audit.md (+ audit.json). Prints no key, token or password: only identities,
serials, dates and counts.
"""
import argparse
import json
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
REPORTS = BUILD / "reports"

ACCESS = re.compile(r'^zt-mtls (\S+) (\S+) "(\S+) (\S+) HTTP/[\d.]+" (\d{3})')
REFUSED = re.compile(r"^zt-mtls refused (\S+): (.*)$")
DENIED = re.compile(r"^zt-mtls denied (\S+?)(?: via (\S+))? (GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (\S+): (\d{3}) ?(.*)$")
LIMITED = re.compile(r"^zt-mtls rate-limited (\S+): (.*)$")
NEXTHOP = re.compile(r"^zt-mtls next hop refused on (\S+) (\S+): (.*)$")
DROP = re.compile(r"zt-drop-(\S+?): .*?SRC=(\S+) DST=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?")
CA_REQ = re.compile(r"path=(/\S+).*?status=(\d{3})")
REVOKED_SERIAL = re.compile(r"certificate ([0-9A-Fa-f]+) of (\S+) is revoked")


# ------------------------------------------------------------------ collect --
def ssh(node, cmd, timeout=90):
    r = subprocess.run(["ssh", "-F", str(BUILD / "ssh_config"), "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                        node, cmd], capture_output=True, text=True, timeout=timeout)
    return r.stdout if r.returncode == 0 else None


def nodes():
    return sorted(p.name for p in (BUILD / "nodes").iterdir() if p.is_dir())


def mtls_nodes():
    return sorted(p.parent.name for p in (BUILD / "nodes").glob("*/mtls.json"))


def crl_nodes():
    """The VMs that enforce revocation (an HTTPS mTLS service): only they have a list to check."""
    return sorted(p.parent.name for p in (BUILD / "nodes").glob("*/mtls.json")
                  if "revocation" in json.loads(p.read_text()))


def parse_mtls(lines):
    """zt-mtls journal lines -> counters (pure: unit-tested)."""
    out = {"requests": Counter(), "status": Counter(), "refused": Counter(), "denied": Counter(),
           "rate_limited": Counter(), "next_hop": Counter(), "revoked_attempts": Counter()}
    for l in lines:
        if m := ACCESS.match(l):
            src, who, method, path, status = m.groups()
            out["requests"][who] += 1
            out["status"][status] += 1
        elif m := DENIED.match(l):
            who, via, method, path, status, why = m.groups()
            out["denied"][(who, f"{method} {path.split('?')[0]}", status, why.strip())] += 1
        elif m := REFUSED.match(l):
            src, reason = m.groups()
            if r := REVOKED_SERIAL.search(reason):
                out["revoked_attempts"][(r.group(1).upper().lstrip("0"), r.group(2))] += 1
            reason = re.sub(r"certificate [0-9A-Fa-f]+ of", "certificate <serial> of", reason)
            reason = re.sub(r"retry after \d+s", "retry after Ns", reason)
            out["refused"][(src, reason[:160])] += 1
        elif m := LIMITED.match(l):
            out["rate_limited"][m.group(1)] += 1
        elif m := NEXTHOP.match(l):
            out["next_hop"][(m.group(2), m.group(3)[:120])] += 1
    return out


def parse_drops(lines):
    c = Counter()
    for l in lines:
        if m := DROP.search(l):
            chain, src, dst, proto, dpt = m.groups()
            c[(chain, src, f"{dst}:{dpt}" if dpt else dst, proto)] += 1
    return c


def parse_ca(lines):
    c = Counter()
    for l in lines:
        if m := CA_REQ.search(l):
            path = re.sub(r"/[0-9a-f]{20,}", "/<id>", m.group(1))
            c[(path, m.group(2))] += 1
    return c


def collect(since):
    data = {"since": since, "nodes": {}, "unreachable": []}
    q = since.replace("'", "")
    for n in nodes():
        d = {}
        drops = ssh(n, f"sudo journalctl -k --since '{q}' --no-pager -o cat | grep zt-drop- || true")
        if drops is None:
            data["unreachable"].append(n)
            continue
        d["drops"] = parse_drops(drops.splitlines())
        if n in mtls_nodes():
            j = ssh(n, f"sudo journalctl -u zt-mtls --since '{q}' --no-pager -o cat") or ""
            d["mtls"] = parse_mtls(j.splitlines())
        if n in crl_nodes():
            rv = ssh(n, "sudo cat /etc/zt/pki/revoked.json")
            d["crl"] = json.loads(rv) if rv else None
        crt = ssh(n, "sudo openssl x509 -in /etc/zt/pki/cert.crt -noout -serial -enddate 2>/dev/null || true") or ""
        d["cert"] = dict(l.split("=", 1) for l in crt.splitlines() if "=" in l)
        data["nodes"][n] = d
    pki = json.loads((BUILD / "pki/pki.json").read_text())
    ca = pki["ca"]["node"]
    if ca in data["nodes"]:
        j = ssh(ca, f"sudo journalctl -u step-ca --since '{q}' --no-pager -o cat") or ""
        data["nodes"][ca]["ca"] = parse_ca(j.splitlines())
    db = ssh("database", "sudo -u postgres psql -d appdb -tA -F '|' -c \""
             f"SELECT 'A', actor, action, count(*) FROM bank.audit WHERE at > now() - interval '{interval(since)}' "
             "GROUP BY 2,3 ORDER BY 4 DESC\" -c \""
             "SELECT 'L', to_char(at, 'YYYY-MM-DD HH24:MI:SS'), actor, action, detail::text FROM bank.audit "
             "ORDER BY id DESC LIMIT 15\" -c \""
             "SELECT 'B', coalesce(sum(amount_cents), 0), count(*) FROM bank.entries\" -c \""
             "SELECT 'T', (SELECT count(*) FROM bank.transfers), (SELECT count(*) FROM bank.incoming)\"")
    data["db"] = parse_db(db) if db is not None else None
    data["clients"] = client_certs(pki)
    for name in ("attacks.json", "remote-client-report.json"):
        p = REPORTS / name
        data[name] = json.loads(p.read_text()) if p.exists() else None
    return data


def interval(since):
    """'24 hours ago' -> '24 hours' for PostgreSQL; anything else -> 24 hours."""
    m = re.match(r"^\s*(\d+)\s*(minute|min|hour|day|week)s?\s+ago\s*$", since)
    if not m:
        return "24 hours"
    unit = {"min": "minute"}.get(m.group(2), m.group(2))
    return f"{m.group(1)} {unit}s"


def parse_db(text):
    out = {"by_actor": [], "last": [], "ledger_sum": None, "entries": 0, "transfers": 0, "incoming": 0}
    for l in text.splitlines():
        f = l.split("|")
        if f[0] == "A" and len(f) == 4:
            out["by_actor"].append((f[1], f[2], int(f[3])))
        elif f[0] == "L" and len(f) >= 5:
            out["last"].append((f[1], f[2], f[3], "|".join(f[4:])[:200]))
        elif f[0] == "B" and len(f) == 3:
            out["ledger_sum"], out["entries"] = int(f[1]), int(f[2])
        elif f[0] == "T" and len(f) == 3:
            out["transfers"], out["incoming"] = int(f[1]), int(f[2])
    return out


def client_certs(pki):
    out = []
    for cn, i in pki["identities"].items():
        if i.get("kind") != "client":
            continue
        d = ROOT / "ansible/.secrets/pki" / cn
        crt = d / "client.crt"
        end = serial = None
        if crt.exists():
            r = subprocess.run(["openssl", "x509", "-in", str(crt), "-noout", "-serial", "-enddate"],
                               capture_output=True, text=True)
            kv = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)
            end, serial = kv.get("notAfter"), kv.get("serial")
        revoked = sorted(p.name for p in (d / "revoked").iterdir()) if (d / "revoked").is_dir() else []
        out.append({"actor": i.get("actor"), "identity": i["uri"], "serial": serial, "not_after": end,
                    "revoked_before": revoked})
    return out


# ------------------------------------------------------------------- render --
def table(head, rows):
    if not rows:
        return ["_none_", ""]
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + \
           ["| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in rows] + [""]


def render(data):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = ["# ZT Bank — security audit", "", f"Generated {now} on the cloud host; period: since {data['since']}.", ""]
    findings = []
    if data["unreachable"]:
        findings.append(f"VMs not reachable over SSH: {', '.join(data['unreachable'])}")

    md += ["## 1. Who used the bank", ""]
    rows = []
    for n, d in data["nodes"].items():
        for who, c in (d.get("mtls") or {}).get("requests", Counter()).most_common():
            rows.append((n, who, c))
    md += table(["service VM", "identity (from its certificate)", "requests"], rows)

    md += ["## 2. Refusals", "", "Every refusal names the real identity (or source address) and the reason.", ""]
    rows = []
    for n, d in data["nodes"].items():
        m = d.get("mtls") or {}
        for (src, why), c in m.get("refused", Counter()).most_common():
            rows.append((n, src, why, c))
        for (who, req, st, why), c in m.get("denied", Counter()).most_common():
            rows.append((n, who, f"{req} -> {st} {why}".strip(), c))
        for who, c in m.get("rate_limited", Counter()).most_common():
            rows.append((n, who, "rate limit (429)", c))
        for (path, why), c in m.get("next_hop", Counter()).most_common():
            rows.append((n, "next hop", f"{path}: {why}", c))
    md += table(["VM", "who", "what was refused", "times"], rows)

    rv = Counter()
    for d in data["nodes"].values():
        rv.update((d.get("mtls") or {}).get("revoked_attempts", Counter()))
    md += ["## 3. Revocation", "", "Attempts with a revoked certificate (stolen copies):", ""]
    md += table(["serial", "identity", "attempts"], [(s, i, c) for (s, i), c in rv.most_common()])
    rows = []
    for n, d in data["nodes"].items():
        crl = d.get("crl")
        if "crl" not in d:
            continue
        if not crl:
            rows.append((n, "MISSING", "-", "-", "-"))
            findings.append(f"{n}: no revocation list (it refuses everyone: fail-closed)")
            continue
        fresh = crl["next_update"] > time.time()
        age = int(time.time() - crl.get("fetched_at", 0))
        rows.append((n, crl.get("crl_number"), len(crl["revoked"]), f"{age} s ago",
                     "fresh" if fresh else "STALE"))
        if not fresh:
            findings.append(f"{n}: revocation list past its next update (refusing everyone)")
        elif age > 180:
            findings.append(f"{n}: revocation list fetched {age} s ago (timer every 60 s): check zt-crl.timer")
    numbers = {r[1] for r in rows if r[1] not in ("MISSING",)}
    if len(numbers) > 1:
        findings.append(f"services enforce different CRLs: {sorted(map(str, numbers))}")
    md += ["CRL enforced by each service:", ""]
    md += table(["VM", "CRL number", "revoked serials", "fetched", "state"], rows)

    md += ["## 4. Certificates", ""]
    rows = []
    for n, d in data["nodes"].items():
        c = d.get("cert") or {}
        if c:
            rows.append((n, c.get("serial", "?"), c.get("notAfter", "?")))
    md += table(["VM", "serial", "expires"], rows)
    md += table(["actor", "identity", "serial", "expires", "revoked earlier"],
                [(c["actor"], c["identity"], c["serial"] or "not issued", c["not_after"] or "-",
                  ", ".join(c["revoked_before"]) or "-") for c in data["clients"]])
    ca = next((d["ca"] for d in data["nodes"].values() if "ca" in d), None)
    md += ["CA activity (step-ca):", ""]
    md += table(["endpoint", "status", "count"], [(p, s, c) for (p, s), c in sorted((ca or {}).items())])

    md += ["## 5. Network drops (nftables, every VM)", ""]
    rows = []
    for n, d in data["nodes"].items():
        for (chain, src, dst, proto), c in d.get("drops", Counter()).most_common(15):
            rows.append((n, chain, src, dst, proto, c))
    md += table(["VM", "rule", "source", "destination", "proto", "packets"], rows)

    md += ["## 6. The bank's own audit trail (PostgreSQL)", ""]
    db = data.get("db")
    if db is None:
        md += ["_database not reachable_", ""]
        findings.append("database not reachable for the audit")
    else:
        md += table(["actor", "action", "count"], db["by_actor"])
        md += ["Last entries:", ""] + table(["at", "actor", "action", "detail"], db["last"])
        bal = db["ledger_sum"] == 0
        md += [f"Ledger: {db['entries']} entries, sum = {db['ledger_sum']} cents "
               f"({'balanced' if bal else 'NOT BALANCED'}); {db['transfers']} transfers, "
               f"{db['incoming']} incoming payments.", ""]
        if not bal:
            findings.append("the ledger is not balanced")

    md += ["## 7. Attack reports", ""]
    a = data.get("attacks.json")
    if a:
        md += [f"Cloud host (`make attacks`, {a['when']}):", ""]
        md += table(["", "attack", "verdict"], [(k, v["title"], v["verdict"]) for k, v in a["attacks"].items()])
        findings += [f"attack {k} not defended: {v['verdict']}" for k, v in a["attacks"].items()
                     if v["verdict"] != "DEFENDED"]
    else:
        md += ["_no attack report yet: `make attacks`_", ""]
    r = data.get("remote-client-report.json")
    if r:
        md += [f"Remote client ({r.get('machine', '?')}, {r['when']}):", ""]
        md += table(["", "attack", "verdict"], [(x["id"], x["title"], x["verdict"]) for x in r["results"]])
        findings += [f"remote attack {x['id']}: BREACH" for x in r["results"] if x["verdict"] == "BREACH"]
    else:
        md += ["_no remote-client report: copy remote-client-report.json to build/reports/_", ""]

    md[4:4] = ["## Findings", ""] + ([f"- ⚠️ {f}" for f in findings] or ["- none: every check above is as expected"]) + [""]
    return "\n".join(md), findings


def jsonable(o):
    if isinstance(o, Counter):
        return [[list(k) if isinstance(k, tuple) else k, v] for k, v in o.most_common()]
    if isinstance(o, dict):
        return {k: jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [jsonable(x) for x in o]
    return o


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default="24 hours ago")
    a = ap.parse_args()
    data = collect(a.since)
    md, findings = render(data)
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "audit.md").write_text(md)
    (REPORTS / "audit.json").write_text(json.dumps(jsonable(data), indent=1, default=str))
    print(md.split("## 1.")[0].strip())
    print(f"\nfull report: {REPORTS / 'audit.md'}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
