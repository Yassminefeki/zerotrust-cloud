#!/usr/bin/env python3
"""Stage 13 — play the attack catalogue (tests/attacks/catalogue.yaml) live and write the report.

    tools/zt-attack.py                 every attack           (make attacks)
    tools/zt-attack.py --only A1,A5    some of them           (make attack A=1  /  A=1,5)
    tools/zt-attack.py --list          the catalogue, nothing run

One pytest run for all the selected tests; the JUnit results are mapped back to the attacks.
Verdict per attack: DEFENDED (every test passed), BREACH (a test failed: the defence did not
hold) or INCOMPLETE (a test errored or was skipped). Report: build/reports/attacks.md (+ .json).
Exit status 0 only if every selected attack is DEFENDED.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CATALOGUE = ROOT / "tests/attacks/catalogue.yaml"
REPORTS = ROOT / "build/reports"


def load():
    return yaml.safe_load(CATALOGUE.read_text())


def select(cat, only):
    if not only:
        return list(cat)
    out = []
    for x in only.split(","):
        x = x.strip().upper()
        x = x if x.startswith("A") else f"A{x}"
        if x not in cat:
            sys.exit(f"unknown attack {x}; known: {', '.join(cat)}")
        out.append(x)
    return out


def nodeid(case):
    """JUnit testcase -> pytest node id (tests.bank.test_bank + test_x[p] -> tests/bank/test_bank.py::test_x[p])."""
    return case.get("classname", "").replace(".", "/") + ".py::" + case.get("name", "")


def covers(ref, nid):
    if "::" not in ref:                          # a whole module
        return nid.startswith(ref + "::")
    return nid == ref or nid.startswith(ref + "[")


def outcome(case):
    for tag, res in (("failure", "failed"), ("error", "error"), ("skipped", "skipped")):
        el = case.find(tag)
        if el is not None:
            return res, (el.get("message") or "").strip().splitlines()[0][:300] if el.get("message") else ""
    return "passed", ""


def run(ids, pytest_args):
    with tempfile.TemporaryDirectory() as d:
        xml = Path(d) / "junit.xml"
        cmd = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-o", "junit_family=xunit1",
               f"--junitxml={xml}", "-v", *pytest_args, *ids]
        t0 = time.time()
        rc = subprocess.call(cmd, cwd=ROOT)
        cases = [] if not xml.exists() else [
            {"id": nodeid(c), "result": outcome(c)[0], "detail": outcome(c)[1], "seconds": float(c.get("time", 0))}
            for c in ET.parse(xml).getroot().iter("testcase")]
        return rc, cases, round(time.time() - t0)


def verdict(results):
    if not results:
        return "INCOMPLETE"
    if any(r["result"] == "failed" for r in results):
        return "BREACH"
    if any(r["result"] != "passed" for r in results):
        return "INCOMPLETE"
    return "DEFENDED"


def report(cat, chosen, cases, seconds):
    rows, out = [], {}
    for a in chosen:
        spec = cat[a]
        res = [c for c in cases if any(covers(ref, c["id"]) for ref in spec["tests"])]
        missing = [ref for ref in spec["tests"] if not any(covers(ref, c["id"]) for c in cases)]
        v = "INCOMPLETE" if missing and verdict(res) == "DEFENDED" else verdict(res)
        out[a] = {"title": spec["title"], "verdict": v, "tests": res, "not_run": missing,
                  "remote": spec.get("remote", [])}
        rows.append((a, spec, v, res, missing))

    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = ["# ZT Bank — attack report", "",
          f"Played live on the cloud host, {when}, in {seconds} s. Catalogue: `tests/attacks/catalogue.yaml`.",
          "Each attack is DEFENDED only if every test that proves its defence passed.", "",
          "| | Attack | Verdict | Tests | Remote client |", "|---|---|---|---|---|"]
    for a, spec, v, res, missing in rows:
        ok = sum(r["result"] == "passed" for r in res)
        mark = {"DEFENDED": "✅ DEFENDED", "BREACH": "❌ BREACH", "INCOMPLETE": "⚠️ INCOMPLETE"}[v]
        md.append(f"| {a} | {spec['title']} | {mark} | {ok}/{len(res) + len(missing)} | "
                  f"{', '.join(spec.get('remote', [])) or '—'} |")
    for a, spec, v, res, missing in rows:
        md += ["", f"## {a} — {spec['title']}  ({v})", "",
               f"- **Attacker:** {spec['attacker']}", f"- **Goal:** {spec['goal']}",
               f"- **Defence:** {spec['defence']}", "", "| Test | Result | s |", "|---|---|---|"]
        for r in res:
            md.append(f"| `{r['id']}` | {r['result']}{(': ' + r['detail']) if r['detail'] else ''} | {r['seconds']:.1f} |")
        for m in missing:
            md.append(f"| `{m}` | not run | |")
    md += ["", "Remote client (B1–B6): played from the remote client with `remote-client/attack.py`; its",
           "report (`remote-client-report.json`) can be dropped in `build/reports/` and is summarised by `make audit`.", ""]
    REPORTS.mkdir(parents=True, exist_ok=True)
    # a partial run (make attack A=...) never overwrites the full catalogue report
    name = "attacks" if list(chosen) == list(cat) else "attacks-" + "-".join(chosen)
    (REPORTS / f"{name}.md").write_text("\n".join(md))
    (REPORTS / f"{name}.json").write_text(json.dumps({"when": when, "attacks": out}, indent=1))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=os.environ.get("A", ""), help="e.g. A1,A5 or 1,5")
    ap.add_argument("--list", action="store_true")
    a, extra = ap.parse_known_args()          # anything else goes to pytest (-x, -k, ...)
    a.pytest_args = extra
    cat = load()
    chosen = select(cat, a.only)
    if a.list:
        for x in chosen:
            print(f"{x:4} {cat[x]['title']}\n     defence: {cat[x]['defence']}\n")
        return 0
    ids = list(dict.fromkeys(ref for x in chosen for ref in cat[x]["tests"]))
    rc, cases, seconds = run(ids, a.pytest_args)
    rows = report(cat, chosen, cases, seconds)
    print("\n================ attack report (build/reports/) ================")
    for x, spec, v, res, missing in rows:
        print(f"  {x:4} {v:11} {spec['title']}")
    bad = [x for x, _, v, _, _ in rows if v != "DEFENDED"]
    print(f"  => {'every attack DEFENDED' if not bad else 'NOT defended: ' + ', '.join(bad)}")
    return 0 if not bad and rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
