#!/usr/bin/env python3
"""Copy the measured results into docs/evidence/ (versioned), anonymised.

    python3 tools/collect-evidence.py            (make evidence)

Sources (all produced on the cloud host, git-ignored):
  build/reports/attacks.md, attacks.json   make attacks       (full catalogue only, see below)
  build/reports/audit.md                   make audit
  build/reports/remote-client-report.json  remote-client/attack.py, copied from the remote client
  build/drift-report.json                  make test-8        -> raw copy + docs/evidence/drift-summary.md
A partial attack run (make attack A=...) is never copied over the full report.
Host names, user names, home paths, Wi-Fi addresses and MAC addresses are replaced; the remote
client's machine name becomes "remote-client". Nothing is copied that the sanitizer cannot read.
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_lib import REPO, Sanitizer  # noqa: E402

SRC = REPO / "build"
DST = REPO / "docs/evidence"
CLEAN = Sanitizer("cloud-host")


def copy_text(src, dst, transform=None):
    if not src.exists():
        print(f"  skip  {src.relative_to(REPO)} (not found)")
        return False
    text = CLEAN(src.read_text(errors="replace"))
    if transform:
        text = transform(text)
    dst.write_text(text)
    print(f"  wrote {dst.relative_to(REPO)}")
    return True


def audit(text):
    return re.sub(r"Remote client \([^,]+,", "Remote client (remote-client,", text)


def remote(text):
    d = json.loads(text)
    d["machine"] = "remote-client"
    return json.dumps(d, indent=1, ensure_ascii=False) + "\n"


def drift_summary(src, dst):
    if not src.exists():
        return
    probes = json.loads(src.read_text())
    by = Counter((p["expected"], "reached" if p["verdict"] in ("open", "connected", "refused") else p["verdict"])
                 for p in probes)
    bad = [p for p in probes if (p["expected"] == "allow") != (p["verdict"] in ("open", "connected", "refused"))]
    lines = ["# Drift report summary", "",
             f"Source: [`drift-report.json`](drift-report.json) (`make test-8`, live N×N probe of the policy matrix).", "",
             f"- probes: {len(probes)}",
             f"- sources: {len({p['src'] for p in probes})}, destinations: {len({p['dst'] for p in probes})}",
             f"- probes whose result differs from the policy: {len(bad)}", "",
             "| Expected | Observed | Probes |", "|---|---|---|"]
    lines += [f"| {e} | {o} | {n} |" for (e, o), n in sorted(by.items())]
    dst.write_text("\n".join(lines) + "\n")
    print(f"  wrote {dst.relative_to(REPO)}")


def main():
    DST.mkdir(parents=True, exist_ok=True)
    att = SRC / "reports/attacks.json"
    if att.exists() and len(json.loads(att.read_text())["attacks"]) >= 11:
        copy_text(SRC / "reports/attacks.md", DST / "attacks.md")
        copy_text(att, DST / "attacks.json")
    else:
        print("  skip  attacks report: not a full catalogue run (run `make attacks` first)")
    copy_text(SRC / "reports/audit.md", DST / "audit.md", audit)
    copy_text(SRC / "reports/remote-client-report.json", DST / "remote-client-report.json", remote)
    if copy_text(SRC / "drift-report.json", DST / "drift-report.json"):
        drift_summary(DST / "drift-report.json", DST / "drift-summary.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
