"""Helpers for offline tests."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def nft(build, node):
    return (build / "nodes" / node / "nftables.conf").read_text()


def mtls(build, node):
    return json.loads((build / "nodes" / node / "mtls.json").read_text())
