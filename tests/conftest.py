"""Shared fixtures for live tests (run on the i5). Read env.yaml + build/ — never hard-code IPs."""
import json

import pytest
import yaml

from ztlib import BUILD, ROOT


@pytest.fixture(scope="session")
def env():
    p = ROOT / "env.yaml"
    if not p.exists():
        pytest.exit("env.yaml missing: cp env.example.yaml env.yaml", returncode=2)
    return yaml.safe_load(p.read_text())


@pytest.fixture(scope="session")
def policy():
    return yaml.safe_load((ROOT / "policy.yaml").read_text())


@pytest.fixture(scope="session")
def zt_host():
    p = BUILD / "host" / "host.json"
    if not p.exists():
        pytest.exit("build/ missing: run `make gen` first", returncode=2)
    return json.loads(p.read_text())
