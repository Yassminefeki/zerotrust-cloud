"""Offline fixtures: generate everything from policy.yaml + env.example.yaml into a tmp dir."""
import copy
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import gen_rules  # noqa: E402


@pytest.fixture(scope="session")
def policy():
    return gen_rules.load_yaml(ROOT / "policy.yaml")


@pytest.fixture(scope="session")
def env():
    return gen_rules.load_yaml(ROOT / "env.example.yaml")


@pytest.fixture(scope="session")
def build(policy, env, tmp_path_factory):
    out = tmp_path_factory.mktemp("build")
    gen_rules.generate(policy, env, out)
    return out


@pytest.fixture(scope="session")
def matrix(build):
    return json.loads((build / "matrix.json").read_text())


@pytest.fixture
def mutable_policy(policy):
    return copy.deepcopy(policy)


def nft(build, node):
    return (build / "nodes" / node / "nftables.conf").read_text()


def mtls(build, node):
    return json.loads((build / "nodes" / node / "mtls.json").read_text())
