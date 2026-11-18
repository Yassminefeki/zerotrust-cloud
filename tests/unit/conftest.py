"""Offline fixtures: generate everything from policy.yaml + env.example.yaml into a tmp dir."""
import copy
import json

import pytest
import yaml

import gen_rules
from unit_helpers import ROOT


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
