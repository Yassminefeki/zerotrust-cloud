# zerotrust-cloud — run everything from the i5 (CLOUD host).
SHELL   := /bin/bash
.ONESHELL:
.DEFAULT_GOAL := help

VENV    := .venv
PY      := $(VENV)/bin/python
PYTEST  := $(VENV)/bin/pytest
BUILD   := build

.PHONY: help venv env gen check test-0 up test destroy clean

help:  ## list targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-12s %s\n", $$1, $$2}'

$(VENV)/.ok: requirements.txt
	python3 -m venv $(VENV) || { echo "need: sudo apt install python3-venv"; exit 1; }
	$(VENV)/bin/pip install -q --upgrade pip
	$(VENV)/bin/pip install -q -r requirements.txt
	touch $@

venv: $(VENV)/.ok  ## create the Python venv (pyyaml, pytest, testinfra)

env.yaml:
	@echo "env.yaml missing -> copying env.example.yaml. EDIT wan_interface (see: ip -br link)."
	cp env.example.yaml env.yaml

env: env.yaml

check: venv env.yaml  ## validate policy.yaml + env.yaml
	$(PY) tools/gen_rules.py --check

gen: venv env.yaml  ## policy.yaml + env.yaml -> build/ (nftables, mTLS, wg, tfvars, inventory, matrix)
	$(PY) tools/gen_rules.py --out $(BUILD)

# ---------------------------------------------------------------- stage 0 --
test-0: venv  ## stage 0: offline tests of the policy and the generator
	$(PYTEST) tests/unit -v

# ------------------------------------------------- full pipeline (filled in by later stages) --
up: gen  ## build everything (stages 1-7)
	@echo ">> stages 1-7 not implemented yet: only 'gen' ran."

test: test-0  ## run every test

destroy:  ## tear down VMs and networks
	@echo ">> nothing to destroy yet (terraform arrives in stage 2)."

clean:  ## remove generated files (keeps env.yaml and secrets)
	rm -rf $(BUILD) .pytest_cache
