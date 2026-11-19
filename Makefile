# zerotrust-cloud — run everything from the i5 (CLOUD host).
SHELL   := /bin/bash
.ONESHELL:
# with .ONESHELL a recipe is ONE script: stop at the first failing line
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

VENV    := .venv
PY      := $(VENV)/bin/python
PYTEST  := $(VENV)/bin/pytest
BUILD   := build
TF      := terraform -chdir=terraform
TFVARS  := -var-file=../$(BUILD)/terraform.tfvars.json
ANSIBLE := cd $(CURDIR)/ansible &&

.PHONY: help venv env gen check test-0 galaxy host test-1 infra wait recreate-vms test-2 ca test-3 firewall test-4 wireguard test-peer test-peer-down test-5 up test destroy clean

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

# ---------------------------------------------------------------- stage 1 --
galaxy:  ## install the Ansible collections (user level, no sudo)
	$(ANSIBLE) ansible-galaxy collection install -r requirements.yml

host: gen galaxy  ## stage 1: prepare the i5 (asks for your sudo password)
	$(ANSIBLE) ansible-playbook host.yml --ask-become-pass

test-1: venv gen  ## stage 1: host preflight tests (asks for sudo once)
	sudo -v
	$(PYTEST) tests/host -v

# ---------------------------------------------------------------- stage 2 --
infra: gen  ## stage 2: libvirt networks + 6 VMs (terraform), then wait for cloud-init
	$(TF) init -input=false
	# -parallelism=1: the 6 VMs share one backing image; libvirt changes its owner at each
	# start (and restores it on failure) without a lock manager, so parallel starts race.
	$(TF) apply -input=false -auto-approve -parallelism=1 $(TFVARS)
	$(MAKE) --no-print-directory wait

wait:  ## wait until every VM answers SSH over mgmt and cloud-init has finished
	$(ANSIBLE) ansible all -m ansible.builtin.wait_for_connection -a "timeout=600"
	$(ANSIBLE) ansible all -m ansible.builtin.shell -a "cloud-init status --wait >/dev/null; rc=\$$?; [ \$$rc -eq 0 ] || [ \$$rc -eq 2 ]"

recreate-vms: gen  ## destroy and re-create the 6 VMs + their disks (keeps networks and base image)
	$(TF) destroy -input=false -auto-approve -target=libvirt_domain.vm -target=libvirt_volume.disk $(TFVARS)
	$(MAKE) --no-print-directory infra

test-2: venv gen  ## stage 2: networks, VMs, IPs, routes, isolation, apt cache
	sudo -v
	$(PYTEST) tests/infra -v

# ---------------------------------------------------------------- stage 3 --
ca: gen  ## stage 3: step-ca on the CA VM (downloads step packages once on the i5)
	$(ANSIBLE) ansible-playbook ca.yml

test-3: venv gen  ## stage 3: CA service, TLS 1.3, policy, 24h issuance, refusals
	$(PYTEST) tests/ca -v

# ---------------------------------------------------------------- stage 4 --
firewall: gen  ## stage 4: default-drop nftables on every VM (auto-rollback if SSH is lost)
	$(ANSIBLE) ansible-playbook firewall.yml

test-4: venv gen  ## stage 4: live rulesets = generated, NxN TCP probes, drop logging
	$(PYTEST) tests/firewall -v

# ---------------------------------------------------------------- stage 5 --
wireguard: gen  ## stage 5: keys (on the i5, never committed), wg0 on the gateway, client exports
	$(ANSIBLE) ansible-playbook wireguard.yml
	@echo ">> i7 client config: $(BUILD)/export/i7/wg0.conf (copy it to the i7 as /etc/wireguard/wg0.conf)"

test-peer: venv  ## (re)start the tunnel test client: netns zt-peer on the i5 (sudo)
	sudo tools/zt-test-peer up $(BUILD)/export/test-peer/wg0.conf

test-peer-down:  ## remove the tunnel test client
	sudo tools/zt-test-peer down

test-5: venv gen  ## stage 5: keys, gateway wg0, handshake, tunnel -> frontend only, impersonation
	sudo -v
	$(PYTEST) tests/wireguard -v

# ------------------------------------------------- full pipeline (filled in by later stages) --
up: host infra ca firewall wireguard  ## build everything (stages 1-7)
	@echo ">> stages 6-7 not implemented yet."

test: test-0 test-1 test-2 test-3 test-4 test-5  ## run every test

destroy: gen  ## tear down VMs, volumes, networks (host prep from stage 1 is kept)
	$(TF) destroy -input=false -auto-approve $(TFVARS)

clean:  ## remove generated files (keeps env.yaml and secrets)
	rm -rf $(BUILD) .pytest_cache
