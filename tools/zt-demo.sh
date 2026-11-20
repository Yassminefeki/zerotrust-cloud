#!/usr/bin/env bash
# Stage 13 — the narrated demo of ZT Bank (make demo), run on the cloud host after `make up`.
# Each step says what it shows, runs it live, and waits for Enter (DEMO_FAST=1: no pauses).
# The revocation step revokes ALICE'S REAL CERTIFICATE (the remote client's Firefox is refused,
# then `make client-certs` issues a new one): it asks first; DEMO_REVOKE=0 skips it.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
CA=build/pki/root_ca.crt
SECRETS=ansible/.secrets/pki
WEB=$($PY -c 'import sys; sys.path[:0]=["tests"]; from ztlive import frontend_url; print(frontend_url(""))')

b=$'\e[1m'; d=$'\e[2m'; g=$'\e[32m'; r=$'\e[31m'; n=$'\e[0m'
step=0
say()   { step=$((step + 1)); printf '\n%s== %d. %s%s\n' "$b" "$step" "$1" "$n"; shift; for l in "$@"; do printf '   %s\n' "$l"; done; }
pause() { [ "${DEMO_FAST:-0}" = 1 ] || read -r -p "   ${d}[Enter]${n} " _; }
run()   { printf '   %s$ %s%s\n' "$d" "$*" "$n"; "$@"; }
cn()    { $PY -c "import json,sys; p=json.load(open('build/pki/pki.json')); print(next(k for k,v in p['identities'].items() if v.get('actor')=='$1'))"; }
# one request from inside the tunnel (the test peer's namespace), as an actor: prints status + body
as() {  # as <actor|DIR> METHOD PATH [json] [extra tls_probe args...]
  local who=$1 m=$2 p=$3 data=${4:-}; shift 4 2>/dev/null || shift 3
  local dir; if [ -d "$who" ]; then dir=$who; else dir=$SECRETS/$(cn "$who"); fi
  local args=(--url "$WEB$p" --ca "$CA" --cert "$dir/client.crt" --key "$dir/client.key" --method "$m")
  [ -n "$data" ] && args+=(--data "$data")
  printf '   %s%s %s %s%s\n' "$d" "$(basename "$who")" "$m" "$p" "$n"
  sudo -n ip netns exec zt-peer python3 tests/tls_probe.py "${args[@]}" "$@" | $PY -c '
import json, sys
r = json.load(sys.stdin); s = r.get("status"); b = r.get("body")
col = "\033[32m" if s and s < 300 else "\033[31m"
print(f"   {col}HTTP {s}\033[0m  " + json.dumps(b)[:300])'
}

sudo -v
ip netns list | grep -qw zt-peer || sudo tools/zt-test-peer up build/export/test-peer/wg0.conf >/dev/null

say "The policy is the source of truth" \
    "Every firewall rule, mTLS allow-list, route, certificate name and DB grant is generated from policy.yaml."
run $PY -c 'import yaml; p=yaml.safe_load(open("policy.yaml"))
print("   actors :", ", ".join(f"{a} ({v[\"role\"]}, via {v[\"entry\"]})" for a, v in p["actors"].items()))
print("   flows  :", ", ".join(f["name"] for f in p["flows"]))'
pause

say "Alice, through WireGuard, with her client certificate" \
    "Who she is comes from her certificate only (SPIFFE ID), never from the request."
as alice GET /api/me
as alice GET /api/accounts
pause

say "Bob tries to read Alice's account, then pretends to be her with headers" \
    "Someone else's account answers 404 (no oracle); identity headers from a client are ignored."
as bob GET /api/accounts/ZTB-ALICE-01/transactions
as bob GET /api/accounts "" --header "X-ZT-Customer: alice" --header "X-ZT-Role: customer"
pause

say "Alice pays Bob 1.00; then a malicious web page tries the same in her browser (CSRF)"
as alice POST /api/transfers '{"from":"ZTB-ALICE-01","to":"ZTB-BOB-01","amount":"1.00","description":"demo","idempotency_key":"demo-'"$(date +%s)"'"}' \
   --header "Origin: ${WEB%/}" --header "Sec-Fetch-Site: same-origin"
as alice POST /api/transfers '{"from":"ZTB-ALICE-01","to":"ZTB-BOB-01","amount":"500.00"}' \
   --header "Origin: https://evil.example" --header "Sec-Fetch-Site: cross-site"
pause

say "Dev (staff) sees system health, never customer data"
as dev GET /api/status
as dev GET /api/accounts
pause

say "The statements bot: own namespace, own WireGuard peer, 1-hour certificate bound to its device"
run make -s bot-run
pause

say "PayFlow pays Alice from the internet, without the VPN: mTLS + signed, time-boxed, single-use"
run make -s pay TO=ZTB-ALICE-01 AMOUNT=2.50
pause

say "Reconnaissance from inside the tunnel: what answers on the frontend?" \
    "(1-1024 + the bank's ports here; make attack A=5 scans all 65535 ports of every address)"
run sudo -n ip netns exec zt-peer python3 tests/port_scan.py "$(echo "$WEB" | sed -E 's#https://([^:]+):.*#\1#')" \
    --ports 1-1024,3142,5432,8443,8444,9000,9443
pause

if [ "${DEMO_REVOKE:-1}" = 1 ]; then
  say "Stolen laptop: revoke Alice's certificate" \
      "On the REMOTE CLIENT, open the bank in Firefox (profile zt-alice) now: it works." \
      "Optionally run there:  python3 remote-client/attack.py B6" \
      "This revokes Alice's real certificate; a new one is issued right after."
  read -r -p "   type yes to revoke Alice's certificate: " ok
  if [ "$ok" = yes ]; then
    run make -s revoke ACTOR=alice REASON="stolen laptop (demo)"
    old=$(ls -td "$SECRETS/$(cn alice)"/revoked/*/ | head -1)
    say "The stolen copy is refused everywhere (no restart), within the minute" \
        "Reload Firefox on the remote client: the same refusal."
    as "${old%/}" GET /api/me
    say "Alice gets a NEW key and certificate" \
        "Send build/export/remote-client/alice/ to the remote client and import the new alice.p12."
    run make -s client-certs
    as alice GET /api/me
  fi
  pause
fi

say "Audit: who did what, every refusal and its reason, the CRL in force, the ledger"
run make -s audit SINCE="30 min ago" || true
printf '\n%sDemo done.%s Attack catalogue: make attacks  -> build/reports/attacks.md\n' "$g" "$n"
