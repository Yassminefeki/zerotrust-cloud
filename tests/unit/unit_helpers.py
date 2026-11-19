"""Helpers for offline tests."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TD = "spiffe://cloud.local"

# A throw-away PKI shaped like the real one: root -> intermediate -> leaves (chain in <name>.crt).
PKI_SH = r"""
set -e
k(){ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
cat > ext.cnf <<'EOF'
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=${ENV::SAN}
EOF
k root.key; openssl req -x509 -new -key root.key -subj /CN=root -days 2 -out root.crt \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
k int.key; openssl req -new -key int.key -subj /CN=int -out int.csr
SAN=URI:x openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -days 2 -extfile ext.cnf -extensions ca -out int.crt 2>/dev/null
leaf(){ k "$1.key"; openssl req -new -key "$1.key" -subj "/CN=$1" -out "$1.csr"
  SAN="$2" openssl x509 -req -in "$1.csr" -CA int.crt -CAkey int.key -days 1 -extfile ext.cnf -extensions leaf -out "$1.leaf" 2>/dev/null
  cat "$1.leaf" int.crt > "$1.crt"; }
leaf frontend  "URI:$TD/frontend,IP:127.0.0.10"
leaf service-a "URI:$TD/service-a,IP:127.0.0.11"
leaf service-b "URI:$TD/service-b,IP:127.0.0.12"
leaf database  "URI:$TD/database,IP:127.0.0.13"
leaf alice     "URI:$TD/customer/alice,DNS:customer-alice"
leaf bob       "URI:$TD/customer/bob,DNS:customer-bob"
leaf dev       "URI:$TD/staff/dev,DNS:staff-dev"
leaf bot       "URI:$TD/bot/statements,DNS:bot-statements"
"""


def nft(build, node):
    return (build / "nodes" / node / "nftables.conf").read_text()


def mtls(build, node):
    return json.loads((build / "nodes" / node / "mtls.json").read_text())
