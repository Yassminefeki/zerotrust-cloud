# ZT Bank — security audit

Generated 2026-11-20 15:27 UTC on the cloud host; period: since 24 hours ago.

## Findings

- none: every check above is as expected

## 1. Who used the bank

| service cloud-host | identity (from its certificate) | requests |
|---|---|---|
| frontend | spiffe://cloud.local/customer/alice | 376 |
| frontend | spiffe://cloud.local/bot/statements | 268 |
| frontend | spiffe://cloud.local/staff/dev | 97 |
| frontend | spiffe://cloud.local/customer/bob | 84 |
| frontend | spiffe://cloud.local/partner/payflow | 69 |
| frontend | spiffe://cloud.local/service-a | 4 |
| service-a | spiffe://cloud.local/frontend | 252 |
| service-a | spiffe://cloud.local/staff/dev | 4 |
| service-b | spiffe://cloud.local/service-a | 228 |
| service-b | spiffe://cloud.local/staff/dev | 4 |

## 2. Refusals

Every refusal names the real identity (or source address) and the reason.

| cloud-host | who | what was refused | times |
|---|---|---|---|
| frontend | 10.10.0.200 | tls handshake: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000) | 197 |
| frontend | 10.10.0.3 | tls handshake: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000) | 54 |
| frontend | 10.10.0.2 | tls handshake: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000) | 19 |
| frontend | 10.10.0.2 | certificate <serial> of ['spiffe://cloud.local/customer/alice'] is revoked | 13 |
| frontend | 10.10.0.200 | tls handshake: [SSL: PEER_DID_NOT_RETURN_A_CERTIFICATE] peer did not return a certificate (_ssl.c:1000) | 8 |
| frontend | 10.20.0.1 | tls handshake: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000) | 7 |
| frontend | 10.10.0.200 | identity spiffe://cloud.local/bot/statements not allowed from 10.10.0.200 (bound to 10.10.0.3/32) | 6 |
| frontend | 10.20.0.1 | identity ['spiffe://cloud.local/customer/alice'] not allowed | 6 |
| frontend | 10.20.0.1 | no route POST /api/accounts | 6 |
| frontend | 10.10.0.200 | identity ['spiffe://cloud.local/partner/payflow'] not allowed | 6 |
| frontend | 10.10.0.200 | route status (GET /api/status) not allowed for spiffe://cloud.local/customer/bob | 6 |
| frontend | 10.10.0.200 | no route GET /admin | 6 |
| frontend | 10.10.0.200 | no route DELETE /api/me | 6 |
| frontend | 10.10.0.200 | no route GET /api/accounts/x/y/transactions | 6 |
| frontend | 10.10.0.200 | no route PUT /api/transfers | 6 |
| frontend | 10.10.0.200 | no route GET /../etc/passwd | 6 |
| frontend | 10.20.0.10 | tls handshake: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000) | 4 |
| frontend | 10.10.0.200 | tls handshake: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1000) | 4 |
| frontend | 10.10.0.200 | identity ['spiffe://cloud.local/service-a'] not allowed | 4 |
| frontend | 10.10.0.200 | tls handshake: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1000) | 4 |
| frontend | 10.10.0.200 | tls handshake: [SSL: UNSUPPORTED_PROTOCOL] unsupported protocol (_ssl.c:1000) | 4 |
| frontend | 10.10.0.200 | route statements (GET /api/statements) not allowed for spiffe://cloud.local/customer/alice | 4 |
| frontend | 10.10.0.200 | route status (GET /api/status) not allowed for spiffe://cloud.local/customer/alice | 4 |
| frontend | 10.10.0.200 | route health (GET /health) not allowed for spiffe://cloud.local/customer/alice | 4 |
| frontend | 10.10.0.200 | route diag-chain (GET /chain) not allowed for spiffe://cloud.local/customer/alice | 4 |
| frontend | 10.10.0.200 | route statements (GET /api/statements) not allowed for spiffe://cloud.local/customer/bob | 4 |
| frontend | 10.10.0.200 | route health (GET /health) not allowed for spiffe://cloud.local/customer/bob | 4 |
| frontend | 10.10.0.200 | route diag-chain (GET /chain) not allowed for spiffe://cloud.local/customer/bob | 4 |
| frontend | 10.10.0.200 | route accounts (GET /api/accounts) not allowed for spiffe://cloud.local/staff/dev | 4 |
| frontend | 10.10.0.200 | route history (GET /api/accounts/*/transactions) not allowed for spiffe://cloud.local/staff/dev | 4 |
| frontend | 10.10.0.200 | route transfer (POST /api/transfers) not allowed for spiffe://cloud.local/staff/dev | 4 |
| frontend | 10.10.0.200 | route statements (GET /api/statements) not allowed for spiffe://cloud.local/staff/dev | 4 |
| frontend | 10.10.0.3 | route accounts (GET /api/accounts) not allowed for spiffe://cloud.local/bot/statements | 4 |
| frontend | 10.10.0.3 | route history (GET /api/accounts/*/transactions) not allowed for spiffe://cloud.local/bot/statements | 4 |
| frontend | 10.10.0.3 | route transfer (POST /api/transfers) not allowed for spiffe://cloud.local/bot/statements | 4 |
| frontend | 10.10.0.3 | route status (GET /api/status) not allowed for spiffe://cloud.local/bot/statements | 4 |
| frontend | 10.10.0.3 | route diag-chain (GET /chain) not allowed for spiffe://cloud.local/bot/statements | 4 |
| frontend | 10.10.0.2 | tls handshake: _ssl.c:983: The handshake operation timed out | 4 |
| frontend | 10.10.0.2 | tls handshake: [SSL: PEER_DID_NOT_RETURN_A_CERTIFICATE] peer did not return a certificate (_ssl.c:1000) | 4 |
| frontend | 10.10.0.2 | tls handshake: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1000) | 4 |
| frontend | 10.10.0.200 | certificate <serial> of ['spiffe://cloud.local/customer/alice'] is revoked | 3 |
| frontend | 10.10.0.200 | revocation status unknown (no fresh CRL): refusing everyone | 3 |
| frontend | 10.20.0.1 | tls handshake: [SSL: PEER_DID_NOT_RETURN_A_CERTIFICATE] peer did not return a certificate (_ssl.c:1000) | 3 |
| frontend | 10.10.0.3 | no route GET /admin | 2 |
| frontend | 10.10.0.3 | no route DELETE /api/me | 2 |
| frontend | 10.10.0.3 | no route GET /api/accounts/x/y/transactions | 2 |
| frontend | 10.10.0.3 | no route PUT /api/transfers | 2 |
| frontend | 10.10.0.3 | no route GET /../etc/passwd | 2 |
| frontend | 10.10.0.2 | tls handshake: [SSL: UNSUPPORTED_PROTOCOL] unsupported protocol (_ssl.c:1000) | 2 |
| frontend | 10.10.0.2 | route status (GET /api/status) not allowed for spiffe://cloud.local/customer/alice | 2 |
| frontend | 10.10.0.2 | route statements (GET /api/statements) not allowed for spiffe://cloud.local/customer/alice | 2 |
| frontend | 10.10.0.2 | route diag-chain (GET /chain) not allowed for spiffe://cloud.local/customer/alice | 2 |
| frontend | 10.10.0.2 | route accounts (GET /api/accounts) not allowed for spiffe://cloud.local/staff/dev | 2 |
| frontend | 10.20.0.1 | tls handshake: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1000) | 2 |
| frontend | 10.20.0.1 | certificate <serial> of ['spiffe://cloud.local/customer/alice'] is revoked | 2 |
| frontend | 10.10.0.2 | tls handshake: [SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca (_ssl.c:1000) | 1 |
| frontend | spiffe://cloud.local/partner/payflow | POST /webhook -> 401 timestamp outside the replay window (+/-300s) | 12 |
| frontend | spiffe://cloud.local/partner/payflow | POST /webhook -> 401 bad signature | 12 |
| frontend | spiffe://cloud.local/customer/alice | POST /api/transfers -> 403 cross-site request refused (cross-site) | 10 |
| frontend | spiffe://cloud.local/partner/payflow | POST /webhook -> 409 replayed request: nonce already used | 6 |
| frontend | spiffe://cloud.local/customer/bob | GET /api/accounts/ZTB-ALICE-01/transactions -> 404 account not found | 6 |
| frontend | spiffe://cloud.local/customer/alice | POST /api/transfers -> 415 send JSON (Content-Type: application/json) | 6 |
| frontend | spiffe://cloud.local/customer/alice | GET /static/A-0001 -> 404 no such file | 4 |
| frontend | spiffe://cloud.local/customer/bob | GET /static/A-0001 -> 404 no such file | 4 |
| frontend | spiffe://cloud.local/staff/dev | GET /static/A-0001 -> 404 no such file | 4 |
| frontend | spiffe://cloud.local/bot/statements | GET /static/A-0001 -> 404 no such file | 4 |
| frontend | spiffe://cloud.local/customer/bob | GET /api/accounts/ZTB-NOBODY-01/transactions -> 404 account not found | 4 |
| frontend | spiffe://cloud.local/customer/bob | POST /api/transfers -> 404 unknown source account | 4 |
| frontend | spiffe://cloud.local/customer/alice | POST /api/transfers -> 404 unknown destination account | 4 |
| frontend | spiffe://cloud.local/customer/alice | POST /api/transfers -> 422 above the maximum per transfer (5000.00 EUR) | 4 |
| frontend | spiffe://cloud.local/customer/alice | POST /api/transfers -> 403 cross-origin request refused | 4 |
| frontend | spiffe://cloud.local/customer/alice | GET /api/accounts/ZTB-BOB-01/transactions -> 404 account not found | 2 |
| frontend | spiffe://cloud.local/customer/alice | POST /api/transfers -> 404 unknown source account | 2 |
| frontend | spiffe://cloud.local/bot/statements | rate limit (429) | 13 |
| service-a | 10.30.0.10 | tls handshake: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000) | 10 |
| service-a | 10.30.0.10 | identity ['spiffe://cloud.local/staff/dev'] not allowed | 4 |
| service-a | 10.30.0.10 | tls handshake: [SSL: UNSUPPORTED_PROTOCOL] unsupported protocol (_ssl.c:1000) | 4 |
| service-a | 10.30.0.10 | no route GET /admin | 4 |
| service-a | 10.30.0.11 | tls handshake: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000) | 2 |
| service-a | spiffe://cloud.local/partner/payflow | POST /incoming -> 409 replayed request: nonce already used | 6 |
| service-a | spiffe://cloud.local/customer/bob | GET /accounts/ZTB-ALICE-01/transactions -> 404 account not found | 6 |
| service-a | spiffe://cloud.local/customer/bob | GET /accounts/ZTB-NOBODY-01/transactions -> 404 account not found | 4 |
| service-a | spiffe://cloud.local/customer/bob | POST /transfers -> 404 unknown source account | 4 |
| service-a | spiffe://cloud.local/customer/alice | POST /transfers -> 404 unknown destination account | 4 |
| service-a | spiffe://cloud.local/customer/alice | POST /transfers -> 422 above the maximum per transfer (5000.00 EUR) | 4 |
| service-a | spiffe://cloud.local/customer/alice | GET /accounts/ZTB-BOB-01/transactions -> 404 account not found | 2 |
| service-a | spiffe://cloud.local/customer/alice | POST /transfers -> 404 unknown source account | 2 |
| service-b | 10.30.0.11 | tls handshake: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000) | 7 |
| service-b | 10.30.0.11 | identity ['spiffe://cloud.local/staff/dev'] not allowed | 4 |
| service-b | 10.30.0.11 | tls handshake: [SSL: UNSUPPORTED_PROTOCOL] unsupported protocol (_ssl.c:1000) | 4 |
| service-b | 10.30.0.12 | tls handshake: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1000) | 2 |
| service-b | spiffe://cloud.local/partner/payflow | POST /ledger/incoming -> 409 replayed request: nonce already used | 6 |
| service-b | spiffe://cloud.local/customer/bob | GET /ledger/accounts/ZTB-ALICE-01/entries -> 404 account not found | 6 |
| service-b | spiffe://cloud.local/customer/bob | GET /ledger/accounts/ZTB-NOBODY-01/entries -> 404 account not found | 4 |
| service-b | spiffe://cloud.local/customer/bob | POST /ledger/transfers -> 404 unknown source account | 4 |
| service-b | spiffe://cloud.local/customer/alice | POST /ledger/transfers -> 404 unknown destination account | 4 |
| service-b | spiffe://cloud.local/customer/alice | GET /ledger/accounts/ZTB-BOB-01/entries -> 404 account not found | 2 |
| service-b | spiffe://cloud.local/customer/alice | POST /ledger/transfers -> 404 unknown source account | 2 |

## 3. Revocation

Attempts with a revoked certificate (stolen copies):

| serial | identity | attempts |
|---|---|---|
| A1B13DF40C8EF3A6F171C06B4BE43EAB | ['spiffe://cloud.local/customer/alice'] | 15 |
| 751A37F2E2B95C9B2F98CC768D60D0ED | ['spiffe://cloud.local/customer/alice'] | 1 |
| 70877D1ADCDCBFD9858C39CCAF4B5BC5 | ['spiffe://cloud.local/customer/alice'] | 1 |
| 87079B2DDD970BF9353A8227AD42C90C | ['spiffe://cloud.local/customer/alice'] | 1 |

CRL enforced by each service:

| cloud-host | CRL number | revoked serials | fetched | state |
|---|---|---|---|---|
| frontend | 4 | 4 | 39 s ago | fresh |
| service-a | 4 | 4 | 38 s ago | fresh |
| service-b | 4 | 4 | 38 s ago | fresh |

## 4. Certificates

| cloud-host | serial | expires |
|---|---|---|
| database | C3623645647D774DE816A50F7571F87F | Nov 21 11:33:35 2026 GMT |
| frontend | 217525C9FCA73AB806EB674B5642BAFC | Nov 21 14:02:58 2026 GMT |
| service-a | 69D9B1C1AD72ACAC518222091C67EE5B | Nov 21 14:02:28 2026 GMT |
| service-b | 7C01025FE69B63301374C8DE8675F29A | Nov 21 11:35:27 2026 GMT |

| actor | identity | serial | expires | revoked earlier |
|---|---|---|---|---|
| alice | spiffe://cloud.local/customer/alice | 7947E92CD8745D8A4726FEBA7F70459C | Nov 21 15:10:55 2026 GMT | A1B13DF40C8EF3A6F171C06B4BE43EAB |
| bob | spiffe://cloud.local/customer/bob | DE6CAEF4F53885F3A0B873EBD9733C69 | Nov 21 13:02:34 2026 GMT | - |
| dev | spiffe://cloud.local/staff/dev | D1C50A31A14990E43A49C681D086B816 | Nov 21 13:02:36 2026 GMT | - |
| statements | spiffe://cloud.local/bot/statements | 0977E4527F90B29A22B05B4473D91CC6 | Nov 20 15:43:33 2026 GMT | - |
| payflow | spiffe://cloud.local/partner/payflow | 450E801E64B72A87591EC8308AB5C4F4 | Nov 21 13:04:27 2026 GMT | - |

CA activity (step-ca):

| endpoint | status | count |
|---|---|---|
| /1.0/crl | 200 | 152 |
| /health | 200 | 3 |
| /provisioners/DbbCwTERmMXSd6jpTLIT6e8uHFjDXaMxlW1rek3gaGs/encrypted-key | 200 | 48 |
| /renew | 201 | 11 |
| /revoke | 200 | 4 |
| /root/<id> | 200 | 50 |
| /sign | 201 | 23 |
| /sign | 401 | 2 |
| /sign | 403 | 21 |

## 5. Network drops (nftables, every cloud-host)

| cloud-host | rule | source | destination | proto | packets |
|---|---|---|---|---|---|
| ca | input | 10.50.0.1 | 10.50.0.10:9000 | TCP | 20 |
| ca | output | 10.50.0.10 | 10.50.0.20:8443 | TCP | 14 |
| ca | output | 10.50.0.10 | 10.50.0.20:8444 | TCP | 14 |
| ca | output | 10.50.0.10 | 10.50.0.30:9443 | TCP | 14 |
| ca | output | 10.50.0.10 | 10.50.0.31:9443 | TCP | 14 |
| ca | output | 10.50.0.10 | 10.50.0.40:5432 | TCP | 14 |
| ca | output | 10.50.0.10 | 10.50.0.2:22 | TCP | 14 |
| ca | output | 10.50.0.10 | 10.50.0.20:22 | TCP | 14 |
| ca | output | 10.50.0.10 | 10.50.0.30:22 | TCP | 14 |
| ca | output | 10.50.0.10 | 10.50.0.40:22 | TCP | 14 |
| ca | output | 10.50.0.10 | 10.50.0.31:22 | TCP | 14 |
| ca | input | 10.50.0.1 | 10.50.0.10:9 | UDP | 4 |
| database | output | 10.50.0.40 | 10.50.0.20:8443 | TCP | 14 |
| database | output | 10.50.0.40 | 10.50.0.20:8444 | TCP | 14 |
| database | output | 10.40.0.10 | 10.40.0.11:9443 | TCP | 14 |
| database | output | 10.50.0.40 | 10.50.0.30:9443 | TCP | 14 |
| database | output | 10.50.0.40 | 10.50.0.31:9443 | TCP | 14 |
| database | output | 10.50.0.40 | 10.50.0.2:22 | TCP | 14 |
| database | output | 10.50.0.40 | 10.50.0.20:22 | TCP | 14 |
| database | output | 10.50.0.40 | 10.50.0.30:22 | TCP | 14 |
| database | output | 10.40.0.10 | 10.40.0.11:22 | TCP | 14 |
| database | output | 10.50.0.40 | 10.50.0.31:22 | TCP | 14 |
| database | output | 10.50.0.40 | 10.50.0.10:22 | TCP | 14 |
| database | input | 10.50.0.1 | 10.50.0.40:5432 | TCP | 14 |
| frontend | output | 10.30.0.10 | 10.30.0.12:9443 | TCP | 26 |
| frontend | output | 10.50.0.20 | 10.50.0.2:22 | TCP | 20 |
| frontend | output | 10.50.0.20 | 10.50.0.30:22 | TCP | 20 |
| frontend | output | 10.50.0.20 | 10.50.0.31:22 | TCP | 20 |
| frontend | output | 10.50.0.20 | 10.50.0.40:22 | TCP | 20 |
| frontend | output | 10.50.0.20 | 10.50.0.10:22 | TCP | 20 |
| frontend | output | 10.50.0.20 | 10.50.0.30:9443 | TCP | 14 |
| frontend | output | 10.50.0.20 | 10.50.0.31:9443 | TCP | 14 |
| frontend | output | 10.50.0.20 | 10.50.0.40:5432 | TCP | 14 |
| frontend | output | 10.20.0.10 | 10.10.0.1:22 | TCP | 14 |
| frontend | output | 10.20.0.10 | 10.20.0.1:22 | TCP | 14 |
| frontend | output | 10.30.0.10 | 10.30.0.11:22 | TCP | 14 |
| frontend | output | 10.30.0.10 | 10.30.0.12:22 | TCP | 14 |
| frontend | input | 10.50.0.1 | 10.50.0.20:8443 | TCP | 14 |
| frontend | input | 10.50.0.1 | 10.50.0.20:8444 | TCP | 14 |
| gateway | forward | 10.10.0.200 | 10.30.0.11:9443 | TCP | 32 |
| gateway | input | 10.10.0.200 | 10.10.0.1:22 | TCP | 28 |
| gateway | forward | 10.10.0.200 | 10.50.0.10:9000 | TCP | 25 |
| gateway | forward | 10.10.0.200 | 10.20.0.10:22 | TCP | 24 |
| gateway | forward | 10.10.0.200 | 10.40.0.10:5432 | TCP | 22 |
| gateway | input | 192.168.122.1 | 192.168.122.10:22 | TCP | 20 |
| gateway | input | 10.10.0.200 | 192.168.122.10:22 | TCP | 18 |
| gateway | input | 10.10.0.200 | 10.20.0.1:22 | TCP | 18 |
| gateway | input | 10.10.0.200 | 10.50.0.2:22 | TCP | 18 |
| gateway | forward | 10.10.0.200 | 10.50.0.1:3142 | TCP | 18 |
| gateway | output | 192.168.122.10 | 10.30.0.10:22 | TCP | 14 |
| gateway | output | 10.50.0.2 | 10.50.0.20:22 | TCP | 14 |
| gateway | output | 192.168.122.10 | 10.30.0.11:22 | TCP | 14 |
| gateway | output | 10.50.0.2 | 10.50.0.30:22 | TCP | 14 |
| gateway | output | 192.168.122.10 | 10.30.0.12:22 | TCP | 14 |
| service-a | output | 10.30.0.11 | 10.30.0.10:8443 | TCP | 14 |
| service-a | output | 10.50.0.30 | 10.50.0.20:8443 | TCP | 14 |
| service-a | output | 10.30.0.11 | 10.30.0.10:8444 | TCP | 14 |
| service-a | output | 10.50.0.30 | 10.50.0.20:8444 | TCP | 14 |
| service-a | output | 10.50.0.30 | 10.50.0.31:9443 | TCP | 14 |
| service-a | output | 10.50.0.30 | 10.50.0.40:5432 | TCP | 14 |
| service-a | output | 10.50.0.30 | 10.50.0.2:22 | TCP | 14 |
| service-a | output | 10.30.0.11 | 10.30.0.10:22 | TCP | 14 |
| service-a | output | 10.50.0.30 | 10.50.0.20:22 | TCP | 14 |
| service-a | output | 10.30.0.11 | 10.30.0.12:22 | TCP | 14 |
| service-a | output | 10.50.0.30 | 10.50.0.31:22 | TCP | 14 |
| service-a | output | 10.50.0.30 | 10.50.0.10:22 | TCP | 14 |
| service-a | output | 10.50.0.30 | 10.50.0.40:22 | TCP | 14 |
| service-a | input | 10.50.0.1 | 10.50.0.30:9443 | TCP | 14 |
| service-b | output | 10.30.0.12 | 10.30.0.10:8443 | TCP | 14 |
| service-b | output | 10.50.0.31 | 10.50.0.20:8443 | TCP | 14 |
| service-b | output | 10.30.0.12 | 10.30.0.10:8444 | TCP | 14 |
| service-b | output | 10.50.0.31 | 10.50.0.20:8444 | TCP | 14 |
| service-b | output | 10.30.0.12 | 10.30.0.11:9443 | TCP | 14 |
| service-b | output | 10.50.0.31 | 10.50.0.30:9443 | TCP | 14 |
| service-b | output | 10.50.0.31 | 10.50.0.40:5432 | TCP | 14 |
| service-b | output | 10.50.0.31 | 10.50.0.2:22 | TCP | 14 |
| service-b | output | 10.30.0.12 | 10.30.0.10:22 | TCP | 14 |
| service-b | output | 10.50.0.31 | 10.50.0.20:22 | TCP | 14 |
| service-b | output | 10.50.0.31 | 10.50.0.30:22 | TCP | 14 |
| service-b | output | 10.30.0.12 | 10.30.0.11:22 | TCP | 14 |
| service-b | output | 10.40.0.11 | 10.40.0.10:22 | TCP | 14 |
| service-b | output | 10.50.0.31 | 10.50.0.10:22 | TCP | 14 |
| service-b | output | 10.50.0.31 | 10.50.0.40:22 | TCP | 14 |

## 6. The bank's own audit trail (PostgreSQL)

| actor | action | count |
|---|---|---|
| spiffe://cloud.local/partner/payflow | incoming_payment | 21 |
| spiffe://cloud.local/customer/alice | transfer | 7 |

Last entries:

| at | actor | action | detail |
|---|---|---|---|
| 2026-11-20 15:24:22 | spiffe://cloud.local/customer/alice | transfer | {"to": "ZTB-BOB-01", "from": "ZTB-ALICE-01", "customer": "alice", "transfer": "c54622b5-355f-4d52-a1a5-0a73becdf982", "amount_cents": 11100} |
| 2026-11-20 14:53:23 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "7aUIhBjJ4ankWnOrqqbIU_puD9etKcEU", "partner": "payflow", "transfer": "839d150b-19f1-4891-a952-bebdd21d6c14", "reference": "PF-fd53fd141c", "amount_cents": 3} |
| 2026-11-20 14:53:23 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "vJiABU2kHuE6Sagf6akNZt4hrxuPUiWH", "partner": "payflow", "transfer": "9e6b8256-b2a6-4fe6-8fcf-5e0268d85546", "reference": "PF-b6f455bf97", "amount_cents": 7} |
| 2026-11-20 14:47:07 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "u1e0S6TwFej-wExx4d8plvOE8schrzqf", "partner": "payflow", "transfer": "fcd8fecf-d8a5-451c-9bb3-b7c3df767acd", "reference": "PF-b5fdf54f34", "amount_cents": 3} |
| 2026-11-20 14:47:07 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "HO3DThC6ShpeSmi_TnLNI8cfAtFZKmwa", "partner": "payflow", "transfer": "159707c6-59ae-4e52-b3c0-2c00205804a9", "reference": "PF-1362da9127", "amount_cents": 7} |
| 2026-11-20 14:04:54 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "vtpos6LRNcryo4U1R87ENq74Kzmdaw0d", "partner": "payflow", "transfer": "db16ac8e-430b-4e7a-8c19-9ad22d429bf8", "reference": "PF-305dac324a", "amount_cents": 2} |
| 2026-11-20 14:04:39 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "w4-SihseL1ARVaEe6-RaBh0VsjuXA_d6", "partner": "payflow", "transfer": "eb3fd3e6-b3f4-440c-8acd-b69a1ff723de", "reference": "PF-76cb07198a", "amount_cents": 3} |
| 2026-11-20 14:04:38 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "t3rSO_5lnKryJcihGojGV3oBBEAFjbJX", "partner": "payflow", "transfer": "39e437ab-f0d2-4f8e-a24c-f5d08bf9ba05", "reference": "PF-ec632b5712", "amount_cents": 7} |
| 2026-11-20 14:04:38 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "lOmKYknP6Lc-wohHG7rhZ5x1nArTVD4Z", "partner": "payflow", "transfer": "50a21a49-fe8e-429a-b39b-fab0a91b7762", "reference": "PF-0f405e74c5", "amount_cents": 7} |
| 2026-11-20 14:04:03 | spiffe://cloud.local/customer/alice | transfer | {"to": "ZTB-BOB-01", "from": "ZTB-ALICE-01", "customer": "alice", "transfer": "b81d4688-fef7-40e5-8d8f-67f2f2a8ab08", "amount_cents": 1} |
| 2026-11-20 14:03:59 | spiffe://cloud.local/customer/alice | transfer | {"to": "ZTB-BOB-01", "from": "ZTB-ALICE-01", "customer": "alice", "transfer": "f3ffe295-06ef-4010-b17f-7650597fc308", "amount_cents": 5} |
| 2026-11-20 14:03:59 | spiffe://cloud.local/customer/alice | transfer | {"to": "ZTB-BOB-01", "from": "ZTB-ALICE-01", "customer": "alice", "transfer": "7a524e88-038e-4b7b-b6df-49ada3727cd7", "amount_cents": 37} |
| 2026-11-20 13:18:08 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "EhIvD6-upag9xT1jX56gvrpQEG6RN6e7", "partner": "payflow", "transfer": "90372284-cfad-4272-9543-3423cf228053", "reference": "PF-9bbb0953fc", "amount_cents": 2} |
| 2026-11-20 13:17:53 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "-RvA6jF36g6TQlt493HCfIGQxON-5dza", "partner": "payflow", "transfer": "7f1aca86-b77f-458a-bc6e-2ab655aa4a85", "reference": "PF-59e2545437", "amount_cents": 3} |
| 2026-11-20 13:17:53 | spiffe://cloud.local/partner/payflow | incoming_payment | {"to": "ZTB-ALICE-01", "nonce": "hZEb8pYbsML7urL140olpBqLO7KGZHmT", "partner": "payflow", "transfer": "5dd950f3-0573-486b-a7e9-7e8a219dab01", "reference": "PF-59baadd305", "amount_cents": 7} |

Ledger: 96 entries, sum = 0 cents (balanced); 48 transfers, 21 incoming payments.

## 7. Attack reports

Cloud host (`make attacks`, 2026-11-20 14:54 UTC):

|  | attack | verdict |
|---|---|---|
| A1 | Stolen laptop (Alice's certificate and key copied) | DEFENDED |
| A2 | Compromised frontend (root on the internet-facing cloud-host) | DEFENDED |
| A3 | Lateral movement from the VPN | DEFENDED |
| A4 | Forged identity | DEFENDED |
| A5 | Reconnaissance (port scans) | DEFENDED |
| A6 | Stolen or guessed WireGuard key | DEFENDED |
| A7 | A customer overstepping (IDOR, forged headers, other roles' routes) | DEFENDED |
| A8 | Cross-site request forgery | DEFENDED |
| A9 | Forged or replayed payment notification | DEFENDED |
| A10 | Flooding and brute force | DEFENDED |
| A11 | Eavesdropping and downgrade | DEFENDED |

Remote client (remote-client, 2026-11-20T15:25:50+00:00):

|  | attack | verdict |
|---|---|---|
| B1 | Outsider on the Wi-Fi scans the cloud host | DEFENDED |
| B2 | Forged identity at the website (through the tunnel) | DEFENDED |
| B3 | VPN client turns hostile: lateral movement and address spoofing (sudo) | DEFENDED |
| B4 | Alice oversteps: Bob's money, forged headers, other roles, cross-site requests | DEFENDED |
| B5 | Forged payment notification from the internet (partner API) | DEFENDED |
| B6 | Revocation watch: Alice's laptop is declared stolen | DEFENDED |
