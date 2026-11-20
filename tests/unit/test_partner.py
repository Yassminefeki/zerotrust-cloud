"""Stage 12 offline: the partner webhook (signature, time window, anti-replay), the rate limit per
identity and the device binding, on the real services + PostgreSQL of test_bank_app.py.

The partner side is tools/payflow.py itself (the program a partner, or the remote client, runs).
"""
import json
import re
import time
import uuid

import pytest

import payflow
from test_bank_app import IP, PARTNER_KEY, accounts, bank, call  # noqa: F401  (bank is a fixture)

SECRET = bytes.fromhex(PARTNER_KEY)
WINDOW = 300


def pay(bank, payment=None, *, ts=None, nonce=None, secret=SECRET, who="payflow", body=None, headers=None,
        tamper=None):
    """Sign like PayFlow and POST to the partner listener -> (status, json, the request sent)."""
    payment = payment or {"reference": f"PF-{uuid.uuid4().hex[:10]}", "to": "ZTB-ALICE-01", "amount": "1.25",
                          "description": "Order"}
    b, h = payflow.signed(secret, payment, ts=ts, nonce=nonce)
    if tamper:
        b = tamper(b)
    b, h = (body if body is not None else b), (headers if headers is not None else h)
    s, out, _ = call(bank, who, "POST", "/webhook", raw=b, headers=h, to="partner")
    return s, out, (b, h)


def balance(bank, acct="ZTB-ALICE-01"):
    return accounts(bank, "alice")[acct]["balance"]


def log(bank, node):
    return (bank["dir"] / f"{node}.log").read_text()


# --------------------------------------------------------------------------- the webhook --
def test_signed_payment_credits_the_customer_once(bank):
    before = float(balance(bank))
    ref = f"PF-{uuid.uuid4().hex[:10]}"
    s, out, _ = pay(bank, {"reference": ref, "to": "ZTB-ALICE-01", "amount": "12.50", "description": "Order 42"})
    assert s == 201, out
    assert out["replayed"] is False and out["amount"] == "12.50" and out["reference"] == ref
    assert "balance" not in json.dumps(out), "the partner learns nothing about the customer's money"
    assert round(float(balance(bank)) - before, 2) == 12.50
    s, hist, _ = call(bank, "alice", "GET", "/api/accounts/ZTB-ALICE-01/transactions")
    top = hist["entries"][0]
    assert top["description"] == f"PayFlow SAS: Order 42 ({ref})" and top["counterparty"] == "ZTB-PAYFLOW-00"


def test_the_same_request_played_twice_is_refused(bank):
    s, out, (b, h) = pay(bank)
    assert s == 201, out
    before = balance(bank)
    s, out, _ = pay(bank, body=b, headers=h)            # captured traffic, sent again byte for byte
    assert s == 409 and "nonce already used" in out["error"], out
    assert balance(bank) == before, "nothing paid twice"
    assert re.search(r"denied spiffe://cloud\.local/partner/payflow via spiffe://cloud\.local/service-a "
                     r"POST /ledger/incoming: 409 replayed request", log(bank, "service-b"))


def test_a_retry_with_a_new_nonce_is_answered_not_paid(bank):
    p = {"reference": f"PF-{uuid.uuid4().hex[:10]}", "to": "ZTB-ALICE-01", "amount": "2.00", "description": "x"}
    assert pay(bank, p)[0] == 201
    before = balance(bank)
    s, out, _ = pay(bank, p)                             # partner did not get our answer, sends again
    assert s == 200 and out["replayed"] is True, out
    assert balance(bank) == before
    s, out, _ = pay(bank, dict(p, amount="3.00"))        # same reference, other amount: refused
    assert s == 409 and "reference already used" in out["error"]


@pytest.mark.parametrize("skew,status", [(-WINDOW - 30, 401), (WINDOW + 30, 401), (-WINDOW + 30, 201)])
def test_time_window(bank, skew, status):
    s, out, _ = pay(bank, ts=int(time.time()) + skew)
    assert s == status, out
    if status == 401:
        assert "replay window" in out["error"]


def test_signature_refusals(bank):
    before = balance(bank)
    s, out, _ = pay(bank, secret=b"\x01" * 32)
    assert (s, out["error"]) == (401, "bad signature")
    s, out, _ = pay(bank, tamper=lambda b: b.replace(b'"amount":"1.25"', b'"amount":"4999.00"'))
    assert (s, out["error"]) == (401, "bad signature"), "amount changed after signing"
    b, h = payflow.signed(SECRET, {"reference": "PF-NOSIG01", "to": "ZTB-ALICE-01", "amount": "1.00"})
    for drop, status in (("X-ZT-Signature", 401), ("X-ZT-Nonce", 400), ("X-ZT-Timestamp", 400)):
        s, out, _ = pay(bank, body=b, headers={k: v for k, v in h.items() if k != drop})
        assert s == status, (drop, out)
    s, out, _ = pay(bank, body=b, headers=dict(h, **{"Content-Type": "text/plain"}))
    assert s == 415
    assert balance(bank) == before
    assert "denied spiffe://cloud.local/partner/payflow POST /webhook: 401 bad signature" in log(bank, "frontend")


@pytest.mark.parametrize("to,amount,status,msg", [
    ("ZTB-NOBODY-01", "1.00", 404, "unknown destination"),
    ("ZTB-BANK-00", "1.00", 404, "unknown destination"),         # not a customer account
    ("ZTB-PAYFLOW-00", "1.00", 404, "unknown destination"),      # its own settlement account
    ("ZTB-ALICE-01", "6000.00", 422, "maximum per transfer"),
    ("ZTB-ALICE-01", "-1", 400, "positive decimal"),
    ("ztb-alice-01", "1.00", 400, "account id"),
])
def test_payment_refusals(bank, to, amount, status, msg):
    s, out, _ = pay(bank, {"reference": f"PF-{uuid.uuid4().hex[:10]}", "to": to, "amount": amount})
    assert s == status and msg in out["error"], out


def test_only_the_partner_identity_and_only_the_webhook(bank):
    b, h = payflow.signed(SECRET, {"reference": "PF-WHO00001", "to": "ZTB-ALICE-01", "amount": "1.00"})
    s, out, _ = call(bank, "alice", "POST", "/webhook", raw=b, headers=h, to="partner")
    assert s == 403 and "not allowed" in out["reason"]
    assert call(bank, "payflow", "GET", "/webhook", to="partner")[0] == 404
    assert call(bank, "payflow", "GET", "/api/accounts", to="partner")[0] == 404
    assert call(bank, "payflow", "GET", "/api/accounts")[0] == 403, "partner identity refused on the customer site"


def test_core_and_ledger_recheck_the_partner(bank):
    """Even the frontend's own certificate cannot credit money while claiming another role."""
    payment = {"reference": "PF-CORE0001", "to": "ZTB-ALICE-01", "amount": "1.00", "nonce": "n" * 20,
               "signed_at": int(time.time())}
    hdr = {"X-ZT-Actor": "spiffe://cloud.local/customer/alice", "X-ZT-Role": "customer", "X-ZT-Customer": "alice"}
    s, out, _ = call(bank, "frontend", "POST", "/incoming", payment, headers=hdr, to="service-a")
    assert s == 403 and "role partner" in out["error"]
    hdr = {"X-ZT-Actor": "spiffe://cloud.local/customer/alice", "X-ZT-Role": "partner"}
    s, out, _ = call(bank, "service-a", "POST", "/ledger/incoming", dict(payment, amount_cents=100),
                     headers=hdr, to="service-b")
    assert s == 403 and "not a payment partner" in out["error"]


def test_partner_client_checks_it_talks_to_the_bank(bank):
    """payflow.py refuses to send anything to a server that is not the bank's frontend."""
    d = bank["dir"]
    ctx = payflow.context(d / "payflow.crt", d / "payflow.key", d / "root.crt")
    host, port = IP["service-a"], bank["ports"]["service-a"]
    with pytest.raises(Exception, match="expected spiffe://cloud.local/frontend"):
        payflow.send(host, port, ctx, b"{}", {})


# -------------------------------------------------------------------- device and rate --
def test_device_bound_identity_refused_from_another_address(bank):
    assert call(bank, "bot", "GET", "/api/statements?month=2026-11")[0] == 200
    s, out, _ = call(bank, "bot", "GET", "/api/statements?month=2026-11", src="127.0.0.66")
    assert s == 403 and "not allowed from 127.0.0.66" in out["reason"]
    assert call(bank, "alice", "GET", "/api/me", src="127.0.0.66")[0] == 200, "only the bound identity"


def test_rate_limit_per_identity(bank):
    """The bot may do 20 requests/min. The 21st in a burst gets 429 + Retry-After; Alice is not
    affected; the burst is logged once; tokens come back with time."""
    codes, retry = [], None
    for _ in range(26):
        s, out, h = call(bank, "bot", "GET", "/api/me")
        codes.append(s)
        if s == 429:
            retry = int(h["Retry-After"])
    assert codes.count(200) <= 20 and codes.count(429) >= 5, codes
    assert codes[-1] == 429 and 1 <= retry <= 3
    assert call(bank, "alice", "GET", "/api/me")[0] == 200, "per identity, not global"
    assert log(bank, "frontend").count("rate-limited spiffe://cloud.local/bot/statements") == 1
    time.sleep(retry + 0.2)
    assert call(bank, "bot", "GET", "/api/me")[0] == 200, "back after Retry-After"
