"""ZT Bank — the application, run by zt-mtls AFTER transport (TLS 1.3), identity (certificate +
allowlist) and route (policy.yaml) checks have passed. One module, three parts:

  web     (frontend)  : the actors' API (+ the static site). The acting identity, role and customer
                        come ONLY from the client certificate; nothing in the request can change them.
  core    (service-a) : business rules: input validation, roles, limits from policy.yaml.
  ledger  (service-b) : the only part that talks to PostgreSQL; reads under row-level security,
                        moves money only through bank.transfer() / bank.incoming_payment().
  partner (frontend)  : the webhook payment partners call from the internet (no VPN): mTLS with the
                        partner's certificate, then an HMAC signature over timestamp + nonce + body,
                        a time window, and a nonce the database accepts only once (anti-replay).

Between the parts, the identity travels in X-ZT-* headers. They are trusted only because an inner
service accepts nothing but its upstream node's certificate (firewall + mTLS + routes).
Amounts are integer cents everywhere; the API shows them as "1234.56" strings.
"""
import hashlib
import hmac
import json
import os
import re
import time
from urllib.parse import quote

ACCOUNT_RE = re.compile(r"^ZTB-[A-Z0-9]{2,12}-[0-9]{2}$")
AMOUNT_RE = re.compile(r"^[0-9]{1,9}(\.[0-9]{1,2})?$")
KEY_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
MONTH_RE = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])$")
CUSTOMER_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
REFERENCE_RE = re.compile(r"^[A-Za-z0-9-]{6,64}$")
SIGNATURE_RE = re.compile(r"^v1=([0-9a-f]{64})$")
WWW = os.environ.get("ZT_WWW", "/usr/local/share/zt-bank/www")
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".ico": "image/x-icon"}


class Reply(Exception):
    """Return this status + body to the caller (a refusal, or a downstream answer)."""

    def __init__(self, status, body):
        super().__init__(body)
        self.status, self.body = status, body


def deny(status, reason):
    raise Reply(status, {"error": reason})


def cents(amount: str) -> int:
    whole, _, frac = amount.partition(".")
    return int(whole) * 100 + int((frac + "00")[:2])


def money(c: int) -> str:
    return f"{'-' if c < 0 else ''}{abs(c) // 100}.{abs(c) % 100:02d}"


def clean_text(s, limit=140):
    """Printable, single-line, bounded text (descriptions shown in the UI and statements)."""
    if not isinstance(s, str):
        deny(400, "description must be text")
    s = "".join(ch for ch in s if ch.isprintable()).strip()
    if len(s) > limit:
        deny(400, f"description longer than {limit} characters")
    return s


def segment(path, i):
    parts = path.strip("/").split("/")
    return parts[i] if len(parts) > i else ""


def passthrough(status, body):
    """A downstream answer: 2xx and 4xx go back as they are, anything else becomes 502."""
    if 200 <= status < 300:
        return status, body
    if 400 <= status < 500:
        raise Reply(status, body)
    raise Reply(502, {"error": "upstream failure"})


# ------------------------------------------------------------------------------- web --
def web(req, t):
    actor = req.actor or {}
    ident = {"X-ZT-Actor": req.peer_id or "", "X-ZT-Role": actor.get("role", ""),
             "X-ZT-Customer": actor.get("customer", "")}
    r = req.route
    if req.method not in ("GET", "HEAD"):
        same_origin_only(req)
    if r in ("web-ui", "web-assets"):
        return static(req.path)
    if r == "accounts":
        return passthrough(*t.api("GET", "/accounts", headers=ident))
    if r == "history":
        acct = segment(req.path, 2)
        if not ACCOUNT_RE.match(acct):
            deny(400, "invalid account id")
        return passthrough(*t.api("GET", f"/accounts/{acct}/transactions", headers=ident))
    if r == "transfer":
        b = req.json()
        allowed = {"from", "to", "amount", "description", "idempotency_key"}
        if set(b) - allowed:
            deny(400, f"unexpected fields: {sorted(set(b) - allowed)}")
        return passthrough(*t.api("POST", "/transfers", body=b, headers=ident))
    if r == "statements":
        month = req.query.get("month", time.strftime("%Y-%m"))
        if not MONTH_RE.match(month):
            deny(400, "month must look like 2026-11")
        return passthrough(*t.api("GET", f"/statements?month={quote(month)}", headers=ident))
    if r == "status":
        return passthrough(*t.api("GET", "/status", headers=ident))
    deny(501, f"route {r} is not part of the web app")


def same_origin_only(req):
    """A browser sends the client certificate to this site whoever asks it to, so a page from
    elsewhere could try to make it POST here (cross-site request forgery). Refused, three ways:
    a JSON body (a cross-site form cannot send one without a CORS preflight, which nothing here
    answers), and the browser's own Origin / Sec-Fetch-Site headers when it sends them."""
    b = getattr(req, "browser", {}) or {}
    if b.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
        deny(415, "send JSON (Content-Type: application/json)")
    site = b.get("Sec-Fetch-Site", "")
    if site and site not in ("same-origin", "none"):
        deny(403, f"cross-site request refused ({site})")
    origin = b.get("Origin", "")
    if origin and origin != f"https://{b.get('Host', '')}":
        deny(403, "cross-origin request refused")


def static(path):
    """The site: index.html for /, otherwise one flat file from the www folder (no sub-paths)."""
    name = "index.html" if path == "/" else segment(path, 1)
    ext = os.path.splitext(name)[1]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) or name.startswith(".") or ext not in STATIC_TYPES:
        deny(404, "no such file")
    f = os.path.join(WWW, name)
    if not os.path.isfile(f):
        deny(404 if path != "/" else 501, "no such file" if path != "/" else "site not deployed yet")
    with open(f, "rb") as fh:
        return 200, ("raw", STATIC_TYPES[ext], fh.read())


# --------------------------------------------------------------------------- partner --
def webhook_signature(secret: bytes, timestamp: str, nonce: str, body: bytes) -> str:
    """HMAC-SHA256 over "<timestamp>.<nonce>.<raw body>" (what the partner signs, byte for byte)."""
    return hmac.new(secret, f"{timestamp}.{nonce}.".encode() + body, hashlib.sha256).hexdigest()


def incoming_fields(b, bank):
    """The payment a partner announces: validated identically at the frontend and in core banking."""
    ref, dst, amount = b.get("reference", ""), b.get("to", ""), b.get("amount", "")
    if not (isinstance(ref, str) and REFERENCE_RE.match(ref)):
        deny(400, "reference: 6-64 letters, digits or dashes")
    if not (isinstance(dst, str) and ACCOUNT_RE.match(dst)):
        deny(400, "to must be an account id like ZTB-ALICE-01")
    if not (isinstance(amount, str) and AMOUNT_RE.match(amount)) or cents(amount) <= 0:
        deny(400, 'amount must be a positive decimal string like "12.50"')
    if cents(amount) > bank["max_transfer_cents"]:
        deny(422, f"above the maximum per transfer ({money(bank['max_transfer_cents'])} {bank['currency']})")
    return {"reference": ref, "to": dst, "amount_cents": cents(amount),
            "description": clean_text(b.get("description", ""), 100)}


def partner(req, t):
    """POST /webhook. Order matters: who (certificate, done by zt-mtls), then is it really them and
    unmodified (signature), then is it fresh (time window), then the payment; the database then
    accepts each nonce once, so a captured request cannot be played again."""
    if req.route != "webhook":
        deny(501, f"route {req.route} is not part of the partner API")
    p = (getattr(req, "listener", {}) or {}).get("partners", {}).get(req.peer_id)
    if not p:
        deny(403, "no webhook secret for this identity")
    b = getattr(req, "browser", {}) or {}
    if b.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
        deny(415, "send JSON (Content-Type: application/json)")
    ts, nonce = req.headers.get("X-ZT-Timestamp", ""), req.headers.get("X-ZT-Nonce", "")
    m = SIGNATURE_RE.match(req.headers.get("X-ZT-Signature", ""))
    if not re.fullmatch(r"[0-9]{1,12}", ts):
        deny(400, "X-ZT-Timestamp: unix time in seconds")
    if not NONCE_RE.match(nonce):
        deny(400, "X-ZT-Nonce: 16-64 letters, digits, - or _ (unique per request)")
    if not m:
        deny(401, "X-ZT-Signature missing or malformed (v1=<hex HMAC-SHA256>)")
    try:
        with open(p["key_file"]) as f:
            secret = bytes.fromhex(f.read().strip())
    except (OSError, ValueError):
        deny(500, "webhook secret unavailable")
    if not hmac.compare_digest(webhook_signature(secret, ts, nonce, req.raw or b""), m.group(1)):
        deny(401, "bad signature")
    window = int(req.listener.get("max_skew_s", 300))
    if abs(time.time() - int(ts)) > window:
        deny(401, f"timestamp outside the replay window (+/-{window}s)")
    payment = incoming_fields(req.json(), t.bank)
    payment.update(nonce=nonce, signed_at=int(ts), amount=money(payment.pop("amount_cents")))
    ident = {"X-ZT-Actor": req.peer_id or "", "X-ZT-Role": "partner", "X-ZT-Customer": ""}
    return passthrough(*t.api("POST", "/incoming", body=payment, headers=ident))


# ------------------------------------------------------------------------------ core --
def caller(req, role):
    """The end user as asserted by the upstream node. Checked again here (defense in depth)."""
    actor = req.headers.get("X-ZT-Actor", "")
    if not actor.startswith("spiffe://"):
        deny(400, "missing acting identity")
    if req.headers.get("X-ZT-Role") != role:
        deny(403, f"this operation is for role {role}")
    customer = req.headers.get("X-ZT-Customer", "")
    if role == "customer" and not CUSTOMER_RE.match(customer):
        deny(400, "missing customer")
    return {"X-ZT-Actor": actor, "X-ZT-Role": role, "X-ZT-Customer": customer}


def core(req, t):
    r = req.route
    bank = t.bank
    if r == "accounts":
        ident = caller(req, "customer")
        status, body = passthrough(*t.api("GET", "/ledger/accounts", headers=ident))
        body["total"] = money(sum(a["balance_cents"] for a in body["accounts"]))
        body["currency"] = bank["currency"]
        for a in body["accounts"]:
            a["balance"] = money(a.pop("balance_cents"))
        return status, body
    if r == "history":
        ident = caller(req, "customer")
        acct = segment(req.path, 1)
        if not ACCOUNT_RE.match(acct):
            deny(400, "invalid account id")
        status, body = passthrough(*t.api("GET", f"/ledger/accounts/{acct}/entries", headers=ident))
        body["balance"] = money(body.pop("balance_cents"))
        for e in body["entries"]:
            e["amount"] = money(e.pop("amount_cents"))
            e["balance_after"] = money(e.pop("balance_after_cents"))
        return status, body
    if r == "transfer":
        ident = caller(req, "customer")
        b = req.json()
        src, dst = b.get("from", ""), b.get("to", "")
        if not (isinstance(src, str) and ACCOUNT_RE.match(src)) or not (isinstance(dst, str) and ACCOUNT_RE.match(dst)):
            deny(400, "from/to must be account ids like ZTB-ALICE-01")
        if src == dst:
            deny(400, "source and destination are the same account")
        amount = b.get("amount", "")
        if not (isinstance(amount, str) and AMOUNT_RE.match(amount)):
            deny(400, 'amount must be a positive decimal string like "12.50"')
        amount_c = cents(amount)
        if amount_c <= 0:
            deny(400, "the amount must be positive")
        if amount_c > bank["max_transfer_cents"]:
            deny(422, f"above the maximum per transfer ({money(bank['max_transfer_cents'])} {bank['currency']})")
        key = b.get("idempotency_key", "")
        if not (isinstance(key, str) and KEY_RE.match(key)):
            deny(400, "idempotency_key: 8-64 letters, digits or dashes (one per transfer, reused on retry)")
        payload = {"from": src, "to": dst, "amount_cents": amount_c,
                   "description": clean_text(b.get("description", "")), "idempotency_key": key}
        status, body = passthrough(*t.api("POST", "/ledger/transfers", body=payload, headers=ident))
        body["amount"] = money(body.pop("amount_cents"))
        body["balance_after"] = money(body.pop("balance_cents"))
        body["currency"] = bank["currency"]
        return status, body
    if r == "statements":
        ident = caller(req, "bot")
        month = req.query.get("month", "")
        if not MONTH_RE.match(month):
            deny(400, "month must look like 2026-11")
        status, body = passthrough(*t.api("GET", f"/ledger/statements?month={quote(month)}", headers=ident))
        for s in body["statements"]:
            for k in ("opening", "credits", "debits", "closing"):
                s[k] = money(s.pop(f"{k}_cents"))
        return status, body
    if r == "status":
        ident = caller(req, "staff")
        status, body = passthrough(*t.api("GET", "/ledger/status", headers=ident))
        body["limits"] = {"currency": bank["currency"], "max_transfer": money(bank["max_transfer_cents"]),
                          "daily_limit": money(bank["daily_limit_cents"])}
        return status, body
    if r == "incoming":
        ident = caller(req, "partner")
        b = req.json()
        payment = incoming_fields(b, bank)
        nonce, signed_at = b.get("nonce", ""), b.get("signed_at")
        if not (isinstance(nonce, str) and NONCE_RE.match(nonce)) or not isinstance(signed_at, int):
            deny(400, "nonce and signed_at are required")
        payment.update(nonce=nonce, signed_at=signed_at)
        status, body = passthrough(*t.api("POST", "/ledger/incoming", body=payment, headers=ident))
        body["amount"] = money(body.pop("amount_cents"))
        body["currency"] = bank["currency"]
        return status, body
    deny(501, f"route {r} is not part of core banking")


# ---------------------------------------------------------------------------- ledger --
def ledger(req, t):
    r = req.route
    if r == "accounts":
        ident = caller(req, "customer")
        # No "WHERE customer = ..." on purpose: row-level security returns this customer's rows only.
        rows = t.db(ident["X-ZT-Customer"], """
            SELECT a.id, a.label, a.currency, coalesce(sum(e.amount_cents), 0)
              FROM bank.accounts a LEFT JOIN bank.entries e ON e.account_id = a.id
             GROUP BY a.id ORDER BY a.id""")
        return 200, {"accounts": [{"id": i, "label": lb, "currency": c, "balance_cents": int(bal)}
                                  for i, lb, c, bal in rows]}
    if r == "history":
        ident = caller(req, "customer")
        acct = segment(req.path, 2)
        if not ACCOUNT_RE.match(acct):
            deny(400, "invalid account id")
        cust = ident["X-ZT-Customer"]
        head = t.db(cust, "SELECT a.id, a.label, a.currency FROM bank.accounts a WHERE a.id = %s", (acct,))
        if not head:
            # invisible under RLS = not this customer's: same answer as a missing account
            deny(404, "account not found")
        rows = t.db(cust, """
            SELECT e.id, e.amount_cents, e.created_at, t.description,
                   CASE WHEN t.from_account = %s THEN t.to_account ELSE t.from_account END
              FROM bank.entries e JOIN bank.transfers t ON t.id = e.transfer_id
             WHERE e.account_id = %s ORDER BY e.id DESC""", (acct, acct))
        balance = sum(int(r_[1]) for r_ in rows)
        running, entries = balance, []
        for eid, amt, at, desc, other in rows[:100]:
            entries.append({"id": eid, "amount_cents": int(amt), "balance_after_cents": running,
                            "at": at.isoformat(timespec="seconds"), "description": desc, "counterparty": other})
            running -= int(amt)
        _, label, currency = head[0]
        return 200, {"account": acct, "label": label, "currency": currency, "balance_cents": balance,
                     "entries": entries}
    if r == "transfer":
        ident = caller(req, "customer")
        b = req.json()
        try:
            int(b["amount_cents"])
        except (KeyError, TypeError, ValueError):
            deny(400, "amount_cents required")
        row = t.db(None, "SELECT * FROM bank.transfer(%s, %s, %s, %s, %s, %s, %s)",
                   (ident["X-ZT-Customer"], ident["X-ZT-Actor"], b.get("idempotency_key"), b.get("from"),
                    b.get("to"), int(b["amount_cents"]), b.get("description", "")), write=True)[0]
        tid, replayed, bal = row
        t.log(f"transfer {tid} {'replayed' if replayed else 'done'} by {ident['X-ZT-Actor']}: "
              f"{b.get('from')} -> {b.get('to')} {b['amount_cents']}")
        return (200 if replayed else 201), {"transfer_id": str(tid), "replayed": replayed,
                                            "from": b.get("from"), "to": b.get("to"),
                                            "amount_cents": int(b["amount_cents"]), "balance_cents": int(bal)}
    if r == "statements":
        caller(req, "bot")
        rows = t.db(None, "SELECT * FROM bank.statements(%s)", (req.query.get("month", ""),))
        return 200, {"month": req.query.get("month"), "statements": [
            {"account": a, "customer": c, "currency": cur, "opening_cents": int(o), "credits_cents": int(cr),
             "debits_cents": int(d), "closing_cents": int(cl)} for a, c, cur, o, cr, d, cl in rows]}
    if r == "status":
        caller(req, "staff")
        return 200, t.db(None, "SELECT bank.status()")[0][0]
    if r == "incoming":
        ident = caller(req, "partner")
        partner_id = t.bank.get("partners", {}).get(ident["X-ZT-Actor"])
        if not partner_id:
            deny(403, "not a payment partner")
        b = req.json()
        try:
            amount_c, signed_at = int(b["amount_cents"]), int(b["signed_at"])
        except (KeyError, TypeError, ValueError):
            deny(400, "amount_cents and signed_at required")
        payment_id, replayed = t.db(None, "SELECT * FROM bank.incoming_payment(%s, %s, %s, %s, %s, %s, %s, %s)",
                                    (partner_id, ident["X-ZT-Actor"], b.get("nonce"), signed_at, b.get("reference"),
                                     b.get("to"), amount_c, b.get("description", "")), write=True)[0]
        t.log(f"incoming payment {payment_id} {'replayed' if replayed else 'credited'} from {ident['X-ZT-Actor']}: "
              f"ref {b.get('reference')} -> {b.get('to')} {amount_c}")
        return (200 if replayed else 201), {"payment_id": str(payment_id), "replayed": replayed,
                                            "reference": b.get("reference"), "to": b.get("to"),
                                            "amount_cents": amount_c}
    deny(501, f"route {r} is not part of the ledger")


APPS = {"web": web, "core": core, "ledger": ledger, "partner": partner}


def handle(app, req, tools):
    """-> (status, body). body: a JSON-able object, or ("raw", content_type, bytes)."""
    try:
        return APPS[app](req, tools)
    except Reply as r:
        # refusals worth auditing (401: bad webhook signature or stale; 409: replay; 415: CSRF)
        if r.status in (401, 403, 404, 409, 415, 422):
            # who really asked: the end user (X-ZT-Actor), and the service it came through
            user = req.headers.get("X-ZT-Actor") or req.peer_id
            via = f" via {req.peer_id}" if user != req.peer_id else ""
            tools.log(f"denied {user}{via} {req.method} {req.path}: {r.status} {r.body.get('error', '')}")
        return r.status, r.body


def pg_error_to_reply(e):
    """bank.* functions raise SQLSTATE ZTnnn where nnn is the HTTP status to return."""
    code = getattr(e, "pgcode", "") or ""
    if code.startswith("ZT") and code[2:].isdigit():
        msg = getattr(getattr(e, "diag", None), "message_primary", None) or "refused"
        return Reply(int(code[2:]), {"error": msg})
    return Reply(500, {"error": "database error"})


def parse_json(raw):
    try:
        b = json.loads(raw or b"{}")
    except ValueError:
        raise Reply(400, {"error": "body must be JSON"})
    if not isinstance(b, dict):
        raise Reply(400, {"error": "body must be a JSON object"})
    return b
