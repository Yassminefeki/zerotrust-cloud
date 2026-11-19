"""Stage 11 offline: the website, served by the real frontend of the offline bank (test_bank_app.py).

* the page and its files: strict CSP, no inline code, text-only rendering in the JS;
* cross-site request forgery: a browser sends the client certificate to the bank whoever asks,
  so POSTs that are not JSON, or that come from another site, are refused;
* with Playwright + Chrome installed: a REAL browser, logged in by nothing but a client
  certificate, for each role (alice moves money, bob cannot see alice, staff, bot), no CSP
  violation, and an attacker's page on another origin that tries to make the browser pay.
"""
import http.server
import os
import re
import threading
import uuid

import pytest

from test_bank_app import accounts, bank, call  # noqa: F401,F811  (bank is a fixture)
from unit_helpers import ROOT

WWW = ROOT / "ansible/roles/app/files/www"


# ---------------------------------------------------------------------------- the files --
def test_site_files_have_no_inline_code():
    html = (WWW / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline <script>"
    assert not re.search(r"\sstyle\s*=", html), "inline style attribute"
    assert not re.search(r"\son[a-z]+\s*=", html, re.I), "inline event handler"
    assert "<style" not in html


def test_javascript_renders_text_only():
    js = (WWW / "app.js").read_text()
    code = "\n".join(l for l in js.splitlines() if not l.strip().startswith("//"))
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                "setTimeout(\"", "localStorage", "sessionStorage", "document.cookie"):
        assert bad not in code, bad


def test_page_and_assets_served_with_security_headers(bank):
    s, body, h = call(bank, "alice", "GET", "/")
    assert s == 200 and h["Content-Type"].startswith("text/html") and b"ZT Bank" in body
    csp = h["Content-Security-Policy"]
    for d in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'"):
        assert d in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"
    assert h["Cross-Origin-Opener-Policy"] == "same-origin"
    assert h["Cache-Control"] in ("no-store", "no-cache"), "never cached without checking"
    for f, ctype in (("app.js", "text/javascript"), ("app.css", "text/css"), ("logo.svg", "image/svg+xml")):
        s, body, h = call(bank, "alice", "GET", f"/static/{f}")
        assert s == 200 and h["Content-Type"].startswith(ctype), f
        assert body == (WWW / f).read_bytes()


@pytest.mark.parametrize("path", ["/static/../zt_bank.py", "/static/.hidden.js", "/static/index.py",
                                  "/static/a/b.js", "/static/missing.js"])
def test_only_the_site_files_are_served(bank, path):
    assert call(bank, "alice", "GET", path)[0] == 404


# --------------------------------------------------------------- cross-site request forgery --
def xfer(key):
    return {"from": "ZTB-ALICE-01", "to": "ZTB-BOB-01", "amount": "0.01", "description": "csrf", "idempotency_key": key}


@pytest.mark.parametrize("headers,status", [
    ({"Content-Type": "text/plain"}, 415),                                    # what a cross-site <form> can send
    ({"Content-Type": "application/x-www-form-urlencoded"}, 415),
    ({"Content-Type": "application/json", "Origin": "https://evil.example"}, 403),
    ({"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}, 403),
    ({"Content-Type": "application/json", "Sec-Fetch-Site": "same-site"}, 403),  # another port/host
])
def test_cross_site_posts_refused(bank, headers, status):
    before = accounts(bank, "alice")["ZTB-ALICE-01"]["balance"]
    s, b, _ = call(bank, "alice", "POST", "/api/transfers", xfer(uuid.uuid4().hex), headers=headers)
    assert s == status, b
    assert accounts(bank, "alice")["ZTB-ALICE-01"]["balance"] == before, "nothing was paid"


def test_same_origin_browser_post_accepted(bank):
    host = bank["url"]
    s, b, _ = call(bank, "alice", "POST", "/api/transfers", xfer(uuid.uuid4().hex),
                   headers={"Origin": f"https://{host}", "Host": host, "Sec-Fetch-Site": "same-origin"})
    assert s == 201, b


def test_csrf_refusals_are_logged(bank):
    log = (bank["dir"] / "frontend.log").read_text()
    assert re.search(r"denied spiffe://cloud\.local/customer/alice POST /api/transfers: 403 cross-site", log)
    assert re.search(r"denied spiffe://cloud\.local/customer/alice POST /api/transfers: 415", log)


# ------------------------------------------------------------------------ a real browser --
try:
    from playwright import sync_api
except ImportError:          # the browser tests skip; everything above still runs
    sync_api = None


@pytest.fixture(scope="module")
def browser(bank):
    if sync_api is None:
        pytest.skip("Playwright not installed (pip install playwright; playwright install chromium)")
    # Playwright presents client certificates through its own TLS client (Node): it must trust
    # the bank's root, exactly like Firefox once the root is imported on the i7
    saved = dict(os.environ)
    os.environ["NODE_EXTRA_CA_CERTS"] = str(bank["dir"] / "root.crt")
    # and it would send that traffic through an outbound proxy if one is set (it does not
    # understand NO_PROXY=127.0.0.0/8): the bank is local, no proxy
    for k in [k for k in os.environ if k.lower() in ("http_proxy", "https_proxy", "all_proxy")]:
        del os.environ[k]
    try:
        yield from _browser()
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(channel="chrome")
        except Exception:
            try:
                b = p.chromium.launch()
            except Exception as e:  # no browser downloaded
                pytest.skip(f"no browser for Playwright: {e}")
        yield b
        b.close()


@pytest.fixture
def as_actor(bank, browser):
    """A browser whose only credential is the actor's client certificate."""
    ctxs = []

    def open_(who):
        d = bank["dir"]
        ctx = browser.new_context(
            ignore_https_errors=True,   # Playwright's own TLS hop to Chrome; the bank's certificate is checked above
            client_certificates=[{"origin": f"https://{bank['url']}",
                                  "certPath": str(d / f"{who}.crt"), "keyPath": str(d / f"{who}.key")}])
        ctxs.append(ctx)
        page = ctx.new_page()
        page.problems = []
        page.on("console", lambda m: m.type in ("error", "warning") and page.problems.append(m.text))
        page.on("pageerror", lambda e: page.problems.append(str(e)))
        page.goto(f"https://{bank['url']}/")
        return page
    yield open_
    for c in ctxs:
        c.close()


def shot(page, name):
    """ZT_SCREENSHOTS=<dir>: keep a picture of each screen (README, review)."""
    d = os.environ.get("ZT_SCREENSHOTS")
    if d:
        page.wait_for_load_state("networkidle")
        page.screenshot(path=os.path.join(d, f"{name}.png"), full_page=True)


def test_browser_without_certificate_gets_nothing(bank, browser):
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    with pytest.raises(sync_api.Error):
        page.goto(f"https://{bank['url']}/", timeout=10000)
    ctx.close()


def test_alice_sees_her_accounts_and_moves_money(bank, as_actor):
    page = as_actor("alice")
    sync_api.expect(page.locator("#who-name")).to_have_text("Alice Martin")
    sync_api.expect(page.locator("#who-role")).to_have_text("customer")
    sync_api.expect(page.locator(".account")).to_have_count(2)
    sync_api.expect(page.locator("#history tbody tr").first).to_be_visible()
    assert "ZTB-BOB-01" not in page.locator("#accounts").inner_text()

    before = accounts(bank, "alice")["ZTB-ALICE-01"]["balance"]
    page.select_option("#xfer-from", "ZTB-ALICE-01")
    page.fill("#xfer-to", "ztb-bob-01")
    page.fill("#xfer-amount", "2,50")
    page.fill("#xfer-desc", "Coffee <script>alert(1)</script>")
    page.click("#xfer-send")
    sync_api.expect(page.locator("#xfer-result")).to_contain_text("Sent")
    after = accounts(bank, "alice")["ZTB-ALICE-01"]["balance"]
    assert round(float(before) - float(after), 2) == 2.50
    # the description is shown as text, never run as code
    sync_api.expect(page.locator("#history tbody tr").first).to_contain_text("<script>alert(1)</script>")
    shot(page, "customer-alice")
    assert page.problems == [], page.problems


def test_browser_refusals_are_shown_not_hidden(bank, as_actor):
    page = as_actor("alice")
    sync_api.expect(page.locator(".account")).to_have_count(2)
    page.fill("#xfer-to", "ZTB-BOB-01")
    page.fill("#xfer-amount", "6000")
    page.click("#xfer-send")
    sync_api.expect(page.locator("#xfer-result")).to_contain_text("maximum per transfer")
    page.fill("#xfer-to", "ZTB-NOBODY-01")
    page.fill("#xfer-amount", "1")
    page.click("#xfer-send")
    sync_api.expect(page.locator("#xfer-result")).to_contain_text("unknown destination")


def test_bob_cannot_open_alices_account_from_the_address_bar(bank, as_actor):
    page = as_actor("bob")
    sync_api.expect(page.locator("#who-name")).to_have_text("Bob Durand")
    sync_api.expect(page.locator(".account")).to_have_count(1)
    r = page.goto(f"https://{bank['url']}/api/accounts/ZTB-ALICE-01/transactions")
    assert r.status == 404


def test_staff_sees_operations_only(bank, as_actor):
    page = as_actor("dev")
    sync_api.expect(page.locator("#who-role")).to_have_text("staff")
    sync_api.expect(page.locator("#stats")).to_contain_text("Balanced")
    assert page.locator("#view-customer").is_hidden()
    assert "ZTB-" not in page.locator("main").inner_text(), "no customer data on the staff screen"
    shot(page, "staff-dev")
    assert page.problems == [], page.problems


def test_bot_sees_statements(bank, as_actor):
    page = as_actor("bot")
    sync_api.expect(page.locator("#who-role")).to_have_text("bot")
    sync_api.expect(page.locator("#statements tbody tr")).to_have_count(3)
    shot(page, "bot-statements")
    assert page.problems == [], page.problems


class Evil(http.server.BaseHTTPRequestHandler):
    """An attacker's page on another origin, opened by alice while her certificate is loaded."""
    target = ""

    def do_GET(self):
        t = self.target
        page = f"""<!DOCTYPE html><html><body>
<form id="f" method="POST" action="{t}/api/transfers" enctype="text/plain">
<input name='{{"from":"ZTB-ALICE-01","to":"ZTB-BOB-01","amount":"999.00","description":"x","idempotency_key":"evil-form-0001","p":"' value='"}}'>
</form>
<script>
fetch("{t}/api/transfers", {{method: "POST", mode: "no-cors", credentials: "include",
  headers: {{"Content-Type": "text/plain"}},
  body: JSON.stringify({{from: "ZTB-ALICE-01", to: "ZTB-BOB-01", amount: "999.00", idempotency_key: "evil-fetch-0001"}})}})
  .finally(() => {{ document.title = "fetched"; document.getElementById("f").submit(); }});
</script></body></html>""".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, *a):
        pass


def test_attacker_page_cannot_make_the_browser_pay(bank, as_actor):
    page = as_actor("alice")
    sync_api.expect(page.locator(".account")).to_have_count(2)
    before = accounts(bank, "alice")["ZTB-ALICE-01"]["balance"]
    Evil.target = f"https://{bank['url']}"
    srv = http.server.HTTPServer(("127.0.0.77", 0), Evil)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with page.expect_navigation(url=re.compile(r"/api/transfers"), timeout=15000) as nav:
            page.goto(f"http://127.0.0.77:{srv.server_port}/")
        assert nav.value.status in (403, 415), nav.value.status
    finally:
        srv.shutdown()
    assert accounts(bank, "alice")["ZTB-ALICE-01"]["balance"] == before, "the attacker's page moved money"
    log = (bank["dir"] / "frontend.log").read_text()
    assert "evil" not in (bank["dir"] / "service-a.log").read_text(), "refused at the frontend, never forwarded"
    assert re.search(r"denied spiffe://cloud\.local/customer/alice POST /api/transfers: 4(03|15)", log)
