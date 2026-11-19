// ZT Bank — the browser side. There is no login: the browser presents the client certificate
// in the TLS handshake and the server derives who you are from it. This file only renders what
// the API returns; every rule (who sees what, limits, ownership) is enforced on the server side.
// Safe rendering: text only (textContent), never innerHTML, no eval, no inline code (CSP).
"use strict";

const $ = (id) => document.getElementById(id);
const ACCOUNT_RE = /^ZTB-[A-Z0-9]{2,12}-[0-9]{2}$/;
const AMOUNT_RE = /^[0-9]{1,9}(\.[0-9]{1,2})?$/;

const state = { me: null, accounts: [], currency: "EUR", selected: null, pending: null, highlightFirst: false };

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}

function money(amount, currency) {
  const n = Number(amount);
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency: currency || state.currency }).format(n);
  } catch (_) {
    return `${amount} ${currency || state.currency}`;
  }
}

function when(iso) {
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function newKey() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// Same origin, JSON in and out. The server refuses POSTs that are not JSON or come from
// another site (cross-site request forgery), so this is the only way the page talks to it.
async function api(method, path, body) {
  const opt = { method, headers: { Accept: "application/json" }, cache: "no-store", credentials: "same-origin" };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);           // a network failure throws a TypeError
  let data = null;
  try { data = await r.json(); } catch (_) { /* not JSON */ }
  if (!r.ok) throw new ApiError(r.status, (data && data.error) || `HTTP ${r.status}`);
  return data;
}

function showError(err) {
  const box = $("error");
  if (!err) { box.hidden = true; box.textContent = ""; return; }
  box.textContent = err instanceof ApiError ? `${err.message} (HTTP ${err.status})` : String(err.message || err);
  box.hidden = false;
}

// ------------------------------------------------------------------------------ who am I --
async function start() {
  try {
    state.me = await api("GET", "/api/me");
  } catch (e) {
    $("loading").hidden = true;
    showError(e);
    return;
  }
  const me = state.me;
  $("who-name").textContent = me.name || me.actor;
  $("who-id").textContent = me.identity;
  $("who-id").title = "Identity from your client certificate (SPIFFE ID)";
  const role = $("who-role");
  role.textContent = me.role;
  role.classList.add(me.role);
  $("who").hidden = false;
  $("session").textContent = `Signed in by certificate as ${me.identity} · ${me.tls}`;
  $("loading").hidden = true;

  const view = $(`view-${me.role}`);
  if (!view) { showError(new Error(`no screen for role ${me.role}`)); return; }
  view.hidden = false;
  if (me.role === "customer") await startCustomer();
  else if (me.role === "staff") await loadStatus();
  else if (me.role === "bot") await startBot();
}

// ------------------------------------------------------------------------------ customer --
async function startCustomer() {
  $("transfer").addEventListener("submit", onTransfer);
  $("xfer-new").addEventListener("click", resetTransfer);
  await loadAccounts();
  if (state.accounts.length) await selectAccount(state.accounts[0].id);
}

async function loadAccounts() {
  const data = await api("GET", "/api/accounts").catch((e) => { showError(e); return null; });
  if (!data) return;
  state.accounts = data.accounts;
  state.currency = data.currency;
  $("total").textContent = money(data.total, data.currency);
  $("xfer-cur").textContent = data.currency;

  const box = $("accounts");
  box.replaceChildren();
  for (const a of data.accounts) {
    const b = el("button", "account");
    b.type = "button";
    b.dataset.id = a.id;
    b.append(el("span", "label", a.label), el("span", "number", a.id), el("span", "balance", money(a.balance, a.currency)));
    b.addEventListener("click", () => selectAccount(a.id));
    if (a.id === state.selected) b.classList.add("selected");
    box.append(b);
  }

  const sel = $("xfer-from");
  const keep = sel.value;
  sel.replaceChildren();
  for (const a of data.accounts) {
    const o = el("option", null, `${a.label} · ${a.id} · ${money(a.balance, a.currency)}`);
    o.value = a.id;
    sel.append(o);
  }
  if (keep) sel.value = keep;
}

async function selectAccount(id) {
  state.selected = id;
  for (const b of document.querySelectorAll(".account")) b.classList.toggle("selected", b.dataset.id === id);
  const data = await api("GET", `/api/accounts/${encodeURIComponent(id)}/transactions`).catch((e) => { showError(e); return null; });
  if (!data) return;
  $("hist-title").textContent = `History · ${data.label}`;
  $("hist-sub").textContent = `${data.account} · balance ${money(data.balance, data.currency)}`;
  const body = $("history").tBodies[0];
  body.replaceChildren();
  if (!data.entries.length) {
    const tr = el("tr");
    const td = el("td", "muted", "No transactions yet.");
    td.colSpan = 4;
    tr.append(td);
    body.append(tr);
  }
  for (const e of data.entries) {
    const tr = el("tr");
    if (state.highlightFirst && e === data.entries[0]) tr.className = "new";
    const desc = el("td", null, e.description || "—");
    desc.append(el("span", "cp", e.counterparty));
    const amt = el("td", `num ${e.amount.startsWith("-") ? "debit" : "credit"}`, money(e.amount, data.currency));
    tr.append(el("td", "date", when(e.at)), desc, amt, el("td", "num", money(e.balance_after, data.currency)));
    body.append(tr);
  }
  state.highlightFirst = false;
}

function formValues() {
  return {
    from: $("xfer-from").value,
    to: $("xfer-to").value.trim().toUpperCase(),
    amount: $("xfer-amount").value.trim().replace(",", "."),
    description: $("xfer-desc").value.trim(),
  };
}

function validate(v) {
  const bad = [];
  $("xfer-to").setAttribute("aria-invalid", String(!ACCOUNT_RE.test(v.to)));
  $("xfer-amount").setAttribute("aria-invalid", String(!(AMOUNT_RE.test(v.amount) && Number(v.amount) > 0)));
  if (!ACCOUNT_RE.test(v.to)) bad.push("the destination looks like ZTB-BOB-01");
  if (!(AMOUNT_RE.test(v.amount) && Number(v.amount) > 0)) bad.push('the amount looks like 12.50');
  if (v.to === v.from) bad.push("choose another account than the source");
  return bad;
}

function result(text, ref, isError) {
  const box = $("xfer-result");
  box.replaceChildren(el("span", null, text));
  if (ref) box.append(el("span", "ref", ref));
  box.classList.toggle("error", Boolean(isError));
  box.hidden = false;
}

// One idempotency key per transfer. If the network fails we do not know whether the bank
// received it: pressing Send again re-uses the SAME key, so it can never be paid twice.
// Changing anything in the form makes it a different transfer, with a new key.
async function onTransfer(ev) {
  ev.preventDefault();
  showError(null);
  const v = formValues();
  const bad = validate(v);
  if (bad.length) { result(`Please check: ${bad.join("; ")}.`, null, true); return; }

  const fp = JSON.stringify(v);
  if (!state.pending || state.pending.fp !== fp) state.pending = { fp, key: newKey() };
  const btn = $("xfer-send");
  btn.disabled = true;
  try {
    const r = await api("POST", "/api/transfers", { ...v, idempotency_key: state.pending.key });
    state.pending = null;
    state.highlightFirst = true;
    result(r.replayed ? `Already done — ${money(r.amount, r.currency)} to ${r.to} was paid once, not twice.`
                      : `Sent ${money(r.amount, r.currency)} to ${r.to}. New balance ${money(r.balance_after, r.currency)}.`,
           `transfer ${r.transfer_id}`);
    $("xfer-send").hidden = true;
    $("xfer-new").hidden = false;
    await loadAccounts();
    await selectAccount(v.from);
  } catch (e) {
    if (e instanceof ApiError && e.status < 500) {
      state.pending = null;                 // a clear refusal: nothing was paid
      result(e.message, `refused by the bank (HTTP ${e.status})`, true);
    } else {
      result("No answer from the bank. Press Send again: it will not be paid twice.",
             `retry key ${state.pending.key}`, true);
    }
  } finally {
    btn.disabled = false;
  }
}

function resetTransfer() {
  $("transfer").reset();
  $("xfer-from").value = state.selected || "";
  $("xfer-result").hidden = true;
  $("xfer-send").hidden = false;
  $("xfer-new").hidden = true;
  state.pending = null;
}

// --------------------------------------------------------------------------------- staff --
async function loadStatus() {
  $("status-refresh").onclick = loadStatus;
  const s = await api("GET", "/api/status").catch((e) => { showError(e); return null; });
  if (!s) return;
  showError(null);
  const items = [
    ["Ledger", s.ledger_balanced && s.unbalanced_transfers === 0 ? "Balanced" : "NOT balanced",
     s.ledger_balanced && s.unbalanced_transfers === 0 ? "good" : "bad"],
    ["Customers", s.customers], ["Accounts", s.accounts],
    ["Transfers today", s.transfers_today], ["Transfers in total", s.transfers_total],
    ["Max per transfer", money(s.limits.max_transfer, s.limits.currency)],
    ["Daily limit per customer", money(s.limits.daily_limit, s.limits.currency)],
    ["Database", `${s.database} · PostgreSQL ${String(s.server_version).split(" ")[0]}`],
  ];
  const box = $("stats");
  box.replaceChildren();
  for (const [k, v, cls] of items) {
    const d = el("div", `stat ${cls || ""}`);
    d.append(el("span", "k", k), el("span", "v", v));
    box.append(d);
  }
}

// ----------------------------------------------------------------------------------- bot --
async function startBot() {
  const m = $("month");
  const now = new Date();
  m.value = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  $("month-form").addEventListener("submit", (ev) => { ev.preventDefault(); loadStatements(); });
  await loadStatements();
}

async function loadStatements() {
  const month = $("month").value;
  const data = await api("GET", `/api/statements?month=${encodeURIComponent(month)}`).catch((e) => { showError(e); return null; });
  if (!data) return;
  showError(null);
  const body = $("statements").tBodies[0];
  body.replaceChildren();
  for (const s of data.statements) {
    const tr = el("tr");
    tr.append(el("td", null, s.account), el("td", null, s.customer),
              el("td", "num", money(s.opening, s.currency)), el("td", "num credit", money(s.credits, s.currency)),
              el("td", "num debit", money(s.debits, s.currency)), el("td", "num", money(s.closing, s.currency)));
    body.append(tr);
  }
}

document.addEventListener("DOMContentLoaded", start);
