#!/usr/bin/env python3
"""pg_probe.py — one PostgreSQL login attempt (psycopg2/libpq), prints JSON. Run on a VM.

    python3 pg_probe.py --host 10.40.0.10 --db appdb --user service_b --ca root.crt \
        [--cert c.crt --key c.key] [--sslmode verify-full|disable]
"""
import argparse
import json

import psycopg2

ap = argparse.ArgumentParser()
ap.add_argument("--host", required=True)
ap.add_argument("--port", type=int, default=5432)
ap.add_argument("--db", required=True)
ap.add_argument("--user", required=True)
ap.add_argument("--ca")
ap.add_argument("--cert")
ap.add_argument("--key")
ap.add_argument("--sslmode", default="verify-full")
ap.add_argument("--customer", help="set zt.customer for the transaction (row-level security)")
ap.add_argument("--sql", help="run this statement instead of the login check; rows or SQLSTATE returned")
a = ap.parse_args()
kw = dict(host=a.host, port=a.port, dbname=a.db, user=a.user, sslmode=a.sslmode, connect_timeout=5)
if a.sslmode != "disable":
    kw.update(sslrootcert=a.ca, ssl_min_protocol_version="TLSv1.3")
    # without --cert, point libpq at files that do not exist so it cannot pick up ~/.postgresql
    kw.update(sslcert=a.cert or "/nonexistent.crt", sslkey=a.key or "/nonexistent.key")
out = {"ok": False, "user": None, "tls": None, "error": None}
try:
    conn = psycopg2.connect(**kw)
    with conn, conn.cursor() as cur:
        cur.execute("SELECT current_user, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
        out["user"], out["tls"] = cur.fetchone()
        if a.customer:
            cur.execute("SELECT set_config('zt.customer', %s, true)", (a.customer,))
        if a.sql:
            cur.execute(a.sql)
            out["rows"] = [list(map(str, r)) for r in cur.fetchall()] if cur.description else []
    conn.close()
    out["ok"] = True
except Exception as e:  # noqa: BLE001
    out["error"] = f"{type(e).__name__}: {e}".strip()
    out["sqlstate"] = getattr(e, "pgcode", None)
print(json.dumps(out))
