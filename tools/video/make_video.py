#!/usr/bin/env python3
"""ZT Bank — démo vidéo (3-5 min), construite à partir des sorties réelles du projet, anonymisées.
Chaque scène = un fichier MP4 (1920x1080, 30 i/s, mêmes réglages), puis concaténation sans réencodage."""
import os
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H, FPS = 1920, 1080, 30
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ.get("ZT_VIDEO_OUT", "/tmp/zt-video/scenes"))
OUT.mkdir(parents=True, exist_ok=True)
SCREENS = ROOT / "docs/screens"

INTER = "/usr/share/fonts/opentype/inter/Inter-{}.otf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONOB = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"


def font(w, s):
    return ImageFont.truetype(INTER.format(w), s)


def mono(s, bold=False):
    return ImageFont.truetype(MONOB if bold else MONO, s)


ZT = (15, 61, 62)
ZTL = (232, 241, 239)
BG = (246, 247, 244)
INK = (24, 32, 32)
MUTED = (96, 108, 106)
OK = (40, 167, 96)
BAD = (220, 70, 60)
AMBER = (230, 180, 70)
TERM = (14, 22, 24)
TERM_TXT = (214, 224, 220)
TERM_DIM = (120, 140, 136)
ACCENT = (110, 210, 190)

ENC = ["-c:v", "libx264", "-preset", "veryfast", "-crf", "20", "-pix_fmt", "yuv420p", "-r", str(FPS)]


# ------------------------------------------------------------------ encoding --
def encode_still(img, dur, name):
    if os.environ.get("PREVIEW"):
        img.save(OUT / f"preview-{name}.png")
        return
    tmp, dst = OUT / f".{name}.tmp.mp4", OUT / f"{name}.mp4"
    png = OUT / f"{name}.png"
    img.save(png)
    vf = f"format=yuv420p,loop=-1:1,trim=duration={dur},fade=t=in:st=0:d=0.4,fade=t=out:st={dur - 0.4}:d=0.4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS), "-i", str(png), "-vf", vf,
                    *ENC, str(tmp)], check=True)
    os.replace(tmp, dst)


def encode_anim(frame_fn, dur, name):
    if os.environ.get("PREVIEW"):
        frame_fn(dur - 1.0)[1].save(OUT / f"preview-{name}.png")
        frame_fn(dur * 0.35)[1].save(OUT / f"preview-{name}-mid.png")
        return
    tmp, dst = OUT / f".{name}.tmp.mp4", OUT / f"{name}.mp4"
    n = int(dur * FPS)
    p = subprocess.Popen(["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
                          "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-",
                          "-vf", f"fade=t=in:st=0:d=0.4,fade=t=out:st={dur - 0.4}:d=0.4", *ENC, str(tmp)],
                         stdin=subprocess.PIPE)
    last_key, last_bytes = None, None
    for i in range(n):
        t = i / FPS
        key, img = frame_fn(t)
        if key != last_key or last_bytes is None:
            last_bytes = (img if img is not None else frame_fn(t, force=True)[1]).convert("RGB").tobytes()
            last_key = key
        p.stdin.write(last_bytes)
    p.stdin.close()
    if p.wait() != 0:
        sys.exit(f"ffmpeg failed on {name}")
    os.replace(tmp, dst)


# ------------------------------------------------------------------- drawing --
def canvas(bg=BG):
    return Image.new("RGB", (W, H), bg)


def header(d, section, step):
    d.rectangle([0, 0, W, 86], fill=ZT)
    d.text((60, 22), "ZT Bank", font=font("Bold", 34), fill=(255, 255, 255))
    d.text((230, 30), "mini-cloud Zero Trust", font=font("Regular", 26), fill=(170, 210, 200))
    tw = d.textlength(section, font=font("SemiBold", 26))
    d.text((W - 60 - tw, 30), section, font=font("SemiBold", 26), fill=(255, 255, 255))
    if step:
        d.rectangle([0, 86, int(W * step), 92], fill=ACCENT)


def wrap(d, text, f, width):
    words, lines, cur = text.split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if d.textlength(t, font=f) <= width:
            cur = t
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def para(d, xy, text, f, width, fill=INK, gap=1.35):
    x, y = xy
    for line in wrap(d, text, f, width):
        d.text((x, y), line, font=f, fill=fill)
        y += int(f.size * gap)
    return y


def caption(d, text):
    f = font("Medium", 34)
    lines = wrap(d, text, f, W - 260)
    h = 30 + len(lines) * 46
    y0 = H - h - 40
    d.rounded_rectangle([110, y0, W - 110, H - 40], radius=18, fill=(0, 0, 0, 200) if False else (20, 30, 30))
    y = y0 + 16
    for line in lines:
        tw = d.textlength(line, font=f)
        d.text(((W - tw) / 2, y), line, font=f, fill=(250, 250, 245))
        y += 46


def pill(d, xy, text, fg, bg, f=None):
    f = f or font("Bold", 24)
    x, y = xy
    tw = d.textlength(text, font=f)
    h = int(f.size * 1.75)
    d.rounded_rectangle([x, y, x + tw + 40, y + h], radius=h // 2, fill=bg)
    d.text((x + 20, y + (h - f.size) / 2 - f.size * 0.12), text, font=f, fill=fg)
    return x + tw + 40


# ------------------------------------------------------------------- scenes --
SCENES = []


def scene(fn):
    SCENES.append(fn)
    return fn


TOTAL = 15


def prog(i):
    return i / TOTAL


@scene
def s01_title():
    img = canvas(ZT)
    d = ImageDraw.Draw(img)
    d.text((140, 300), "ZT Bank", font=font("Bold", 120), fill=(255, 255, 255))
    d.text((140, 450), "Un mini-cloud Zero Trust sur un seul portable", font=font("Medium", 54), fill=(190, 228, 218))
    d.text((140, 540), "6 VM · WireGuard · mTLS TLS 1.3 · PKI SPIFFE · PostgreSQL · attaques et audit",
           font=font("Regular", 36), fill=(200, 220, 215))
    d.rectangle([140, 640, 520, 646], fill=ACCENT)
    d.text((140, 690), "Démo — sorties réelles du projet, condensées et anonymisées", font=font("Regular", 30),
           fill=(170, 200, 195))
    d.text((140, 960), "github.com/Yassminefeki/PQC-Cloud-Lab", font=font("SemiBold", 32), fill=(255, 255, 255))
    encode_still(img, 7, "s01")


@scene
def s02_sujet():
    img = canvas()
    d = ImageDraw.Draw(img)
    header(d, "1 · Le sujet", prog(1))
    d.text((120, 150), "Ne faire confiance à rien, par défaut", font=font("Bold", 64), fill=ZT)
    para(d, (120, 250), "Le modèle « château fort » croit tout ce qui est derrière le pare-feu. Le zero trust "
         "(NIST SP 800-207) exige qu'à chaque saut, chaque requête prouve qui l'envoie, par où elle passe et ce "
         "qu'elle a le droit de faire — et que tout refus soit tracé.", font("Regular", 36), 1680, MUTED)
    rows = [("Ne jamais croire le réseau", "pare-feu default drop sur CHAQUE VM, aucune VM routée"),
            ("Authentifier chaque requête", "mTLS TLS 1.3 à chaque saut, base de données comprise"),
            ("Identités courtes", "certificats SPIFFE 24 h (1 h pour le robot), CA interne"),
            ("Moindre privilège", "routes par rôle, rôle SQL sans écriture, sécurité par ligne"),
            ("Supposer la compromission", "révocation < 1 min, fail-closed, chaque couche revérifie"),
            ("Tout journaliser", "chaque refus nomme le vrai responsable ; make audit")]
    y = 480
    for a, b in rows:
        d.rounded_rectangle([120, y, 1800, y + 72], radius=12, fill=ZTL)
        d.text((150, y + 18), a, font=font("SemiBold", 32), fill=ZT)
        d.text((700, y + 19), b, font=font("Regular", 31), fill=INK)
        y += 86
    encode_still(img, 15, "s02")


def box(d, xy, wh, title, sub, fill=ZTL, outline=ZT):
    x, y = xy
    w, h = wh
    d.rounded_rectangle([x, y, x + w, y + h], radius=14, fill=fill, outline=outline, width=3)
    tw = d.textlength(title, font=font("Bold", 30))
    d.text((x + (w - tw) / 2, y + 14), title, font=font("Bold", 30), fill=ZT)
    sw = d.textlength(sub, font=font("Regular", 22))
    d.text((x + (w - sw) / 2, y + 54), sub, font=font("Regular", 22), fill=MUTED)


def arrow(d, a, b, color=ZT, width=5, label=None, dashed=False):
    import math
    (x1, y1), (x2, y2) = a, b
    if dashed:
        n = int(math.hypot(x2 - x1, y2 - y1) // 18)
        for i in range(0, n, 2):
            p = (x1 + (x2 - x1) * i / n, y1 + (y2 - y1) * i / n)
            q = (x1 + (x2 - x1) * (i + 1) / n, y1 + (y2 - y1) * (i + 1) / n)
            d.line([p, q], fill=color, width=width)
    else:
        d.line([a, b], fill=color, width=width)
    ang = math.atan2(y2 - y1, x2 - x1)
    s = 18
    d.polygon([(x2, y2), (x2 - s * math.cos(ang - 0.4), y2 - s * math.sin(ang - 0.4)),
               (x2 - s * math.cos(ang + 0.4), y2 - s * math.sin(ang + 0.4))], fill=color)
    if label:
        lf = font("Medium", 24)
        if abs(y2 - y1) < 5:          # horizontal: label above the line, centred
            tw = d.textlength(label, font=lf)
            d.text(((x1 + x2) / 2 - tw / 2, y1 - 36), label, font=lf, fill=ZT)
        else:
            d.text(((x1 + x2) / 2 + 14, (y1 + y2) / 2 - 16), label, font=lf, fill=ZT)


@scene
def s03_archi():
    img = canvas()
    d = ImageDraw.Draw(img)
    header(d, "2 · Architecture", prog(2))
    bw, bh = 400, 96
    cx = 760
    box(d, (120, 140), (380, bh), "Poste distant", "Firefox · WireGuard", fill=(255, 255, 255), outline=MUTED)
    box(d, (cx, 140), (bw, bh), "Cloud host", "DNAT par nom d'interface", fill=(255, 255, 255), outline=MUTED)
    box(d, (120, 300), (380, bh), "PayFlow", "Internet, sans VPN", fill=(255, 255, 255), outline=MUTED)
    ys = [300, 450, 600, 750, 900]
    names = [("VM1 gateway", "WireGuard · nftables"), ("VM2 frontend", ":8443 site · :8444 partenaire"),
             ("VM3 service-a", "core : règles métier"), ("VM4 service-b", "ledger : seul client de la base"),
             ("VM5 database", "PostgreSQL 16 · RLS · append-only")]
    for (n, s), y in zip(names, ys):
        box(d, (cx, y), (bw, bh), n, s)
    box(d, (1420, 600), (380, bh), "VM6 ca", "step-ca · CRL")
    arrow(d, (500, 188), (cx, 188), label="UDP 51820")
    arrow(d, (500, 348), (cx - 2, 348), label="TCP 8444")
    arrow(d, (cx + bw / 2, 236), (cx + bw / 2, 300))
    labels = ["tunnel → :8443 seulement", "mTLS", "mTLS", "TLS 1.3 + certificat"]
    for y, lab in zip(ys[:-1], labels):
        arrow(d, (cx + bw / 2, y + bh), (cx + bw / 2, y + 150), label=lab)
    for y in (450, 600, 750):
        arrow(d, (cx + bw, y + bh / 2), (1420, 648), color=MUTED, width=3, dashed=True)
    for t, y in (("dmz 10.20.0.0/24", 480), ("app 10.30.0.0/24", 630), ("data 10.40.0.0/24", 930)):
        d.text((470, y), t, font=font("Regular", 26), fill=MUTED)
    d.text((1420, 720), "mgmt 10.50.0.0/24", font=font("Regular", 26), fill=MUTED)
    d.text((1420, 760), "(pointillés : enrôlement, CRL)", font=font("Regular", 22), fill=MUTED)
    para(d, (120, 520), "Trois verrous à chaque saut : le réseau (nftables), le transport (WireGuard puis "
         "TLS 1.3), l'identité (certificat + liste + route).", font("Medium", 28), 300, INK)
    encode_still(img, 20, "s03")


@scene
def s04_policy():
    img = canvas()
    d = ImageDraw.Draw(img)
    header(d, "3 · Une seule source de vérité", prog(3))
    d.text((120, 140), "policy.yaml  →  gen_rules.py  →  toute la configuration", font=font("Bold", 52), fill=ZT)
    d.rounded_rectangle([120, 240, 900, 900], radius=16, fill=TERM)
    code = ["flows:", "  - {from: tunnel,    to: https}", "  - {from: frontend,  to: api-a}",
            "  - {from: service-a, to: api-b}", "  - {from: service-b, to: postgres}", "",
            "actors:", "  alice: {role: customer, entry: tunnel}", "  dev:   {role: staff,    entry: tunnel}",
            "  payflow: {role: partner, entry: internet}", "", "routes:", "  https:",
            "    - {method: POST, path: /api/transfers,", "       allow: [customer]}"]
    y = 270
    for line in code:
        col = ACCENT if line.endswith(":") and not line.startswith(" ") else TERM_TXT
        d.text((160, y), line, font=mono(28), fill=col)
        y += 40
    outs = ["nftables de chaque VM (default drop)", "mtls.json : identités, listes, routes, CRL",
            "pg_hba : service-b seul, par certificat", "politique d'émission de la CA",
            "WireGuard, Terraform, inventaire Ansible", "matrice attendue → les tests"]
    y = 260
    for o in outs:
        d.rounded_rectangle([1000, y, 1800, y + 90], radius=12, fill=ZTL, outline=ZT, width=2)
        d.text((1030, y + 26), o, font=font("Medium", 30), fill=ZT)
        arrow(d, (905, 610), (998, y + 45), width=3)
        y += 115
    caption(d, "Écrite une fois, générée partout, vérifiée par plus de 450 tests : toute dérive est détectée.")
    encode_still(img, 15, "s04")


def term_scene(name, title, section, step, blocks, dur, cap, prompt_by_block=None, cps=28, line_s=0.09,
               start=0.6, font_size=26):
    """blocks: list of (prompt, command, [output lines]); typed then revealed line by line."""
    f, fb = mono(font_size), mono(font_size, True)
    lh = int(font_size * 1.45)
    timeline, t = [], start
    for prompt, cmd, out in blocks:
        timeline.append(("cmd", t, prompt, cmd))
        t += len(cmd) / cps + 0.35
        for line in out:
            timeline.append(("out", t, line))
            t += line_s
        t += 0.5

    def color(line):
        u = line.upper()
        if "BREACH" in u and "NOT" not in u:
            return BAD
        if "REFUSED" in u or "DEFENDED" in u or "PASSED" in u or "NONE:" in u:
            return OK
        if line.startswith("   [INFO") or line.startswith("==") or line.startswith("#"):
            return ACCENT
        if line.strip().startswith("->"):
            return TERM_DIM
        return TERM_TXT

    base = canvas()
    bd = ImageDraw.Draw(base)
    header(bd, section, step)
    bd.text((120, 120), title, font=font("Bold", 44), fill=ZT)
    x0, y0, x1, y1 = 100, 190, W - 100, H - 170
    bd.rounded_rectangle([x0, y0, x1, y1], radius=16, fill=TERM)
    for i, c in enumerate([(237, 106, 94), (245, 191, 79), (98, 197, 84)]):
        bd.ellipse([x0 + 24 + i * 34, y0 + 18, x0 + 44 + i * 34, y0 + 38], fill=c)
    caption(bd, cap)
    max_lines = (y1 - y0 - 70) // lh

    def frame(t, force=False):
        lines = []
        for ev in timeline:
            if ev[1] > t:
                if ev[0] == "cmd":
                    pass
                break
        shown = []
        for ev in timeline:
            if ev[0] == "cmd":
                _, t0, prompt, cmd = ev
                if t < t0:
                    break
                k = min(len(cmd), int((t - t0) * cps))
                shown.append(("cmd", prompt, cmd[:k], k < len(cmd)))
            else:
                if t < ev[1]:
                    break
                shown.append(("out", ev[2]))
        key = (len(shown), shown[-1][2] if shown and shown[-1][0] == "cmd" else None, int(t * 2) % 2)
        img = base.copy()
        d = ImageDraw.Draw(img)
        vis = shown[-max_lines:]
        y = y0 + 60
        for item in vis:
            if item[0] == "cmd":
                _, prompt, text, typing = item
                d.text((x0 + 30, y), prompt, font=fb, fill=ACCENT)
                px = x0 + 30 + d.textlength(prompt + " ", font=fb)
                d.text((px, y), text, font=f, fill=(255, 255, 255))
                if typing or item is vis[-1]:
                    if int(t * 2) % 2 == 0:
                        cx = px + d.textlength(text, font=f) + 4
                        d.rectangle([cx, y + 4, cx + 14, y + lh - 6], fill=(255, 255, 255))
            else:
                line = item[1]
                if d.textlength(line, font=f) > x1 - x0 - 60:
                    while d.textlength(line + "…", font=f) > x1 - x0 - 60:
                        line = line[:-1]
                    line += "…"
                d.text((x0 + 30, y), line, font=f, fill=color(item[1]))
            y += lh
        return key, img

    total = max(dur, t + 3)
    encode_anim(frame, round(total, 1), name)
    return total


@scene
def s05_build():
    blocks = [("cloud-host$", "make up && make test", [
        "make host        stage 1: the cloud host (DNAT by interface name, mDNS, apt cache)",
        "make infra       stage 2: 5 networks + 6 VMs (Terraform, cloud-init)",
        "make ca          stage 3: step-ca, TLS 1.3 only, issuance policy",
        "make firewall    stage 4: default-drop nftables on every VM (auto-rollback)",
        "make wireguard   stage 5: keys never committed, gateway wg0, client exports",
        "make certs       stage 6: 24h SPIFFE certificates, renewal timers",
        "make services    stage 7: PostgreSQL (client cert only) + mTLS services",
        "make bot         stage 12: the statements bot in its own namespace",
        "...",
        "test-1 ... test-13: every stage tested live, in order",
    ])]
    term_scene("s05", "Tout se construit et se vérifie par étapes", "4 · Construction", prog(4), blocks, 14,
               "Une commande par étape, chacune idempotente et suivie de ses tests en direct sur les VM.")


@scene
def s06_alice():
    img = canvas()
    d = ImageDraw.Draw(img)
    header(d, "5 · Alice, sans mot de passe", prog(5))
    shot = Image.open(SCREENS / "customer-alice.png").convert("RGB")
    shot.thumbnail((1180, 900))
    img.paste(shot, (90, 120))
    d.rectangle([90, 120, 90 + shot.width, 120 + shot.height], outline=(200, 205, 200), width=2)
    x = 1330
    d.text((x, 150), "Le certificat est l'identité", font=font("Bold", 40), fill=ZT)
    y = para(d, (x, 220), "Firefox présente le certificat d'Alice pendant la poignée de main TLS : "
             "pas d'écran de connexion, pas de mot de passe.", font("Regular", 30), 520, INK)
    y = para(d, (x, y + 20), "L'identité vient du certificat seulement :", font("Regular", 30), 520, INK)
    d.text((x, y + 6), "spiffe://cloud.local/", font=mono(25), fill=ZT)
    d.text((x, y + 40), "  customer/alice", font=mono(25), fill=ZT)
    y = para(d, (x, y + 100), "La description <script>alert(1)</script> s'affiche comme du texte : CSP stricte, "
             "aucune injection.", font("Regular", 30), 520, INK)
    para(d, (x, y + 20), "Données fictives de démonstration.", font("Regular", 24), 520, MUTED)
    encode_still(img, 14, "s06")


@scene
def s07_overstep():
    out = [
        "== B4: Alice oversteps: Bob's money, forged headers, other roles, cross-site requests",
        "   [INFO                 ] Alice's own accounts: ['ZTB-ALICE-01', 'ZTB-ALICE-02']",
        "   [REFUSED (as expected)] read ZTB-BOB-01's history (IDOR)",
        "                           -> HTTP 404: account not found",
        "   [REFUSED (as expected)] transfer FROM ZTB-BOB-01 to Alice",
        "                           -> HTTP 404: unknown source account",
        "   [REFUSED (as expected)] forged identity headers (X-ZT-Customer: bob ...)",
        "                           -> still only ['ZTB-ALICE-01', 'ZTB-ALICE-02']",
        "   [REFUSED (as expected)] staff-only route /api/status",
        "                           -> HTTP 403: route status (GET /api/status) not allowed for spiffe://cloud.local/customer/alice",
        "   [REFUSED (as expected)] cross-site FORM post (classic CSRF)",
        "                           -> HTTP 415: send JSON (Content-Type: application/json)",
        "   [REFUSED (as expected)] cross-site JSON post (fetch from a malicious page)",
        "                           -> HTTP 403: cross-site request refused (cross-site)",
        "   [REFUSED (as expected)] Dev (staff) reads customer accounts",
        "                           -> HTTP 403: route accounts (GET /api/accounts) not allowed for spiffe://cloud.local/staff/dev",
    ]
    term_scene("s07", "Une cliente qui déborde (depuis le poste distant)", "6 · Moindre privilège", prog(6),
               [("remote-client$", "python3 remote-client/attack.py B4", out)], 20,
               "Le compte de Bob répond 404 comme un compte inexistant ; les en-têtes forgés sont ignorés ; le CSRF est refusé.",
               line_s=0.28)


@scene
def s08_dev():
    img = canvas()
    d = ImageDraw.Draw(img)
    header(d, "7 · Même poste, autres droits", prog(7))
    shot = Image.open(SCREENS / "staff-dev.png").convert("RGB")
    shot.thumbnail((1100, 700))
    img.paste(shot, (90, 150))
    d.rectangle([90, 150, 90 + shot.width, 150 + shot.height], outline=(200, 205, 200), width=2)
    x = 1260
    d.text((x, 170), "Dev, support", font=font("Bold", 44), fill=ZT)
    para(d, (x, 240), "Même portable, même tunnel qu'Alice — mais un autre certificat. Dev voit la santé "
         "de la banque (grand livre équilibré, compteurs, plafonds), jamais une donnée client.",
         font("Regular", 31), 560, INK)
    para(d, (x, 560), "C'est l'identité, pas le réseau, qui décide.", font("SemiBold", 32), 560, ZT)
    encode_still(img, 10, "s08")


@scene
def s09_payflow():
    out = [
        "== B5: Forged payment notification from the internet (partner API)",
        "   [REFUSED (as expected)] signed-looking webhook, NO client certificate",
        "                           -> handshake refused (tlsv13 alert certificate required)",
        "   [REFUSED (as expected)] self-signed certificate claiming PayFlow",
        "                           -> handshake refused (tlsv1 alert unknown ca)",
        "   [REFUSED (as expected)] Alice's genuine certificate on the partner API",
        "                           -> HTTP 403: identity not allowed",
        "   [REFUSED (as expected)] Alice's balance after the forged payments",
        "                           -> unchanged",
    ]
    term_scene("s09", "Faux paiements depuis Internet", "8 · Partenaire PayFlow", prog(8),
               [("remote-client$", "python3 remote-client/attack.py B5 --cloud-host <wifi>", out)], 14,
               "Le seul port publié exige le certificat du partenaire, une signature HMAC, ±300 s et un nonce à usage unique.",
               line_s=0.3)


@scene
def s10_attacks():
    out = ["collected 119 items", "...", "119 passed in 304.14s (0:05:04)", "",
           "================ attack report (build/reports/attacks.md) ================",
           "  A1   DEFENDED    Stolen laptop (Alice's certificate and key copied)",
           "  A2   DEFENDED    Compromised frontend (root on the internet-facing VM)",
           "  A3   DEFENDED    Lateral movement from the VPN",
           "  A4   DEFENDED    Forged identity",
           "  A5   DEFENDED    Reconnaissance (port scans)",
           "  A6   DEFENDED    Stolen or guessed WireGuard key",
           "  A7   DEFENDED    A customer overstepping (IDOR, forged headers, other roles' routes)",
           "  A8   DEFENDED    Cross-site request forgery",
           "  A9   DEFENDED    Forged or replayed payment notification",
           "  A10  DEFENDED    Flooding and brute force",
           "  A11  DEFENDED    Eavesdropping and downgrade",
           "  => every attack DEFENDED"]
    term_scene("s10", "Onze attaques jouées depuis le cloud host", "9 · Catalogue d'attaques", prog(9),
               [("cloud-host$", "make attacks", out)], 22,
               "Une attaque n'est DEFENDED que si tous les tests qui prouvent sa défense passent : 119 sur 119.",
               line_s=0.35)


@scene
def s11_lateral():
    out = ["== B3: VPN client turns hostile: lateral movement and address spoofing (sudo)",
           "   [INFO                 ] routing EVERY bank network into the tunnel: the gateway alone must stop us",
           "   [INFO                 ] control: the website still answers -> open",
           "   [REFUSED (as expected)] api-a@service-a 10.30.0.11:9443 through the tunnel        -> silent",
           "   [REFUSED (as expected)] api-b@service-b 10.30.0.12:9443 through the tunnel        -> silent",
           "   [REFUSED (as expected)] postgres@database 10.40.0.10:5432 through the tunnel      -> silent",
           "   [REFUSED (as expected)] step-ca@ca 10.50.0.10:9000 through the tunnel             -> silent",
           "   [REFUSED (as expected)] ssh@gateway 10.50.0.2:22 through the tunnel               -> silent",
           "   [REFUSED (as expected)] ssh@database 10.50.0.40:22 through the tunnel             -> silent",
           "   [REFUSED (as expected)] partner-api@frontend 10.20.0.10:8444 through the tunnel   -> silent",
           "   [REFUSED (as expected)] spoofing another VPN client's address 10.10.0.3          -> silent",
           "   [INFO                 ] your WireGuard routes are restored",
           "", "  B3  DEFENDED  VPN client turns hostile: lateral movement and address spoofing"]
    term_scene("s11", "Un client VPN devient hostile", "10 · Mouvement latéral", prog(10),
               [("remote-client$", "sudo python3 remote-client/attack.py B3", out)], 18,
               "Tous les réseaux internes routés dans le tunnel : seul le site répond, le reste ne renvoie rien — pas même un refus.",
               line_s=0.32)


@scene
def s12_revoke():
    """Écran partagé : le cloud host révoque, le poste distant est refusé."""
    left = [("cloud-host$", "make revoke ACTOR=alice REASON='stolen laptop'",
             ["TASK [One-time revocation token, minted on the CA]  (censored due to no_log)",
              "TASK [Revoke serial A1B13DF4…]                       changed",
              "TASK [Fetch the new CRL now]                         ok: frontend, service-a, service-b",
              ">> alice: old key set aside; 'make client-certs' issues a new key + certificate"])]
    right = ["== B6: Revocation watch: Alice's laptop is declared stolen",
             "   Alice is in. Now, on the cloud host: make revoke ACTOR=alice",
             "   polling every 5 s ...",
             "   [REFUSED (as expected)] stolen copy of Alice's certificate",
             "     -> HTTP 403: certificate A1B13DF4… of",
             "        ['spiffe://cloud.local/customer/alice'] is revoked",
             "   [INFO] reload the bank in Firefox: the same refusal",
             "", "  B6  DEFENDED"]
    f, fb = mono(23), mono(23, True)
    lh = 34
    base = canvas()
    bd = ImageDraw.Draw(base)
    header(bd, "11 · Portable volé : révocation en direct", prog(11))
    bd.text((100, 120), "Le cloud host révoque…", font=font("Bold", 40), fill=ZT)
    bd.text((990, 120), "…le poste distant est refusé", font=font("Bold", 40), fill=ZT)
    panes = [(80, 190, 940, 880), (980, 190, 1840, 880)]
    for x0, y0, x1, y1 in panes:
        bd.rounded_rectangle([x0, y0, x1, y1], radius=14, fill=TERM)
    caption(bd, "Sans redémarrage : chaque service télécharge la CRL signée chaque minute ; sans liste fraîche, tout le monde est refusé (fail-closed).")

    def frame(t, force=False):
        img = base.copy()
        d = ImageDraw.Draw(img)
        # droite : B6 attend dès le début
        y = 230
        r_lines = right[:3] if t < 9 else right[:3 + min(len(right) - 3, int((t - 9) / 0.5) + 1)]
        dots = "." * (1 + int(t * 2) % 3) if t < 9 else ""
        for i, line in enumerate(r_lines):
            if i == 2 and t < 9:
                line = "   polling every 5 s " + dots
            col = OK if ("REFUSED" in line or "DEFENDED" in line) else (ACCENT if line.startswith("==") else TERM_TXT)
            for j, part in enumerate(wrap(d, line, f, 800) or [""]):
                d.text((1000 + (40 if j else 0), y), part, font=f, fill=col)
                y += lh
        # gauche : commande tapée à t=2, sorties ensuite
        prompt, cmd, out = left[0]
        y = 230
        if t > 2:
            k = min(len(cmd), int((t - 2) * 26))
            d.text((100, y), prompt, font=fb, fill=ACCENT)
            px = 100 + d.textlength(prompt + " ", font=fb)
            d.text((px, y), cmd[:k], font=f, fill=(255, 255, 255))
            y += lh * 2
            t_out = 2 + len(cmd) / 26 + 0.6
            for i, line in enumerate(out):
                if t < t_out + i * 1.0:
                    break
                words = wrap(d, line, f, 820)
                for w_ in words:
                    d.text((100, y), w_, font=f, fill=TERM_TXT if not w_.startswith(">>") else ACCENT)
                    y += lh
        key = (int(t * 4),)
        return key, img

    encode_anim(frame, 20, "s12")


@scene
def s13_scan():
    out = ["== B1: Outsider on the Wi-Fi scans the cloud host",
           "   scanning 65535 TCP ports from outside the tunnel...",
           "   [INFO] 65535 ports in 19 s",
           "   [REFUSED (as expected)] each open port: is it a bank service?  -> no (not signed by the bank's CA)",
           "   [INFO] partner API 8444/tcp: published on purpose, presents the bank's certificate (B5)",
           "   [INFO] the cloud host's OWN services reachable from the Wi-Fi: see THREAT-MODEL, risk 2",
           "   [INFO] WireGuard (UDP 51820) is invisible to a scan: it never answers without a valid key",
           "", "  B1  DEFENDED"]
    term_scene("s13", "Reconnaissance depuis le Wi-Fi", "12 · Scan de ports", prog(12),
               [("remote-client$", "python3 remote-client/attack.py B1 --cloud-host <wifi>", out)], 14,
               "Seul le port partenaire présente le certificat de la banque. Le scan révèle aussi les services propres du portable : risque documenté.",
               line_s=0.35)


@scene
def s14_audit():
    out = ["# ZT Bank — security audit", "", "## Findings", "",
           "- none: every check above is as expected", "",
           "full report: build/reports/audit.md",
           "  1 who used the bank (requests per identity)",
           "  2 every refusal, with its reason and the real identity",
           "  3 revocation: the CRL enforced by each service",
           "  4 certificates (VMs and actors), CA activity",
           "  5 nftables drops on every VM",
           "  6 the bank's audit trail and ledger balance",
           "  7 attack reports: cloud host A1-A11, remote client B1-B6"]
    term_scene("s14", "Audit final", "13 · Audit", prog(13),
               [("cloud-host$", "make audit", out)], 13,
               "Lecture seule, aucune clé ni mot de passe affiché : aucune anomalie.", line_s=0.3)


@scene
def s15_end():
    img = canvas()
    d = ImageDraw.Draw(img)
    header(d, "14 · Bilan", prog(14))
    d.text((120, 150), "Résultat", font=font("Bold", 60), fill=ZT)
    x = 120
    x = pill(d, (x, 250), "A1–A11  DEFENDED", (255, 255, 255), OK, font("Bold", 30)) + 20
    x = pill(d, (x, 250), "B1–B6  DEFENDED", (255, 255, 255), OK, font("Bold", 30)) + 20
    x = pill(d, (x, 250), "Audit : aucune anomalie", (255, 255, 255), OK, font("Bold", 30)) + 20
    pill(d, (x, 250), "Révocation < 1 min", ZT, ZTL, font("Bold", 30))
    d.text((120, 360), "Risques résiduels, documentés", font=font("SemiBold", 40), fill=ZT)
    risks = ["un frontend compromis peut agir au nom des clients (dans leurs limites)",
             "le cloud host détient toutes les clés et expose ses propres services au Wi-Fi",
             "la VM ca ; révocation ≤ 60 s ; PostgreSQL ne lit pas la CRL",
             "pas encore post-quantique : perspective X25519MLKEM768 (TLS) et Rosenpass (WireGuard)"]
    y = 430
    for r in risks:
        d.ellipse([130, y + 14, 146, y + 30], fill=AMBER)
        d.text((170, y), r, font=font("Regular", 33), fill=INK)
        y += 62
    d.rounded_rectangle([120, 740, 1800, 960], radius=18, fill=ZT)
    d.text((170, 770), "Tout est dans le dépôt : code, documentation pas à pas, rapport LaTeX", font=font("Medium", 34),
           fill=(200, 230, 222))
    d.text((170, 830), "github.com/Yassminefeki/PQC-Cloud-Lab", font=font("Bold", 50), fill=(255, 255, 255))
    d.text((170, 905), "make up  ·  make test  ·  make attacks  ·  make audit  ·  make demo", font=mono(28),
           fill=ACCENT)
    encode_still(img, 14, "s15")


if __name__ == "__main__":
    only = set(sys.argv[1:])
    for fn in SCENES:
        if only and fn.__name__.split("_")[0] not in only:
            continue
        print("scene", fn.__name__, flush=True)
        fn()
