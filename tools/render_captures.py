#!/usr/bin/env python3
"""Turn the demo transcripts (already anonymised by the demo scripts) into terminal-style PNG
captures for the report.

    python3 tools/render_captures.py build/demo/cloud-host            -> docs/screens/demo/cloud-host-C1.png …
    python3 tools/render_captures.py ~/zt-demo-captures --prefix remote-client

Needs Pillow (Ubuntu: sudo apt install python3-pil). The text is sanitised AGAIN before drawing,
so a transcript edited by hand cannot leak a host name or a Wi-Fi address into the report.
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_lib import REPO, Sanitizer  # noqa: E402

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    sys.exit("Pillow is missing: sudo apt install python3-pil   (or .venv/bin/pip install pillow)")

FONTS = ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/usr/share/fonts/TTF/DejaVuSansMono.ttf"]
BG, FG, DIM, GREEN, RED, YELLOW, CYAN, TITLE = ((14, 22, 24), (214, 224, 220), (120, 140, 136), (90, 200, 130),
                                                 (235, 95, 85), (235, 190, 90), (110, 210, 190), (255, 255, 255))


def load_font(size):
    for f in FONTS:
        if Path(f).exists():
            return ImageFont.truetype(f, size), ImageFont.truetype(f.replace("Mono.ttf", "Mono-Bold.ttf"), size) \
                if Path(f.replace("Mono.ttf", "Mono-Bold.ttf")).exists() else ImageFont.truetype(f, size)
    d = ImageFont.load_default()
    return d, d


def color(line, prompt):
    u = line.upper()
    if line.startswith(prompt):
        return None
    if "BREACH" in u and "NOT" not in u:
        return RED
    if any(k in u for k in ("REFUSED", "DEFENDED", " PASSED", "NONE: EVERY")):
        return GREEN
    if re.search(r"HTTP (4\d\d|5\d\d)", line):
        return YELLOW
    if line.startswith("#") or line.startswith("=="):
        return CYAN
    if line.strip().startswith("->"):
        return DIM
    return FG


def render(txt, out, width_chars=110, size=20, prompt="$"):
    lines = txt.read_text(errors="replace").splitlines()
    title = lines[0].lstrip("# ").strip() if lines and lines[0].startswith("# ") else txt.stem
    body = lines[1:] if lines and lines[0].startswith("# ") else lines
    wrapped = []
    for l in body:
        l = l.replace("\t", "    ")
        while len(l) > width_chars:
            wrapped.append(l[:width_chars])
            l = "    " + l[width_chars:]
        wrapped.append(l)
    wrapped = wrapped[:60] + (["…"] if len(wrapped) > 60 else [])
    f, fb = load_font(size)
    cw = f.getlength("M")
    lh = int(size * 1.45)
    w = int(cw * width_chars) + 60
    h = 70 + lh * max(len(wrapped), 1) + 30
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    for i, c in enumerate([(237, 106, 94), (245, 191, 79), (98, 197, 84)]):
        d.ellipse([20 + i * 26, 18, 34 + i * 26, 32], fill=c)
    d.text((110, 14), title, font=fb, fill=TITLE)
    y = 60
    for l in wrapped:
        col = color(l, prompt)
        if col is None:
            p, _, rest = l.partition(" ")
            d.text((30, y), p, font=fb, fill=CYAN)
            d.text((30 + f.getlength(p + " "), y), rest, font=f, fill=TITLE)
        else:
            d.text((30, y), l, font=f, fill=col)
        y += lh
    img.save(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--prefix", help="cloud-host or remote-client (default: from the folder's name)")
    ap.add_argument("--out", default=str(REPO / "docs/screens/demo"))
    a = ap.parse_args()
    src = Path(a.folder).expanduser()
    prefix = a.prefix or ("remote-client" if "remote" in src.name or "zt-demo-captures" in src.name else src.name)
    clean = Sanitizer(prefix)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    files = sorted(src.glob("*.txt"))
    if not files:
        sys.exit(f"no transcript (*.txt) in {src}")
    for t in files:
        tmp = out / f".{t.stem}.txt"
        tmp.write_text(clean(t.read_text(errors="replace")))
        dst = out / f"{prefix}-{t.stem}.png"
        render(tmp, dst, prompt=f"{prefix}$")
        tmp.unlink()
        print(f"  {dst.relative_to(REPO) if dst.is_relative_to(REPO) else dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
