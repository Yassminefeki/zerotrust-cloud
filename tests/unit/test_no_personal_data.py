"""The repository is public: nothing in it may identify the machines or the people who ran it,
and no secret may ever be committed. Checked on every file Git tracks (or would track)."""
import re
import subprocess

import pytest

from unit_helpers import ROOT

PATTERNS = {
    "home directory of a user": re.compile(r"/home/(?!<|user\b|\$|ubuntu\b)[a-z][a-z0-9._-]+"),
    "MAC address": re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I),
    "e-mail address": re.compile(r"\b[\w.+-]+@(?!example\.|anthropic\.com)[\w-]+\.(?!(?:service|timer|socket|target|mount|path)\b)[a-z]{2,}\b", re.I),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "WireGuard key value": re.compile(r"(?:PrivateKey|PresharedKey)\s*=\s*[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]{2}"),
    "home-LAN address": re.compile(r"\b(?:192\.168\.(?!122\.)\d{1,3}|10\.(?!(?:10|20|30|40|50)\.0\.)\d{1,3}\.\d{1,3})\.\d{1,3}\b"),
}
SKIP_SUFFIXES = (".png", ".jpg", ".pdf", ".mp4", ".ico")


def tracked():
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.split()
        if out:
            return [ROOT / f for f in out]
    except (OSError, subprocess.CalledProcessError):
        pass
    ignored = (".venv", "build", ".secrets", "__pycache__", ".git", ".pytest_cache", ".terraform")
    return [p for p in ROOT.rglob("*") if p.is_file() and not any(x in p.parts for x in ignored)
            and p.name != "env.yaml"]


@pytest.mark.parametrize("what", sorted(PATTERNS))
def test_no_personal_or_secret_data_in_the_repository(what):
    hits = []
    for f in tracked():
        if f.suffix in SKIP_SUFFIXES or not f.is_file():
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if PATTERNS[what].search(line) and "noqa: personal-data" not in line:
                hits.append(f"{f.relative_to(ROOT)}:{n}")
    assert not hits, f"{what} found (location only, content not shown): {hits[:10]}"
