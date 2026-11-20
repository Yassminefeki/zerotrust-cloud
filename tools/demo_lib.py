"""Shared by the two narrated demos (tools/demo.py on the cloud host, remote-client/demo.py on the
remote client): scenes, pauses, commands shown and run, and an output SANITIZER so that nothing
recorded on screen or saved identifies the machines (user, host name, home path, Wi-Fi address,
MAC addresses). Standard library only: the remote client has nothing else installed."""
import getpass
import ipaddress
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

C = {"b": "\033[1m", "d": "\033[2m", "g": "\033[32m", "r": "\033[31m", "c": "\033[36m", "y": "\033[33m", "n": "\033[0m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}

# the virtual networks of the policy (and libvirt's NAT network): safe to show
SAFE_NETS = [ipaddress.ip_network(n) for n in
             ("10.10.0.0/24", "10.20.0.0/24", "10.30.0.0/24", "10.40.0.0/24", "10.50.0.0/24",
              "192.168.122.0/24", "127.0.0.0/8", "0.0.0.0/32")]
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5,}[0-9a-fA-F]{2}\b")


class Sanitizer:
    """Replaces what identifies the machines. `role` is how the machine is named on screen."""

    def __init__(self, role, extra=()):
        self.role = role
        home = str(Path.home())
        sudo_home = None
        if os.environ.get("SUDO_USER"):
            import pwd
            sudo_home = pwd.getpwnam(os.environ["SUDO_USER"]).pw_dir
        users = {getpass.getuser(), os.environ.get("SUDO_USER") or ""} - {"", "root"}
        names = {socket.gethostname(), socket.gethostname().split(".")[0]} - {""}
        self.rules = []
        for h in filter(None, (sudo_home, home if home != "/root" else None)):
            self.rules.append((re.compile(re.escape(h) + r"\b"), "~"))
        self.rules.append((re.compile(re.escape(str(REPO))), "<repo>"))
        for n in sorted(names, key=len, reverse=True):
            self.rules.append((re.compile(re.escape(n), re.I), role))
        for u in sorted(users, key=len, reverse=True):
            self.rules.append((re.compile(r"\b" + re.escape(u) + r"\b"), "user"))
        for x in extra:
            if x:
                self.rules.append((re.compile(re.escape(x)), "<hidden>"))

    @staticmethod
    def _ip(m):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            return m.group(0)
        return m.group(0) if any(ip in n for n in SAFE_NETS) else "<wifi-ip>"

    def __call__(self, text):
        text = text.replace(str(REPO), "<repo>")
        for rx, rep in self.rules:
            text = rx.sub(rep, text)
        text = MAC.sub("<mac>", text)
        return IPV4.sub(self._ip, text)


class Demo:
    def __init__(self, role, prompt, capture_dir, fast=False, extra_hidden=()):
        self.role, self.prompt, self.fast = role, prompt, fast
        self.clean = Sanitizer(role, extra_hidden)
        self.dir = Path(capture_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log = None

    # ------------------------------------------------------------------ scenes --
    def scene(self, sid, title, explain):
        if self.log:
            self.log.close()
        self.log = open(self.dir / f"{sid}.txt", "w")
        self.log.write(f"# {title}\n")
        bar = "─" * 78
        print(f"\n{C['c']}{bar}{C['n']}\n{C['b']}{C['c']}{sid} · {title}{C['n']}")
        for line in explain:
            print(f"  {line}")
        print(f"{C['c']}{bar}{C['n']}")

    def say(self, text):
        print(f"{C['y']}➜ {text}{C['n']}")

    def other_side(self, text):
        """An instruction for the OTHER machine (shown big, never recorded in the capture)."""
        print(f"\n{C['b']}{C['y']}  ┃ SUR L'AUTRE MACHINE : {text}{C['n']}\n")

    def pause(self, what="Entrée pour continuer"):
        if self.fast:
            return
        try:
            input(f"{C['d']}  [{what}]{C['n']} ")
        except EOFError:
            pass

    # ---------------------------------------------------------------- commands --
    def run(self, cmd, shown=None, interactive=False, check=False, env=None, cwd=REPO, color=True):
        """Show `shown` (or the command, sanitized), run it, stream its output sanitized and save it
        to the scene's capture. interactive=True: the command talks to the terminal (sudo, scp
        passwords), its output is neither captured nor sanitized — use only for silent steps."""
        text = shown or (cmd if isinstance(cmd, str) else " ".join(shlex.quote(c) for c in cmd))
        text = self.clean(text)
        print(f"{C['b']}{C['g']}{self.prompt}{C['n']} {text}")
        if self.log:
            self.log.write(f"{self.prompt} {text}\n")
        sh = isinstance(cmd, str)
        if interactive:
            return subprocess.call(cmd, shell=sh, cwd=cwd, env=env)
        p = subprocess.Popen(cmd, shell=sh, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1, errors="replace")
        for line in p.stdout:
            line = self.clean(line.rstrip("\n"))
            print(colorize(line) if color else line, flush=True)
            if self.log:
                self.log.write(re.sub(r"\033\[[0-9;]*m", "", line) + "\n")
        rc = p.wait()
        if check and rc != 0:
            print(f"{C['r']}  (la commande a échoué : {rc}){C['n']}")
        return rc

    def note(self, text):
        print(f"  {C['d']}{text}{C['n']}")
        if self.log:
            self.log.write(f"# {text}\n")

    def done(self):
        if self.log:
            self.log.close()
            self.log = None
        print(f"\n{C['g']}Démo terminée.{C['n']} Transcriptions anonymisées : {self.clean(str(self.dir))}/")
        print("Les transformer en captures PNG pour le rapport :  python3 tools/render_captures.py "
              f"{self.clean(str(self.dir))}")


def colorize(line):
    u = line.upper()
    if "BREACH" in u and "NOT" not in u:
        return f"{C['r']}{line}{C['n']}"
    if any(k in u for k in ("REFUSED", "DEFENDED", " PASSED", "NONE: EVERY")):
        return f"{C['g']}{line}{C['n']}"
    if re.search(r"HTTP (4\d\d|5\d\d)|\b(403|404|409|415|401|429)\b", line):
        return f"{C['y']}{line}{C['n']}"
    return line


def wait_s(seconds, label):
    for i in range(seconds, 0, -1):
        print(f"\r  {label} {i:3d} s ", end="", flush=True)
        time.sleep(1)
    print()
