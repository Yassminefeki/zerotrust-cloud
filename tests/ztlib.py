"""Helpers for live tests."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"


def run(cmd, sudo=False, check=False, timeout=30):
    """Run a command; with sudo=True uses `sudo -n` (Makefile primes sudo with `sudo -v`)."""
    if isinstance(cmd, str):
        cmd = ["bash", "-c", cmd]
    if sudo:
        cmd = ["sudo", "-n"] + cmd
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise AssertionError(f"{cmd} failed ({r.returncode}):\n{r.stdout}\n{r.stderr}")
    return r


def need(binary):
    if not shutil.which(binary):
        pytest.fail(f"{binary} not installed (run `make host`)")
