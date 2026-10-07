"""Fail if anything shaped like a real API key is committed (one was found in agent/.env.example once)."""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY = re.compile(r"(sk-(proj-)?[A-Za-z0-9_\-]{30,}|sk-ant-[A-Za-z0-9_\-]{30,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,})")


def test_no_api_keys_in_tracked_files():
    try:
        files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        files = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file() and ".venv" not in p.parts]
    leaks = []
    for name in files:
        path = ROOT / name
        if path.suffix in {".sqlite", ".png", ".gif", ".jpg"} or not path.is_file():
            continue
        for match in KEY.finditer(path.read_text(errors="ignore")):
            leaks.append(f"{name}: {match.group(0)[:12]}...")
    assert not leaks, leaks
