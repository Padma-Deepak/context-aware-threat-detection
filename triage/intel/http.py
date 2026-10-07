"""Cached HTTP for intel feeds. Same modes as the LLM cache: readwrite (default), replay, off."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class IntelCacheMiss(RuntimeError):
    pass


class HttpCache:
    def __init__(self, path=None, mode=None):
        self.mode = mode or os.getenv("TRIAGE_INTEL_CACHE", "readwrite")
        path = path or os.getenv("TRIAGE_INTEL_CACHE_PATH", str(ROOT / ".intel_cache" / "http.sqlite"))
        self._lock = threading.Lock()
        if self.mode != "off":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(str(path), check_same_thread=False)
            self.db.execute("CREATE TABLE IF NOT EXISTS http (key TEXT PRIMARY KEY, status INT, body TEXT, fetched REAL)")

    @staticmethod
    def key(method, url, body=None):
        return hashlib.sha256(json.dumps([method, url, body], sort_keys=True).encode()).hexdigest()

    def request(self, method: str, url: str, *, headers=None, params=None, json_body=None, max_age=None,
                timeout=30.0) -> tuple[int, str]:
        full = url + ("?" + "&".join(f"{k}={v}" for k, v in sorted((params or {}).items())) if params else "")
        k = self.key(method, full, json_body)
        if self.mode != "off":
            with self._lock:
                row = self.db.execute("SELECT status, body, fetched FROM http WHERE key = ?", (k,)).fetchone()
            if row and (self.mode == "replay" or max_age is None or time.time() - row[2] < max_age):
                return row[0], row[1]
            if self.mode == "replay":
                raise IntelCacheMiss(f"{method} {full} not recorded (TRIAGE_INTEL_CACHE=replay)")
        import httpx

        resp = httpx.request(method, url, headers=headers, params=params, json=json_body, timeout=timeout,
                             follow_redirects=True)
        if self.mode != "off" and resp.status_code < 500 and resp.status_code != 429:
            with self._lock:
                self.db.execute("INSERT OR REPLACE INTO http VALUES (?,?,?,?)", (k, resp.status_code, resp.text, time.time()))
                self.db.commit()
        return resp.status_code, resp.text


_CACHE = None


def cache() -> HttpCache:
    global _CACHE
    if _CACHE is None:
        _CACHE = HttpCache()
    return _CACHE
