"""Read-only SQL access to one ExCyTIn incident database, shaped for an LLM.

Three layers of protection, because the agent writes the SQL:
  1. the MySQL user only has SELECT (see setup_db.py),
  2. a statement allow-list here (SELECT / SHOW / DESCRIBE / EXPLAIN / WITH, one statement),
  3. a server-side execution timeout (--max-execution-time in the compose file).

Results are capped (rows and characters) so one careless ``SELECT *`` cannot flood the context
window. The cap is reported to the model ("showing 15 of >15 rows") so it knows to filter.
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field

_ALLOWED = re.compile(r"^\s*(select|show|describe|desc|explain|with)\b", re.IGNORECASE)
_COMMENTS = re.compile(r"(--[^\n]*|#[^\n]*|/\*.*?\*/)", re.DOTALL)
MAX_ROWS = int(os.getenv("TRIAGE_MAX_ROWS", "15"))
MAX_CELL = int(os.getenv("TRIAGE_MAX_CELL", "1200"))
MAX_CHARS = int(os.getenv("TRIAGE_MAX_RESULT_CHARS", "8000"))


@dataclass
class SQLResult:
    query: str
    columns: list = field(default_factory=list)
    rows: list = field(default_factory=list)  # list[dict], cells truncated for the prompt
    full_rows: list = field(default_factory=list)  # same rows untruncated: what memory indexes
    truncated: bool = False  # more rows existed than were returned
    error: str | None = None

    def render(self, max_chars: int = MAX_CHARS) -> str:
        if self.error:
            return f"SQL error: {self.error}"
        if not self.rows:
            return "0 rows."
        more = f" of more than {len(self.rows)}" if self.truncated else ""
        lines = [f"{len(self.rows)}{more} rows. Columns: {', '.join(self.columns)}"]
        used = len(lines[0])
        for i, row in enumerate(self.rows):
            line = json.dumps(row, ensure_ascii=False, default=str)
            if used + len(line) > max_chars:
                lines.append(f"... {len(self.rows) - i} more rows hidden (result too long; select fewer columns)")
                break
            lines.append(line)
            used += len(line) + 1
        return "\n".join(lines)


def check_query(query: str) -> str | None:
    """Return an error message if the query is not an allowed single read-only statement."""
    stripped = _COMMENTS.sub(" ", query or "").strip().rstrip(";").strip()
    if not stripped:
        return "empty query"
    if ";" in stripped:
        return "only one statement per call"
    if not _ALLOWED.match(stripped):
        return "only SELECT, SHOW, DESCRIBE, EXPLAIN or WITH queries are allowed"
    if re.search(r"\binto\s+(outfile|dumpfile)\b|\bload_file\s*\(|\bsleep\s*\(|\bbenchmark\s*\(", stripped, re.I):
        return "this query uses a disallowed function"
    return None


def _plain(value):
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return value


def _cell(value):
    if isinstance(value, str) and len(value) > MAX_CELL:
        return value[:MAX_CELL] + f"...[+{len(value) - MAX_CELL} chars]"
    return value


class IncidentDB:
    """One incident database. ``connect`` is a zero-arg factory returning a DB-API connection,
    so tests can pass ``sqlite3.connect(":memory:")``."""

    def __init__(self, incident: int | str, connect=None, max_rows: int = MAX_ROWS):
        self.incident = int(str(incident).replace("incident_", ""))
        self.name = f"incident_{self.incident}"
        self.max_rows = max_rows
        self._connect = connect or self._mysql_factory()
        self._local = threading.local()
        self._tables = None

    def _mysql_factory(self):
        def connect():
            import mysql.connector

            return mysql.connector.connect(
                host=os.getenv("EXCYTIN_HOST", "127.0.0.1"),
                port=int(os.getenv("EXCYTIN_PORT", "3316")),
                user=os.getenv("EXCYTIN_USER", "reader"),
                password=os.getenv("EXCYTIN_PASSWORD", "reader"),
                database=self.name,
                connection_timeout=10,
                autocommit=True,
            )

        return connect

    def _conn(self):
        # One connection per thread: the runner investigates incidents concurrently.
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._local.conn = self._connect()
        return conn

    def run(self, query: str, params=None) -> SQLResult:
        problem = check_query(query)
        if problem:
            return SQLResult(query=query, error=problem)
        try:
            cur = self._conn().cursor()
            cur.execute(query, params) if params else cur.execute(query)
            columns = [d[0] for d in (cur.description or [])]
            fetched = cur.fetchmany(self.max_rows + 1) if columns else []
            try:
                cur.fetchall()  # drain so the connection is reusable
            except Exception:
                pass
            cur.close()
        except Exception as exc:  # the model sees the error and can fix its SQL
            self._reset_on_disconnect(exc)
            return SQLResult(query=query, error=f"{exc.__class__.__name__}: {exc}"[:500])
        kept = fetched[: self.max_rows]
        full = [{c: _plain(v) for c, v in zip(columns, r)} for r in kept]
        rows = [{c: _cell(v) for c, v in row.items()} for row in full]
        return SQLResult(query=query, columns=columns, rows=rows, full_rows=full, truncated=len(fetched) > self.max_rows)

    @property
    def placeholder(self) -> str:
        """Parameter marker for this connection's driver ('%s' for MySQL, '?' for sqlite)."""
        return "?" if "sqlite" in type(self._conn()).__module__ else "%s"

    def _reset_on_disconnect(self, exc):
        if "connection" in str(exc).lower() or "gone away" in str(exc).lower():
            self._local.conn = None

    def tables(self) -> list[str]:
        if self._tables is None:
            res = self.run("SHOW TABLES")
            if res.error:  # sqlite (tests) has no SHOW TABLES
                cur = self._conn().cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                self._tables = [r[0] for r in cur.fetchall()]
            else:
                self._tables = sorted(next(iter(r.values())) for r in res.rows) if res.rows else []
                if res.truncated:  # SHOW TABLES must not be capped
                    cur = self._conn().cursor()
                    cur.execute("SHOW TABLES")
                    self._tables = sorted(r[0] for r in cur.fetchall())
        return self._tables

    def schema_text(self) -> str:
        """Every table with its exact column names, one per line. Giving this to the agent up front removes
        schema guessing (the most common failure in the main run was 'Unknown column')."""
        if getattr(self, "_schema_text", None) is None:
            self._schema_text = "\n".join(self.describe(t) for t in self.tables())
        return self._schema_text

    def describe(self, table: str) -> str:
        if table not in self.tables():
            return f"Unknown table {table!r}. Tables: {', '.join(self.tables())}"
        cur = self._conn().cursor()
        try:
            cur.execute(f"SELECT * FROM `{table}` LIMIT 0")
        except Exception:
            cur.execute(f'SELECT * FROM "{table}" LIMIT 0')
        cols = [d[0] for d in cur.description]
        cur.fetchall()
        cur.close()
        return f"{table}: " + ", ".join(cols)
