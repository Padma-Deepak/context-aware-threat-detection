"""
Database connection module for the security-investigation MCP server.

Phase 5: data.py's accessor functions now query PostgreSQL (schema in
db/schema.sql, seed data in db/seed.sql) instead of in-memory dicts. This
module owns the connection pool and is the only place that talks to
psycopg2 directly.

Requires the DATABASE_URL environment variable, e.g.:
    postgresql://user:password@localhost:5432/secinvest

Importing this module with DATABASE_URL unset fails immediately with a
clear error, rather than deferring to a cryptic connection error the
first time a query actually runs.
"""

import os
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
import psycopg2.pool

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is not set.\n"
        "mcp_server/db.py requires a PostgreSQL connection string, e.g.:\n"
        "    export DATABASE_URL='postgresql://user:password@localhost:5432/secinvest'\n"
        "Apply db/schema.sql and db/seed.sql to that database before running the server."
    )

_pool = psycopg2.pool.SimpleConnectionPool(1, 10, dsn=DATABASE_URL)


@contextmanager
def get_cursor():
    """Yield a RealDictCursor backed by a pooled connection.

    Commits on clean exit, rolls back on exception, and always returns
    the connection to the pool.
    """
    conn = _pool.getconn()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                yield cur
    finally:
        _pool.putconn(conn)


def close_pool():
    """Close all pooled connections. Mainly useful for clean test teardown."""
    _pool.closeall()
