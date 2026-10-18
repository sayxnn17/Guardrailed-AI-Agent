"""Database access for the agent's query path.

Everything here connects as the least-privilege `agent_reader` role. The
database itself (grants, row-level security, read-only default, timeout)
is what makes this safe; the Python layers added later are extra, not the only defense.
"""
from __future__ import annotations

import json

import psycopg

from .config import Settings


class QueryError(Exception):
    """The database rejected or failed the query. The message is safe to show the LLM."""


def connect(settings: Settings, role: str = "agent_reader") -> psycopg.Connection:
    # A fresh login each time, so role-level settings (statement_timeout etc.) apply.
    return psycopg.connect(settings.conninfo(role))


def load_schema_catalog(conn: psycopg.Connection) -> list[dict]:
    """What the LLM is told about the data: the agent_api views, columns and comments."""
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT table_name, column_name, data_type, table_comment, column_comment
                           FROM agent_api.schema_catalog""")
            rows = cur.fetchall()
    except psycopg.Error as e:
        conn.rollback()
        raise QueryError(f"cannot read agent_api.schema_catalog ({_msg(e)}). "
                         f"Has 002_security.sql been run on this database?") from e
    finally:
        conn.rollback()
    return [dict(zip(["table", "column", "type", "table_comment", "column_comment"], r)) for r in rows]


def run_query(conn: psycopg.Connection, sql: str, org_id: str, max_rows: int):
    """Run `sql` as the tenant `org_id`. Returns (columns, rows, truncated).

    The tenant is set for this transaction only; the transaction is always rolled back,
    so nothing the query does can persist.
    """
    if not sql.strip():
        raise QueryError("the model returned an empty query")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.current_org_id', %s, true)", (str(org_id),))
            # prepare=True makes the SERVER refuse multi-statement SQL ("cannot insert multiple
            # commands into a prepared statement"), independent of any Python-side parser.
            cur.execute(sql, prepare=True)
            if cur.description is None:
                raise QueryError("the statement did not return a result set")
            columns = [d.name for d in cur.description]
            rows = cur.fetchmany(max_rows + 1)
    except psycopg.Error as e:
        raise QueryError(_msg(e)) from e
    finally:
        conn.rollback()
    truncated = len(rows) > max_rows
    return columns, rows[:max_rows], truncated


def plan_cost(conn: psycopg.Connection, sql: str, org_id: str) -> float:
    """The planner's estimated total cost for `sql`, without running it (EXPLAIN, no ANALYZE).

    Used as a cost guard: a query that would scan enormous amounts of data is refused
    before it runs, instead of waiting for the timeout to kill it.
    """
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.current_org_id', %s, true)", (str(org_id),))
            cur.execute("EXPLAIN (FORMAT JSON) " + sql, prepare=True)
            plan = cur.fetchone()[0]
    except psycopg.Error as e:
        raise QueryError(_msg(e)) from e
    finally:
        conn.rollback()
    if isinstance(plan, str):
        plan = json.loads(plan)
    return float(plan[0]["Plan"]["Total Cost"])


def _msg(e: psycopg.Error) -> str:
    diag = getattr(e, "diag", None)
    return (getattr(diag, "message_primary", None) or str(e)).strip()
