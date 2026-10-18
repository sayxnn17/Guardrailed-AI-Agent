"""Command line interface.

    python -m sqlagent --check                    # verify DB roles, schema and Ollama
    python -m sqlagent --list-orgs                # show organizations you can act as
    python -m sqlagent --org acme-corp            # interactive chat as that organization
    python -m sqlagent --org acme-corp -q "How many users do we have?"

The organization stands in for "who is logged in". In a real deployment it comes
from authentication; here it is chosen on the command line.
"""
from __future__ import annotations

import argparse
import re
import sys
import uuid

import psycopg

from . import db
from .agent import Agent, AgentResult
from .config import Settings
from .llm import OllamaProvider

BANNER = ("Guardrails active: input guard, SQL validator, cost guard, read-only database role with "
          "row-level security.\nNot built yet: confirmation flow for changes, output redaction/validation.")


def _table(columns: list[str], rows: list[tuple], limit: int = 15, width: int = 36) -> str:
    cell = lambda v: ("" if v is None else str(v))[:width]
    data = [[cell(v) for v in r] for r in rows[:limit]]
    widths = [max([len(c)] + [len(r[i]) for r in data]) for i, c in enumerate(columns)]
    line = lambda vals: "  ".join(v.ljust(w) for v, w in zip(vals, widths))
    out = [line(columns), line(["-" * w for w in widths])] + [line(r) for r in data]
    if len(rows) > limit:
        out.append(f"... {len(rows) - limit} more rows")
    return "\n".join(out)


def _print_result(res: AgentResult, show_sql: bool = True) -> None:
    if show_sql and res.sql:
        print(f"\nSQL (attempt {res.attempts}):\n  " + res.sql.replace("\n", "\n  "))
    if res.refused:
        print(f"\n[blocked by guardrail: {res.guardrail}]  {res.answer}")
    elif res.error:
        print(f"\nCould not answer: {res.error}")
    else:
        if res.rows:
            print("\n" + _table(res.columns, res.rows))
        print(f"\n{res.answer}")
    print(f"\n[{res.latency_ms} ms | {res.prompt_tokens} prompt + {res.completion_tokens} "
          f"completion tokens | {res.attempts} attempt(s) | {res.model}]")


def _admin_connect(settings: Settings) -> psycopg.Connection:
    if not settings.admin_url:
        sys.exit("DATABASE_URL is not set. It is only used by this dev CLI to look up "
                 "organizations (a real app gets the organization from login).")
    return psycopg.connect(settings.admin_url)


def _list_orgs(settings: Settings) -> list[tuple]:
    with _admin_connect(settings) as conn, conn.cursor() as cur:
        cur.execute("""SELECT slug, name, status, country_code, org_id FROM app.organizations
                       ORDER BY slug""")
        return cur.fetchall()


def _resolve_org(settings: Settings, arg: str) -> str:
    try:
        return str(uuid.UUID(arg))
    except ValueError:
        pass
    with _admin_connect(settings) as conn, conn.cursor() as cur:
        cur.execute("SELECT org_id FROM app.organizations WHERE slug = %s", (arg,))
        row = cur.fetchone()
    if not row:
        sys.exit(f"No organization with slug '{arg}'. Try: python -m sqlagent --list-orgs")
    return str(row[0])


def check(settings: Settings) -> int:
    ok_all = True

    def report(ok: bool, msg: str, hint: str = "") -> None:
        nonlocal ok_all
        ok_all &= ok
        print(f"[{'OK' if ok else 'FAIL'}] {msg}" + (f"\n       -> {hint}" if (hint and not ok) else ""))

    try:
        conn = db.connect(settings, "agent_reader")
        report(True, f"logged in as agent_reader on {settings.db_host}:{settings.db_port}/{settings.db_name}")
    except psycopg.Error as e:
        report(False, f"cannot log in as agent_reader: {str(e).strip().splitlines()[0]}",
               "Run 002_security.sql on this database, and check DB_HOST / DB_PORT / DB_NAME / "
               "AGENT_READER_PASSWORD in .env")
        conn = None
    if conn:
        try:
            n = len({c["table"] for c in db.load_schema_catalog(conn)})
            report(n >= 12, f"agent_api exposes {n} views", "Run 002_security.sql on this database")
        except db.QueryError as e:
            report(False, str(e))
        try:
            cols, rows, _ = db.run_query(conn, "SELECT count(*) FROM users",
                                         "00000000-0000-0000-0000-000000000000", 10)
            report(rows[0][0] == 0, "no tenant data visible without a valid organization (RLS fails closed)")
        except db.QueryError as e:
            report(False, f"RLS check failed: {e}")
        try:
            # RETURNING makes a (wrongly) permitted DELETE come back as a result set,
            # so only a genuine database refusal lands in the except branch.
            db.run_query(conn, "DELETE FROM users RETURNING 1",
                         "00000000-0000-0000-0000-000000000000", 10)
            report(False, "DELETE was allowed for agent_reader - security is NOT set up correctly")
        except db.QueryError:
            report(True, "agent_reader cannot write (DELETE is refused by the database)")
        conn.close()
    ok, msg = OllamaProvider(settings.ollama_url, settings.ollama_model).check()
    report(ok, msg)
    return 0 if ok_all else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sqlagent", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", default="acme-corp", help="organization slug or UUID to act as")
    ap.add_argument("-q", "--question", help="ask one question and exit")
    ap.add_argument("--check", action="store_true", help="verify setup and exit")
    ap.add_argument("--list-orgs", action="store_true", help="list organizations and exit")
    ap.add_argument("--hide-sql", action="store_true", help="do not print the generated SQL")
    args = ap.parse_args(argv)
    settings = Settings.from_env()

    if args.check:
        return check(settings)
    if args.list_orgs:
        for slug, name, status, country, org_id in _list_orgs(settings):
            print(f"{slug:<28} {status:<10} {country}  {org_id}  {name}")
        return 0

    org_id = _resolve_org(settings, args.org)
    agent = Agent(settings, OllamaProvider(settings.ollama_url, settings.ollama_model))
    print(BANNER)
    try:
        if args.question:
            _print_result(agent.ask(args.question, org_id), not args.hide_sql)
            return 0
        print(f"Acting as organization {args.org}. Ask a question, or type /quit.\n")
        while True:
            try:
                q = input("you> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not q:
                continue
            if q in ("/quit", "/exit", "quit", "exit"):
                break
            _print_result(agent.ask(q, org_id), not args.hide_sql)
            print()
    finally:
        agent.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
