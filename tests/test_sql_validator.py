"""SQL validator tests. Pure Python: no database, no model."""
from __future__ import annotations

import re

import pytest

from sqlagent.guardrails import validate_sql
from sqlagent.prompt import SQL_SYSTEM

VIEWS = {"organizations", "users", "plans", "roles", "user_roles", "subscriptions", "invoices",
         "invoice_items", "payment_methods", "usage_events", "monthly_usage", "monthly_revenue"}


def check(sql, **kw):
    return validate_sql(sql, VIEWS, **kw)


VALID = [
    "SELECT count(*) FROM users",
    "SELECT * FROM agent_api.users",
    "SELECT status, count(*) FROM users GROUP BY status ORDER BY 2 DESC",
    "SELECT u.full_name FROM users u JOIN user_roles ur ON ur.user_id = u.user_id "
    "JOIN roles r ON r.role_id = ur.role_id WHERE r.name = 'admin'",
    "SELECT date_trunc('month', issued_at) AS m, sum(amount_cents) / 100.0 FROM invoices "
    "WHERE status = 'paid' GROUP BY 1 ORDER BY 1",
    "SELECT metadata->>'endpoint' AS ep, count(*) FROM usage_events "
    "WHERE occurred_at >= now() - interval '30 days' GROUP BY 1",
    "SELECT count(*) FILTER (WHERE status = 'active') AS a FROM users",
    "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY amount_cents) FROM invoices",
    "WITH t AS (SELECT * FROM users WHERE status = 'active') SELECT count(*) FROM t",
    "WITH a AS (SELECT user_id FROM users), b AS (SELECT user_id FROM a) SELECT count(*) FROM b",
    "SELECT email FROM users WHERE email ILIKE '%@acme.example' AND full_name LIKE 'A%'",
    "SELECT user_id FROM users UNION SELECT user_id FROM user_roles",
    "SELECT coalesce(phone, 'n/a'), length(full_name), lower(email) FROM users",
    "SELECT to_char(issued_at, 'YYYY-MM') FROM invoices",
    "SELECT * FROM (SELECT status, count(*) c FROM invoices GROUP BY status) s WHERE c > 1",
    "SELECT 'UNANSWERABLE' AS answer",
    "SELECT row_number() OVER (ORDER BY issued_at DESC), invoice_number FROM invoices",
    "SELECT * FROM users LIMIT 10",
    "SELECT * FROM users;",
]


@pytest.mark.parametrize("sql", VALID)
def test_valid_queries_are_accepted(sql):
    v = check(sql)
    assert v.ok, (v.rule, v.reason)


def test_every_example_in_the_prompt_passes_our_own_validator():
    examples = re.findall(r"```sql\n(.*?)```", SQL_SYSTEM, re.S)
    assert len(examples) >= 4
    for sql in examples:
        v = check(sql)
        assert v.ok, (sql, v.rule, v.reason)


INVALID = [
    # -- not a single read-only SELECT
    ("SELECT 1; DROP TABLE users", "multiple_statements"),
    ("SELECT 1; SELECT 2", "multiple_statements"),
    ("DELETE FROM users", "not_select"),
    ("UPDATE users SET status = 'active'", "not_select"),
    ("INSERT INTO plans (code) VALUES ('x')", "not_select"),
    ("DROP TABLE users", "not_select"),
    ("TRUNCATE invoices", "not_select"),
    ("SET app.current_org_id = '00000000-0000-0000-0000-000000000000'", "not_select"),
    ("COPY (SELECT 1) TO PROGRAM 'id'", "not_select"),
    ("DO $$ BEGIN PERFORM 1; END $$", "unsafe_syntax"),
    ("EXPLAIN ANALYZE DELETE FROM users", "not_select"),
    ("GRANT ALL ON users TO public", "not_select"),
    ("WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d", "not_read_only"),
    ("WITH u AS (UPDATE users SET status = 'x' RETURNING *) SELECT * FROM u", "not_read_only"),
    ("SELECT * INTO newtable FROM users", "select_into"),
    ("SELECT * FROM users FOR UPDATE", "locking_clause"),
    ("WITH RECURSIVE r AS (SELECT 1 UNION ALL SELECT 1 FROM r) SELECT * FROM r", "recursive_cte"),
    # -- tables outside agent_api
    ("SELECT * FROM app.users", "forbidden_table"),
    ("SELECT password_hash FROM app.users", "forbidden_table"),
    ("SELECT * FROM app.agent_audit_log", "forbidden_table"),
    ("SELECT * FROM pg_catalog.pg_roles", "forbidden_table"),
    ("SELECT * FROM information_schema.tables", "forbidden_table"),
    ("SELECT * FROM pg_shadow", "forbidden_table"),
    ("SELECT * FROM schema_catalog", "forbidden_table"),
    ("SELECT * FROM users u, pg_class c", "forbidden_table"),
    ("SELECT * FROM users WHERE user_id IN (SELECT oid FROM pg_authid)", "forbidden_table"),
    ("SELECT * FROM otherdb.public.users", "forbidden_table"),
    ("WITH pg_shadow AS (SELECT * FROM pg_shadow) SELECT * FROM pg_shadow", "forbidden_table"),
    # -- functions
    ("SELECT set_config('app.current_org_id', 'x', true)", "forbidden_function"),
    ("SELECT pg_sleep(10)", "forbidden_function"),
    ("SELECT * FROM users WHERE pg_sleep(1) IS NULL", "forbidden_function"),
    ("SELECT pg_read_file('/etc/passwd')", "forbidden_function"),
    ("SELECT * FROM pg_ls_dir('/')", "forbidden_function"),
    ("SELECT query_to_xml('delete from users', true, true, '')", "forbidden_function"),
    ("SELECT current_setting('app.current_org_id')", "forbidden_function"),
    ("SELECT version()", "forbidden_function"),
    ("SELECT current_user", "forbidden_function"),
    ("SELECT current_database()", "forbidden_function"),
    ("SELECT dblink('host=evil', 'select 1')", "forbidden_function"),
    ("SELECT pg_terminate_backend(1)", "forbidden_function"),
    ("SELECT lo_import('/etc/passwd')", "forbidden_function"),
    ("SELECT nextval('s')", "forbidden_function"),
    ("SELECT app.current_org()", "forbidden_function"),
    ("SELECT repeat('a', 1000000000)", "forbidden_function"),
    ("SELECT lpad('a', 1000000000, 'b')", "forbidden_function"),
    ("SELECT rpad('a', 1000000000, 'b')", "forbidden_function"),
    ("SELECT space(1000000000)", "forbidden_function"),
    ("SELECT pg_catalog.pg_sleep(1)", "forbidden_function"),
    # -- parser-differential tricks and hidden syntax
    ("SELECT 1 -- ; DROP TABLE users", "unsafe_syntax"),
    ("SELECT 1 /* x */", "unsafe_syntax"),
    ("SELECT 'a\\' ; DROP TABLE users; --'", "unsafe_syntax"),
    ("SELECT E'a\\'b'", "unsafe_syntax"),
    ("SELECT $$x$$", "unsafe_syntax"),
    ("SELECT $tag$x$tag$", "unsafe_syntax"),
    # -- shape
    ("", "empty"),
    ("   ;  ", "empty"),
    ("this is not sql at all", "parse_error"),
    ("SELECT * FROM users LIMIT 100000", "limit_too_large"),
    ("SELECT * FROM users LIMIT (SELECT 5)", "limit_not_literal"),
    ("SELECT " + ", ".join(["1"] * 3000), "too_long"),
]


@pytest.mark.parametrize("sql,rule", INVALID)
def test_invalid_queries_are_rejected_with_the_right_rule(sql, rule):
    v = check(sql)
    assert not v.ok, f"should have been rejected: {sql!r}"
    assert v.rule == rule, (v.rule, v.reason)
    assert v.reason


def test_limit_is_added_when_missing():
    v = check("SELECT * FROM users")
    assert v.ok and v.sql.rstrip().endswith("LIMIT 100")


def test_limit_is_added_to_a_union_exactly_once():
    v = check("SELECT user_id FROM users UNION SELECT user_id FROM user_roles ORDER BY 1")
    assert v.ok and v.sql.count("LIMIT") == 1


def test_existing_limit_is_kept():
    assert check("SELECT * FROM users LIMIT 7").sql == "SELECT * FROM users LIMIT 7"


def test_limit_at_the_maximum_is_allowed_and_custom_defaults_apply():
    assert check("SELECT * FROM users LIMIT 1000").ok
    assert check("SELECT * FROM users", default_limit=5, max_limit=10).sql.endswith("LIMIT 5")
    assert check("SELECT * FROM users LIMIT 11", max_limit=10).rule == "limit_too_large"


def test_a_cte_in_scope_is_allowed_but_a_forward_reference_is_not():
    assert check("WITH a AS (SELECT 1 AS x), b AS (SELECT x FROM a) SELECT * FROM b").ok
    assert check("WITH b AS (SELECT x FROM a), a AS (SELECT 1 AS x) SELECT * FROM b").rule == "forbidden_table"
