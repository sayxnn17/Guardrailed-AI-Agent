"""SQL validator: decides whether model-written SQL may run at all.

The model's output is untrusted input. This module parses it with a real SQL parser
(sqlglot, PostgreSQL dialect) instead of pattern-matching, and accepts only:

  * exactly ONE statement, which is a plain SELECT (CTEs / UNION allowed)
  * that reads only the agent_api views (or its own CTEs)
  * and calls only allowlisted functions
  * with a bounded LIMIT (added if missing)

Everything else is rejected with a short reason that is fed back to the model.
It is one layer: the database still enforces read-only access, row-level security,
timeouts, and (via a prepared statement) single-statement execution.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import sqlglot
from sqlglot import expressions as exp
from sqlglot.errors import SqlglotError

logging.getLogger("sqlglot").setLevel(logging.ERROR)   # parser warns when it falls back to Command

MAX_SQL_CHARS = 5000

# Functions the parser does NOT know natively, that we explicitly permit. Anything unknown
# and not listed here (set_config, pg_sleep, pg_read_file, dblink, query_to_xml, ...) is rejected.
ALLOWED_UNKNOWN_FUNCTIONS = frozenset("""
age date_part date_bin to_date to_timestamp make_date make_time make_timestamp make_timestamptz isfinite
initcap char_length octet_length btrim ltrim rtrim split_part starts_with concat concat_ws left right
replace translate regexp_replace regexp_match regexp_matches regexp_split_to_array reverse format
abs ceil ceiling floor trunc mod power sqrt exp ln log sign div width_bucket
bool_and bool_or every stddev stddev_pop stddev_samp variance var_pop var_samp corr covar_pop covar_samp
percentile_cont percentile_disc mode jsonb_agg json_agg jsonb_object_agg json_object_agg
row_number rank dense_rank percent_rank cume_dist ntile lag lead first_value last_value nth_value
jsonb_array_length json_array_length jsonb_typeof json_typeof jsonb_extract_path jsonb_extract_path_text
json_extract_path_text jsonb_object_keys jsonb_each jsonb_each_text to_jsonb to_json
jsonb_build_object json_build_object jsonb_build_array json_build_array
array_length cardinality array_to_string string_to_array unnest array_position array_cat generate_series
""".split())

# Functions the parser knows natively but that either leak server/session details
# (version, current_user, ...) or can allocate huge amounts of memory (repeat, lpad, space).
_DENIED_TYPED_NAMES = ("CurrentVersion", "CurrentDatabase", "CurrentSchema", "CurrentUser",
                       "SessionUser", "CurrentCatalog", "Repeat", "Pad", "Space")
DENIED_TYPED = tuple(getattr(exp, n) for n in _DENIED_TYPED_NAMES if hasattr(exp, n))

# Anything that writes, changes schema, or controls the session.
_FORBIDDEN_NAMES = ("Insert", "Update", "Delete", "Merge", "Create", "Drop", "Alter", "AlterTable", "Command",
                    "Set", "Copy", "TruncateTable", "Grant", "Revoke", "Transaction", "Commit", "Rollback",
                    "Use", "Pragma", "Analyze", "Kill", "Declare", "Execute", "LoadData", "Refresh")
FORBIDDEN_NODES = tuple(getattr(exp, n) for n in _FORBIDDEN_NAMES if hasattr(exp, n))
_SET_OPERATION = getattr(exp, "SetOperation", exp.Union)

_UNSAFE_LEXICAL = [
    (re.compile(r"--|/\*|\*/"), "SQL comments are not allowed"),
    (re.compile(r"\$[A-Za-z_]*\$"), "dollar-quoted strings are not allowed"),
    (re.compile(r"\\"), "backslashes are not allowed"),
    (re.compile(r"(?<![A-Za-z0-9_])[eEuU]&?'"), "escape-string syntax is not allowed"),
    (re.compile(r"\x00"), "NUL characters are not allowed"),
]


@dataclass(frozen=True)
class Validation:
    ok: bool
    sql: str = ""            # the SQL to run (with LIMIT enforced) when ok
    rule: str | None = None  # machine-readable reason, used for metrics
    reason: str | None = None


def _reject(rule: str, reason: str) -> Validation:
    return Validation(False, rule=rule, reason=reason)


def validate_sql(sql: str, allowed_tables: set[str] | frozenset[str], *,
                 max_limit: int = 1000, default_limit: int = 100) -> Validation:
    sql = (sql or "").strip()
    while sql.endswith(";"):
        sql = sql[:-1].rstrip()
    if not sql:
        return _reject("empty", "the query is empty")
    if len(sql) > MAX_SQL_CHARS:
        return _reject("too_long", f"the query is longer than {MAX_SQL_CHARS} characters")
    for pattern, why in _UNSAFE_LEXICAL:
        if pattern.search(sql):
            return _reject("unsafe_syntax", why)

    try:
        statements = [s for s in sqlglot.parse(sql, read="postgres") if s is not None]
    except SqlglotError as e:
        return _reject("parse_error", f"could not parse as PostgreSQL ({str(e).splitlines()[0][:120]})")
    if not statements:
        return _reject("empty", "the query is empty")
    if len(statements) > 1:
        return _reject("multiple_statements", "only a single statement is allowed")

    root = statements[0]
    while isinstance(root, exp.Subquery):
        root = root.this
    if not isinstance(root, (exp.Select, _SET_OPERATION)):
        return _reject("not_select", f"only SELECT queries are allowed (got {type(root).__name__.upper()})")

    # --- nothing that writes, changes schema, or controls the session, even nested in a CTE
    for node in root.walk():
        if isinstance(node, FORBIDDEN_NODES):
            return _reject("not_read_only", f"{type(node).__name__.upper()} is not allowed")
    if any(root.find_all(exp.Into)):
        return _reject("select_into", "SELECT ... INTO creates a table and is not allowed")
    if any(root.find_all(exp.Lock)):
        return _reject("locking_clause", "FOR UPDATE / FOR SHARE locking is not allowed")
    for w in root.find_all(exp.With):
        if w.args.get("recursive"):
            return _reject("recursive_cte", "WITH RECURSIVE is not allowed")

    # --- tables: only agent_api views, or a CTE that is actually in scope
    allowed = {t.lower() for t in allowed_tables}
    for table in root.find_all(exp.Table):
        if not isinstance(table.this, exp.Identifier):
            continue                      # table-valued function: handled by the function check
        name, schema = table.name.lower(), (table.db or "").lower()
        if table.catalog:
            return _reject("forbidden_table", "cross-database references are not allowed")
        if schema and schema != "agent_api":
            return _reject("forbidden_table", f"schema '{schema}' is not accessible; use the listed tables only")
        if not schema and name in _visible_ctes(table):
            continue
        if name not in allowed:
            return _reject("forbidden_table", f"'{name}' is not an available table or view")

    # --- functions
    for fn in root.find_all(exp.Func):
        if isinstance(fn, exp.Anonymous):
            if isinstance(fn.parent, exp.Dot):
                return _reject("forbidden_function", f"schema-qualified function call '{fn.name}' is not allowed")
            if fn.name.lower() not in ALLOWED_UNKNOWN_FUNCTIONS:
                return _reject("forbidden_function", f"function '{fn.name}' is not allowed")
        elif DENIED_TYPED and isinstance(fn, DENIED_TYPED):
            return _reject("forbidden_function", f"function {fn.sql_name()} is not allowed")

    # --- bounded result size
    limit = root.args.get("limit")
    if limit is None:
        final = f"{sql}\nLIMIT {default_limit}"
        # belt and braces: the rewritten text must still be exactly one statement with a limit
        recheck = [s for s in sqlglot.parse(final, read="postgres") if s is not None]
        if len(recheck) != 1 or recheck[0].args.get("limit") is None:
            return _reject("internal", "could not safely add a LIMIT")
        return Validation(True, final)
    value = getattr(limit, "expression", None)
    if not isinstance(limit, exp.Limit) or not isinstance(value, exp.Literal) or value.is_string:
        return _reject("limit_not_literal", "use a plain 'LIMIT n' with a number (FETCH FIRST, LIMIT ALL and "
                                            "computed limits are not supported)")
    if int(value.name) > max_limit:
        return _reject("limit_too_large", f"LIMIT {value.name} is above the maximum of {max_limit}")
    return Validation(True, sql)


def _visible_ctes(table: exp.Table) -> set[str]:
    """CTE names this table reference can legally see (scope-aware, no self-reference)."""
    names: set[str] = set()
    node = table
    while node.parent is not None:
        parent = node.parent
        if isinstance(node, exp.CTE) and isinstance(parent, exp.With):
            # inside CTE number i: only CTEs defined before it are visible
            idx = parent.expressions.index(node)
            names |= {c.alias.lower() for c in parent.expressions[:idx]}
        elif not isinstance(node, exp.With):
            with_node = next((v for v in parent.args.values() if isinstance(v, exp.With)), None)
            if with_node is not None:       # we came up from the query body: every CTE is visible
                names |= {c.alias.lower() for c in with_node.expressions}
        node = parent
    return names
