"""Builds the messages sent to the LLM."""
from __future__ import annotations

import json
import re
from datetime import date

from .llm import Message

SQL_SYSTEM = """You are a careful PostgreSQL expert. Translate the user's question into ONE read-only SQL query.

Rules:
- Output ONLY the SQL inside a ```sql code block. No explanation.
- Use only the tables/views listed below, by bare name (e.g. users, invoices). Never use a schema prefix.
- Write a single SELECT (CTEs are fine). Never write INSERT, UPDATE, DELETE, DDL, SET, or several statements.
- Rows are automatically limited to the current organization. Do NOT filter on org_id.
- Columns ending in _cents are cents: divide by 100.0 to show dollars.
- usage_events is huge: always filter on occurred_at. For monthly totals prefer monthly_usage and monthly_revenue.
- Add LIMIT 100 unless the question is a count or an aggregate.
- Use status values exactly as documented in the column comments.
- If the question cannot be answered from these tables, return exactly: SELECT 'UNANSWERABLE' AS answer;
- Today's date is {today}.

Examples:
Q: How many users are active?
```sql
SELECT count(*) AS active_users FROM users WHERE status = 'active';
```
Q: What was our paid revenue in each of the last 3 months?
```sql
SELECT month, paid_cents / 100.0 AS paid_usd FROM monthly_revenue
WHERE month >= date_trunc('month', CURRENT_DATE) - interval '3 months' ORDER BY month;
```
Q: Which invoices are overdue?
```sql
SELECT invoice_number, amount_cents / 100.0 AS amount_usd, due_at FROM invoices
WHERE status = 'open' AND due_at < now() ORDER BY due_at LIMIT 100;
```
Q: Who are the admins?
```sql
SELECT u.full_name, u.email FROM users u
JOIN user_roles ur ON ur.user_id = u.user_id
JOIN roles r ON r.role_id = ur.role_id
WHERE r.name = 'admin' LIMIT 100;
```

Available tables and views:
{schema}"""

ANSWER_SYSTEM = """You are a data assistant. Answer the user's question using ONLY the query results provided.
Be concise: one to three sentences. Convert cents to dollars when you mention money.
If there are no rows, say that no matching data was found. Never invent numbers or names that are not in the results."""


def format_schema(catalog: list[dict]) -> str:
    out: list[str] = []
    current = None
    for c in catalog:
        if c["table"] != current:
            current = c["table"]
            out.append(f"\nTABLE {current}" + (f" -- {c['table_comment']}" if c["table_comment"] else ""))
        note = f" -- {c['column_comment']}" if c["column_comment"] else ""
        out.append(f"  {c['column']} {c['type']}{note}")
    return "\n".join(out).strip()


def build_sql_messages(question: str, catalog: list[dict], today: date | None = None) -> list[Message]:
    system = SQL_SYSTEM.format(today=(today or date.today()).isoformat(), schema=format_schema(catalog))
    return [{"role": "system", "content": system}, {"role": "user", "content": question}]


def build_repair_messages(messages: list[Message], bad_reply: str, feedback: str) -> list[Message]:
    """Ask the model to try again, telling it exactly what was wrong."""
    return messages + [
        {"role": "assistant", "content": bad_reply},
        {"role": "user", "content": feedback},
    ]


def db_error_feedback(error: str) -> str:
    return (f"That query failed with this PostgreSQL error:\n{error}\n"
            f"Return a corrected query only, in a ```sql block.")


def guardrail_feedback(rule: str, reason: str) -> str:
    return (f"Your query was rejected by a safety check ({rule}): {reason}\n"
            f"Write ONE read-only SELECT using only the listed tables and views, in a ```sql block. "
            f"If the question cannot be answered that way, return: SELECT 'UNANSWERABLE' AS answer;")


def build_answer_messages(question: str, columns: list[str], rows: list[tuple],
                          truncated: bool, show_rows: int = 30) -> list[Message]:
    shown = rows[:show_rows]
    payload = {"question": question, "columns": columns,
               "rows": [list(r) for r in shown], "total_rows_returned": len(rows),
               "more_rows_not_shown": truncated or len(rows) > show_rows}
    return [{"role": "system", "content": ANSWER_SYSTEM},
            {"role": "user", "content": json.dumps(payload, default=str)}]


_FENCE = re.compile(r"```(?:sql|postgresql|postgres)?[ \t]*\n?(.*?)```", re.S | re.I)
_START = re.compile(r"^[ \t]*(select|with)\b", re.I | re.M)


def extract_sql(text: str) -> str:
    """Pull the SQL out of a model reply (fenced block, or the first SELECT/WITH line onward)."""
    m = _FENCE.search(text)
    if m:
        sql = m.group(1)
    else:
        s = _START.search(text)
        sql = text[s.start():].split("\n\n")[0] if s else text
    return sql.strip().rstrip(";").strip()
