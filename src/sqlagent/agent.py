"""The core pipeline: question -> input guard -> SQL -> validator -> cost guard -> run -> answer.

Active guardrails (stages 3-4):
  * input guard      screens the question before any model sees it
  * SQL validator    single SELECT, agent_api views only, allowlisted functions, bounded LIMIT
  * cost guard       EXPLAIN-based refusal of queries the planner thinks are too expensive
  * database         read-only role, row-level security, timeout, single-statement execution
Not yet built: permission layer for write requests (stage 5), output guardrails (stage 6).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import psycopg

from . import db
from .config import Settings
from .guardrails import InputGuard, validate_sql
from .llm import LLMError, LLMProvider
from .prompt import (build_answer_messages, build_repair_messages, build_sql_messages,
                     db_error_feedback, extract_sql, guardrail_feedback)


@dataclass
class AgentResult:
    question: str
    org_id: str
    status: str = "error"                    # "answered" | "refused" | "error"
    sql: str | None = None
    columns: list[str] = field(default_factory=list)
    rows: list[tuple] = field(default_factory=list)
    truncated: bool = False
    answer: str = ""
    error: str | None = None                 # set when status == "error"
    guardrail: str | None = None             # which guardrail refused the request
    block_reason: str | None = None
    interventions: list[str] = field(default_factory=list)   # guardrail rules that fired, even if later fixed
    attempts: int = 0
    latency_ms: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    model: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "answered"

    @property
    def refused(self) -> bool:
        return self.status == "refused"


class Agent:
    def __init__(self, settings: Settings, llm: LLMProvider, input_guard: InputGuard | None = None):
        self.settings = settings
        self.llm = llm
        self.input_guard = input_guard or InputGuard()
        self._conn: psycopg.Connection | None = None
        self._catalog: list[dict] | None = None

    # -- connection / schema ---------------------------------------------------
    def _connection(self) -> psycopg.Connection:
        if self._conn is None or self._conn.closed or self._conn.broken:
            self._conn = db.connect(self.settings, "agent_reader")
        return self._conn

    def catalog(self) -> list[dict]:
        if self._catalog is None:
            self._catalog = db.load_schema_catalog(self._connection())
        return self._catalog

    def close(self) -> None:
        if self._conn is not None and not self._conn.closed:
            self._conn.close()

    # -- main entry point ---------------------------------------------------------
    def ask(self, question: str, org_id: str) -> AgentResult:
        t0 = time.perf_counter()
        res = AgentResult(question=question, org_id=str(org_id))
        try:
            self._run(res, question, org_id)
        except LLMError as e:
            res.status, res.error = "error", str(e)
        except db.QueryError as e:           # e.g. schema catalog unreadable
            res.status, res.error = "error", str(e)
        res.latency_ms = int((time.perf_counter() - t0) * 1000)
        return res

    def _run(self, res: AgentResult, question: str, org_id: str) -> None:
        s = self.settings

        # 1. input guard: runs before any model call, so a blocked request costs no tokens
        verdict = self.input_guard.check(question)
        if not verdict.allowed:
            res.status, res.guardrail, res.block_reason = "refused", verdict.category, verdict.reason
            res.answer = verdict.user_message
            res.interventions.append(f"input:{verdict.category}")
            return

        catalog = self.catalog()
        allowed_tables = {c["table"] for c in catalog}
        messages = build_sql_messages(question, catalog)

        # 2. generate -> validate -> cost-check -> execute, with a bounded repair loop
        failure: tuple[str, str | None, str] | None = None     # (kind, rule, text)
        for attempt in range(1, s.max_repairs + 2):
            res.attempts = attempt
            reply = self.llm.chat(messages, max_tokens=400)
            self._tally(res, reply)
            res.sql = extract_sql(reply.text)
            failure = None

            check = validate_sql(res.sql, allowed_tables, max_limit=s.max_limit,
                                 default_limit=s.default_limit)
            if not check.ok:
                failure = ("guardrail", check.rule, check.reason)
            else:
                res.sql = check.sql
                try:
                    cost = db.plan_cost(self._connection(), res.sql, org_id)
                    if cost > s.max_plan_cost:
                        failure = ("guardrail", "cost_guard",
                                   f"estimated cost {cost:,.0f} is above the limit of {s.max_plan_cost:,.0f}; "
                                   f"ask for less data or add filters")
                    else:
                        res.columns, res.rows, res.truncated = db.run_query(
                            self._connection(), res.sql, org_id, s.max_rows)
                except db.QueryError as e:
                    failure = ("db_error", None, str(e))

            if failure is None:
                break
            kind, rule, text = failure
            if kind == "guardrail":
                res.interventions.append(f"sql:{rule}")
                feedback = guardrail_feedback(rule, text)
            else:
                feedback = db_error_feedback(text)
            messages = build_repair_messages(messages, reply.text, feedback)

        # 3. outcome
        if failure is None:
            res.status, res.guardrail, res.block_reason = "answered", None, None
            res.answer = self._answer(res)
        elif failure[0] == "guardrail":
            res.status, res.guardrail, res.block_reason = "refused", failure[1], failure[2]
            res.answer = ("I couldn't produce a safe query for that request, so I didn't run anything. "
                          + failure[2][0].upper() + failure[2][1:] + ".")
        else:
            res.status, res.error = "error", failure[2]

    # -- helpers --------------------------------------------------------------------
    def _answer(self, res: AgentResult) -> str:
        # The prompt's convention for "the data cannot answer this".
        if res.rows and len(res.rows) == 1 and res.rows[0][0] == "UNANSWERABLE":
            return "I can't answer that from the data available to me."
        try:
            reply = self.llm.chat(build_answer_messages(res.question, res.columns, res.rows,
                                                        res.truncated), max_tokens=300)
        except LLMError as e:
            return f"(The query ran, but I couldn't write a summary: {e})"
        self._tally(res, reply)
        return reply.text.strip()

    @staticmethod
    def _tally(res: AgentResult, reply) -> None:
        res.prompt_tokens += reply.prompt_tokens
        res.completion_tokens += reply.completion_tokens
        res.model = reply.model or res.model
