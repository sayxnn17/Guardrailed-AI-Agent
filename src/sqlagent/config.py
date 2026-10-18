"""Settings, read from the environment (and a .env file if one exists)."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from psycopg.conninfo import make_conninfo


@dataclass(frozen=True)
class Settings:
    db_host: str = "127.0.0.1"
    db_port: int = 5432
    db_name: str = "saas_dev"
    admin_url: str | None = None          # superuser URL: seed script + dev org lookup only
    reader_password: str = "agent_reader_dev"
    writer_password: str = "agent_writer_dev"
    ops_password: str = "agent_ops_dev"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5-coder:7b"
    max_rows: int = 200                   # rows fetched from the DB per question
    max_repairs: int = 1                  # extra LLM attempts after a rejected or failing query
    max_limit: int = 1000                 # largest LIMIT a query may ask for
    default_limit: int = 100              # LIMIT added when the model writes none
    max_plan_cost: float = 200_000.0      # planner cost above which a query is refused

    @classmethod
    def from_env(cls) -> "Settings":
        # override=True: the .env file wins over a stale variable left in your shell.
        load_dotenv(override=True)
        g = os.environ.get
        d = cls()
        return cls(
            db_host=g("DB_HOST", d.db_host),
            db_port=int(g("DB_PORT", d.db_port)),
            db_name=g("DB_NAME", d.db_name),
            admin_url=g("DATABASE_URL") or None,
            reader_password=g("AGENT_READER_PASSWORD", d.reader_password),
            writer_password=g("AGENT_WRITER_PASSWORD", d.writer_password),
            ops_password=g("AGENT_OPS_PASSWORD", d.ops_password),
            ollama_url=g("OLLAMA_URL", d.ollama_url).rstrip("/"),
            ollama_model=g("OLLAMA_MODEL", d.ollama_model),
            max_rows=int(g("AGENT_MAX_ROWS", d.max_rows)),
            max_repairs=int(g("AGENT_MAX_REPAIRS", d.max_repairs)),
            max_limit=int(g("AGENT_MAX_LIMIT", d.max_limit)),
            default_limit=int(g("AGENT_DEFAULT_LIMIT", d.default_limit)),
            max_plan_cost=float(g("AGENT_MAX_PLAN_COST", d.max_plan_cost)),
        )

    def conninfo(self, role: str) -> str:
        """libpq key/value connection string for one of the agent's roles.

        Key/value form needs no URL-encoding, so passwords with @ # / are safe.
        """
        password = {"agent_reader": self.reader_password,
                    "agent_writer": self.writer_password,
                    "agent_ops": self.ops_password}[role]
        return make_conninfo(host=self.db_host, port=self.db_port, dbname=self.db_name,
                             user=role, password=password)
