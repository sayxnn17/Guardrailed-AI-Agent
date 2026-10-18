"""Input guardrail: screens the user's question BEFORE any model sees it.

Rule-based on purpose: it is fast, free, deterministic and testable, and it cannot be
talked out of its decision by the text it is screening. It is one layer of several; the SQL
validator and the database still protect you if something slips through here.

Categories
  prompt_injection  tries to change the agent's rules, reveal its prompt, or smuggle instructions
  data_exfiltration asks for other tenants' data, secrets, or system catalogs
  raw_sql           the user pasted SQL or injection syntax instead of asking in plain language
  write_intent      asks to change or delete data; allowed only via the permission layer (stage 5)
  invalid_input     empty or too long
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

MAX_QUESTION_CHARS = 1000

REFUSALS = {
    "prompt_injection": "I can't follow instructions that try to change my rules or reveal how I work. "
                        "Ask me a question about your organization's data instead.",
    "data_exfiltration": "I can only answer questions about your own organization's data, and I can't "
                         "reveal credentials, secrets or system internals.",
    "raw_sql": "Please ask in plain language. I write the database query myself, so pasted SQL "
               "and query syntax aren't accepted.",
    "write_intent": "That would change or delete data. Changes need an explicit confirmation step, "
                    "which isn't available yet, so I can't do that.",
    "invalid_input": "Please send a question between 1 and %d characters." % MAX_QUESTION_CHARS,
}


@dataclass(frozen=True)
class GuardVerdict:
    action: str                  # "allow" | "block" | "confirm"
    category: str | None = None
    reason: str | None = None
    user_message: str | None = None

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


def normalize(text: str) -> str:
    """NFKC (folds fullwidth/compat characters), drop invisible characters, lowercase."""
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if ch in "\n\t" or unicodedata.category(ch) not in ("Cf", "Cc"))
    return re.sub(r"[ \t]+", " ", t.lower()).strip()


_I = re.I | re.S
_RULES: list[tuple[str, str, re.Pattern]] = [
    # --- prompt injection -------------------------------------------------------------
    ("prompt_injection", "ignore-instructions", re.compile(
        r"\b(ignore|disregard|forget|override|bypass|circumvent|skip|disable)\b.{0,40}"
        r"\b(previous|prior|above|earlier|preceding|all|any|your|the|these|those|safety|security)\b.{0,40}"
        r"\b(instructions?|rules?|prompts?|guidelines?|guardrails?|restrictions?|constraints?|"
        r"polic(?:y|ies)|safeguards?|filters?|checks?)\b", _I)),
    ("prompt_injection", "reveal-prompt", re.compile(
        r"\b(reveal|show|print|repeat|display|output|leak|share|tell me|what (?:is|are))\b.{0,30}"
        r"\b(your|the)\b.{0,20}\b(system prompt|instructions|initial prompt|hidden prompt|prompt|rules|"
        r"configuration)\b", _I)),
    ("prompt_injection", "system-prompt", re.compile(r"\bsystem prompt\b", _I)),
    ("prompt_injection", "role-hijack", re.compile(
        r"\byou are now\b|\bfrom now on,? you\b|\bnew instructions?\s*[:\-]|\bpretend (?:to be|you are|that you)\b|"
        r"\bact as (?:an? )?(?:unrestricted|unfiltered|admin|root|dba|different|another|evil)\b|"
        r"\broleplay\b.{0,20}\b(?:as|an?)\b", _I)),
    ("prompt_injection", "jailbreak", re.compile(
        r"\b(?:developer|debug|god|admin|sudo|dan|maintenance)\s+mode\b|\bjailbreak(?:ed)?\b|"
        r"\bdo anything now\b", _I)),
    ("prompt_injection", "delimiter-injection", re.compile(
        r"<\|?(?:im_start|im_end|system|assistant|endoftext)\|?>|\[/?inst\]|```\s*(?:system|assistant)|"
        r"^\s*(?:system|assistant)\s*:", re.I | re.M)),
    ("prompt_injection", "encoded-payload", re.compile(r"[a-z0-9+/]{60,}={0,2}", re.I)),
    # --- data exfiltration ------------------------------------------------------------
    ("data_exfiltration", "other-tenants", re.compile(
        r"\b(?:other|another|different|competitor'?s?|someone else'?s)\b.{0,20}"
        r"\b(?:organi[sz]ations?|tenants?|compan(?:y|ies)|orgs?)\b|"
        r"\b(?:all|every|each)\s+(?:the\s+)?(?:other\s+)?(?:organi[sz]ations?|tenants?|orgs?|compan(?:y|ies))\b|"
        r"\bacross\s+(?:all\s+)?(?:organi[sz]ations|tenants|orgs|companies)\b", _I)),
    ("data_exfiltration", "tenant-tampering", re.compile(
        r"\borg_id\b|current_org|app\.current|\bset role\b|\bsession_authorization\b", _I)),
    ("data_exfiltration", "secrets", re.compile(
        r"\b(?:password hash(?:es)?|hashed passwords?|bcrypt|processor[_ ]token|api[_ ]keys?|secret keys?|"
        r"access tokens?|full card numbers?|card numbers?|cvv|cvc)\b|"
        r"\b(?:show|give|list|dump|reveal|export|tell)\b.{0,20}\bpasswords?\b", _I)),
    ("data_exfiltration", "system-catalogs", re.compile(
        r"\b(?:pg_catalog|information_schema|pg_shadow|pg_authid|pg_roles|pg_user|pg_stat_\w+|agent_audit_log)\b", _I)),
    ("data_exfiltration", "dump-everything", re.compile(
        r"\b(?:dump|exfiltrate|export)\b.{0,20}\b(?:database|db|everything|all (?:the )?(?:data|tables|records))\b", _I)),
    # --- raw SQL / injection syntax ---------------------------------------------------
    ("raw_sql", "sql-statement", re.compile(
        r"^\s*(?:select\b.+\bfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b|"
        r"drop\s+(?:table|database|schema|role|user|view|index)\b|alter\s+(?:table|role|user|database)\b|"
        r"truncate\s+table\b|create\s+(?:table|role|user|database|function)\b|grant\b.+\bto\b)", _I)),
    ("raw_sql", "statement-chaining", re.compile(
        r";\s*(?:drop|delete|insert|update|alter|truncate|select|set|copy|grant)\b|"
        r"\bunion\s+(?:all\s+)?select\b|/\*|\*/", _I)),
    ("raw_sql", "classic-injection", re.compile(
        r"'\s*(?:or|and)\s*'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|--\s*$|;\s*--", _I | re.M)),
    ("raw_sql", "dangerous-function", re.compile(
        r"\b(?:pg_sleep|set_config|current_setting|pg_read_file|pg_ls_dir|lo_import|lo_export|dblink|"
        r"copy\s+.+\s+(?:to|from)\s+program)\b", _I)),
    # --- write intent (to be routed to the permission layer) ---------------------------
    ("write_intent", "imperative-write", re.compile(
        r"(?:^|[.;!?:]\s+|\b(?:please|pls|can you|could you|would you|will you|i want you to|i need you to|"
        r"go ahead and|now|just|and|then|next|also|after that)\s+)"
        r"(?:delete|remove|drop|truncate|wipe|erase|purge|destroy|update|modify|insert|alter|deactivate|"
        r"suspend|cancel|disable|revoke|grant|void|refund|rename)\b", _I)),
]

# Phrases checked on a letters-and-digits-only copy, to catch "i.g.n.o.r.e  p r e v i o u s ..." tricks.
_COMPACT_PHRASES = ("ignorepreviousinstructions", "ignoreallpreviousinstructions", "ignoretheaboveinstructions",
                    "ignoreyourinstructions", "disregardpreviousinstructions", "disregardallinstructions",
                    "forgetpreviousinstructions", "systemprompt", "revealyourprompt", "developermode",
                    "jailbreak", "overridesecurity", "bypassguardrails", "bypasssecurity")


class InputGuard:
    def check(self, question: str | None) -> GuardVerdict:
        if question is None or not question.strip() or len(question) > MAX_QUESTION_CHARS:
            return self._verdict("block", "invalid_input", "empty or longer than the limit")
        text = normalize(question)
        for category, name, pattern in _RULES:
            if pattern.search(text):
                action = "confirm" if category == "write_intent" else "block"
                return self._verdict(action, category, f"matched rule '{name}'")
        compact = re.sub(r"[^a-z0-9]", "", text)
        for phrase in _COMPACT_PHRASES:
            if phrase in compact:
                return self._verdict("block", "prompt_injection", "obfuscated injection phrase")
        return GuardVerdict("allow")

    @staticmethod
    def _verdict(action: str, category: str, reason: str) -> GuardVerdict:
        return GuardVerdict(action, category, reason, REFUSALS[category])
