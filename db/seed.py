#!/usr/bin/env python3
"""Seed the multi-tenant SaaS database with realistic fake data.

Usage
-----
    pip install "psycopg[binary]" faker
    export DATABASE_URL=postgresql://postgres:<password>@localhost:5432/saas_demo
    python db/seed.py                       # 50 orgs, ~2000 usage events per org
    python db/seed.py --orgs 100 --events-per-org 5000
    python db/seed.py --truncate            # wipe seeded tables first, then reseed

Run it as a superuser (or app_owner): row-level security must not filter the
inserts. Run it after 001_schema.sql (and 002_security.sql if you use it).
The same --seed always produces the same data (except timestamps, which are
relative to "now").

The fixed organization `acme-corp` is fully predictable, so evals can assert
exact answers (assumes the seed runs on or after 2026-10-04):
    12 users (10 active, 1 invited, 1 deactivated), owner Alice Anderson,
    21 paid invoices (Jan 2025 - Sep 2026) of 12900 cents each = 270900 total,
    exactly 1000 usage events, 200 of each event type, 1 quantity each.
"""
from __future__ import annotations

import argparse
import calendar
import json
import os
import random
import re
import string
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import psycopg
from faker import Faker

UTC = timezone.utc
COUNTRIES = ["IN", "US", "DE", "GB", "BR", "AU", "SG"]
COUNTRY_WEIGHTS = [30, 30, 10, 10, 8, 6, 6]
ACME_ORG_ID = uuid.UUID("acacacac-0000-4000-8000-000000000001")
ACME_SUB_ID = uuid.UUID("acacacac-0000-4000-8000-0000000000a1")
MIN_ORGS = 12

# Deliberate edge cases (index = position among generated, non-acme orgs).
EDGE = {
    0: "no_invoices", 1: "no_invoices",
    2: "no_events", 3: "no_events",
    4: "past_due", 5: "past_due", 6: "past_due",
    7: "deactivated_only",
    8: "weird_names",
}

ACME_USERS = [  # name, status, roles
    ("Alice Anderson", "active", ["owner", "billing"]),
    ("Bob Brown", "active", ["admin"]),
    ("Carol Clark", "active", ["billing"]),
    ("David Davis", "active", ["member"]),
    ("Eve Evans", "active", ["member"]),
    ("Frank Foster", "active", ["member"]),
    ("Grace Green", "active", ["member"]),
    ("Henry Hall", "active", ["viewer"]),
    ("Irene Ito", "active", ["member"]),
    ("Jack Johnson", "active", ["member"]),
    ("Karen Kim", "invited", ["member"]),
    ("Leo Lopez", "deactivated", ["member"]),
]
EVENT_TYPES = ["api_call", "storage_gb", "seat_login", "export", "webhook"]


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def add_months(dt: datetime, n: int) -> datetime:
    y = dt.year + (dt.month - 1 + n) // 12
    m = (dt.month - 1 + n) % 12 + 1
    return dt.replace(year=y, month=m, day=min(dt.day, calendar.monthrange(y, m)[1]))


def new_uuid(rng: random.Random) -> uuid.UUID:
    return uuid.UUID(int=rng.getrandbits(128), version=4)


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def rand_dt(rng: random.Random, lo: datetime, hi: datetime) -> datetime:
    if hi <= lo:
        return lo
    return (lo + timedelta(seconds=rng.random() * (hi - lo).total_seconds())).replace(microsecond=0)


def fake_bcrypt(rng: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits + "./"
    return "$2b$12$" + "".join(rng.choice(alphabet) for _ in range(53))


@dataclass
class Org:
    id: uuid.UUID
    name: str
    slug: str
    country: str
    status: str
    created_at: datetime
    kind: str = "normal"
    end_at: datetime | None = None   # churn / suspension date: events stop here
    users: list = field(default_factory=list)


@dataclass
class Plan:
    id: int
    code: str
    price: int
    seat_limit: int | None


# ----------------------------------------------------------------------------
# generation
# ----------------------------------------------------------------------------
def make_users(org: Org, n: int, rng: random.Random, fake: Faker, now: datetime,
               role_ids: dict[str, int]):
    """Returns (user rows, user_role rows) and fills org.users."""
    user_rows, role_rows = [], []
    used = set()
    domain = f"{org.slug}.example"

    def email_for(name: str) -> str:
        base = re.sub(r"[^a-z0-9]+", ".", name.lower()).strip(".") or "user"
        email, k = f"{base}@{domain}", 1
        while email in used:
            k += 1
            email = f"{base}{k}@{domain}"
        used.add(email)
        return email

    def add_user(name, status, roles, phone, created, last_login):
        uid = new_uuid(rng)
        user_rows.append((uid, org.id, email_for(name), name, phone, fake_bcrypt(rng),
                          status, created, created, last_login))
        for r in roles:
            role_rows.append((org.id, uid, role_ids[r], created))
        org.users.append({"id": uid, "status": status})

    names = [fake.name() for _ in range(n)]
    if org.kind == "weird_names":
        names += ["Conan O'Brien", "Maximilian " + "Wolfeschlegelsteinhausenbergerdorff-" * 4 + "Smith"]
    for i, name in enumerate(names):
        is_owner = i == 0
        if org.kind == "deactivated_only":
            status = "deactivated"
        elif is_owner:
            status = "active"
        elif org.status == "churned":
            status = rng.choices(["active", "deactivated"], [30, 70])[0]
        elif org.status == "trial":
            status = rng.choices(["active", "invited"], [50, 50])[0]
        else:
            status = rng.choices(["active", "invited", "deactivated"], [80, 8, 12])[0]
        roles = ["owner"] if is_owner else [rng.choices(
            ["admin", "billing", "member", "viewer"], [10, 8, 60, 22])[0]]
        if not is_owner and rng.random() < 0.10:  # many-to-many: some hold two roles
            extra = rng.choice([r for r in ["admin", "billing", "member", "viewer"] if r not in roles])
            if extra != "admin" or "admin" not in roles:
                roles.append(extra)
        created = org.created_at if is_owner else rand_dt(
            rng, org.created_at, min(now, org.created_at + timedelta(days=90)))
        if status == "active":
            last = rand_dt(rng, max(created, now - timedelta(days=60)), now) if rng.random() < 0.85 else None
        elif status == "deactivated":
            hi = now - timedelta(days=10)
            last = rand_dt(rng, created, hi) if hi > created and rng.random() < 0.7 else None
        else:
            last = None
        phone = None if rng.random() < 0.10 else fake.phone_number()
        add_user(name, status, roles, phone, created, last)
    return user_rows, role_rows


def make_subscriptions(org: Org, n_users: int, plans: dict[str, Plan], rng: random.Random,
                       now: datetime):
    """Returns list of subscription dicts (oldest first)."""
    churned = org.status == "churned"
    span_end = org.end_at if churned else now
    span = (span_end - org.created_at).total_seconds()
    span_days = int(span // 86400)

    if org.status == "trial":
        k = 1
    elif org.kind == "past_due":
        k = 1
    else:
        k = max(1, min(rng.choice([1, 1, 2, 2, 3]), span_days // 60))

    if org.status == "trial":
        bucket = [plans["starter"]]
    elif org.kind == "past_due":
        bucket = [plans["starter"], plans["pro"]]
    elif n_users <= 3:
        bucket = [plans["free"], plans["starter"], plans["starter"]]
    elif n_users <= 10:
        bucket = [plans["starter"], plans["pro"]]
    elif n_users <= 25:
        bucket = [plans["pro"]]
    else:
        bucket = [plans["pro"], plans["enterprise"]]
    seg_plans = sorted((rng.choice(bucket) for _ in range(k)), key=lambda p: p.price)

    bounds = [org.created_at]
    for i in range(1, k):
        jitter = rng.uniform(-span / (4 * k), span / (4 * k))
        bounds.append((org.created_at + timedelta(seconds=span * i / k + jitter)).replace(microsecond=0))
    bounds.append(span_end.replace(microsecond=0))

    subs = []
    for i in range(k):
        final = i == k - 1
        plan = seg_plans[i]
        seats = max(1, n_users + rng.randint(-1, 2))
        if plan.seat_limit:
            seats = min(seats, plan.seat_limit)
        if org.status == "trial":
            seats = min(seats, 3)
        cycle = "monthly" if (org.kind == "past_due" or rng.random() < 0.8) else "annual"
        sub = {"id": new_uuid(rng), "org_id": org.id, "plan": plan, "seats": seats,
               "cycle": cycle, "started_at": bounds[i], "ended_at": None}
        if not final:
            sub["status"], sub["ended_at"] = "canceled", bounds[i + 1]
        elif org.status == "trial":
            sub["status"] = "trialing"
        elif org.status == "active":
            sub["status"] = "past_due" if org.kind == "past_due" else "active"
        elif org.status == "suspended":
            cancel = rng.random() < 0.5
            sub["status"] = "canceled" if cancel else "past_due"
            org.end_at = (bounds[i] + (now - bounds[i]) * rng.uniform(0.3, 0.9)).replace(microsecond=0)
            if cancel:
                sub["ended_at"] = org.end_at
        else:  # churned
            sub["status"], sub["ended_at"] = "canceled", org.end_at
        subs.append(sub)
    return subs


def make_invoices(sub: dict, rng: random.Random, now: datetime, counter: list[int]):
    """Returns (invoice rows, item rows)."""
    plan: Plan = sub["plan"]
    if plan.price == 0 or sub["status"] == "trialing":
        return [], []
    step = 1 if sub["cycle"] == "monthly" else 12
    end = sub["ended_at"] or now
    invs, items = [], []
    i = 0
    while True:
        issued = add_months(sub["started_at"], i * step)
        if issued >= end or issued > now:
            break
        i += 1
        due = issued + timedelta(days=14 if step == 1 else 30)
        age_days = (now - issued).days
        paid_at = None
        if age_days < 7:
            status = rng.choices(["draft", "open", "paid"], [30, 40, 30])[0]
        elif age_days < 45:
            status = rng.choices(["open", "paid"], [60, 40])[0]
        else:
            status = rng.choices(["paid", "void", "uncollectible"], [93, 3, 4])[0]
        if status == "paid":
            hi = min(due + timedelta(days=3), now)
            if hi <= issued + timedelta(hours=1):
                status = "open"
            else:
                paid_at = rand_dt(rng, issued + timedelta(hours=1), hi)
        lines = []
        if step == 1:
            lines.append((f"{plan.code.title()} plan - monthly", 1, plan.price))
        else:
            lines.append((f"{plan.code.title()} plan - annual (15% discount)", 1, int(plan.price * 12 * 0.85)))
        if sub["seats"] > 3:
            lines.append(("Additional seats", sub["seats"] - 3, 300 * step))
        if rng.random() < 0.25:
            lines.append(("API overage (per 10k calls)", rng.randint(1, 30), 150))
        invs.append({"issued": issued, "due": due, "status": status, "paid_at": paid_at,
                     "lines": lines})
    if sub["status"] == "past_due":  # last two invoices unpaid -> overdue receivables
        for inv in invs[-2:]:
            inv["status"], inv["paid_at"] = "open", None

    inv_rows, item_rows = [], []
    for inv in invs:
        counter[0] += 1
        inv_id = new_uuid(rng)
        amount = sum(q * u for _, q, u in inv["lines"])
        inv_rows.append((inv_id, sub["org_id"], sub["id"], f"INV-{inv['issued'].year}-{counter[0]:06d}",
                         inv["status"], "USD", amount, inv["issued"], inv["due"], inv["paid_at"]))
        for desc, q, u in inv["lines"]:
            item_rows.append((sub["org_id"], inv_id, desc, q, u))
    return inv_rows, item_rows


def make_payment_methods(org: Org, rng: random.Random, fake: Faker, now: datetime):
    if org.status == "trial":
        return []
    rows = []
    n = 1 if org.status == "churned" else rng.choice([1, 1, 2])
    for i in range(n):
        token = "tok_" + "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(24))
        rows.append((new_uuid(rng), org.id, rng.choices(["visa", "mastercard", "amex", "rupay"],
                                                         [50, 30, 10, 10])[0],
                     f"{rng.randint(0, 9999):04d}", rng.randint(1, 12), now.year + rng.randint(1, 4),
                     f"billing@{org.slug}.example", token, i == 0))
    return rows


def event_payload(etype: str, rng: random.Random):
    if etype == "api_call":
        return rng.randint(1, 50), {
            "endpoint": rng.choice(["/v1/orders", "/v1/customers", "/v1/invoices", "/v1/reports", "/v1/search"]),
            "status_code": rng.choices([200, 400, 401, 404, 500], [90, 4, 2, 3, 1])[0],
            "region": rng.choice(["ap-south-1", "us-east-1", "eu-west-1"])}
    if etype == "storage_gb":
        return rng.randint(1, 20), {"bucket": rng.choice(["attachments", "exports", "backups"])}
    if etype == "seat_login":
        return rng.randint(1, 3), {"method": rng.choice(["password", "sso"])}
    if etype == "export":
        return rng.randint(1, 3), {"format": rng.choice(["csv", "json", "xlsx"]), "rows": rng.randint(10, 50000)}
    return rng.randint(1, 3), {"target": rng.choice(["slack", "zapier", "custom"]), "delivered": rng.random() < 0.97}


def make_events(org: Org, count: int, rng: random.Random, now: datetime):
    start = max(org.created_at, now - timedelta(days=360))
    end = org.end_at or now
    if count <= 0 or end <= start + timedelta(hours=1):
        return []
    pool = [u["id"] for u in org.users if u["status"] == "active"] or [u["id"] for u in org.users]
    span = (end - start).total_seconds()
    spike_start = None
    if org.status == "active" and span > 40 * 86400 and rng.random() < 0.15:
        spike_start = start + timedelta(seconds=rng.random() * (span - 25 * 86400))
    rows = []
    for _ in range(count):
        if spike_start and rng.random() < 0.35:
            t = spike_start + timedelta(seconds=rng.random() * 25 * 86400)
        else:
            t = start + timedelta(seconds=rng.random() * span)
        t = min(t, end).replace(microsecond=0)
        etype = rng.choices(EVENT_TYPES, [70, 4, 15, 6, 5])[0]
        qty, meta = event_payload(etype, rng)
        uid = None if rng.random() < 0.05 else rng.choice(pool)
        rows.append((org.id, uid, etype, qty, json.dumps(meta), t))
    return rows


# ----------------------------------------------------------------------------
# acme-corp: fully predictable
# ----------------------------------------------------------------------------
def build_acme(plans, role_ids, now, rng):
    created = datetime(2024, 12, 15, tzinfo=UTC)
    org = Org(ACME_ORG_ID, "Acme Corp", "acme-corp", "US", "active", created, kind="acme")
    users, uroles = [], []
    for i, (name, status, roles) in enumerate(ACME_USERS, start=1):
        uid = uuid.UUID(f"acacacac-1111-4000-8000-{i:012d}")
        email = name.lower().replace(" ", ".") + "@acme.example"
        ucreated = created + timedelta(days=i)
        last = None if status == "invited" else now - timedelta(hours=i * 7)
        users.append((uid, org.id, email, name, f"+1-555-01{i:02d}", "$2b$12$" + "A" * 53, status,
                      ucreated, ucreated, last))
        for r in roles:
            uroles.append((org.id, uid, role_ids[r], ucreated))
        org.users.append({"id": uid, "status": status})
    pro = plans["pro"]
    sub = {"id": ACME_SUB_ID, "org_id": org.id, "plan": pro, "seats": 12, "cycle": "monthly",
           "started_at": datetime(2025, 1, 1, tzinfo=UTC), "ended_at": None, "status": "active"}
    invs, items = [], []
    n = 0
    y, m = 2025, 1
    while True:
        issued = datetime(y, m, 1, tzinfo=UTC)
        paid = issued + timedelta(days=3)
        if (y, m) > (2026, 9) or paid > now:
            break
        n += 1
        inv_id = uuid.UUID(f"acacacac-3333-4000-8000-{n:012d}")
        invs.append((inv_id, org.id, ACME_SUB_ID, f"INV-ACME-{n:04d}", "paid", "USD", 12900,
                     issued, issued + timedelta(days=14), paid))
        items.append((org.id, inv_id, "Pro plan - monthly", 1, 9900))
        items.append((org.id, inv_id, "Additional seats", 2, 1500))
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    pms = [(uuid.UUID("acacacac-4444-4000-8000-000000000001"), org.id, "visa", "4242", 12,
            now.year + 3, "billing@acme.example", "tok_acme_fixed_000000000001", True)]
    active_ids = [u["id"] for u in org.users if u["status"] == "active"]
    events = []
    for i in range(1000):
        t = (now - timedelta(days=360) + timedelta(seconds=i * 360 * 86400 / 1000)).replace(microsecond=0)
        etype = EVENT_TYPES[i % 5]
        meta = {"endpoint": "/v1/orders", "status_code": 200} if etype == "api_call" else {"fixed": True}
        events.append((org.id, active_ids[i % len(active_ids)], etype, 1, json.dumps(meta), t))
    return org, users, uroles, [sub], invs, items, pms, events


# ----------------------------------------------------------------------------
# database I/O
# ----------------------------------------------------------------------------
def copy_rows(cur, table: str, cols: list[str], rows: list[tuple]):
    if not rows:
        return
    with cur.copy(f"COPY {table} ({', '.join(cols)}) FROM STDIN") as cp:
        for r in rows:
            cp.write_row(r)


def run_checks(cur, acme_expect: dict) -> list[tuple[str, bool, str]]:
    def val(sql, params=None):
        cur.execute(sql, params)
        return cur.fetchone()[0]

    checks = [
        ("one live subscription per org (max)",
         val("SELECT count(*) FROM (SELECT org_id FROM app.subscriptions WHERE status IN "
             "('trialing','active','past_due') GROUP BY 1 HAVING count(*) > 1) s") == 0, ""),
        ("invoice amount equals sum of its items",
         val("SELECT count(*) FROM app.invoices i WHERE amount_cents <> (SELECT coalesce(sum(line_total_cents),0) "
             "FROM app.invoice_items it WHERE it.invoice_id = i.invoice_id)") == 0, ""),
        ("paid_at is set only when status = paid",
         val("SELECT count(*) FROM app.invoices WHERE (status = 'paid') <> (paid_at IS NOT NULL)") == 0, ""),
        ("subscription seats within plan seat_limit",
         val("SELECT count(*) FROM app.subscriptions s JOIN app.plans p USING (plan_id) "
             "WHERE p.seat_limit IS NOT NULL AND s.seats > p.seat_limit") == 0, ""),
        ("every org has exactly one owner",
         val("SELECT count(*) FROM app.organizations o WHERE (SELECT count(*) FROM app.user_roles ur "
             "JOIN app.roles r USING (role_id) WHERE ur.org_id = o.org_id AND r.name = 'owner') <> 1") == 0, ""),
        ("every org with a card has exactly one default",
         val("SELECT count(*) FROM (SELECT org_id FROM app.payment_methods GROUP BY 1 "
             "HAVING count(*) FILTER (WHERE is_default) <> 1) s") == 0, ""),
        ("no usage events landed in the default partition",
         val("SELECT count(*) FROM app.usage_events_default") == 0, ""),
        ("edge: >=2 orgs with zero invoices",
         val("SELECT count(*) FROM app.organizations o WHERE NOT EXISTS "
             "(SELECT 1 FROM app.invoices i WHERE i.org_id = o.org_id)") >= 2, ""),
        ("edge: >=2 orgs with zero usage events",
         val("SELECT count(*) FROM app.organizations o WHERE NOT EXISTS "
             "(SELECT 1 FROM app.usage_events e WHERE e.org_id = o.org_id)") >= 2, ""),
        ("edge: >=3 orgs past_due with an overdue open invoice",
         val("SELECT count(DISTINCT s.org_id) FROM app.subscriptions s JOIN app.invoices i "
             "ON i.subscription_id = s.subscription_id WHERE s.status = 'past_due' "
             "AND i.status = 'open' AND i.due_at < now()") >= 3, ""),
        ("edge: >=1 org with only deactivated users",
         val("SELECT count(*) FROM app.organizations o WHERE EXISTS (SELECT 1 FROM app.users u WHERE u.org_id = o.org_id) "
             "AND NOT EXISTS (SELECT 1 FROM app.users u WHERE u.org_id = o.org_id AND u.status <> 'deactivated')") >= 1, ""),
        ("edge: a user name with an apostrophe",
         val("SELECT count(*) FROM app.users WHERE full_name LIKE '%''%'") >= 1, ""),
        ("edge: a user name longer than 100 chars",
         val("SELECT count(*) FROM app.users WHERE length(full_name) > 100") >= 1, ""),
        ("edge: every country code IN/US/DE/GB/BR/AU/SG present",
         val("SELECT count(DISTINCT country_code) FROM app.organizations WHERE country_code = ANY(%s)",
             (COUNTRIES,)) == len(COUNTRIES), ""),
        ("acme-corp: 12 users",
         val("SELECT count(*) FROM app.users u JOIN app.organizations o USING (org_id) WHERE o.slug = 'acme-corp'") == 12, ""),
        ("acme-corp: invoice count and paid total match",
         (val("SELECT count(*) FROM app.invoices i JOIN app.organizations o USING (org_id) WHERE o.slug = 'acme-corp'"),
          val("SELECT coalesce(sum(amount_cents),0) FROM app.invoices i JOIN app.organizations o USING (org_id) "
              "WHERE o.slug = 'acme-corp' AND i.status = 'paid'")) == (acme_expect["invoices"], acme_expect["total"]), ""),
        ("acme-corp: exactly 1000 usage events, 200 per type",
         val("SELECT count(*) FROM app.usage_events e JOIN app.organizations o USING (org_id) WHERE o.slug = 'acme-corp'") == 1000
         and val("SELECT count(DISTINCT n) FROM (SELECT count(*) n FROM app.usage_events e JOIN app.organizations o "
                 "USING (org_id) WHERE o.slug = 'acme-corp' GROUP BY event_type) s") == 1, ""),
    ]
    return checks


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dsn", default=os.environ.get("DATABASE_URL"), help="Postgres DSN (or set DATABASE_URL)")
    ap.add_argument("--orgs", type=int, default=50, help=f"number of organizations incl. acme-corp (min {MIN_ORGS})")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--events-per-org", type=int, default=2000)
    ap.add_argument("--truncate", action="store_true", help="wipe seeded tables first")
    args = ap.parse_args()
    if not args.dsn:
        ap.error("no database: pass --dsn or set DATABASE_URL")
    if args.orgs < MIN_ORGS:
        ap.error(f"--orgs must be at least {MIN_ORGS} so every edge case fits")

    rng = random.Random(args.seed)
    Faker.seed(args.seed)
    fake = Faker()
    now = datetime.now(UTC).replace(microsecond=0)

    with psycopg.connect(args.dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM app.organizations")
            if cur.fetchone()[0] > 0:
                if not args.truncate:
                    print("organizations is not empty. Re-run with --truncate to wipe and reseed.", file=sys.stderr)
                    return 2
                cur.execute("TRUNCATE app.organizations RESTART IDENTITY CASCADE")

            cur.execute("SELECT plan_id, code, monthly_price_cents, seat_limit FROM app.plans")
            plans = {c: Plan(i, c, p, s) for i, c, p, s in cur.fetchall()}
            cur.execute("SELECT name, role_id FROM app.roles")
            role_ids = dict(cur.fetchall())
            for m in range(-12, 1):  # make sure the monthly partitions we need exist
                cur.execute("SELECT app.ensure_usage_partition(%s)",
                            (add_months(now.replace(day=1), m).date(),))

            T = {k: [] for k in ["orgs", "users", "uroles", "subs", "invs", "items", "pms", "events"]}
            summary = {"orgs": 0}

            # --- acme-corp (fixed) ---
            acme, au, ar, asubs, ainv, aitems, apm, aev = build_acme(plans, role_ids, now, rng)
            T["orgs"].append((acme.id, acme.name, acme.slug, acme.country, acme.status, acme.created_at, acme.created_at))
            T["users"] += au; T["uroles"] += ar; T["invs"] += ainv; T["items"] += aitems
            T["pms"] += apm; T["events"] += aev
            T["subs"].append((ACME_SUB_ID, acme.id, plans["pro"].id, "active", "monthly", 12,
                              asubs[0]["started_at"], None, asubs[0]["started_at"]))
            acme_expect = {"invoices": len(ainv), "total": sum(r[6] for r in ainv)}

            # --- generated orgs ---
            used_slugs = {"acme-corp"}
            counter = [0]
            for j in range(args.orgs - 1):
                kind = EDGE.get(j, "normal")
                country = COUNTRIES[j % 7] if j < 7 else rng.choices(COUNTRIES, COUNTRY_WEIGHTS)[0]
                if kind == "no_invoices":
                    status = "trial"
                elif kind == "past_due" or kind in ("deactivated_only", "weird_names", "no_events"):
                    status = "active"
                else:
                    status = rng.choices(["trial", "active", "suspended", "churned"], [15, 65, 10, 10])[0]
                if status == "trial":
                    created = now - timedelta(days=rng.randint(1, 28), seconds=rng.randint(0, 86399))
                elif status == "churned":
                    created = now - timedelta(days=rng.randint(240, 730))
                elif kind == "past_due":
                    created = now - timedelta(days=rng.randint(150, 400))
                else:
                    created = now - timedelta(days=rng.randint(120, 730))
                created = created.replace(microsecond=0)

                name = fake.company()
                slug = slugify(name) or f"org-{j}"
                while slug in used_slugs:
                    slug += f"-{rng.randint(2, 99)}"
                used_slugs.add(slug)
                org = Org(new_uuid(rng), name, slug, country, status, created, kind)
                if status == "churned":
                    org.end_at = (now - timedelta(days=rng.randint(10, 90))).replace(microsecond=0)

                if status == "trial":
                    n_users = rng.randint(1, 4)
                elif kind == "deactivated_only":
                    n_users = rng.randint(3, 6)
                elif kind == "weird_names":
                    n_users = rng.randint(4, 8)
                else:
                    n_users = max(3, min(40, int(rng.lognormvariate(1.6, 0.7)) + 3))

                urows, rrows = make_users(org, n_users, rng, fake, now, role_ids)
                subs = make_subscriptions(org, len(org.users), plans, rng, now)
                T["orgs"].append((org.id, org.name, org.slug, org.country, org.status, org.created_at, org.created_at))
                T["users"] += urows; T["uroles"] += rrows
                for s in subs:
                    T["subs"].append((s["id"], org.id, s["plan"].id, s["status"], s["cycle"], s["seats"],
                                      s["started_at"], s["ended_at"], s["started_at"]))
                    irows, itrows = make_invoices(s, rng, now, counter)
                    T["invs"] += irows; T["items"] += itrows
                T["pms"] += make_payment_methods(org, rng, fake, now)

                factor = {"churned": 0.3, "trial": 0.05, "suspended": 0.4}.get(status, 1.0)
                factor *= min(2.5, max(0.3, rng.lognormvariate(0, 0.5)))
                count = 0 if kind == "no_events" else int(args.events_per_org * factor)
                T["events"] += make_events(org, count, rng, now)

            # --- load (dependency order) ---
            copy_rows(cur, "app.organizations", ["org_id", "name", "slug", "country_code", "status", "created_at", "updated_at"], T["orgs"])
            copy_rows(cur, "app.users", ["user_id", "org_id", "email", "full_name", "phone", "password_hash", "status", "created_at", "updated_at", "last_login_at"], T["users"])
            copy_rows(cur, "app.user_roles", ["org_id", "user_id", "role_id", "granted_at"], T["uroles"])
            copy_rows(cur, "app.subscriptions", ["subscription_id", "org_id", "plan_id", "status", "billing_cycle", "seats", "started_at", "ended_at", "updated_at"], T["subs"])
            copy_rows(cur, "app.invoices", ["invoice_id", "org_id", "subscription_id", "invoice_number", "status", "currency", "amount_cents", "issued_at", "due_at", "paid_at"], T["invs"])
            copy_rows(cur, "app.invoice_items", ["org_id", "invoice_id", "description", "quantity", "unit_price_cents"], T["items"])
            copy_rows(cur, "app.payment_methods", ["payment_method_id", "org_id", "card_brand", "card_last4", "exp_month", "exp_year", "billing_email", "processor_token", "is_default"], T["pms"])
            copy_rows(cur, "app.usage_events", ["org_id", "user_id", "event_type", "quantity", "metadata", "occurred_at"], T["events"])
            cur.execute("SELECT app.refresh_reporting_views()")

            # --- self-check: fail loudly, roll back ---
            results = run_checks(cur, acme_expect)
            failed = [n for n, ok, _ in results if not ok]
            for n, ok, _ in results:
                print(("PASS  " if ok else "FAIL  ") + n)
            if failed:
                conn.rollback()
                print(f"\n{len(failed)} self-check(s) failed. Nothing was committed.", file=sys.stderr)
                return 1

            print("\nRow counts:")
            for t in ["organizations", "users", "user_roles", "subscriptions", "invoices",
                      "invoice_items", "payment_methods", "usage_events"]:
                cur.execute(f"SELECT count(*) FROM app.{t}")
                print(f"  {t:<16}{cur.fetchone()[0]:>9,}")
            cur.execute("SELECT status, count(*) FROM app.organizations GROUP BY 1 ORDER BY 2 DESC")
            print("  org statuses:  " + ", ".join(f"{s}={c}" for s, c in cur.fetchall()))
        conn.commit()
    print("\nSeed committed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
