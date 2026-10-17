-- =====================================================================
-- 001_schema.sql: core schema for the multi-tenant SaaS demo
--
-- Requires PostgreSQL 15+ (uses ON DELETE SET NULL (column) on a composite FK).
-- Run as a superuser. Every object below ends up owned by the NOLOGIN role
-- app_owner, so ownership is separate from the roles the agent connects as.
--
-- Design notes
--   * Tenant key: every tenant-scoped table carries org_id.
--   * Composite FKs (org_id, x_id) make cross-tenant references impossible
--     at the database level, e.g. an invoice can never point at another
--     organization's subscription.
--   * usage_events is range-partitioned by month on occurred_at.
--   * Reporting aggregates live in materialized views.
-- =====================================================================
BEGIN;

CREATE EXTENSION IF NOT EXISTS citext;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_owner') THEN
    CREATE ROLE app_owner NOLOGIN;
  END IF;
END $$;

CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION app_owner;
COMMENT ON SCHEMA app IS 'Base tables. Never exposed to the agent directly; see agent_api views.';

SET LOCAL ROLE app_owner;
SET LOCAL search_path = app, public;

-- ---------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------
CREATE TYPE app.org_status          AS ENUM ('trial', 'active', 'suspended', 'churned');
CREATE TYPE app.user_status         AS ENUM ('invited', 'active', 'deactivated');
CREATE TYPE app.subscription_status AS ENUM ('trialing', 'active', 'past_due', 'canceled');
CREATE TYPE app.billing_cycle       AS ENUM ('monthly', 'annual');
CREATE TYPE app.invoice_status      AS ENUM ('draft', 'open', 'paid', 'void', 'uncollectible');
CREATE TYPE app.event_type          AS ENUM ('api_call', 'storage_gb', 'seat_login', 'export', 'webhook');
CREATE TYPE app.audit_status        AS ENUM ('allowed', 'blocked', 'needs_confirmation', 'confirmed', 'rejected', 'error');

-- ---------------------------------------------------------------------
-- Generic trigger: keep updated_at fresh
-- ---------------------------------------------------------------------
CREATE FUNCTION app.set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- ---------------------------------------------------------------------
-- Global reference data (not tenant-scoped)
-- ---------------------------------------------------------------------
CREATE TABLE app.plans (
  plan_id             smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  code                text    NOT NULL UNIQUE,
  name                text    NOT NULL,
  monthly_price_cents integer NOT NULL CHECK (monthly_price_cents >= 0),
  seat_limit          integer CHECK (seat_limit IS NULL OR seat_limit > 0),
  included_api_calls  integer NOT NULL DEFAULT 0 CHECK (included_api_calls >= 0),
  is_active           boolean NOT NULL DEFAULT true
);

CREATE TABLE app.roles (
  role_id     smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name        text NOT NULL UNIQUE,
  description text
);

-- ---------------------------------------------------------------------
-- Tenants and users
-- ---------------------------------------------------------------------
CREATE TABLE app.organizations (
  org_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL,
  slug         text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]+$'),
  country_code char(2) NOT NULL CHECK (country_code ~ '^[A-Z]{2}$'),
  status       app.org_status NOT NULL DEFAULT 'trial',
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.users (
  user_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL REFERENCES app.organizations (org_id) ON DELETE CASCADE,
  email         citext NOT NULL CHECK (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  full_name     text NOT NULL,
  phone         text,
  password_hash text NOT NULL,
  status        app.user_status NOT NULL DEFAULT 'invited',
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  UNIQUE (org_id, email),
  UNIQUE (org_id, user_id)          -- target for composite tenant-safe FKs
);

-- Many-to-many: users <-> roles
CREATE TABLE app.user_roles (
  org_id     uuid     NOT NULL,
  user_id    uuid     NOT NULL,
  role_id    smallint NOT NULL REFERENCES app.roles (role_id),
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (org_id, user_id) REFERENCES app.users (org_id, user_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------
-- Billing
-- ---------------------------------------------------------------------
CREATE TABLE app.subscriptions (
  subscription_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid     NOT NULL REFERENCES app.organizations (org_id) ON DELETE CASCADE,
  plan_id         smallint NOT NULL REFERENCES app.plans (plan_id),
  status          app.subscription_status NOT NULL,
  billing_cycle   app.billing_cycle NOT NULL DEFAULT 'monthly',
  seats           integer NOT NULL DEFAULT 1 CHECK (seats > 0),
  started_at      timestamptz NOT NULL DEFAULT now(),
  ended_at        timestamptz,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CHECK (ended_at IS NULL OR ended_at > started_at),
  UNIQUE (org_id, subscription_id)
);

-- Partial unique index: at most one live subscription per organization.
CREATE UNIQUE INDEX uq_subscriptions_one_live_per_org
  ON app.subscriptions (org_id)
  WHERE status IN ('trialing', 'active', 'past_due');

CREATE TABLE app.invoices (
  invoice_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL,
  subscription_id uuid NOT NULL,
  invoice_number  text NOT NULL UNIQUE,
  status          app.invoice_status NOT NULL DEFAULT 'draft',
  currency        char(3) NOT NULL DEFAULT 'USD' CHECK (currency ~ '^[A-Z]{3}$'),
  amount_cents    bigint NOT NULL CHECK (amount_cents >= 0),
  issued_at       timestamptz NOT NULL DEFAULT now(),
  due_at          timestamptz NOT NULL,
  paid_at         timestamptz,
  CHECK (due_at >= issued_at),
  CHECK ((status = 'paid') = (paid_at IS NOT NULL)),
  UNIQUE (org_id, invoice_id),
  FOREIGN KEY (org_id, subscription_id) REFERENCES app.subscriptions (org_id, subscription_id)
);

CREATE TABLE app.invoice_items (
  item_id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  org_id           uuid    NOT NULL,
  invoice_id       uuid    NOT NULL,
  description      text    NOT NULL,
  quantity         integer NOT NULL CHECK (quantity > 0),
  unit_price_cents integer NOT NULL CHECK (unit_price_cents >= 0),
  line_total_cents bigint GENERATED ALWAYS AS (quantity::bigint * unit_price_cents) STORED,
  FOREIGN KEY (org_id, invoice_id) REFERENCES app.invoices (org_id, invoice_id) ON DELETE CASCADE
);

CREATE TABLE app.payment_methods (
  payment_method_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL REFERENCES app.organizations (org_id) ON DELETE CASCADE,
  card_brand      text NOT NULL CHECK (card_brand IN ('visa', 'mastercard', 'amex', 'rupay')),
  card_last4      char(4) NOT NULL CHECK (card_last4 ~ '^[0-9]{4}$'),
  exp_month       smallint NOT NULL CHECK (exp_month BETWEEN 1 AND 12),
  exp_year        smallint NOT NULL CHECK (exp_year BETWEEN 2020 AND 2100),
  billing_email   citext NOT NULL,
  processor_token text NOT NULL,     -- secret: never exposed to the agent
  is_default      boolean NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX uq_payment_methods_one_default_per_org
  ON app.payment_methods (org_id) WHERE is_default;

-- ---------------------------------------------------------------------
-- Usage events: range-partitioned by month
-- ---------------------------------------------------------------------
CREATE TABLE app.usage_events (
  event_id    bigint GENERATED ALWAYS AS IDENTITY,
  org_id      uuid NOT NULL,
  user_id     uuid,
  event_type  app.event_type NOT NULL,
  quantity    integer NOT NULL DEFAULT 1 CHECK (quantity > 0),
  metadata    jsonb NOT NULL DEFAULT '{}'::jsonb,
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (event_id, occurred_at),
  FOREIGN KEY (org_id, user_id) REFERENCES app.users (org_id, user_id)
    ON DELETE SET NULL (user_id)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE app.usage_events_default PARTITION OF app.usage_events DEFAULT;

CREATE FUNCTION app.ensure_usage_partition(p_month date) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  v_start timestamptz := (date_trunc('month', p_month)::date)::timestamp AT TIME ZONE 'UTC';
  v_end   timestamptz := v_start + interval '1 month';
  v_name  text := format('usage_events_y%sm%s', to_char(v_start AT TIME ZONE 'UTC', 'YYYY'),
                                                to_char(v_start AT TIME ZONE 'UTC', 'MM'));
BEGIN
  EXECUTE format(
    'CREATE TABLE IF NOT EXISTS app.%I PARTITION OF app.usage_events FOR VALUES FROM (%L) TO (%L)',
    v_name, v_start, v_end);
  RETURN v_name;
END $$;

-- 14 months back through 3 months ahead of the day the migration runs.
SELECT app.ensure_usage_partition((date_trunc('month', now()) + make_interval(months => m))::date)
FROM generate_series(-14, 3) AS m;

-- ---------------------------------------------------------------------
-- Agent audit log (written only via a SECURITY DEFINER function, see 002)
-- ---------------------------------------------------------------------
CREATE TABLE app.agent_audit_log (
  audit_id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  org_id            uuid,
  question          text NOT NULL,
  generated_sql     text,
  status            app.audit_status NOT NULL,
  guardrail         text,                 -- which guardrail fired, if any
  block_reason      text,
  row_count         integer CHECK (row_count IS NULL OR row_count >= 0),
  latency_ms        integer CHECK (latency_ms IS NULL OR latency_ms >= 0),
  prompt_tokens     integer CHECK (prompt_tokens IS NULL OR prompt_tokens >= 0),
  completion_tokens integer CHECK (completion_tokens IS NULL OR completion_tokens >= 0),
  model             text,
  created_at        timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------
CREATE INDEX ix_users_org_status          ON app.users (org_id, status);
CREATE INDEX ix_users_last_login          ON app.users (last_login_at DESC) WHERE last_login_at IS NOT NULL;
CREATE INDEX ix_user_roles_role           ON app.user_roles (role_id);
CREATE INDEX ix_subscriptions_plan        ON app.subscriptions (plan_id);
CREATE INDEX ix_invoices_org_issued       ON app.invoices (org_id, issued_at DESC);
CREATE INDEX ix_invoices_subscription     ON app.invoices (subscription_id);
CREATE INDEX ix_invoices_open_due         ON app.invoices (due_at) WHERE status = 'open';
CREATE INDEX ix_invoice_items_invoice     ON app.invoice_items (org_id, invoice_id);

CREATE INDEX ix_usage_events_org_time     ON app.usage_events (org_id, occurred_at DESC);
CREATE INDEX ix_usage_events_type_time    ON app.usage_events (event_type, occurred_at);
CREATE INDEX ix_usage_events_user         ON app.usage_events (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX ix_usage_events_metadata     ON app.usage_events USING gin (metadata jsonb_path_ops);

CREATE INDEX ix_audit_created             ON app.agent_audit_log (created_at DESC);
CREATE INDEX ix_audit_status_created      ON app.agent_audit_log (status, created_at DESC);

-- ---------------------------------------------------------------------
-- updated_at triggers
-- ---------------------------------------------------------------------
CREATE TRIGGER trg_organizations_updated  BEFORE UPDATE ON app.organizations
  FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER trg_users_updated          BEFORE UPDATE ON app.users
  FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();
CREATE TRIGGER trg_subscriptions_updated  BEFORE UPDATE ON app.subscriptions
  FOR EACH ROW EXECUTE FUNCTION app.set_updated_at();

-- ---------------------------------------------------------------------
-- Materialized views (reporting aggregates)
-- Note: materialized views do not support RLS. They are only reachable
-- through the filtered wrapper views created in 002.
-- ---------------------------------------------------------------------
CREATE MATERIALIZED VIEW app.mv_monthly_usage AS
SELECT org_id,
       date_trunc('month', occurred_at AT TIME ZONE 'UTC')::date AS month,
       event_type,
       count(*)                AS event_count,
       sum(quantity)::bigint   AS total_quantity
FROM app.usage_events
GROUP BY 1, 2, 3;

CREATE UNIQUE INDEX ux_mv_monthly_usage ON app.mv_monthly_usage (org_id, month, event_type);

CREATE MATERIALIZED VIEW app.mv_monthly_revenue AS
SELECT org_id,
       date_trunc('month', issued_at AT TIME ZONE 'UTC')::date AS month,
       count(*)                                                     AS invoice_count,
       coalesce(sum(amount_cents) FILTER (WHERE status IN ('open', 'paid')), 0)::bigint AS invoiced_cents,
       coalesce(sum(amount_cents) FILTER (WHERE status = 'paid'), 0)::bigint            AS paid_cents
FROM app.invoices
WHERE status <> 'draft'
GROUP BY 1, 2;

CREATE UNIQUE INDEX ux_mv_monthly_revenue ON app.mv_monthly_revenue (org_id, month);

CREATE FUNCTION app.refresh_reporting_views() RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY app.mv_monthly_usage;
  REFRESH MATERIALIZED VIEW CONCURRENTLY app.mv_monthly_revenue;
END $$;

-- ---------------------------------------------------------------------
-- Reference data
-- ---------------------------------------------------------------------
INSERT INTO app.plans (code, name, monthly_price_cents, seat_limit, included_api_calls) VALUES
  ('free',       'Free',        0,     3,      1000),
  ('starter',    'Starter',     2900,  10,     50000),
  ('pro',        'Pro',         9900,  50,     500000),
  ('enterprise', 'Enterprise',  49900, NULL,   5000000);

INSERT INTO app.roles (name, description) VALUES
  ('owner',   'Full control of the organization, including billing'),
  ('admin',   'Manage users and settings'),
  ('billing', 'View and manage invoices and payment methods'),
  ('member',  'Regular product access'),
  ('viewer',  'Read-only product access');

RESET ROLE;
COMMIT;
