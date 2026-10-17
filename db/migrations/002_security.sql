-- =====================================================================
-- 002_security.sql: roles, row-level security, agent-facing views, audit
--
-- Requires 001_schema.sql to have run first. Run as a superuser.
--
-- Security model (defense in depth: each layer assumes the one before it failed)
--
--   Layer 1  Python guardrails      (outside the DB)
--   Layer 2  Roles + GRANTs         agent_reader can only SELECT, only safe
--                                   columns, only through agent_api views
--   Layer 3  Row-level security     rows are filtered to ONE tenant, set per
--                                   transaction via app.current_org_id
--   Layer 4  Session limits         statement_timeout, read-only default,
--                                   temp file cap, connection cap
--   Layer 5  Append-only audit log  agent roles cannot read or write it
--
-- Roles
--   agent_reader  runs every normal question. SELECT only.
--   agent_writer  used ONLY after the user confirms a risky action.
--   agent_ops     metrics and audit logging. Not tenant-scoped.
--   app_owner     owns all objects (NOLOGIN, created in 001).
--
-- KNOWN LIMIT: the tenant id travels in a session setting. Postgres cannot
-- stop a connected role from running SET app.current_org_id = '...', so the
-- Python SQL validator MUST reject SET / RESET / set_config() in generated SQL.
-- The Python layer sets the tenant with set_config(..., true) on its own.
-- =====================================================================
BEGIN;

-- ---------------------------------------------------------------------
-- 1. Login roles (superuser section)
--    The passwords below are DEVELOPMENT placeholders. Change them:
--      ALTER ROLE agent_reader PASSWORD '...';
-- ---------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_reader') THEN
    CREATE ROLE agent_reader LOGIN PASSWORD 'agent_reader_dev'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS CONNECTION LIMIT 20;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_writer') THEN
    CREATE ROLE agent_writer LOGIN PASSWORD 'agent_writer_dev'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS CONNECTION LIMIT 5;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_ops') THEN
    CREATE ROLE agent_ops LOGIN PASSWORD 'agent_ops_dev'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS CONNECTION LIMIT 5;
  END IF;
END $$;

-- Per-role session limits. These apply at LOGIN; SET ROLE does not pick them up.
ALTER ROLE agent_reader SET search_path                        = agent_api, public;
ALTER ROLE agent_reader SET statement_timeout                  = '5s';
ALTER ROLE agent_reader SET lock_timeout                       = '2s';
ALTER ROLE agent_reader SET idle_in_transaction_session_timeout = '15s';
ALTER ROLE agent_reader SET default_transaction_read_only      = on;
ALTER ROLE agent_reader SET temp_file_limit                    = '256MB';
ALTER ROLE agent_reader SET work_mem                           = '16MB';

ALTER ROLE agent_writer SET search_path                        = agent_api, public;
ALTER ROLE agent_writer SET statement_timeout                  = '10s';
ALTER ROLE agent_writer SET lock_timeout                       = '3s';
ALTER ROLE agent_writer SET idle_in_transaction_session_timeout = '30s';

ALTER ROLE agent_ops    SET search_path                        = app, public;
ALTER ROLE agent_ops    SET statement_timeout                  = '10s';

-- Nobody connects by default. Only these roles may reach this database.
DO $$
BEGIN
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO agent_reader, agent_writer, agent_ops',
                 current_database());
  -- REFRESH MATERIALIZED VIEW CONCURRENTLY needs a temp table, and the refresh
  -- function runs as app_owner. The agent roles get no TEMP privilege.
  EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO app_owner', current_database());
END $$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;   -- no one creates objects in public
-- citext operators live in public, so the agent roles need to see it (read only).
GRANT USAGE ON SCHEMA public TO agent_reader, agent_writer, agent_ops;

-- ---------------------------------------------------------------------
-- 2. The agent-facing schema (owned by app_owner)
-- ---------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS agent_api AUTHORIZATION app_owner;
COMMENT ON SCHEMA agent_api IS
  'The ONLY schema the SQL agent may query. Curated views; sensitive columns are not exposed.';

SET LOCAL ROLE app_owner;
SET LOCAL search_path = app, public;

-- ---------------------------------------------------------------------
-- 3. Tenant context + row-level security
-- ---------------------------------------------------------------------
-- Fails closed: if no tenant is set, current_org() is NULL and no rows match.
CREATE FUNCTION app.current_org() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('app.current_org_id', true), '')::uuid
$$;
COMMENT ON FUNCTION app.current_org() IS
  'Tenant for this transaction. Set with: SELECT set_config(''app.current_org_id'', <uuid>, true).';

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['organizations','users','user_roles','subscriptions',
                           'invoices','invoice_items','payment_methods','usage_events']
  LOOP
    EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', t);
    -- (SELECT ...) wrapper makes Postgres evaluate current_org() once per query, not per row.
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON app.%I
         AS PERMISSIVE FOR ALL TO agent_reader, agent_writer
         USING      (org_id = (SELECT app.current_org()))
         WITH CHECK (org_id = (SELECT app.current_org()))', t);
  END LOOP;
END $$;
-- Table owner is not subject to RLS (no FORCE): app_owner and superusers keep
-- maintenance access. agent roles are not owners, so they are always filtered.
-- Partitions need no policy: agent roles hold no grants on them, so they can
-- only reach usage_events through the parent, where the policy applies.

-- ---------------------------------------------------------------------
-- 4. Column-level grants on base tables (what the views may read)
--    Not granted anywhere: users.password_hash, payment_methods.processor_token
-- ---------------------------------------------------------------------
GRANT USAGE ON SCHEMA app TO agent_reader, agent_writer;   -- needed by security_invoker views
GRANT EXECUTE ON FUNCTION app.current_org() TO agent_reader, agent_writer;

GRANT SELECT (org_id, name, slug, country_code, status, created_at)
  ON app.organizations TO agent_reader, agent_writer;
GRANT SELECT (user_id, org_id, email, full_name, phone, status, created_at, last_login_at)
  ON app.users TO agent_reader, agent_writer;
GRANT SELECT (payment_method_id, org_id, card_brand, card_last4, exp_month, exp_year,
              billing_email, is_default)
  ON app.payment_methods TO agent_reader, agent_writer;
GRANT SELECT ON app.plans, app.roles, app.user_roles, app.subscriptions,
                app.invoices, app.invoice_items, app.usage_events
  TO agent_reader, agent_writer;

-- Writer: the narrow set of risky actions the demo supports (after confirmation).
GRANT UPDATE (status, full_name, phone) ON app.users TO agent_writer;
GRANT DELETE ON app.users        TO agent_writer;
GRANT DELETE ON app.usage_events TO agent_writer;

-- ---------------------------------------------------------------------
-- 5. agent_api views (security_invoker => RLS applies as the caller)
-- ---------------------------------------------------------------------
CREATE VIEW agent_api.organizations WITH (security_invoker = true) AS
  SELECT org_id, name, slug, country_code, status, created_at FROM app.organizations;

CREATE VIEW agent_api.users WITH (security_invoker = true) AS
  SELECT user_id, org_id, email, full_name, phone, status, created_at, last_login_at
  FROM app.users;

CREATE VIEW agent_api.plans WITH (security_invoker = true) AS
  SELECT plan_id, code, name, monthly_price_cents, seat_limit, included_api_calls, is_active
  FROM app.plans;

CREATE VIEW agent_api.roles WITH (security_invoker = true) AS
  SELECT role_id, name, description FROM app.roles;

CREATE VIEW agent_api.user_roles WITH (security_invoker = true) AS
  SELECT org_id, user_id, role_id, granted_at FROM app.user_roles;

CREATE VIEW agent_api.subscriptions WITH (security_invoker = true) AS
  SELECT subscription_id, org_id, plan_id, status, billing_cycle, seats, started_at, ended_at
  FROM app.subscriptions;

CREATE VIEW agent_api.invoices WITH (security_invoker = true) AS
  SELECT invoice_id, org_id, subscription_id, invoice_number, status, currency, amount_cents,
         issued_at, due_at, paid_at
  FROM app.invoices;

CREATE VIEW agent_api.invoice_items WITH (security_invoker = true) AS
  SELECT item_id, org_id, invoice_id, description, quantity, unit_price_cents, line_total_cents
  FROM app.invoice_items;

CREATE VIEW agent_api.payment_methods WITH (security_invoker = true) AS
  SELECT payment_method_id, org_id, card_brand, card_last4, exp_month, exp_year,
         billing_email, is_default
  FROM app.payment_methods;

CREATE VIEW agent_api.usage_events WITH (security_invoker = true) AS
  SELECT event_id, org_id, user_id, event_type, quantity, metadata, occurred_at
  FROM app.usage_events;

-- Materialized views cannot have RLS, so the wrappers filter explicitly.
-- (No security_invoker here: the caller has no access to app.mv_*; the view
-- owner reads it, and the WHERE clause is the tenant boundary.)
CREATE VIEW agent_api.monthly_usage AS
  SELECT org_id, month, event_type, event_count, total_quantity
  FROM app.mv_monthly_usage
  WHERE org_id = app.current_org();

CREATE VIEW agent_api.monthly_revenue AS
  SELECT org_id, month, invoice_count, invoiced_cents, paid_cents
  FROM app.mv_monthly_revenue
  WHERE org_id = app.current_org();

-- Schema description the Python prompt-builder reads to give the LLM context.
CREATE VIEW agent_api.schema_catalog AS
  SELECT c.relname                                  AS table_name,
         a.attname                                  AS column_name,
         format_type(a.atttypid, a.atttypmod)       AS data_type,
         NOT a.attnotnull                           AS is_nullable,
         obj_description(c.oid, 'pg_class')         AS table_comment,
         col_description(c.oid, a.attnum)           AS column_comment
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
  WHERE n.nspname = 'agent_api' AND c.relkind = 'v' AND c.relname <> 'schema_catalog'
  ORDER BY c.relname, a.attnum;

-- Reader gets SELECT on every view. Writer gets SELECT plus targeted DML on two.
GRANT USAGE ON SCHEMA agent_api TO agent_reader, agent_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA agent_api TO agent_reader, agent_writer;
GRANT UPDATE (status, full_name, phone) ON agent_api.users TO agent_writer;
GRANT DELETE ON agent_api.users        TO agent_writer;
GRANT DELETE ON agent_api.usage_events TO agent_writer;

-- ---------------------------------------------------------------------
-- 6. Documentation for the LLM (surfaced through agent_api.schema_catalog)
-- ---------------------------------------------------------------------
COMMENT ON VIEW agent_api.organizations IS
  'Customer companies (tenants). Rows are automatically limited to the current organization; do not filter by org_id.';
COMMENT ON VIEW agent_api.users IS
  'People belonging to the organization. Contains PII (email, phone). Join roles via user_roles.';
COMMENT ON VIEW agent_api.plans IS
  'Global pricing plans. Prices are in cents. seat_limit NULL means unlimited.';
COMMENT ON VIEW agent_api.roles IS
  'Global role definitions: owner, admin, billing, member, viewer.';
COMMENT ON VIEW agent_api.user_roles IS
  'Many-to-many link: users.user_id = user_roles.user_id AND user_roles.role_id = roles.role_id.';
COMMENT ON VIEW agent_api.subscriptions IS
  'Subscription history. Live statuses: trialing, active, past_due. Join: subscriptions.plan_id = plans.plan_id. ended_at NULL means still running.';
COMMENT ON VIEW agent_api.invoices IS
  'Invoices per subscription. Join: invoices.subscription_id = subscriptions.subscription_id. Amounts are in cents. paid_at is set only when status = paid.';
COMMENT ON VIEW agent_api.invoice_items IS
  'Line items. Join: invoice_items.invoice_id = invoices.invoice_id. line_total_cents = quantity * unit_price_cents.';
COMMENT ON VIEW agent_api.payment_methods IS
  'Cards on file. Only brand, last 4 digits and expiry are exposed; no card numbers or tokens.';
COMMENT ON VIEW agent_api.usage_events IS
  'Large event table, partitioned by month. ALWAYS filter on occurred_at. metadata is jsonb (e.g. metadata->>''endpoint'').';
COMMENT ON VIEW agent_api.monthly_usage IS
  'Precomputed usage per month and event_type. Prefer this over scanning usage_events for monthly totals.';
COMMENT ON VIEW agent_api.monthly_revenue IS
  'Precomputed monthly invoiced and paid amounts in cents (drafts excluded). Prefer this for revenue questions.';

COMMENT ON COLUMN agent_api.users.email  IS 'PII: email address.';
COMMENT ON COLUMN agent_api.users.phone  IS 'PII: phone number. May be NULL.';
COMMENT ON COLUMN agent_api.users.status IS 'invited | active | deactivated';
COMMENT ON COLUMN agent_api.organizations.status IS 'trial | active | suspended | churned';
COMMENT ON COLUMN agent_api.subscriptions.status IS 'trialing | active | past_due | canceled';
COMMENT ON COLUMN agent_api.invoices.status IS 'draft | open | paid | void | uncollectible';
COMMENT ON COLUMN agent_api.invoices.amount_cents IS 'Total in cents. Divide by 100 for currency units.';
COMMENT ON COLUMN agent_api.usage_events.event_type IS 'api_call | storage_gb | seat_login | export | webhook';
COMMENT ON COLUMN agent_api.payment_methods.billing_email IS 'PII: billing contact email.';

-- ---------------------------------------------------------------------
-- 7. Audit log: append-only, written only through a SECURITY DEFINER function
-- ---------------------------------------------------------------------
CREATE FUNCTION app.audit_log_is_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'agent_audit_log is append-only (% blocked)', TG_OP;
END $$;

CREATE TRIGGER trg_audit_no_update_delete
  BEFORE UPDATE OR DELETE ON app.agent_audit_log
  FOR EACH ROW EXECUTE FUNCTION app.audit_log_is_append_only();

CREATE TRIGGER trg_audit_no_truncate
  BEFORE TRUNCATE ON app.agent_audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION app.audit_log_is_append_only();

CREATE FUNCTION app.log_agent_query(
  p_org_id            uuid,
  p_question          text,
  p_generated_sql     text,
  p_status            app.audit_status,
  p_guardrail         text    DEFAULT NULL,
  p_block_reason      text    DEFAULT NULL,
  p_row_count         integer DEFAULT NULL,
  p_latency_ms        integer DEFAULT NULL,
  p_prompt_tokens     integer DEFAULT NULL,
  p_completion_tokens integer DEFAULT NULL,
  p_model             text    DEFAULT NULL
) RETURNS bigint
LANGUAGE sql SECURITY DEFINER SET search_path = app, pg_temp AS $$
  INSERT INTO app.agent_audit_log
    (org_id, question, generated_sql, status, guardrail, block_reason,
     row_count, latency_ms, prompt_tokens, completion_tokens, model)
  VALUES
    (p_org_id, p_question, p_generated_sql, p_status, p_guardrail, p_block_reason,
     p_row_count, p_latency_ms, p_prompt_tokens, p_completion_tokens, p_model)
  RETURNING audit_id;
$$;

-- Let agent_ops refresh the materialized views without owning them.
ALTER FUNCTION app.refresh_reporting_views() SECURITY DEFINER SET search_path = app, pg_temp;

-- ---------------------------------------------------------------------
-- 8. Observability views (KPIs for the README)
-- ---------------------------------------------------------------------
CREATE VIEW app.agent_metrics_daily AS
SELECT (created_at AT TIME ZONE 'UTC')::date                                    AS day,
       count(*)                                                                 AS requests,
       count(*) FILTER (WHERE status IN ('allowed', 'confirmed'))               AS answered,
       count(*) FILTER (WHERE status = 'blocked')                               AS blocked,
       count(*) FILTER (WHERE status = 'needs_confirmation')                    AS needs_confirmation,
       count(*) FILTER (WHERE status = 'rejected')                              AS rejected,
       count(*) FILTER (WHERE status = 'error')                                 AS errors,
       round(100.0 * count(*) FILTER (WHERE status IN ('blocked', 'rejected'))
             / count(*), 2)                                                     AS refusal_rate_pct,
       round(avg(latency_ms))::int                                              AS avg_latency_ms,
       (percentile_cont(0.5)  WITHIN GROUP (ORDER BY latency_ms))::int          AS p50_latency_ms,
       (percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms))::int          AS p95_latency_ms,
       coalesce(sum(prompt_tokens), 0)::bigint                                  AS prompt_tokens,
       coalesce(sum(completion_tokens), 0)::bigint                              AS completion_tokens
FROM app.agent_audit_log
GROUP BY 1;

CREATE VIEW app.agent_blocks_by_guardrail AS
SELECT coalesce(guardrail, 'unspecified') AS guardrail,
       count(*)                           AS blocked_count
FROM app.agent_audit_log
WHERE status IN ('blocked', 'rejected')
GROUP BY 1;

COMMENT ON VIEW app.agent_metrics_daily IS
  'Daily KPIs from the audit log: volume, refusal rate, latency percentiles, token usage.';
COMMENT ON VIEW app.agent_blocks_by_guardrail IS
  'How many requests each guardrail stopped.';

-- ---------------------------------------------------------------------
-- 9. agent_ops grants (the only role that touches the audit log)
-- ---------------------------------------------------------------------
GRANT USAGE ON SCHEMA app TO agent_ops;
GRANT SELECT ON app.agent_audit_log, app.agent_metrics_daily, app.agent_blocks_by_guardrail
  TO agent_ops;
GRANT EXECUTE ON FUNCTION app.refresh_reporting_views() TO agent_ops;
GRANT EXECUTE ON FUNCTION app.log_agent_query(
  uuid, text, text, app.audit_status, text, text, integer, integer, integer, integer, text
) TO agent_ops;

-- ---------------------------------------------------------------------
-- 10. Lock down functions: nobody gets EXECUTE by accident
-- ---------------------------------------------------------------------
REVOKE EXECUTE ON FUNCTION app.refresh_reporting_views()  FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION app.ensure_usage_partition(date) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION app.set_updated_at()           FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION app.audit_log_is_append_only() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION app.log_agent_query(
  uuid, text, text, app.audit_status, text, text, integer, integer, integer, integer, text
) FROM PUBLIC;
-- Triggers still fire: trigger functions do not need EXECUTE for the table's users.

RESET ROLE;
COMMIT;
