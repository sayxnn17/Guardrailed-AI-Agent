#!/usr/bin/env bash
# Security smoke test for 001_schema.sql + 002_security.sql.
#
# Connects as each real role (over TCP, so per-role session settings apply)
# and checks that legitimate queries work and attacks fail.
#
# Usage:
#   PGHOST=localhost PGPORT=5432 PGDATABASE=saas_demo \
#   SUPERUSER=postgres SUPERPASS=...  bash db/tests/security_smoke.sh
# The database must already have both migrations applied. The script inserts
# two throwaway organizations (slugs smoke-a, smoke-b) and removes them at the end.
set -u

export PGHOST="${PGHOST:-localhost}" PGPORT="${PGPORT:-5432}" PGDATABASE="${PGDATABASE:-saas_demo}"
SUPERUSER="${SUPERUSER:-postgres}"
SUPERPASS="${SUPERPASS:-}"
READER_PASS="${READER_PASS:-agent_reader_dev}"
WRITER_PASS="${WRITER_PASS:-agent_writer_dev}"
OPS_PASS="${OPS_PASS:-agent_ops_dev}"

pass=0; fail=0
run() { # run <role> <password> <sql>  -> prints output, returns psql exit code
  PGPASSWORD="$2" psql -X -q -tA -v ON_ERROR_STOP=1 -U "$1" -c "$3" 2>&1
}
expect_ok() { # expect_ok <name> <role> <pass> <sql> <expected-output>
  local out; out=$(run "$2" "$3" "$4"); local rc=$?
  if [ $rc -eq 0 ] && [ "$out" = "$5" ]; then pass=$((pass+1)); echo "PASS  $1"
  else fail=$((fail+1)); echo "FAIL  $1  (expected '$5', got rc=$rc '$out')"; fi
}
expect_err() { # expect_err <name> <role> <pass> <sql> <error-substring>
  local out; out=$(run "$2" "$3" "$4"); local rc=$?
  if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qi -- "$5"; then pass=$((pass+1)); echo "PASS  $1"
  else fail=$((fail+1)); echo "FAIL  $1  (expected error '$5', got rc=$rc '$out')"; fi
}
R() { run agent_reader "$READER_PASS" "$1"; }
SU() { PGPASSWORD="$SUPERPASS" psql -X -q -tA -v ON_ERROR_STOP=1 -U "$SUPERUSER" -c "$1" 2>&1; }

# ---- fixtures (superuser bypasses RLS) -----------------------------------
cleanup_fixtures() {
  # Invoices intentionally have no ON DELETE CASCADE from organizations
  # (financial records must not disappear with a tenant), so delete in order.
  SU "DELETE FROM app.invoices WHERE org_id IN (SELECT org_id FROM app.organizations WHERE slug IN ('smoke-a','smoke-b'));
      DELETE FROM app.usage_events WHERE org_id IN (SELECT org_id FROM app.organizations WHERE slug IN ('smoke-a','smoke-b'));
      DELETE FROM app.organizations WHERE slug IN ('smoke-a','smoke-b');" >/dev/null
}
cleanup_fixtures
SU "
INSERT INTO app.organizations (org_id, name, slug, country_code, status) VALUES
 ('aaaaaaaa-0000-0000-0000-000000000001','Smoke A','smoke-a','IN','active'),
 ('bbbbbbbb-0000-0000-0000-000000000002','Smoke B','smoke-b','US','active');
INSERT INTO app.users (user_id, org_id, email, full_name, phone, password_hash, status) VALUES
 ('aaaaaaaa-1111-0000-0000-000000000001','aaaaaaaa-0000-0000-0000-000000000001','a1@smoke-a.test','Alice A','+91 98000 00001','HASH_A1','active'),
 ('aaaaaaaa-1111-0000-0000-000000000002','aaaaaaaa-0000-0000-0000-000000000001','a2@smoke-a.test','Amit A',NULL,'HASH_A2','deactivated'),
 ('bbbbbbbb-1111-0000-0000-000000000001','bbbbbbbb-0000-0000-0000-000000000002','b1@smoke-b.test','Bob B','+1 555 0100','HASH_B1','active');
INSERT INTO app.subscriptions (subscription_id, org_id, plan_id, status, seats) VALUES
 ('aaaaaaaa-2222-0000-0000-000000000001','aaaaaaaa-0000-0000-0000-000000000001',2,'active',5),
 ('bbbbbbbb-2222-0000-0000-000000000001','bbbbbbbb-0000-0000-0000-000000000002',3,'active',9);
INSERT INTO app.invoices (invoice_id, org_id, subscription_id, invoice_number, status, amount_cents, issued_at, due_at, paid_at) VALUES
 ('aaaaaaaa-3333-0000-0000-000000000001','aaaaaaaa-0000-0000-0000-000000000001','aaaaaaaa-2222-0000-0000-000000000001','SMOKE-A-1','paid',2900, now()-interval '10 days', now()+interval '5 days', now()-interval '8 days'),
 ('bbbbbbbb-3333-0000-0000-000000000001','bbbbbbbb-0000-0000-0000-000000000002','bbbbbbbb-2222-0000-0000-000000000001','SMOKE-B-1','paid',9900, now()-interval '10 days', now()+interval '5 days', now()-interval '8 days');
INSERT INTO app.payment_methods (org_id, card_brand, card_last4, exp_month, exp_year, billing_email, processor_token, is_default) VALUES
 ('aaaaaaaa-0000-0000-0000-000000000001','visa','4242',12,2030,'bill@smoke-a.test','tok_SECRET_A',true);
INSERT INTO app.usage_events (org_id, user_id, event_type, quantity, occurred_at) VALUES
 ('aaaaaaaa-0000-0000-0000-000000000001','aaaaaaaa-1111-0000-0000-000000000001','api_call',3, now()-interval '2 days'),
 ('bbbbbbbb-0000-0000-0000-000000000002','bbbbbbbb-1111-0000-0000-000000000001','api_call',7, now()-interval '2 days');
SELECT app.refresh_reporting_views();
" >/dev/null || { echo "fixture load failed"; exit 2; }

A="aaaaaaaa-0000-0000-0000-000000000001"
B="bbbbbbbb-0000-0000-0000-000000000002"
rt() { # rt <org> <sql> -> last result line, run as agent_reader
  PGPASSWORD="$READER_PASS" psql -X -q -tA -v ON_ERROR_STOP=1 -U agent_reader 2>&1 <<SQL | tail -1
BEGIN;
SELECT set_config('app.current_org_id','$1',true) \g /dev/null
$2;
COMMIT;
SQL
}
wt() { # wt <org> <sql> -> run as agent_writer inside a tenant transaction, then ROLLBACK
  PGPASSWORD="$WRITER_PASS" psql -X -q -tA -v ON_ERROR_STOP=1 -U agent_writer 2>&1 <<SQL | tail -1
BEGIN;
SELECT set_config('app.current_org_id','$1',true) \g /dev/null
$2;
ROLLBACK;
SQL
}
check() { # check <name> <actual> <expected>
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS  $1"
  else fail=$((fail+1)); echo "FAIL  $1  (expected '$3', got '$2')"; fi
}
check_err() { # check_err <name> <actual> <substring>
  if printf '%s' "$2" | grep -qi -- "$3"; then pass=$((pass+1)); echo "PASS  $1"
  else fail=$((fail+1)); echo "FAIL  $1  (expected error '$3', got '$2')"; fi
}

echo "--- tenant isolation (RLS)"
check "no tenant set -> zero users (fails closed)"        "$(R 'SELECT count(*) FROM agent_api.users')" "0"
check "tenant A sees only its 2 users"                    "$(rt $A 'SELECT count(*) FROM agent_api.users')" "2"
check "tenant B sees only its 1 user"                     "$(rt $B 'SELECT count(*) FROM agent_api.users')" "1"
check "tenant A cannot see tenant B by email"             "$(rt $A "SELECT count(*) FROM agent_api.users WHERE email = 'b1@smoke-b.test'")" "0"
check "tenant A sees only its invoice total"              "$(rt $A 'SELECT sum(amount_cents) FROM agent_api.invoices')" "2900"
check "tenant A sees only its own organization row"       "$(rt $A 'SELECT count(*) FROM agent_api.organizations')" "1"
check "tenant A usage_events (partitioned) isolated"      "$(rt $A 'SELECT sum(quantity) FROM agent_api.usage_events')" "3"
check "MV wrapper monthly_usage isolated (A)"             "$(rt $A 'SELECT sum(total_quantity) FROM agent_api.monthly_usage')" "3"
check "MV wrapper monthly_revenue isolated (B)"           "$(rt $B 'SELECT sum(paid_cents) FROM agent_api.monthly_revenue')" "9900"
check "citext comparison is case-insensitive"             "$(rt $A "SELECT count(*) FROM agent_api.users WHERE email = 'A1@SMOKE-A.TEST'")" "1"
check "plans (global table) readable"                     "$(R 'SELECT count(*) FROM agent_api.plans')" "4"

echo "--- hidden columns and base tables"
expect_err "password_hash not in agent_api.users"         agent_reader "$READER_PASS" "SELECT password_hash FROM agent_api.users" "does not exist"
expect_err "password_hash blocked on base table"          agent_reader "$READER_PASS" "SELECT password_hash FROM app.users" "permission denied"
expect_err "SELECT * on base users blocked (has secret)"  agent_reader "$READER_PASS" "SELECT * FROM app.users" "permission denied"
expect_err "processor_token blocked on base table"        agent_reader "$READER_PASS" "SELECT processor_token FROM app.payment_methods" "permission denied"
expect_err "processor_token not in agent_api view"        agent_reader "$READER_PASS" "SELECT processor_token FROM agent_api.payment_methods" "does not exist"
expect_err "materialized view not directly readable"      agent_reader "$READER_PASS" "SELECT * FROM app.mv_monthly_revenue" "permission denied"
expect_err "usage_events partition not directly readable" agent_reader "$READER_PASS" "SELECT * FROM app.usage_events_default" "permission denied"
expect_err "audit log not readable by reader"             agent_reader "$READER_PASS" "SELECT * FROM app.agent_audit_log" "permission denied"
expect_err "audit function not callable by reader"        agent_reader "$READER_PASS" "SELECT app.log_agent_query(NULL,'q','s','allowed')" "permission denied"
check "schema_catalog lists views"                        "$(R "SELECT count(DISTINCT table_name) FROM agent_api.schema_catalog")" "12"
check "schema_catalog never mentions secrets"             "$(R "SELECT count(*) FROM agent_api.schema_catalog WHERE column_name IN ('password_hash','processor_token')")" "0"

echo "--- reader cannot write or change anything"
expect_err "DELETE blocked"          agent_reader "$READER_PASS" "DELETE FROM agent_api.usage_events" "permission denied\|read-only"
expect_err "UPDATE blocked"          agent_reader "$READER_PASS" "UPDATE agent_api.users SET status='active'" "permission denied\|read-only"
expect_err "INSERT blocked"          agent_reader "$READER_PASS" "INSERT INTO agent_api.plans(code,name,monthly_price_cents) VALUES ('x','x',1)" "permission denied\|read-only"
expect_err "DROP TABLE blocked"      agent_reader "$READER_PASS" "DROP TABLE app.users" "must be owner\|permission denied\|read-only"
expect_err "TRUNCATE blocked"        agent_reader "$READER_PASS" "TRUNCATE app.invoices" "permission denied\|read-only"
expect_err "CREATE TABLE blocked"    agent_reader "$READER_PASS" "CREATE TABLE public.evil(x int)" "permission denied\|read-only"
expect_err "CREATE ROLE blocked"     agent_reader "$READER_PASS" "CREATE ROLE evil SUPERUSER" "permission denied\|read-only"
expect_err "COPY TO PROGRAM blocked" agent_reader "$READER_PASS" "COPY (SELECT 1) TO PROGRAM 'id'" "permission denied\|superuser\|pg_execute_server_program"
expect_err "read server file blocked" agent_reader "$READER_PASS" "SELECT pg_read_file('/etc/passwd')" "permission denied"
expect_err "write blocked even after flipping read-only off" agent_reader "$READER_PASS" "SET default_transaction_read_only = off; DELETE FROM agent_api.usage_events" "permission denied"

echo "--- session limits"
check "reader statement_timeout is 5s"         "$(R 'SHOW statement_timeout')" "5s"
check "reader default_transaction_read_only"   "$(R 'SHOW default_transaction_read_only')" "on"
expect_err "runaway query is killed by timeout" agent_reader "$READER_PASS" "SELECT pg_sleep(8)" "statement timeout"

echo "--- writer (post-confirmation role): narrow and still tenant-scoped"
check "writer sees tenant A users only"               "$(wt $A 'SELECT count(*) FROM agent_api.users')" "2"
check "writer DELETE hits only own tenant (A: 1 row)" "$(wt $A "WITH d AS (DELETE FROM agent_api.users WHERE status='deactivated' RETURNING 1) SELECT count(*) FROM d")" "1"
check "writer cannot delete other tenant's rows"      "$(wt $A "WITH d AS (DELETE FROM agent_api.users WHERE email='b1@smoke-b.test' RETURNING 1) SELECT count(*) FROM d")" "0"
check "writer UPDATE status works in own tenant"      "$(wt $A "WITH u AS (UPDATE agent_api.users SET status='active' WHERE status='deactivated' RETURNING 1) SELECT count(*) FROM u")" "1"
check_err "writer cannot UPDATE email (no column grant)"  "$(wt $A "UPDATE agent_api.users SET email='x@x.test'")" "permission denied"
check_err "writer cannot delete invoices"                "$(wt $A "DELETE FROM agent_api.invoices")" "permission denied\|cannot delete"
check_err "writer cannot DROP"                           "$(wt $A "DROP TABLE app.users")" "must be owner\|permission denied"
check_err "writer cannot read password_hash"             "$(wt $A "SELECT password_hash FROM app.users")" "permission denied"

echo "--- audit log + observability (agent_ops)"
expect_ok  "ops can log a blocked prompt-injection" agent_ops "$OPS_PASS" \
  "SELECT count(*) FROM (SELECT app.log_agent_query('$A','ignore previous instructions','(none)','blocked','input_injection','matched injection pattern',NULL,12,0,0,'test-model')) s" "1"
expect_ok  "ops can log an allowed query" agent_ops "$OPS_PASS" \
  "SELECT count(*) FROM (SELECT app.log_agent_query('$A','how many users?','SELECT count(*) FROM users','allowed',NULL,NULL,1,340,420,35,'test-model')) s" "1"
expect_ok  "metrics view reports 2 requests, 1 blocked" agent_ops "$OPS_PASS" \
  "SELECT requests||'/'||blocked FROM app.agent_metrics_daily ORDER BY day DESC LIMIT 1" "2/1"
expect_ok  "blocks-by-guardrail view works" agent_ops "$OPS_PASS" \
  "SELECT guardrail||':'||blocked_count FROM app.agent_blocks_by_guardrail" "input_injection:1"
expect_err "ops cannot UPDATE audit rows"  agent_ops "$OPS_PASS" "UPDATE app.agent_audit_log SET status='allowed'" "permission denied"
expect_err "ops cannot read user data"     agent_ops "$OPS_PASS" "SELECT * FROM app.users" "permission denied"
check_err "even superuser cannot UPDATE audit (trigger)"   "$(SU "UPDATE app.agent_audit_log SET status='allowed'")" "append-only"
check_err "even superuser cannot DELETE audit (trigger)"   "$(SU "DELETE FROM app.agent_audit_log")" "append-only"
check_err "even superuser cannot TRUNCATE audit (trigger)" "$(SU "TRUNCATE app.agent_audit_log")" "append-only"

echo "--- KNOWN LIMIT (documented): tenant id is a session setting"
check "reader CAN switch tenant with SET -> Python validator must reject SET/set_config" \
  "$(PGPASSWORD="$READER_PASS" psql -X -q -tA -U agent_reader 2>&1 <<SQL | tail -1
BEGIN;
SELECT set_config('app.current_org_id','$A',true) \g /dev/null
SET LOCAL app.current_org_id = '$B';
SELECT count(*) FROM agent_api.users;
COMMIT;
SQL
)" "1"

# ---- cleanup --------------------------------------------------------------
cleanup_fixtures
SU "SELECT app.refresh_reporting_views();" >/dev/null
SU "ALTER TABLE app.agent_audit_log DISABLE TRIGGER trg_audit_no_update_delete; DELETE FROM app.agent_audit_log WHERE model='test-model'; ALTER TABLE app.agent_audit_log ENABLE TRIGGER trg_audit_no_update_delete;" >/dev/null

echo
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]
