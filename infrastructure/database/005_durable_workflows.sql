-- Tenant-isolated sequential workflow journal. All runtime access via tenant-scoped transactions.
BEGIN;
CREATE TABLE IF NOT EXISTS universal_connect.workflow_runs (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
  definition_digest text NOT NULL CHECK (definition_digest ~ '^[0-9a-f]{64}$'),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','uncertain')),
  current_step integer NOT NULL DEFAULT 0 CHECK (current_step >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(tenant_id,idempotency_key)
);
CREATE TABLE IF NOT EXISTS universal_connect.workflow_steps (
  run_id uuid NOT NULL REFERENCES universal_connect.workflow_runs(id) ON DELETE CASCADE,
  tenant_id text NOT NULL,
  step_index integer NOT NULL CHECK (step_index >= 0),
  kind text NOT NULL CHECK (kind IN ('read','write')),
  connection_id text NOT NULL,
  request jsonb NOT NULL CHECK (jsonb_typeof(request)='object'),
  approval_id text,
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','uncertain')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 10),
  lease_token uuid,
  leased_until timestamptz,
  output jsonb,
  last_error text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(run_id,step_index),
  CONSTRAINT workflow_steps_approval CHECK (kind='read' OR approval_id IS NOT NULL),
  CONSTRAINT workflow_steps_lease CHECK (
    (status='running' AND lease_token IS NOT NULL AND leased_until IS NOT NULL)
    OR (status<>'running' AND lease_token IS NULL AND leased_until IS NULL))
);
CREATE INDEX IF NOT EXISTS workflow_steps_eligible_idx ON universal_connect.workflow_steps(tenant_id,status,leased_until);
CREATE INDEX IF NOT EXISTS workflow_runs_tenant_idx ON universal_connect.workflow_runs(tenant_id,status);
ALTER TABLE universal_connect.workflow_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.workflow_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.workflow_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.workflow_steps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workflow_run_tenant ON universal_connect.workflow_runs;
CREATE POLICY workflow_run_tenant ON universal_connect.workflow_runs
  USING (tenant_id=nullif(current_setting('app.tenant_id',true),''))
  WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),''));
DROP POLICY IF EXISTS workflow_step_tenant ON universal_connect.workflow_steps;
CREATE POLICY workflow_step_tenant ON universal_connect.workflow_steps
  USING (tenant_id=nullif(current_setting('app.tenant_id',true),''))
  WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),''));
GRANT SELECT,INSERT,UPDATE ON universal_connect.workflow_runs TO uc_runtime;
GRANT SELECT,INSERT,UPDATE ON universal_connect.workflow_steps TO uc_runtime;
COMMIT;
