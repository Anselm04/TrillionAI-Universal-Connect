-- Delegated workflow execution must be explicitly authorized, scoped and expiring.
BEGIN;
CREATE TABLE IF NOT EXISTS universal_connect.workflow_delegations (
  tenant_id text NOT NULL,
  run_id uuid NOT NULL REFERENCES universal_connect.workflow_runs(id) ON DELETE CASCADE,
  actor_id text NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, run_id, actor_id)
);
CREATE TABLE IF NOT EXISTS universal_connect.workflow_reconciliations (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL,
  run_id uuid NOT NULL,
  step_index integer NOT NULL,
  reviewer_id text NOT NULL,
  decision text NOT NULL CHECK(decision IN ('confirmed_completed','confirmed_not_executed')),
  evidence_reference text NOT NULL CHECK(length(evidence_reference) BETWEEN 8 AND 512),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(tenant_id,run_id,step_index)
);
ALTER TABLE universal_connect.workflow_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.workflow_delegations FORCE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.workflow_reconciliations ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.workflow_reconciliations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workflow_delegations_tenant ON universal_connect.workflow_delegations;
CREATE POLICY workflow_delegations_tenant ON universal_connect.workflow_delegations
  USING(tenant_id=nullif(current_setting('app.tenant_id',true),''))
  WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),''));
DROP POLICY IF EXISTS workflow_reconciliations_tenant ON universal_connect.workflow_reconciliations;
CREATE POLICY workflow_reconciliations_tenant ON universal_connect.workflow_reconciliations
  USING(tenant_id=nullif(current_setting('app.tenant_id',true),''))
  WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),''));
-- Delegations are issued/revoked by a separate privileged management service, never by workers.
GRANT SELECT ON universal_connect.workflow_delegations TO uc_runtime;
-- Workers can append immutable reconciliation evidence only.
GRANT INSERT, SELECT ON universal_connect.workflow_reconciliations TO uc_runtime;
COMMIT;
