-- Privilege-separated workflow management + immutable authorization events.
BEGIN;
CREATE TABLE IF NOT EXISTS universal_connect.workflow_management_audit (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL,
  run_id uuid NOT NULL,
  operator_id text NOT NULL,
  action text NOT NULL CHECK(action IN ('delegation.issued','delegation.revoked','recovery.accepted')),
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE universal_connect.workflow_management_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.workflow_management_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workflow_management_audit_tenant ON universal_connect.workflow_management_audit;
CREATE POLICY workflow_management_audit_tenant ON universal_connect.workflow_management_audit
  USING (tenant_id=nullif(current_setting('app.tenant_id',true),''))
  WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),''));
-- This role is intentionally separate from uc_runtime used by connector workers.
-- Provision its password only in a protected management backend.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'uc_manager') THEN
    CREATE ROLE uc_manager NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA universal_connect TO uc_manager;
GRANT SELECT ON universal_connect.workflow_runs TO uc_manager;
GRANT SELECT ON universal_connect.workflow_steps TO uc_manager;
GRANT SELECT, INSERT, UPDATE(revoked_at) ON universal_connect.workflow_delegations TO uc_manager;
GRANT SELECT, UPDATE(status,current_step,updated_at) ON universal_connect.workflow_runs TO uc_manager;
GRANT SELECT, UPDATE(status,last_error,updated_at) ON universal_connect.workflow_steps TO uc_manager;
GRANT INSERT, SELECT ON universal_connect.workflow_reconciliations TO uc_manager;
GRANT INSERT, SELECT ON universal_connect.workflow_management_audit TO uc_manager;
COMMIT;
