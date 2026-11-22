-- Self-service connections require explicit ownership, separate from tenant membership.
-- Older connection rows remain legacy/unmanaged until explicitly migrated by an administrator.
BEGIN;
CREATE TABLE IF NOT EXISTS universal_connect.connection_owners (
  connection_id text PRIMARY KEY REFERENCES universal_connect.connections(id) ON DELETE CASCADE,
  tenant_id text NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS connection_owners_actor_idx
  ON universal_connect.connection_owners(tenant_id,actor_id);
ALTER TABLE universal_connect.connection_owners ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.connection_owners FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_connection_owners ON universal_connect.connection_owners;
CREATE POLICY tenant_connection_owners ON universal_connect.connection_owners
  USING (tenant_id=nullif(current_setting('app.tenant_id',true),''))
  WITH CHECK (tenant_id=nullif(current_setting('app.tenant_id',true),''));
-- Provisioning is exclusively via the server after verified actor and tenant authorization.
GRANT SELECT, INSERT ON universal_connect.connection_owners TO uc_runtime;
GRANT INSERT ON universal_connect.connections TO uc_runtime;
-- Disabling a connection is allowed only via the self-service management backend.
GRANT UPDATE(enabled,updated_at) ON universal_connect.connections TO uc_runtime;
COMMIT;
