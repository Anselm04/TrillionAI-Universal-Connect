-- Persist independent token verification results without storing provider secrets.
BEGIN;
CREATE TABLE IF NOT EXISTS universal_connect.connection_health (
  connection_id text PRIMARY KEY REFERENCES universal_connect.connections(id) ON DELETE CASCADE,
  tenant_id text NOT NULL,
  state text NOT NULL CHECK(state IN ('connected','reconnect_required','unavailable')),
  checked_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS connection_health_tenant_idx
  ON universal_connect.connection_health(tenant_id,checked_at DESC);
ALTER TABLE universal_connect.connection_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.connection_health FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_connection_health ON universal_connect.connection_health;
CREATE POLICY tenant_connection_health ON universal_connect.connection_health
 USING(tenant_id=nullif(current_setting('app.tenant_id',true),''))
 WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),''));
GRANT SELECT,INSERT,UPDATE(state,checked_at) ON universal_connect.connection_health TO uc_runtime;
COMMIT;
