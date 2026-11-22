-- Audited customer OAuth connection lifecycle, deliberately excluding secrets.
BEGIN;
CREATE TABLE IF NOT EXISTS universal_connect.oauth_connection_events (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL,
  actor_id text NOT NULL,
  connection_id text NOT NULL,
  provider_id text NOT NULL,
  action text NOT NULL CHECK (action IN ('oauth.started','oauth.connected','oauth.disconnected')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oauth_connection_events_tenant_idx
  ON universal_connect.oauth_connection_events(tenant_id,created_at DESC);
ALTER TABLE universal_connect.oauth_connection_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.oauth_connection_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oauth_connection_events_tenant ON universal_connect.oauth_connection_events;
CREATE POLICY oauth_connection_events_tenant ON universal_connect.oauth_connection_events
  USING(tenant_id=nullif(current_setting('app.tenant_id',true),''))
  WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),''));
GRANT INSERT, SELECT ON universal_connect.oauth_connection_events TO uc_runtime;
COMMIT;
