-- Persistent, atomic per-tenant/provider request budgets.
BEGIN;
CREATE TABLE IF NOT EXISTS universal_connect.provider_rate_limits (
  tenant_id text NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 128),
  provider_id text NOT NULL CHECK (provider_id ~ '^[a-z][a-z0-9._-]{1,127}$'),
  window_id bigint NOT NULL,
  request_count integer NOT NULL CHECK (request_count >= 0),
  PRIMARY KEY (tenant_id, provider_id, window_id)
);
CREATE INDEX IF NOT EXISTS provider_rate_limits_window_idx
  ON universal_connect.provider_rate_limits(window_id);
ALTER TABLE universal_connect.provider_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.provider_rate_limits FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_provider_rate_limits ON universal_connect.provider_rate_limits;
CREATE POLICY tenant_provider_rate_limits ON universal_connect.provider_rate_limits
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));
GRANT SELECT, INSERT, UPDATE(request_count) ON universal_connect.provider_rate_limits TO uc_runtime;
COMMIT;
