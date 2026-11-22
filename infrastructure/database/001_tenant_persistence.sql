-- Run as migration owner; the runtime role must NOT own these tables.
BEGIN;
CREATE SCHEMA IF NOT EXISTS universal_connect;

CREATE TABLE IF NOT EXISTS universal_connect.connections (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  connector_id text NOT NULL,
  enabled boolean NOT NULL DEFAULT false,
  capabilities jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT connections_capabilities_array CHECK (jsonb_typeof(capabilities) = 'array'),
  CONSTRAINT connections_nonempty_ids CHECK (
    length(id) BETWEEN 1 AND 128 AND length(tenant_id) BETWEEN 1 AND 128
    AND length(connector_id) BETWEEN 1 AND 128)
);
CREATE INDEX IF NOT EXISTS connections_tenant_idx ON universal_connect.connections(tenant_id);

CREATE TABLE IF NOT EXISTS universal_connect.approvals (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  actor_id text NOT NULL,
  connection_id text NOT NULL REFERENCES universal_connect.connections(id),
  capability text NOT NULL,
  request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS approvals_tenant_idx ON universal_connect.approvals(tenant_id, connection_id);
CREATE TABLE IF NOT EXISTS universal_connect.audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  tenant_id text NOT NULL,
  actor_id text NOT NULL,
  connection_id text NOT NULL,
  connector_id text NOT NULL,
  capability text NOT NULL,
  event text NOT NULL CHECK (event IN ('connector.denied','connector.executed','connector.failed')),
  reason text
);
CREATE INDEX IF NOT EXISTS audit_tenant_time_idx
  ON universal_connect.audit_events(tenant_id, created_at DESC);

ALTER TABLE universal_connect.connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.connections FORCE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.audit_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_connection_access ON universal_connect.connections;
CREATE POLICY tenant_connection_access ON universal_connect.connections
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));
DROP POLICY IF EXISTS tenant_approval_access ON universal_connect.approvals;
CREATE POLICY tenant_approval_access ON universal_connect.approvals
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));
DROP POLICY IF EXISTS tenant_audit_access ON universal_connect.audit_events;
CREATE POLICY tenant_audit_access ON universal_connect.audit_events
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));
COMMIT;
