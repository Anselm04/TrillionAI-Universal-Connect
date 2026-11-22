-- OAuth PKCE flow metadata; no plaintext verifier, tokens, or client secrets.
BEGIN;
CREATE TABLE IF NOT EXISTS universal_connect.oauth_pending (
  state_hash text PRIMARY KEY CHECK(state_hash ~ '^[0-9a-f]{64}$'),
  tenant_id text NOT NULL,
  actor_id text NOT NULL,
  connection_id text NOT NULL REFERENCES universal_connect.connections(id) ON DELETE CASCADE,
  provider_id text NOT NULL,
  verifier_version text NOT NULL,
  verifier_nonce bytea NOT NULL CHECK(octet_length(verifier_nonce)=12),
  verifier_tag bytea NOT NULL CHECK(octet_length(verifier_tag)=16),
  verifier_ciphertext bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oauth_pending_tenant_idx ON universal_connect.oauth_pending(tenant_id,connection_id);
ALTER TABLE universal_connect.oauth_pending ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.oauth_pending FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oauth_pending_tenant ON universal_connect.oauth_pending;
CREATE POLICY oauth_pending_tenant ON universal_connect.oauth_pending
  USING(tenant_id=nullif(current_setting('app.tenant_id',true),''))
  WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),''));
GRANT SELECT,INSERT,UPDATE(consumed_at) ON universal_connect.oauth_pending TO uc_runtime;
COMMIT;
