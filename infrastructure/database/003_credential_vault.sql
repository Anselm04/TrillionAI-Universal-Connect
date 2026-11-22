-- Encrypted credential storage. Encryption keys never reside in this database.
BEGIN;
CREATE TABLE IF NOT EXISTS universal_connect.credentials (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  connection_id text NOT NULL REFERENCES universal_connect.connections(id) ON DELETE CASCADE,
  name text NOT NULL,
  key_version text NOT NULL,
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  tag bytea NOT NULL CHECK (octet_length(tag) = 16),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 65536),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT credentials_valid_name CHECK (name ~ '^[A-Za-z][A-Za-z0-9_-]{0,63}$'),
  CONSTRAINT credentials_nonempty_ids CHECK (
    length(id) BETWEEN 1 AND 128 AND length(tenant_id) BETWEEN 1 AND 128
    AND length(connection_id) BETWEEN 1 AND 128 AND length(key_version) BETWEEN 1 AND 128),
  CONSTRAINT credentials_unique_name UNIQUE (tenant_id, connection_id, name)
);
CREATE INDEX IF NOT EXISTS credentials_connection_idx ON universal_connect.credentials(tenant_id, connection_id);
ALTER TABLE universal_connect.credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE universal_connect.credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_credentials ON universal_connect.credentials;
CREATE POLICY tenant_credentials ON universal_connect.credentials
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));
-- Scoped backend only; no direct end-user database connections.
GRANT SELECT, INSERT, UPDATE, DELETE ON universal_connect.credentials TO uc_runtime;
COMMIT;
