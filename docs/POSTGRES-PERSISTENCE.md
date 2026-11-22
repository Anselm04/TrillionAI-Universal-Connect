# PostgreSQL tenant persistence

This subsystem provides real PostgreSQL implementations of the connector gateway's connection lookup, approval consumption and audit append interfaces. No external managed service is needed: CI uses an ephemeral PostgreSQL service.

## Database roles

Run migrations as a dedicated migration owner. Provision the `uc_runtime` role separately without SUPERUSER, BYPASSRLS, table ownership or DDL privileges. Apply `001_tenant_persistence.sql` followed by `002_runtime_grants.sql`. The application uses only `uc_runtime` credentials.

Connections and approval records must be created by separately authenticated, authorization-checked management services. Runtime access is intentionally limited to connection SELECT, approval SELECT + UPDATE(consumed_at) and audit INSERT + SELECT.

Every runtime database operation runs inside an explicit transaction with transaction-local `app.tenant_id`. FORCE ROW LEVEL SECURITY provides defense in depth; database ownership and bypass privileges would invalidate that guarantee. Reject an unscoped tenant request. Never let the HTTP client choose its principal/tenant directly.

An approval binds tenant, actor, connection, capability, canonical request payload, optional idempotency key and expiry. `UPDATE ... RETURNING` consumes it once atomically, including concurrent callers. Applications issuing approvals must persist the same `approvalRequestDigest`, and must verify the authorization of the issuing actor.

Audit entries are appended using a runtime role that has no UPDATE/DELETE privileges. For compliance requirements use additional tamper-evident off-database export; a privileged database administrator can still modify stored logs.

## Remaining requirements

This PR does not provision a real identity provider, expose a customer API or store external provider tokens. It does not yet guarantee exactly-once external execution: approval is consumed *before* provider execution, and retry reconciliation requires a durable operation ledger and idempotency implementation. Privileged migrations, disaster recovery and backups require separate operational work.

The integration test runs PostgreSQL locally on a CI runner with temporary test-only credentials. Never use those credentials for production.
