# Authoritative execution gateway — security contract

The gateway is an **application library**, not an HTTP endpoint or production identity provider.

Identity middleware MUST authenticate each request with a verified OIDC/JWT or appropriately protected service identity, and construct `Principal` **server-side**. Never trust tenant or subject fields supplied by a client.

ConnectionStore MUST return tenant-owned persisted connections from a database with tenant isolation.
PolicyEngine MUST enforce per-tenant entitlements, scopes, user roles and any elevated assurance requirements.
ApprovalStore MUST atomically verify *and consume* a narrowly scoped, unexpired, authenticated approval linked to tenant, actor, connection, operation **and request payload**. The provided SDK alone cannot establish these facts.
AuditSink MUST be durable and fail closed for sensitive operations; do not write secrets or full customer payloads to logs.
Write operations MUST have idempotency and reconciliation safeguards before being connected to external production APIs. This library does not implement distributed idempotency.
An interface or mock is **not** evidence that a production adapter, identity provider or database has been integrated.

Security follow-ups: authenticated HTTP API, PostgreSQL implementations with RLS, approval persistence/locking, durable audit, protected secrets, runtime operation input schemas, rate limiting, egress SSRF prevention, token lifecycle, production replay safety and end-to-end integration tests.

No live customer credentials, purchases, marketing posts or actual third-party integrations are activated by this PR.
