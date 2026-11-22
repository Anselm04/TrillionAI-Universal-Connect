# OAuth 2.0 authorization-code + PKCE lifecycle

The provider-neutral OAuth connection engine uses existing tenant-isolated PostgreSQL transactions, AES-256-GCM encryption and a fixed, guarded outbound transport.

## Implemented

1. `begin`: requires a server-verified actor/tenant principal, tenant-owned enabled connection and registered fixed provider config. Generates 256-bit random state and code verifier, S256 code challenge, and stores the state hash and encrypted verifier in a 10-minute PostgreSQL record. The authorization URL uses a fixed registered HTTPS redirect URI.
2. `complete`: requires a newly verified actor/tenant principal and the exact same tenant, connection, provider, and one-time state. State consumption is atomic *before* code exchange; failed exchanges do not allow replay. Authorization code is exchanged via the injected guarded transport, and returned bearer/refresh tokens are stored together encrypted as a single vault entry.
3. `refresh`: requires a verified principal and active connection, takes a PostgreSQL transaction advisory lock keyed by tenant/connection and refreshes tokens with no automatic unsafe parallel replay. Provider rotation updates access+refresh credentials together in the vault.
4. `disconnect`: attempts provider revocation first when a configured endpoint exists, then deletes encrypted local tokens. Revocation failures are surfaced, not silently ignored.

OAuth provider endpoints are registered infrastructure configuration, never user-provided URLs. Each approved token/revoke origin must also be placed in the hardened egress transport allowlist. This module contains no public callback endpoint; calling services must validate the current Identity session and explicitly authorize connect/refresh/revoke actions.

## Security and deployment requirements

- OAuth session/state is server-side. Keep the OAuth callback tied to a verified authenticated user session; do not trust state alone or complete a connection solely on public callback query parameters. Browser session + CSRF protection are required when adding web routes.
- OAuth app registration and consent screens are provider-specific. Some providers require a confidential OAuth client secret or HTTP Basic authentication at the token endpoint, and some return form-encoded tokens. Those providers need explicit reviewed extensions; never put client secrets in Flutter or source control.
- Refresh locks hold a database transaction while calling the upstream token endpoint and updating the vault. Keep network timeouts short, size DB pool appropriately, and add recoverable refresh state/rotation reconciliation for providers that invalidate the previous refresh token immediately. A crash after provider rotation but before vault persistence requires user reconnection or a provider-specific recovery mechanism.
- The generic OAuth service does not infer authorization from `Principal` fields: the application API **must** obtain a principal from Identity and enforce connection policy/capability consent. The service verifies tenant ownership at the database level but does not replace role/entitlement authorization.
- Never put access/refresh tokens, authorization codes, client secrets or PKCE verifiers into logs, analytics, URLs apart from provider-required short-lived authorization code callback parameters, or workflow payloads.
- TLS and IP-restricted egress, protected encryption key provider, webhook verification, distributed operation quotas, cleanup of expired pending states, token refresh scheduling, crash reconciliation, audit logs, provider-specific consent revocation, and live acceptance tests are still required for production.

CI tests use fake OAuth responses and disposable PostgreSQL, not paid provider calls or real customer credentials.
