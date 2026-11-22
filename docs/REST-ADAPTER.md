# Fixed-origin REST provider adapter (first executable provider integration)

This is an executable REST connector for approved providers, not a generic open URL proxy. It implements GET records.read, POST records.write, JSON responses with a 256 KiB default stream cap, request timeout, fixed paths, no redirect following, bounded retries of GET on 429/502/503/504, and no automatic POST retries.

Use `FixedRestConnector` with `ConnectorRegistry` and the authoritative `ExecutionGateway`. Provider configuration must be approved and compiled by the backend, never accepted from customer request bodies. The `verified` flag only marks reviewed provider configuration as executable; external API acceptance remains separate.

For authenticated providers, pass `vaultCredentialRunner(vault)`. Credentials are accessed only by tenant+connection scope through the encrypted vault; the adapter does not persist plaintext, though the HTTP Authorization header necessarily constructs an ephemeral JS string. Never log network headers, errors containing credentials or raw secret values.

**Critical SSRF boundary:** `networkTransport` uses fetch and by itself does **not** guarantee DNS rebinding/private-network protection. Production MUST provide a hardened network egress proxy or dispatcher enforcing an IP-based allowlist after DNS resolution, private/metadata IP blocking, and no proxy bypass. Until then use only fixed infrastructure-vetted destinations with a firewall restricting outbound traffic. A config hostname check cannot prevent DNS rebinding alone.

Rate limiting beyond provider 429 response handling is not yet implemented; implement bounded per-tenant/provider queues before production. OAuth refresh/revocation, OpenAPI schema import, retries with Retry-After, durable idempotency and real provider testing also remain.

The tests use fake transport responses, never paid provider calls or customer tokens.
