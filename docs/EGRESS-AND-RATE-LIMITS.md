# Hardened outbound network and rate-limit controls

The REST adapter now **requires a tenant/provider rate-limit reservation before every network attempt**, including a transient-response retry. Requests fail closed if no limiter is provided or its backing database is unavailable.

## Networking

Use `createGuardedNetworkTransport({ allowedOrigins: ['https://approved-api.example.com'] })` as the outbound transport for a reviewed provider configuration.

- Undici uses an Agent-local DNS lookup hook to check the **same IP addresses supplied to the socket connection**, not an earlier preflight DNS query that could be replaced between lookup and connect.
- The entire DNS answer must consist of globally routable IPv4/IPv6 addresses. Private, loopback, link-local, metadata, multicast, special-use and IPv4-mapped private addresses are denied. Failure to resolve denies.
- TLS verifies the original hostname. Requests must target an exact infrastructure-configured HTTPS origin. Redirects and HTTP downgrades are disallowed.
- The unguarded `networkTransport` export has been removed from the REST adapter.
- The transport does not select a proxy from process environment variables. Egress infrastructure must additionally enforce IP-based firewall/network policies, including restrictions on database and metadata IPs, and monitor provider endpoints.

**Important:** Code-level DNS checks are defense in depth, not a substitute for an external network boundary. A compromised process can bypass code policy. Restrict outbound network access at the deployment layer.

## Distributed tenant rate limit

`PostgresProviderRateLimiter` uses a dedicated FORCE-RLS table with an atomic `INSERT ... ON CONFLICT DO UPDATE ... WHERE request_count < limit RETURNING` operation, based on PostgreSQL's own clock. Each (tenant, provider, window) pair has its own quota across concurrent servers. Denied attempts do not invoke the provider. Retry attempts consume quota.

Example server-side setup:

```ts
const transport = createGuardedNetworkTransport({allowedOrigins: ['https://api.example.com']});
const limiter = new PostgresProviderRateLimiter(pool, {maxRequests:60,windowSeconds:60});
const connector = new FixedRestConnector(reviewedConfig, transport, vaultCredentialRunner(vault), limiter);
registry.register(connector);
```

The HTTP gateway must derive the tenant and principal from verified Identity and enforce authorization before it calls the connector. **Never** accept origin, connection ID, provider config or rate limit policy as trusted client-supplied authorization facts.

## Qualification limitations

Tests exercise the security policy without contacting third-party APIs and exercise atomic quotas against an ephemeral PostgreSQL service. Live DNS/TLS behavior against approved providers, independent egress-firewall configuration, distributed workload stress, rate-limit observability, burst control and OAuth token refresh remain independent engineering/acceptance work. Fixed-window limits permit bursts at the window boundary; add a stricter token bucket if the provider contract requires smooth pacing.

No real customer tokens, provider charges or paid services are required to run these tests.
