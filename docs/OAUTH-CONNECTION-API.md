# Customer OAuth connection routes — GitHub foundation

The backend-only `createOAuthConnectionRouter` mounts three JSON endpoints under a fixed prefix:

- POST `/:connectionId/start` — bearer-authorized and session-verified customer gives explicit `{ "consent": true, "requestedAccess": "profile" }`; returns a GitHub authorization URL; only authorized repository permissions may use `"repositories"`
- POST `/:connectionId/complete` — authenticated web frontend submits the OAuth callback `code` and `state` to the backend, which matches the original authenticated tenant/actor/connection and consumes the state once
- DELETE `/:connectionId` — removes the locally stored OAuth token set, with an explicit response indicating whether upstream provider revocation was confirmed (GitHub provider-specific upstream revocation is **not yet implemented**, so it is false)

All actions require verified TrillionAI Identity bearer token, active session, tenant membership, an allowed HTTPS browser Origin header, a server-side operation policy and per-tenant OAuth rate reservation. A privileged service must implement the injected policy and verify account ownership, explicit approved scopes and entitlements. The API cannot authorize itself from a request-supplied boolean alone.

**Callback architecture**: This API deliberately does not accept an unauthenticated GET callback that exchanges tokens. Instead, register an HTTPS callback URL to an **existing authenticated frontend route on the same origin**. On return, the frontend must read `code` and `state` from its own callback URL, immediately remove them from browser history using `history.replaceState`, then POST them to the backend with a fresh Identity bearer token and selected connection ID. The state is matched to the account and tenant and consumed once by the OAuth service. Never put an Identity bearer token in URL query strings, web logs or third-party redirects.

The frontend should display provider scopes and clear consent language before start, and offer an explicit Disconnect action. The backend must configure `supportsRepositoryAccess` consistently with its **pre-registered GitHub OAuth scope selection**; the generic OAuth service cannot dynamically increase scopes per individual request. Broad `repo` access is never enabled by a mere user-supplied flag.

No API request can specify outbound URLs, token endpoint, client secret or redirect URI. The actual OAuth implementation uses fixed provider registration and the encrypted tenant vault, including one-use PKCE state. JSON response headers disable caching, referrers, and content sniffing.

**Security/deployment requirements:** Enforce an external TLS load balancer and allowlisted Origin policy, avoid permissive CORS, apply edge quotas and bot protection, protect backend secret/key material, and monitor OAuth events. In production, audit writes should be coordinated with lifecycle operations to avoid completed external actions without a corresponding audit event. Implement a secure audited authorization policy and verify against an actual Identity and GitHub OAuth environment before enabling customer connections.

The API test uses fake Identity and OAuth providers and a disposable PostgreSQL audit table; it does not execute real GitHub requests or store actual customer credentials.
