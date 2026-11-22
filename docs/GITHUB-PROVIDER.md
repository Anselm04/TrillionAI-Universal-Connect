# GitHub.com OAuth provider adapter (read-only)

The first **concrete provider** is GitHub.com. It implements `github.profile.read` via `GET https://api.github.com/user` and `github.repositories.read` via `GET https://api.github.com/user/repos`. Results are projected into explicit profile/repository metadata fields. It does **not** execute Git pushes, issue changes, deploy, write repository content, or mutate GitHub.

## Real GitHub requirements

GitHub.com supports PKCE S256 for OAuth apps; its OAuth authorization-code and refresh-token exchanges additionally require the registered app's **client secret**. GitHub returns lowercase `bearer` in token responses. The shared OAuth core now supports an injected backend-only `OAuthClientSecrets` callback and case-insensitive bearer normalization. These are based on GitHub's published API documentation.

- Authorization URL: `https://github.com/login/oauth/authorize`
- Token exchange: `https://github.com/login/oauth/access_token`
- API origin: `https://api.github.com`
- Default scopes: `read:user`. Optional `repo` scope gives **broad public/private repository access** and requires an explicit permission/consent choice. Don't silently request it.
- GitHub OAuth application token revocation requires its privileged OAuth application endpoint with client authentication; it is not a generic RFC 7009 revocation URL. Therefore this provider omits `revokeUrl`. Implement the provider-specific authenticated revocation endpoint before describing disconnect as revocation at GitHub.

Use `githubOAuthProvider` in the registered OAuth provider list, pass a protected server-side client secret provider, and pass `PostgresCredentialVault` for encrypted token storage. To read APIs, use `GitHubReadConnector` with the same vault and PostgreSQL provider rate limiter. A `createGuardedNetworkTransport` configured for **both** `https://github.com` and `https://api.github.com` is required (a single origin cannot reach all endpoints). The vault's `oauth_tokens` entry contains JSON, which the GitHub adapter parses and validates; it is **not** a raw bearer string.

## Qualification status

The connector manifest remains `implemented`, **not `verified`**, until testing against real authorized GitHub OAuth app credentials and permissions. The production registry blocks unverified adapters by design. The simulated tests prove request shape, fixed paths, token use, response validation, OAuth client-secret handling and PostgreSQL flow; they do not prove GitHub granted permissions.

The first repository listing retrieves GitHub's default first page only. Implement authenticated safe pagination and quotas before treating it as a complete repository inventory.

Production needs a validated callback router, authenticated Identity user journey, consent, real GitHub OAuth application registration, privileged revocation, audit, monitoring, egress/firewall policy, idempotent refresh recovery and security review. No paid services, real GitHub tokens or customer activity were used for these tests.

Sources: GitHub's published REST API user and repository endpoint documentation and OAuth Apps authorizing-apps documentation.
