# GitHub verified connection health and token revocation

GitHub OAuth token **presence** does not mean authorization is valid. The new `POST /managed-connections/:connectionId/verify` route requires a verified Identity session, tenant-scoped ownership, quota and a configured `GitHubLifecycleService`. It sends a bounded `GET https://api.github.com/user` request through the existing guarded egress transport using the encrypted vault token. Returned state:
- `connected`: GitHub returned HTTP 200 and verification was less than 15 minutes ago.
- `verification_required`: encrypted token exists, but the verification is absent or stale.
- `reconnect_required`: token expired or GitHub returned 401.
- `unavailable`: GitHub returned another status or network/limit failed; **403 is not treated as proof of revocation**.
- `awaiting_authorization`: no encrypted OAuth token; `disconnected`: disabled connection.

The shared API now requires configured `githubLifecycle` and `localTokenVault` for `DELETE /connections/:connectionId`; it no longer silently falls back to deleting local tokens only. GitHub revocation uses the documented **DELETE https://api.github.com/applications/{client_id}/token** endpoint with OAuth app client ID/secret in server-only HTTP Basic auth and a JSON `access_token` body. HTTP **204** is necessary before removing encrypted local credentials and recording the disconnection event. Network errors or other statuses do not silently remove local credentials.

The transport's allowed origins must include `https://api.github.com`. All token and client-secret material remains on the server, and secrets must be wiped by the injected secure callback. The owner-scoped route also performs a rate reservation before touching provider credentials.

## Important limits and follow-up

Provider revocation can succeed at GitHub and local storage may still fail to delete: report an error, do not claim both succeeded, and reconcile after checking provider state. Updating the encrypted token vault and GitHub cannot be made atomic in a single PostgreSQL transaction. The local `connection_health` table records provider verification without exposing secrets; its timestamps do not constitute permanent token validity. This implementation does not make the read connector production-qualified.

Explicit provider acceptance tests, auditable retry/reconciliation, secure server key management, deployment firewall/TLS controls and a fully wired backend service are required for production. CI tests use local HTTP stubs and disposable PostgreSQL, **not live GitHub credentials**.

GitHub reference: https://docs.github.com/en/rest/apps/oauth-applications and https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api
