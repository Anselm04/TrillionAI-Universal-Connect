# Node.js service composition and controlled startup

The executable entrypoint is `packages/service/src/main.ts`. It wires the existing Identity boundary, PostgreSQL runtime tenant pool, encrypted credential vault, strict two-origin network transport, provider rate limiter, GitHub OAuth token exchange, GitHub token health/revocation, server-side connection ownership, organization discovery and customer OAuth APIs.

## Required backend-only environment

Set these in the protected backend runtime environment, not a Flutter build, GitHub source file or browser:

| Name | Meaning |
|---|---|
| `PORT` | Local loopback port for a TLS-reverse-proxied service, e.g. 8080 |
| `PUBLIC_ORIGIN` | Trusted HTTPS public origin of Flutter portal and API (no path) |
| `DATABASE_URL` | PostgreSQL runtime user with tenant RLS grants |
| `SUPABASE_URL` | Same Supabase Auth authority as TrillionAI Identity |
| `SUPABASE_PUBLISHABLE_KEY` | Supabase publishable or anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-only protected admin service credential |
| `GITHUB_CLIENT_ID` | Registered GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | Secret from that registered GitHub OAuth App |
| `GITHUB_CALLBACK_URL` | Must exactly be `PUBLIC_ORIGIN/oauth/callback` |
| `VAULT_KEY_BASE64` | 32 random bytes, base64, supplied by secret manager |
| `VAULT_KEY_VERSION` | Active encryption key version; all new encrypted records use it |
| `VAULT_PREVIOUS_KEYS_JSON` | Optional protected JSON object mapping older versions to 32-byte base64 keys for staged rotation (maximum 16) |

Install Node 22+, run `npm install`, apply SQL migrations 001 through 011 using an **administrative migration identity**, run `npm run service:preflight` as a read-only deployment gate, and start with `npm run service:start`. Do **not** run schema migration as uc_runtime or expose the server directly to the internet. Protect the backend runtime environment using deployment secret management and rotate it by version. No secret values should be committed to GitHub.

## Request paths

- `GET /health/live`: process liveness; not proof of provider health.
- `GET /health/ready`: PostgreSQL readiness; does not test live GitHub or Identity.
- `GET /organizations`: authenticated Identity membership selection.
- `POST/GET /managed-connections`: create/list user-owned GitHub connections.
- `GET /managed-connections/:id`: connection state.
- `POST /managed-connections/:id/verify`: authorized real GitHub token probe.
- `POST /connections/:id/start`: explicit profile-scope consent and PKCE authorization.
- `POST /connections/:id/complete`: authenticated one-time callback code exchange.
- `DELETE /connections/:id`: GitHub-confirmed revocation before local deletion.

The service intentionally **does not mount** privileged workflow management/recovery routes and does not permit broad GitHub repository scope by default. Reconcile these only in a separate, independently authorized service with fresh MFA and provider-specific evidence. Unknown paths fail with HTTP 404.

## Deployment network model

The Node HTTP listener binds to `127.0.0.1`; run it behind a reverse proxy serving the Flutter static build and the API on the **same verified HTTPS origin**. Proxy only the explicit API paths, strip unexpected headers, enforce request/connection quotas and set a restrictive CORS and browser security policy. Route `/oauth/callback` to the Flutter shell. The API checks browser Origin and verified Identity bearer, and no cookies authorize mutations.

The egress transport permits only the preconfigured GitHub OAuth and REST origins and blocks private/reserved DNS resolutions and redirects. Put outbound firewall-level restrictions around the process too. The external Supabase Identity SDK has its own backend network route to the configured Supabase project; enforce the corresponding approved network policy at the deployment boundary.

## Honest deployment limitations

This PR composes an executable backend, but GitHub OAuth app registration, production deployment, external Secrets/rotation integration, cross-service audit reconciliation, provider-specific refresh behavior and full end-to-end acceptance with real Identity/GitHub accounts remain unverified. Key rotation is now supported with `VAULT_PREVIOUS_KEYS_JSON`, but **never delete an old version** until both encrypted credentials and unexpired OAuth pending PKCE states have been re-encrypted or expired. Run a controlled `PostgresCredentialVault.rotate` sweep for authorized tenant-scoped credentials, then verify remaining database `key_version` and `verifier_version` references using an operator-approved read-only inventory before retiring historical keys. Keep the old key accessible through rollback. This environment adapter is intended for protected secret injection; use KMS/HSM-backed key management for stronger production isolation. Fail closed rather than fabricating a decryption key.

CI only runs mocked GitHub/Identity interactions with disposable PostgreSQL. **Do not claim the service is live or externally verified from passing CI.**

## Deployment release gate

1. Build and test on a clean checkout using GitHub Actions. Do not supply production secrets to CI.
2. Apply reviewed, ordered SQL migrations with a separate privileged migration identity. **Do not run the test setup script on production.**
3. Configure the runtime DB identity as `uc_runtime` with no superuser, bypass-RLS, role-management or database-creation privilege.
4. Inject runtime secrets through a protected secrets manager. The backend requires the active key and any historical keys needed for encrypted records.
5. Run `npm run service:preflight`. It checks runtime DB role, tenant RLS enabled and forced, customer table privileges, and key schema columns without mutating data.
6. Start the service behind an authenticated TLS reverse proxy; `/health/ready` repeats the database preflight. Limit the exposure of `/health/live` and `/health/ready` to the internal load balancer.
7. Verify real Identity registration/MFA and GitHub OAuth consent, callback, revocation, network policy, logs, rate limits and error recovery in an owner-controlled acceptance environment **only after explicit authorization**.
8. Record a rollback plan, tested database backups and a clear owner approval before allowing external customers.

**Limits:** The preflight checks critical objects and forced tenant RLS but does not prove all migration checksums or validate every RLS policy expression. It is not a substitute for audited migration tracking, a reverse-proxy security review or real provider acceptance. A green health endpoint is not proof of external provider availability.
