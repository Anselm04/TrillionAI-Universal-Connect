# Self-service connection management

The Node.js service exposes a separate `/managed-connections` router mounted on the **same HTTPS origin** as the Flutter portal. It requires the verified TrillionAI Identity bearer token, selected organization UUID, Origin, and a management rate-limit reservation.

- `POST /managed-connections/` with empty JSON `{}`: creates one tenant-scoped GitHub connection and server-generated opaque connection ID. No client-specified provider, capabilities, owner or connection ID is accepted.
- `GET /managed-connections/`: lists no more than 20 connections owned by the authenticated actor, without returning credentials.
- `GET /managed-connections/:connectionId`: reports an owned connection's status; others are indistinguishable from missing connections.

The new `connection_owners` table provides **user-level isolation within an organization**, in addition to the existing tenant RLS. The `ownerConnectionPolicy(store)` is the concrete ownership enforcement bridge for the previously merged OAuth router. Wire this policy to `createOAuthConnectionRouter`, not a permissive policy stub. Older legacy connection rows without an ownership row are intentionally inaccessible to self-service APIs.

Statuses are `awaiting_authorization`, `connected` or `disconnected`. Connected means an encrypted OAuth token row exists, not that the upstream access token is currently healthy or independently verified. The UI must not claim GitHub access is live without provider verification.

**Security and operations:** A hard per-actor limit of 20 self-service connections prevents unbounded provisioning. Runtime receives limited SQL INSERT grants for connections/owners and never gains unrestricted DELETE rights. Database permission alone cannot distinguish the privileged Node.js API from other components sharing the uc_runtime DB role; production should separate a provisioning database role, add a transactionally durable create audit, plan/billing checks, lifecycle cleanup, and provider health state. Do not expose raw DB roles or service keys to customers.

The existing OAuth path `/connections/:connectionId/start|complete` and `DELETE /connections/:connectionId` remains unchanged. The Flutter portal can create a connection and use its ID, then list/inspect it. Provider-side revocation is still not implemented, and a disconnected credential need not mean the connection record has been disabled. These are deliberate distinctions, not proof of a live account.

Tests use fake Identity, local Express and disposable PostgreSQL, not paid APIs or real customers.
