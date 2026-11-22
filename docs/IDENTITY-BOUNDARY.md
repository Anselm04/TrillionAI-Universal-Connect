# TrillionAI Identity → Universal Connect integration contract

This package integrates with the current **TrillionAI-Identity** architecture inspected on 22 November 2026. Identity uses one Supabase Auth project, not a second standalone identity issuer. In Identity's `backend/src/guards.ts`, Supabase validates the bearer token, `identity_session_active` confirms the session is not revoked, and role enforcement is server-side. In `backend/src/server.ts`, tenant membership is stored in `identity_memberships` with fields `organisation_id`, `user_id`, `role` and `status`.

Universal Connect's `makeSupabaseIdentityBoundary` uses the same trusted Supabase Auth verification and session RPC, then requires active tenant membership for the requested organization. It rejects an OAuth client-bound token and checks the session ID *only after* the provider has verified its token. Global owner/admin status never automatically grants tenant access. Organization owner/admin must have AAL2.

The resulting `principal` is suitable for `ExecutionGateway.execute`, but the app must never build it from client-supplied IDs. `tenantId` is the requested organization identifier, checked against Identity membership; only the token comes from the verified bearer. The elevated organization role is informational: authorization for actual connector capabilities must come from the gateway's own persisted policy engine.

## Important limitations

- There is no HTTP router or deployed gateway here; this is a real executable authentication boundary library, plus unit tests with injected provider doubles.
- The actual Supabase adapter is implemented, but no live user login or session checks have been performed against a deployed Identity provider. That requires an authorized integration environment.
- Existing Identity's privileged user checks require fresh MFA evidence for some operations; the AAL2 check alone here is **not** sufficient for every owner/admin mutation. Add explicit Identity fresh-factor verification as a separate privileged-operation policy before offering those actions.
- The `SUPABASE_SERVICE_ROLE_KEY` is a powerful server secret. It belongs only in a protected backend runtime, never in Flutter, the browser, logs, GitHub files or public configuration.
- This integration does not modify TrillionAI Identity or AppForge.
