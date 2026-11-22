# Privileged workflow management API

This PR introduces an internal Express router with POST /delegations/:runId, DELETE /delegations/:runId, and POST /recover/:runId/:stepIndex. It is *not* a standalone public deployment.

**Authentication:** Each request is checked against the existing TrillionAI Identity Supabase Auth verifier, session revocation RPC and active organization membership. The authenticated token and tenant are never taken from JSON. Issuance/revocation are restricted to the verified workflow actor. The principal must hold organization owner/admin status and AAL2 with a verified TOTP authentication method timestamp no older than 15 minutes. The JWT method timestamp is read only after Identity has authenticated the exact bearer token. Other methods do not count.

**Database separation:** `uc_manager` is a separate role from `uc_runtime`. Workers retain SELECT-only delegation access; management writes delegation rows and append-only audit entries through transaction-local tenant RLS. The management role must have its own protected credentials, network restrictions and a separately secured workload.

**Recovery:** The caller must be freshly MFA-verified and a server-side `RecoveryEvidence.verify()` implementation must independently verify the provider's actual result for this run, tenant, action and evidence reference. A client-supplied receipt alone is not proof. The reconciliation record is the **atomic authoritative recovery audit** committed in the same transaction as the status change. Never mark a remote action completed without verifying upstream evidence. The engine does not auto-replay uncertain writes.

**Before any deployment:** Provide a real provider-specific evidence verifier (no permissive mock), protected TLS and same-origin/cross-origin controls, request rate limits, separate manager database user credentials, secure app secrets, tested live Identity MFA, evidence retention and monitoring. Keep service roles out of Flutter/web clients. Authorization and provider verification must be reviewed as a whole, not only as unit tests. No real customer accounts are connected here.
