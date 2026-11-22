# Authorized workflow execution and reconciliation

Workers do not impersonate user sessions. `AuthorizedWorkflowExecutor` requires two independently verified facts for each step: (1) the actor is still an email-verified, active organization member according to TrillionAI Identity; (2) a narrowly run-scoped, unexpired, unrevoked delegation exists in PostgreSQL.

`makeSupabaseActorDirectory` implements the actor lookup with Supabase server-side admin user lookup and the existing `identity_memberships` table. Only backend runtime environments may hold the service-role credential. The client cannot set an arbitrary tenant/actor via this worker. The gateway still checks connection ownership, allowed capabilities, active policy, and atomic approvals.

## Delegation issuance

The runtime role has SELECT-only access to `workflow_delegations`. A separate privileged management process must authorize and issue delegations **after authentication and consent**. This PR does not expose or implement an issuance API. Do not bypass delegation checking to make tasks run. Revoked or expired delegations fail closed.

## Uncertain operation reconciliation

`AuditedWorkflowRecovery` requires independently authenticated reviewer authorization from an injected `RecoveryApproval` implementation, and an 8–512 character nonsecret evidence reference (such as provider confirmation ID). It locks the workflow/step inside a tenant-scoped transaction and writes a single, append-only reconciliation record atomically with the status decision.

- `confirmed_completed`: if the provider can prove it completed the action, the workflow advances without dispatching the old write again
- `confirmed_not_executed`: terminates the workflow as failed **without resending the write**
- If evidence is inconclusive, leave the workflow `uncertain` and do not advance it

The privileged review-verification service and actual provider verification are **not** implemented in this PR. This is an internal recovery component, not a public endpoint; a placeholder or user-provided 'approved' string MUST NOT be used as authorization evidence.

## Remaining production requirements

- Reliable short-lived delegation issuance and authorization audits, including privileges at creation.
- A deployment workload identity for workers; tenant IDs must come from an authenticated internal scheduler.
- Protected operator recovery API with verified reviewer MFA, independent provider lookup and immutable evidence retention.
- AAL2/fresh-MFA enforcement for privileged operations; the worker does not forge assurance level 2.
- Dedicated least-privilege DB roles for management, workers and auditors, backups, heartbeat, metrics, retry policy and provider-specific idempotency reconciliation.
- Live Identity provider acceptance tests; do not enable automated customer write actions yet.

All CI tests use fake identities and a temporary PostgreSQL instance. No paid resources or real customer actions are used.
