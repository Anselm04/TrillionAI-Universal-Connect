# Durable workflow execution — initial PostgreSQL engine

This implementation follows established durable workflow ideas from the imported Temporal reference, but does not copy Temporal source or claim compatibility with its service.

## Supported

- Bounded sequential workflow definitions persisted in PostgreSQL with tenant RLS.
- Tenant-and-actor-scoped workflow idempotency keys; conflicting re-use fails rather than silently changing a workflow.
- Atomic step claims via FOR UPDATE SKIP LOCKED; claim token fences prevent stale workers committing results.
- Per-step bounded lease and attempt records; expired read claims can be recovered.
- **Expired or failed writes become uncertain**, never automatically replayed. An external provider may have performed the action even if the local process crashed.
- No stored plaintext tokens. Steps record connector IDs, bounded request JSON and explicit approval IDs, not provider bearer secrets.
- Completion results and workflow status persist, recoverable after process restarts.

## Important architectural boundaries

Call `enqueue` only after verified Identity and authorization for the proposed workflow. `runOne` requires a **trusted executor** which must authenticate the actor's current session or use an explicitly authorized service principal, re-evaluate tenant membership, capability policy, approvals and subscription entitlements, then call `ExecutionGateway`. Do not treat persisted actor IDs as fresh proof of authentication.

The current implementation has **at-least-once reads** (read endpoints must be side-effect free) and **at-most-once automatic write dispatch**, subject to uncertainty after crashes. Exactly-once remote execution cannot be guaranteed without provider idempotency/reconciliation.

A workflow with an uncertain write requires an explicit audited operator reconciliation decision. **No automatic retry of uncertain writes is implemented.** A future operational API must verify the upstream provider's actual result before allowing an operator to resume.

Lease expiry is not a cancellation signal: a slow read may still run while another worker reclaims it. Provider-side read rate limits and timeout deadlines should be stricter than lease duration. This first implementation does not include heartbeats, compensation/sagas, provider event outbox, scheduling, cron, throttled tenant polling, or worker fleet orchestration.

CI uses disposable PostgreSQL 16 and test doubles; no paid orchestrator or live third-party APIs.
