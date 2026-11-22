# Credential vault — security and deployment contract

This package encrypts customer-supplied API tokens or OAuth secrets before PostgreSQL storage using AES-256-GCM, a fresh cryptographically random 96-bit nonce for each encryption, and additional authenticated data binding the ciphertext to tenant, connection, and secret name.

The backend never stores encryption keys in PostgreSQL. Supply a versioned `VaultKeyProvider` whose key material is obtained from a protected secret manager or KMS. A file checked into Git, a public Flutter bundle, a customer-readable setting or a database row is never an acceptable place for master keys. The tests generate temporary random keys and fake credentials, and use disposable PostgreSQL in GitHub Actions; no paid provider is needed for CI.

The vault uses the existing tenant-local transaction helper and a FORCE RLS table. Only an authenticated and authorized backend component may construct the VaultScope. The package is not a public credential endpoint. The current database runtime role can read ciphertext and write/delete credentials: it must be restricted to a server whose invocation has already passed Identity, tenant ownership and capability/approval policy checks. Do not expose database credentials directly to customers.

`withCredential` passes a Buffer into a trusted internal callback and wipes that Buffer in a `finally` block. This does not erase strings or any copies created by the callback. Avoid copying secrets into logs, analytics, queue payloads, exceptions or return values. Only execute authorized provider requests inside this callback. Ciphertext is always bound to the same tenant, connection and name; tampering fails authentication.

The `rotate` method re-encrypts individual stored secrets under the active key version, retaining the prior version until all ciphertext using that version has been rotated and verified. Key compromise should trigger incident response and replacement of provider credentials too. **Rotating the encryption key does not rotate the upstream OAuth token or API key**; provider-level rotation must be handled by a separately authorized connector workflow.

## Before production
- Implement a real protected KMS/secret-manager key provider and secure runtime credential provisioning.
- Keep key-provider privileges out of public clients; restrict backend access via Identity and policy engine.
- Add privilege-separated secret-management endpoints, audit every use/rotation/revocation and require elevated policy for maintenance.
- Implement OAuth refresh/revoke using provider-specific adapters and tested consent lifecycle.
- Add operational backup/restore and key version retirement strategy. Avoid persisting secret plaintext in error messages.
- Test against a real identity environment before enabling customer connections.

The CI test keys are ephemeral and never shared with production.
