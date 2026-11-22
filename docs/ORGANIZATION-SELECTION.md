# Verified organization discovery

The new `GET /organizations` route uses a verified Identity bearer, checks an active session and confirmed email, then lists only active `identity_memberships` for the authenticated actor. An owner/admin membership is returned only with AAL2. It never accepts caller-supplied user IDs or organization IDs for discovery. Roles and organization UUIDs are returned; organization names require a separately authorized Identity directory schema.

The Flutter portal fetches this list and selects an authorized organization instead of requiring customers to type a UUID. Selecting an organization changes the active connection context; the backend re-verifies organization membership independently for every sensitive action.

The public route returns no credentials and rate-limits by a SHA-256 digest of the bearer. In production, prefer a dedicated Identity discovery quota keyed by server-verified user ID, rather than treating an opaque bearer digest as a stable cross-refresh user key. Enforce edge rate limits as well.

The organization discovery API must be mounted on the same HTTPS origin as Flutter. No real Identity accounts or provider tokens were used during automated tests.
