# TrillionAI Connect — Flutter customer OAuth portal

This is a **Flutter web application** for the TrillionAI Universal Connect backend. It provides TrillionAI Identity email/password sign-in, explicit GitHub permission selection and consent, safe OAuth redirects and callback submission, and a local-disconnect action.

## Build

```sh
cd apps/connect-portal
flutter pub get
flutter analyze
flutter test
flutter build web --release \
  --dart-define=SUPABASE_URL=https://YOUR_IDENTITY_PROJECT.supabase.co \
  --dart-define=SUPABASE_ANON_KEY=YOUR_PUBLIC_SUPABASE_ANON_KEY
```

The Supabase anon/publishable key may be public, but **never** put the service-role key, OAuth client secret or vault keys in Flutter source, flags or web bundles. The CI uses a fake URL/public-key string; it does not authenticate real customers.

## Reverse proxy and callback

Serve the Flutter static web build from a trusted HTTPS origin, for example `https://connect.example.com/`. Route `/connections/*` to the Node.js OAuth API **on that exact same origin**, without sending browser bearer tokens to untrusted intermediaries. The API enforces the Origin header and rejects cross-site calls. Route `/oauth/callback` back to the Flutter app shell (SPA rewrite). Register `https://connect.example.com/oauth/callback` as the GitHub OAuth App callback URL and use that exact value in the backend provider configuration.

The UI saves only the short-lived pending state, tenant and connection ID in origin-scoped session storage before redirecting. On callback it immediately erases the `code` and `state` from the address bar/history; validates returned state against the original tab's session storage; and posts the code to the authenticated backend endpoint. The server independently validates user, tenant, connection, PKCE and one-time state. It never sends OAuth tokens or client secrets into the browser.

If the user is signed out during callback, the portal **does not exchange tokens** and requires a new connection attempt. Successful disconnect removes locally stored credentials, but does not claim GitHub server-side token revocation. The UI instructs customers to revoke the OAuth app in GitHub Settings → Applications if they need to invalidate provider access.

## Important limits

- This is a functioning web UI artifact, not an actual deployed service. The GitHub connector remains `implemented`, not externally verified.
- The current backend expects a **pre-provisioned connection ID and organization UUID**. Before a public product launch, implement secure self-service connection provisioning/list/status, permission-policy enforcement and tenant selection. Do not infer authorization from user-entered IDs.
- Repo scope is not silently escalated by this UI. The server's `supportsRepositoryAccess` flag and provider pre-registration must explicitly allow it, and broad GitHub OAuth `repo` scope requires informed user consent.
- Owner/admin tenants may require further Identity MFA elevation (AAL2). This UI does not weaken Identity rules or forge assurance claims.
- The app uses a browser-only OAuth redirect implementation. Future iOS/Android builds require supported deep links/universal links and an app-specific callback strategy, not a web-only `dart:html` implementation. All backend endpoints remain Node.js.
- Secure hosting, production key management, CORS/origin policy, audit reliability, rate limits, privacy policy and real Identity/GitHub acceptance remain required before a real-customer launch.

No paid provider activity or production connection is used by automated tests.
