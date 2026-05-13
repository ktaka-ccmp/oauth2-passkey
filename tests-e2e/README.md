# tests-e2e

Browser-level end-to-end tests for `oauth2-passkey-axum` using Playwright +
Chrome's virtual authenticator. Exercises the full authentication flows
(OAuth2 popup, Passkey registration/authentication) against a real Chromium
browser running JavaScript and WebAuthn APIs.

These tests complement the existing HTTP-level integration tests
(`oauth2_passkey_axum/tests/`) and security tests (`tests-security/`) by
covering things HTTP tests cannot: real JS execution, WebAuthn API
interaction (`navigator.credentials.create/get`), popup-window message
passing, and Signal API calls.

## Prerequisites

- Rust toolchain (already required by the workspace)
- Node.js 18 or newer
- Linux: Playwright system dependencies (one-off)

```bash
cd tests-e2e
npm install
npx playwright install chromium    # downloads Chromium headless shell
```

## Running

```bash
cd tests-e2e
npx playwright test                  # headless, all tests
npx playwright test --headed         # watch in a real browser window
npx playwright test --ui             # Playwright's interactive UI
E2E_BROWSER_LOG=1 npx playwright test # forward browser console to terminal
```

Playwright's `webServer` config starts the two background services
automatically and shuts them down at the end:

| Service | Bin | Port | Purpose |
|---------|-----|------|---------|
| `mock-oidc` | workspace member `mock-oidc` | 19876 | Standalone OIDC provider — discovery, /authorize, /token, /userinfo, JWKS |
| `demo-both` | workspace member `demo-both` | 13001 | System under test — `oauth2-passkey-axum` integrated into a small Axum app |

Both bind to `127.0.0.1` and are reached via `localhost:<port>` from the
browser. The browser-side base URL must be `localhost` (not `127.0.0.1`)
because Chrome rejects WebAuthn on IP-literal origins
(`SecurityError: This is an invalid domain`).

Set `DEMO_BOTH_PORT` / `MOCK_OIDC_PORT` to override the defaults if those
ports are taken on your machine.

## What is covered

| Test | What it verifies |
|------|------------------|
| `smoke.spec.ts` | Login page renders, mock-oidc discovery doc is reachable |
| `passkey.spec.ts` | Register a passkey via virtual authenticator, log out, sign back in with the same authenticator |
| `oauth2.spec.ts` | OAuth2 popup against `mock-oidc`, dismiss the passkey promotion popup (`O2P_PASSKEY_PROMOTION=ask`), verify session |
| `account-passkey-mgmt.spec.ts` | From the account page, add a second passkey (using a second virtual authenticator), delete the first one, verify counts |
| `admin.spec.ts` | Register admin via passkey (first user → admin), have a second user log in via OAuth2, list users from admin index, force-logout the second user via admin detail page, verify they're actually logged out |
| `conditional-ui.spec.ts` | Register a passkey, log out, visit the conditional-UI page — the CDP virtual authenticator auto-resolves the conditional `credentials.get()` and the page redirects to `/` |
| `fedcm.spec.ts` | Drive `/oauth2/fedcm/nonce` → mint a signed JWT via mock-oidc's `/test/issue_token` → `/oauth2/fedcm/callback` end-to-end (happy path creates a session, wrong-nonce path is rejected) |
| `oauth2-linking-protection.spec.ts` | Phase 1: stale/missing/garbage `context=` on `add_to_user` is rejected (incl. session rotation invalidating the previously-rendered token), fresh token redirects to the IdP. Phase 2: simulate a session swap during the IdP round-trip and confirm the callback's `misc_session` lookup wins — the account links to the initiator, not the current-cookie user |
| `passkey-registration-protection.spec.ts` | Phase 1: stale/missing/garbage `X-CSRF-Token` on `/passkey/register/start` is rejected (incl. session rotation). Phase 2: simulate a session swap between `register/start` and `register/finish` — the `verify_session_then_finish_registration` user_id check must reject with "User ID mismatch", and no credential is persisted to either user |
| `demo-both-protected.spec.ts` | Regression coverage for `demo-both/src/protected.rs` (p1–p6 + nested/p3): anonymous-redirect, `Option<AuthUser>` branching, `X-CSRF-Token` response header, AJAX POST CSRF (403 without header), `Extension<AuthUser>` / `Extension<CsrfToken>` injection, form-CSRF four branches (valid / mismatch / missing / header-bypass) — guards the integrator-facing usage surface of the library's protection primitives |
| `demo-custom-login.spec.ts` | `demo-custom-login`'s `O2P_LOGIN_URL=/login` redirect contract: anonymous protected routes redirect to the consumer's own page, authed users on `/login` redirect to `/`, custom `/`, `/protected`, `/account`, `/admin` all render user info |
| `demo-cross-origin.spec.ts` | `demo-cross-origin` (Pattern 2): cross-origin cookie scope (auth server on :13010 → API server on :13011 both on `localhost`), `is_authenticated_user_401` middleware on the API server (401 anon / 200 with cookie), CORS preflight accepted from the auth origin and rejected from unknown origins |
| `demo-todo.spec.ts` | `demo-todo` (1:N pattern, Postgres-backed): anonymous redirect, form-CSRF protected create/toggle/delete, missing-CSRF 403, user isolation on `user_id`-keyed rows |
| `demo-profile.spec.ts` | `demo-profile` (1:1 pattern, Postgres-backed): anonymous redirect, lazy-create default profile on first GET, form-CSRF protected update, wrong-CSRF 403, user isolation |

A GitHub Actions workflow at `.github/workflows/e2e.yml` runs the same suite
on PR and push to `master`/`dev`. It is marked `continue-on-error` while the
suite stabilises so failures show up in the Actions tab but do not gate
merges.

## Architecture notes

```
┌─────────────┐    ┌──────────────┐
│ Playwright  │◀──▶│   Chromium   │
│  (Node TS)  │    │  + CDP VAuth │
└─────────────┘    └──────┬───────┘
                          │ HTTP
                          ▼
              ┌───────────────────┐
              │ demo-both (Rust)  │
              │ port 13001        │
              │   ↓ OIDC discovery │
              └───────────┬───────┘
                          ▼
              ┌───────────────────┐
              │ mock-oidc (Rust)  │
              │ port 19876        │
              └───────────────────┘
```

`mock-oidc` is a standalone binary at the workspace root. The runtime user
identity can be overridden mid-test via `POST /test/config`:

```ts
await request.post(`${MOCK_OIDC_URL}/test/config`, {
  data: { email: 'alt@example.com', sub: 'alt-sub', name: 'Alt' },
});
```

The shared logic lives in the `mock-oidc-core` library crate, which is also
used by the in-process test fixture
`oauth2_passkey_axum/tests/common/axum_mock_server.rs`. There is no
duplication — both consumers build their router from the same source.

### Virtual authenticator setup

The helper `helpers/webauthn.ts` attaches a CDP virtual authenticator to a
page. Call it **after** `page.goto(...)` so the CDP session is bound to the
correct target:

```ts
await page.goto('/o2p/user/login');
const authenticator = await addVirtualAuthenticator(page);
// ...
await authenticator.remove();
```

Defaults emulate a platform authenticator with resident keys, automatic UV,
and automatic user-presence simulation (matches what the library asks for
in registration options: `authenticator_attachment: platform`,
`resident_key: required`).

## Known gotchas

1. **Chromium only.** CDP virtual authenticator is Chromium-specific.
   Firefox / Safari WebAuthn must still be tested manually.
2. **Sequential, not parallel.** Tests share a single in-memory SQLite
   database. `fullyParallel: false` and `workers: 1` keep them deterministic.
3. **Network idle waits.** Many flows end with `location.reload()` in JS.
   Tests use `page.waitForLoadState('networkidle')` rather than racing a
   subsequent `page.goto`.
4. **Logout requires `?redirect=`.** `/o2p/user/logout` only redirects when
   the `redirect` query is supplied; without it the response is just
   header-clearing with no body.
5. **One internal authenticator per context.** Chrome only allows a single
   platform/`internal` virtual authenticator. Additional ones must use
   `usb`/`nfc`/`ble` (cross-platform). See `account-passkey-mgmt.spec.ts`.

## Per-test DB reset

`oauth2-passkey-axum` exposes `POST {O2P_ROUTE_PREFIX}/test/reset`
(default `POST /o2p/test/reset`) when its `e2e-test` Cargo feature is
on. Each demo's `Cargo.toml` declares a passthrough feature of the
same name; the Playwright `webServer` entries opt in via `cargo run -p
<demo> --features e2e-test`. The same flag also gates `dotenv()` off
at compile time so the workspace-root `.env` cannot leak into the
test environment. **The demo source code carries zero runtime test
wiring** — without the feature flag, neither the route nor the
dotenv skip is compiled.

Each spec calls `resetDb(baseUrl)` from `helpers/db.ts` at the top,
which hits the library route on the target demo and also resets
`mock-oidc`'s `TestUser` back to the default identity. Library state
(users, passkeys, oauth2 accounts, login history) is cascade-deleted
and SQLite autoincrement counters are reset so the next registered
user lands at `sequence_number=1` again.

App-side tables in `demo-todo` / `demo-profile` keep their rows; rows
are keyed by random user_id UUIDs so they never leak into subsequent
tests.

## Deferred to later phases

- Account-management flows beyond passkey CRUD (rename, OAuth2
  link/unlink, edit profile, delete account)
- Promotion popup *accept* path (currently only the dismiss path is
  tested)
- Browser-driven FedCM dialog (current FedCM spec is API-level — the
  browser dialog needs a real Google config endpoint reachable from the
  browser, which CI cannot provide)
- Remove `continue-on-error: true` from `.github/workflows/e2e.yml` once
  the suite is proven stable in CI
