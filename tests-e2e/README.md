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
5. **`.env` is skipped.** Playwright sets `DEMO_BOTH_SKIP_DOTENV=1` so
   demo-both doesn't read the workspace-root `.env` (which may set values
   like `PASSKEY_AUTHENTICATOR_ATTACHMENT=platform` that conflict with the
   second virtual authenticator used in the account-management test).
6. **One internal authenticator per context.** Chrome only allows a single
   platform/`internal` virtual authenticator. Additional ones must use
   `usb`/`nfc`/`ble` (cross-platform). See `account-passkey-mgmt.spec.ts`.

## Deferred to later phases

- `data-testid` rollout across more templates for selector stability
- Account-management flows beyond passkey CRUD (rename, OAuth2 link/unlink,
  edit profile, delete account)
- Admin-panel flows (user list, force logout)
- Conditional UI / autofill
- FedCM (`navigator.credentials.get({ identity: ... })`)
- Promotion popup *accept* path (currently only the dismiss path is tested)
- Multi-user / re-link scenarios (currently the DB is fresh per server
  start, but state persists across tests in a single run)
- Remove `continue-on-error: true` from `.github/workflows/e2e.yml` once
  the suite is proven stable in CI
