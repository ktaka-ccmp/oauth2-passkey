# Issue: POST-based OAuth2 account linking initiation (Alt 5B validation)

## Metadata

- ID: 20260512-0335
- Created: 2026-05-12-03-35
- Closed:
- Status: open
- Priority: medium
- Difficulty: medium
- Related Issues:
  - `20260226-2018` Simplify OAuth2 Account Linking API (parent — Alt 5B originates from this issue's Timeline entry on 2026-05-12T02:46)

## Problem

Investigate whether OAuth2 account linking initiation can be migrated
from the current GET-navigation + URL-embedded `page_session_token`
mechanism to a POST-based flow.

The POST-based variant under investigation (Alt 5 pattern B from the
parent issue's Timeline):

1. Client opens an empty popup synchronously within the click
   handler: `window.open('about:blank', name, features)`.
2. Client issues a CSRF-protected POST (`X-CSRF-Token` header) to a
   new `link-prepare` endpoint.
3. Server validates CSRF automatically (existing header mechanism),
   generates the OAuth2 authorization URL via the existing
   `prepare_oauth2_auth_request` (which already binds user_id via
   `misc_session`), and returns it as JSON `{ auth_url }`.
4. Client navigates the pre-opened popup: `popup.location.href = auth_url`.
5. Callback flow (`/oauth2/{provider}/authorized`) is unchanged.

If viable, this would eliminate the `page_session_token` concept
from the user-facing API surface while preserving the security
model. The session-boundary attack (page rendered under session A,
clicked under session B) is detected by the same per-session CSRF
token mechanism that already protects every other authenticated
endpoint — no HMAC obfuscation needed because the CSRF token never
appears in a URL.

This is a validation/investigation issue, not an implementation
commitment. Output should be: go/no-go decision, plus — if go — a
coexistence plan with the current GET-based mechanism.

## Timeline

### 2026-05-12T03:35 — Issue created from parent's Timeline

Branched from `20260226-2018` to track this as an independent
investigation. Coexistence and env-var switching design choices
recorded in Latest Plan below.

## Latest Plan

### Coexistence design

Both code paths can live side-by-side without conflict:

| Layer | GET path (current) | POST path (new) |
|---|---|---|
| Server endpoint | GET `/oauth2/{provider}` with `?mode=add_to_user&context=...` | POST `/oauth2/{provider}/link-prepare` returning `{ auth_url }` |
| JS function | `oauth2.openSelectPopup(mode, token)` | `oauth2.linkAccount(provider)` |
| Server-side template input | `page_session_token` (HMAC of csrf_token) | `csrf_token` (already exposed as `AuthUser.csrf_token`) |
| CSRF validation | `verify_page_session_token` | Existing `X-CSRF-Token` header middleware (auto) |

The two paths share `prepare_oauth2_auth_request` and the OAuth2
callback handler — only initiation differs.

### Env var switch design

New env var `O2P_LINKING_MODE` (values: `get` | `post`, default `get`
for backward compatibility):

- Controls which path the **built-in `/user/account` page** uses
  (button onclick handler and template token embedding).
- Does **not** restrict which endpoints are served — both are always
  available, so downstream custom UIs can pick either explicitly
  regardless of the env var.
- Injected into `oauth2.js` at serve time (like FedCM's
  `OAUTH2_CLIENT_ID`, see `oauth2.rs:155-171`).

This isolates the user-facing built-in behavior from the underlying
capability. Custom UIs are not forced to migrate, and downgrading
the env var is always safe.

### Investigation steps

1. Build minimal POST-based linking prototype in `demo-both/`:
   - POST handler at `/auth/oauth2/{provider}/link-prepare`
   - JS function `linkAccountPost(provider)`
   - Test page with both buttons (GET-mode, POST-mode) for A/B comparison

2. Cross-browser verification on Chrome / Firefox / Safari (desktop)
   and at least one mobile browser:
   - Popup-blocker behavior with `window.open('about:blank', ...)` →
     `popup.location.href = ...` sequence
   - COOP (`Cross-Origin-Opener-Policy: same-origin`) interaction with
     the existing `auth_complete` postMessage handshake
     (`oauth2.js:168-173`)
   - Graceful failure when popup is blocked
   - Popup cleanup when `fetch` fails after popup opens

3. Security equivalence end-to-end tests:
   - Session-boundary attack: open page under session A, switch cookie
     to session B in another tab, click link, confirm POST fails 403
   - CSRF replay: an `X-CSRF-Token` from session A cannot initiate
     linking under session B
   - Stale-page: leave page open, logout/login, click; confirm reject

4. Go/no-go decision recorded as Timeline entry with findings.

5. If go: migration plan
   - vX.Y.0: Add POST path. `O2P_LINKING_MODE=get` default. Document both.
   - vX.(Y+1).0: Flip default to `post`. GET still works.
   - vX.0.0 (next major): Decide whether to remove GET path.

### Files (during investigation; final scope decided after go/no-go)

- `oauth2_passkey_axum/src/oauth2.rs` — new POST handler
- `oauth2_passkey_axum/static/oauth2.js` — new JS function
- `oauth2_passkey_axum/templates/user_account.j2` — env-var-driven button
- `oauth2_passkey_axum/src/config.rs` — new env var
- `oauth2_passkey_axum/src/user/account.rs` — conditionally skip page_session_token when in POST mode
- `demo-both/` — proof-of-concept test page
- `docs/src/security/page-session.md` — describe both alternatives and decision

### Implementation Tasks

- [ ] Prototype POST endpoint + JS function (behind `O2P_LINKING_MODE=post`)
- [ ] Cross-browser smoke test (Chrome / Firefox / Safari / mobile)
- [ ] Security tests: session-drift attack rejected in POST mode
- [ ] COOP interaction test
- [ ] Popup-blocker fallback behavior verified
- [ ] Record go/no-go decision in Timeline
- [ ] If go: implement env-var dispatch in `user_account.j2`
- [ ] If go: document coexistence and migration in `docs/src/security/`
- [ ] If go: update parent issue `20260226-2018` Latest Plan

### Verification

End-to-end manual test in `demo-both`:

1. With `O2P_LINKING_MODE=get`: linking works as today (regression test)
2. With `O2P_LINKING_MODE=post`: linking works on Chrome / Firefox / Safari,
   including popup-blocker edge cases
3. Session-drift attack: rejected with 403 in both modes
4. No regressions in OAuth2 callback handling, FedCM flow, popup
   `auth_complete` message handling

## Resolution
