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

### 2026-05-12T12:32 — Prototype landed; manual testing pending

Branch: `feat/oauth2-post-linking-prototype`.

Server-side endpoint and client-side JS are implemented and the
A/B demo page is in place. The env-var gating
(`O2P_LINKING_MODE`) and the built-in `/user/account` page
integration are intentionally deferred — those are only relevant
once the cross-browser/security validation says go.

**Code added:**

- `oauth2_passkey_axum/src/oauth2.rs` — new POST handler
  `oauth2_link_prepare`. Registered at
  `POST /oauth2/{provider}/link-prepare`. Uses `AuthUser`
  extractor (session validity + `X-CSRF-Token` header verified
  automatically by `session.rs` lines 188-243). Calls existing
  `prepare_oauth2_auth_request(provider, headers, Some("add_to_user"))`
  and returns JSON `{ "auth_url": "..." }` plus `Set-Cookie`
  response headers (OAuth2 CSRF cookie, same as the GET path).
  Both endpoints share the same `prepare_oauth2_auth_request`
  and the same callback handler — only the initiation transport
  differs.

- `oauth2_passkey_axum/static/oauth2.js` — new function
  `oauth2.linkAccountPost(provider, csrfToken)`. Opens
  `about:blank` popup synchronously inside the click handler
  (so popup blockers see the user gesture), then issues a
  `fetch` POST with `X-CSRF-Token`, then navigates the popup to
  the returned `auth_url`. Listens for `auth_complete`
  `postMessage` from the popup (same convention as
  `openSelectPopup`).

- `demo-both/Cargo.toml` — added direct dep on `oauth2-passkey`
  (path) so the demo can call `generate_page_session_token` for
  the GET-mode button. Limited to demo scope; library API not
  expanded.

- `demo-both/src/protected.rs` — `p7` handler computing both
  `csrf_token` (for POST path) and `page_session_token` (for
  GET path), rendered into the new template.

- `demo-both/templates/p7.j2` — side-by-side A/B page at `/p7`
  with two buttons (GET and POST), the raw tokens displayed,
  and a manual-test checklist matching this issue's
  Verification section.

**How to run the prototype:**

```bash
cd demo-both
cargo run   # serves on :3001
# Open http://localhost:3001/p7 in the test browser
# (requires OAUTH2_GOOGLE_CLIENT_ID / SECRET and ORIGIN set,
#  same as any demo-both run; see dot.env.example)
```

**Tests pending (cross-browser, manual):**

The Implementation Tasks below (cross-browser smoke test,
session-drift, COOP, popup-blocker) are user-driven and cannot
be done from this branch. The A/B demo page exposes both flows
side-by-side so they can be exercised under identical
conditions. Findings should be recorded as the next Timeline
entry, followed by the go/no-go decision.

**Build status at prototype landing:**

- `cargo fmt --all` clean
- `cargo clippy --workspace --all-targets --all-features` clean
- `cargo test --workspace --all-features` all pass
- No regressions in existing OAuth2 callback handling or
  `auth_complete` postMessage path (both flows share the
  callback).

### 2026-05-12T12:42 — Implementation correction: env-var dispatch + built-in page

The previous T12:32 entry mis-described the scope as a
prototype with an A/B demo in `demo-both/p7`. That violated
the original coexistence design in Latest Plan, which calls
for the env-var dispatch to live in the library itself and
the built-in `/user/account` page to switch on it. Per user
feedback ("ちゃんと実装して。環境変数で切り分けられるように"),
the demo additions were reverted and the proper integration
landed.

**Reverted (no longer in this branch):**

- `demo-both/templates/p7.j2` — deleted
- `demo-both/src/protected.rs` — `p7` handler/route removed
- `demo-both/Cargo.toml` — direct `oauth2-passkey` path dep removed
- `Cargo.lock` — restored

**Added (proper Alt 5B integration):**

- `oauth2_passkey_axum/src/config.rs` — new `LinkingMode` enum
  and `O2P_LINKING_MODE` env var (default `get`, values
  `get` / `post`, invalid value panics at startup like sibling
  config keys do).
- `oauth2_passkey_axum/src/oauth2.rs` — `serve_oauth2_js`
  prepends `const O2P_LINKING_MODE = '{get|post}';` to the
  served `oauth2.js`, matching the existing FedCM injection
  pattern (`O2P_FEDCM` → `FEDCM_ENABLED`/`OAUTH2_CLIENT_ID`).
- `oauth2_passkey_axum/src/user/account.rs` —
  `UserAccountTemplate` gains `linking_mode_is_post: bool` and
  `providers: Vec<TemplateProvider>`. In `post` mode the
  legacy `page_session_token` HMAC is skipped (empty string)
  and the providers list is populated via
  `enabled_provider_views()`.
- `oauth2_passkey_axum/templates/user_account.j2` —
  OAuth2 Accounts section now branches:
  - `get` (default): unchanged single button
    (`openSelectPopup('add_to_user', PAGE_SESSION_TOKEN)`)
  - `post`: one button per enabled provider, each calling
    `oauth2.linkAccountPost(provider_name, csrfToken)`. Uses
    the existing `csrfToken` JS const already defined in the
    page (no new template variable required).

**Endpoints remain coexistent.** Both
`GET /oauth2/{provider}` (with the legacy
`mode=add_to_user&context=...` query) and
`POST /oauth2/{provider}/link-prepare` are always served. The
env var only controls which one the built-in account page
uses. Downstream applications with custom UIs continue to
work without changes; setting `O2P_LINKING_MODE=post` only
flips the built-in page's button rendering.

**UX note for `O2P_LINKING_MODE=post`.** The legacy single-
button `openSelectPopup` UX (with a provider-picker popup
when multi-provider) is replaced in POST mode by an inline
per-provider button row directly on the account page. For
single-provider setups (the typical case) the UX is
effectively identical (one button click → IDP popup). For
multi-provider setups the picker is now inline; users see
the choices on the page instead of in a popup. If this
asymmetry turns out to matter, a follow-up can add a JS
provider-picker dialog for POST mode.

**Build status:**

- `cargo fmt --all` clean
- `cargo clippy --workspace --all-targets --all-features` clean
- `cargo test --workspace --all-features` all pass

### 2026-05-12T13:08 — Rename + UX unification

Two follow-on changes in response to review feedback.

**Rename `O2P_LINKING_MODE` → `OAUTH2_LINKING_MODE`** to match
the project's env-var naming convention:

- `O2P_*` — library-wide cross-cutting config (route prefix,
  login URL, CSRF header policy, custom CSS, FedCM, passkey
  promotion, etc.)
- `OAUTH2_*` — OAuth2-flow-specific config (`OAUTH2_GOOGLE_CLIENT_ID`,
  `OAUTH2_RESPONSE_MODE`, `OAUTH2_CSRF_COOKIE_NAME`,
  `OAUTH2_CSRF_COOKIE_MAX_AGE`, etc.)
- `PASSKEY_*` — passkey-specific config

The linking-mode switch is OAuth2-flow-specific, so it belongs
in the `OAUTH2_*` bucket. Touched: env var name, Rust static,
JS const prepended by `serve_oauth2_js`, Timeline references in
this issue.

**Question raised in review:** does Register/Sign-in also flip
to POST when `OAUTH2_LINKING_MODE=post`? **Answer: no, and the
env var is scoped accordingly.** Reasons:

1. The `page_session_token` mechanism only fires for
   `mode=add_to_user` (`oauth2.rs` `oauth2_initiate` and
   `oauth2_select`). Register and Sign-in modes
   (`create_user`, `login`, `create_user_or_login`) have never
   used it.
2. Register/Sign-in start from an unauthenticated state, so
   the Phase 1 session-boundary threat (page rendered as
   session A, clicked as session B) does not apply — there is
   no session A to drift from.
3. Even if we wanted POST-mode initiation for Register/Sign-in,
   it cannot work: those flows have no session and therefore
   no session CSRF token to send via `X-CSRF-Token`. POST mode
   requires an authenticated session.
4. Phase 2 protection (`misc_session`, tracked in
   `oauth2-linking-protection.md` Phase 2) covers the OAuth2
   round-trip identically for all modes regardless of
   initiation transport.

The docstring on the env var was tightened to say "linking
transport" so the scope is explicit.

**UX unification: POST mode now routes through the popup like
GET mode.** The earlier implementation rendered per-provider
inline buttons on the `/user/account` page in POST mode while
GET mode had a single `Add New OAuth2 Account` button opening
a select popup. That asymmetry was an implementation shortcut,
not a design choice. Restored a single-button parent UI in
both modes, with the existing select popup handling the
provider-picker step.

Touched:

- `oauth2_passkey_axum/templates/user_account.j2` — reverted
  to the original single-button `openSelectPopup` invocation.
  When `OAUTH2_LINKING_MODE=post`, `PAGE_SESSION_TOKEN` is an
  empty string, which `openSelectPopup` already treats as
  "omit `&context=`".
- `oauth2_passkey_axum/src/user/account.rs` — removed the
  per-provider `TemplateProvider` plumbing and the
  `linking_mode_is_post` / `providers` template fields. The
  conditional `page_session_token` computation (HMAC in GET
  mode, empty in POST mode) is retained.
- `oauth2_passkey_axum/src/oauth2.rs` (`oauth2_select`
  handler):
  - In POST mode + `add_to_user`, skip the
    `verify_page_session_token` check (Phase 1 protection is
    enforced at `/link-prepare` time via `X-CSRF-Token`).
  - In POST mode, skip the single-provider 302 shortcut
    (browsers cannot 303-redirect a GET request to a POST
    endpoint). The template renders for single-provider
    setups too, with a JS auto-trigger that mimics the
    GET-mode 302 UX (brief popup flash, then IDP).
  - New `SelectProviderTemplate` fields:
    `post_linking_active`, `csrf_token`,
    `single_provider_auto_trigger`.
- `oauth2_passkey_axum/templates/select_provider.j2` —
  branches on `post_linking_active`:
  - GET mode (default): existing anchor-tag buttons that
    navigate to `/oauth2/{provider}?mode=...&context=...`.
  - POST mode: `<button onclick="oauth2LinkSelect(...)">`,
    with an inline JS handler that fetches `/link-prepare`
    and navigates `window.location` (i.e. the popup itself)
    to the returned `auth_url`. For single-provider setups,
    `window.addEventListener('load', ...)` auto-triggers it.

The popup's session-bound CSRF token is embedded server-side
as `CSRF_TOKEN` in the rendered template; the popup is
same-origin with the parent and shares the session cookie, so
the token is the same value the parent uses for any other
authenticated request.

**Build status:**

- `cargo fmt --all` clean
- `cargo clippy --workspace --all-targets --all-features` clean
- `cargo test --workspace --all-features` all pass

### 2026-05-12T13:55 — Form-target POST select (Option E)

Review noticed that the T13:08 "Hybrid POST + popup" approach
had skipped `page_session_token` verification at the popup
boundary, which leaves the parent-render-to-popup-open window
of session drift undetected. The T13:08 implementation was
therefore broken — the popup loaded under whatever session was
current at click time, and `csrf_token` embedded by the server
in the rendered template was the new session's token rather
than the parent's. The session-binding chain was effectively
severed at the popup boundary.

The fix landed as **Option E (Form-target POST select)**,
which restores the popup-select UX while eliminating
`page_session_token` from the user-facing path entirely:

- **Popup boundary uses form-body csrf_token** instead of
  URL-embedded HMAC. The parent renders a hidden
  `<form method=POST target=PopupWindow>` carrying the session
  csrf_token in a body field. Clicking the link button calls
  `oauth2.startLinkingViaForm`, which opens the popup
  synchronously inside the user gesture and then submits the
  form to it. The server-side handler `POST /oauth2/select`
  verifies the form body's csrf_token against the current
  session's csrf_token via `subtle::ConstantTimeEq`. Drift
  detected here.
- **POST body avoids the URL-leakage concern** that originally
  motivated `page_session_token`'s HMAC obfuscation. Form
  bodies don't appear in Referer headers, browser history, or
  default access logs, so the raw csrf_token can ride along
  without an extra one-way derivation step.
- **Action endpoint stays POST + X-CSRF-Token**.
  `oauth2_link_prepare` was tightened to explicitly require
  `csrf_via_header_verified` (the `AuthUser` extractor lets
  form-like POSTs through with manual delegation; this
  endpoint only accepts header-verified fetch POSTs).
- **page_session_token is no longer required from the
  user-facing path** in POST mode. `user/account.rs` emits an
  empty string for `page_session_token` when
  `OAUTH2_LINKING_MODE=post`; the template uses the form
  helper instead.

**Files in this revision:**

- `oauth2_passkey_axum/src/oauth2.rs`:
  - Revert `oauth2_select` (GET) to its pre-Alt-5B form
    (`page_session_token` mandatory for `add_to_user`, 302
    shortcut for single-provider unconditional). It passes
    `post_linking_active: false` and empty `csrf_token` to the
    template since GET-mode buttons navigate, not POST.
  - New `oauth2_select_post` handler: form-body parse,
    `subtle::ConstantTimeEq` against session csrf, render
    template with `post_linking_active: true` and
    `single_provider_auto_trigger` set when one provider is
    enabled.
  - Route updated to `.route("/select", get(oauth2_select).post(oauth2_select_post))`.
  - `oauth2_link_prepare` requires `csrf_via_header_verified`
    so it can't be reached via form-like POST without an
    `X-CSRF-Token` header.
- `oauth2_passkey_axum/src/user/account.rs`:
  - `UserAccountTemplate` gains `linking_mode_is_post: bool`
    (the template needs to branch; `page_session_token` is
    empty in POST mode).
- `oauth2_passkey_axum/templates/user_account.j2`:
  - POST mode: hidden `<form>` + button calling
    `oauth2.startLinkingViaForm`.
  - GET mode: existing `openSelectPopup` button.
- `oauth2_passkey_axum/static/oauth2.js`:
  - New `oauth2.startLinkingViaForm(formId, popupName)`:
    synchronously opens the named popup, attaches the
    `auth_complete` listener, then submits the named form.
- `oauth2_passkey_axum/templates/select_provider.j2`:
  - Unchanged from the T13:08 revision; it already branches on
    `post_linking_active` and uses `oauth2LinkSelect` (fetch
    + popup navigation) for POST mode.

**Threat coverage** (now equivalent to GET mode):

| Drift window | GET (legacy) | POST (Option E) |
|---|---|---|
| Parent render → popup open | URL `page_session_token` HMAC | Form-body `csrf_token` (`ct_eq`) |
| Popup load → button click | URL `page_session_token` HMAC at `oauth2_initiate` | `X-CSRF-Token` header at `/link-prepare` |
| OAuth2 IDP round-trip | `misc_session` | `misc_session` |

**Build status:**

- `cargo fmt --all` clean
- `cargo clippy --workspace --all-targets --all-features` clean
- `cargo test --workspace --all-features` all pass

### 2026-05-12T15:03 — Refinement: explicit mode reject in oauth2_link_prepare

Review surfaced that the handler hardcoded `Some("add_to_user")`
when calling `prepare_oauth2_auth_request` and silently ignored
any incoming `mode` query parameter. An authenticated user
calling `POST /oauth2/google/link-prepare?mode=login` would have
the request transparently coerced into an `add_to_user` flow,
which is confusing to debug.

Background analysis (not changing the design, just documenting
it):

- POST mode's Phase 1 protection is the `X-CSRF-Token` check
  inside the `AuthUser` extractor; that check requires a session
  CSRF token, which only authenticated users have.
- Therefore `login` / `create_user` / `create_user_or_login`
  modes — which start from an unauthenticated state — can't be
  served by this endpoint regardless of intent. They continue
  to use `GET /oauth2/{provider}`.
- The asymmetry (GET handles all modes, POST handles only
  `add_to_user`) is intentional and tracked in this Timeline.
- Expanding POST to all modes was considered and rejected as
  YAGNI: there is no current consumer for POST-based login init
  and the existing GET path covers it.

Refinement: explicitly reject any non-`add_to_user` `mode` query
parameter with `400 Bad Request` and a directive pointing at
`GET /oauth2/{provider}` for other modes. A missing `mode` is
still treated as `add_to_user` (no change to existing JS
callers in `linkAccountPost` and `oauth2LinkSelect`, neither of
which sends `mode`).

Files: `oauth2_passkey_axum/src/oauth2.rs` only —
`oauth2_link_prepare` gains a `Query<HashMap<String, String>>`
extractor and an early reject branch. Docstring updated to
state the scope.

**Build status:**

- `cargo fmt --all` clean
- `cargo clippy --workspace --all-targets --all-features` clean
- `cargo test --workspace --all-features` all pass

### 2026-05-12T15:09 — Rename: POST /oauth2/{provider}/link-prepare → POST /oauth2/{provider}

URL consolidation. The dedicated `/link-prepare` suffix carried no
information beyond "this is the POST variant of OAuth2 init for
add_to_user mode", which is better expressed by HTTP method
overloading on the same resource path. Final routing:

```
GET  /oauth2/{provider}  → oauth2_initiate      (303 redirect)
POST /oauth2/{provider}  → oauth2_initiate_post (JSON {auth_url})
```

Symmetric handler naming (`oauth2_initiate` and
`oauth2_initiate_post`) reflects that they are two transports for
the same operation (initiate an OAuth2 authorization request),
not two operations.

Touched:

- `oauth2_passkey_axum/src/oauth2.rs`: route entry collapsed to
  `.get(oauth2_initiate).post(oauth2_initiate_post)`. Handler
  renamed from `oauth2_link_prepare`. Docstring tightened.
- `oauth2_passkey_axum/static/oauth2.js` (`linkAccountPost`) and
  `oauth2_passkey_axum/templates/select_provider.j2`
  (`oauth2LinkSelect`): fetch URL changed from
  `/oauth2/${provider}/link-prepare` → `/oauth2/${provider}`.
- `oauth2_passkey_axum/src/config.rs`: `OAUTH2_LINKING_MODE`
  docstring updated to refer to "both methods on
  `/oauth2/{provider}`".
- `oauth2_passkey_axum/tests-security/cross_flow_security.rs`:
  two assertions updated `METHOD_NOT_ALLOWED (405)` →
  `UNAUTHORIZED (401)`. Previously the tests relied on
  POST being unregistered to produce 405; now POST is
  registered but `AuthUser` rejects unauthenticated requests
  with 401. Same security outcome (request refused before any
  handler logic runs), different status code. Comments inline
  document the reason for the change.

The earlier Timeline entries (T12:32, T12:42, T13:08, T13:55,
T15:03) and the Latest Plan still reference the historical
`/link-prepare` path; they reflect the design as of those
timestamps and per schema (Timeline is append-only) are left
as-is. The new URL is the source of truth going forward.

**Build status:**

- `cargo fmt --all` clean
- `cargo clippy --workspace --all-targets --all-features` clean
- `cargo test --workspace --all-features` all pass

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
- `docs/src/security/oauth2-linking-protection.md` — describe both alternatives and decision

### Implementation Tasks

- [x] Prototype POST endpoint + JS function
- [x] Env-var dispatch (`OAUTH2_LINKING_MODE=get|post`, default `get`) and built-in `/user/account` page integration; single-button popup UX preserved across both modes (POST routes through `/oauth2/select` with a fetch+navigate flow inside the popup)
- [ ] Cross-browser smoke test (Chrome / Firefox / Safari / mobile) using `demo-both` (or any other demo) with `OAUTH2_LINKING_MODE=post`
- [ ] Security tests: session-drift attack rejected in POST mode (logout/login in another tab, then click any provider button — expect 401)
- [ ] COOP interaction test (set `Cross-Origin-Opener-Policy: same-origin` on parent and verify `auth_complete` postMessage still reaches the opener)
- [ ] Popup-blocker fallback behavior verified (strict blocker → buttons fail gracefully, no half-state)
- [ ] Record go/no-go decision in Timeline
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
