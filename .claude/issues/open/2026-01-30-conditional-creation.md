# Issue: Passkey Registration Promotion After Login

## Table of Contents

- [Description](#description)
- [Design Constraints](#design-constraints)
- [Approach](#approach)
- [Impact on Existing Code](#impact-on-existing-code)
- [New Files](#new-files)
- [Related Files](#related-files-read-only-reference)
- [References](#references)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 2026-01-30-07

## Status: open

## Priority: medium

## Difficulty: large

## Description

Prompt users to register a passkey after successful OAuth2 login, encouraging adoption
of passkey authentication for faster future logins.

### Core Problem

The server cannot determine whether a user's existing passkeys are available on their
current device/authenticator. Passkeys are per-authenticator (per device/platform), so
a server-side `has_passkey` flag is insufficient -- a user may have a passkey on their
MacBook but not on their Android phone.

### Solution: excludeCredentials + Client-Side Promotion

Use WebAuthn's `excludeCredentials` parameter during registration. The authenticator
itself rejects with `InvalidStateError` if it already has a matching credential. This
eliminates the need for server-side per-device detection.

## Design Constraints

1. **Zero changes to existing Passkey flow code** -- existing registration, authentication,
   and all existing handlers/JS must remain completely untouched
2. **Environment variable toggle** -- the feature is experimental and must be disabled by
   default, controlled by `O2P_PASSKEY_PROMOTION` (default: `false`)
3. **Additive only** -- all changes are new files and conditional route registration

## Approach

### Architecture: New Endpoint Wrapping Existing Flow

The promotion registration start uses a **new endpoint** that internally calls the
existing `handle_start_registration_core()`, serializes the result to JSON, and appends
`excludeCredentials` by querying the user's existing credentials. The existing
`/passkey/register/finish` endpoint is reused as-is.

```
Existing flow (unchanged):
  POST /passkey/register/start  -> handle_start_registration (existing handler)
  POST /passkey/register/finish -> handle_finish_registration (existing handler)

Promotion flow (new, only when O2P_PASSKEY_PROMOTION=true):
  POST /passkey/promotion/register/start -> promotion_start_registration (NEW handler)
  POST /passkey/register/finish          -> handle_finish_registration (existing, reused)
```

The new handler wraps the existing core function:
```rust
async fn promotion_start_registration(auth_user: AuthUser, ...) -> ... {
    // 1. Call existing flow unchanged
    let options = handle_start_registration_core(Some(&session_user), request).await?;

    // 2. Serialize to JSON and append excludeCredentials
    let mut json = serde_json::to_value(&options)?;
    let credentials = list_credentials_core(user_id).await?;
    json["excludeCredentials"] = serde_json::json!(
        credentials.iter().map(|c| json!({"type": "public-key", "id": c.credential_id}))
    );

    Ok(Json(json))
}
```

### Client-Side: New JS File (passkey_promotion.js)

A new `passkey_promotion.js` file handles all promotion-specific logic. Existing
`passkey.js` and `oauth2.js` remain untouched.

**sessionStorage flag:** A new `message` event listener (alongside the existing one in
`oauth2.js`) sets `sessionStorage('oauth2_login_just_completed')` when receiving
`'auth_complete'`. This listener fires before the existing `setTimeout(reload, 10)`,
so the flag is set before the page reloads.

**Promotion registration:** Calls the new `/passkey/promotion/register/start` endpoint
(which returns `excludeCredentials`), transforms them to Uint8Array, and calls
`navigator.credentials.create()`. Handles `InvalidStateError` gracefully.

**Promotion UI:** On `DOMContentLoaded`, checks for sessionStorage flag, localStorage
opt-out, and WebAuthn support. Shows modal with Accept / Not Now / Don't Ask Again.

**Post-login redirect:** After OAuth2 login, the login page redirects authenticated
users to `O2P_DEFAULT_REDIRECT` (default: `/`). The sessionStorage flag survives
this redirect. The destination page must include `passkey_promotion.js` for the
promotion to trigger.

### Environment Variable

```
O2P_PASSKEY_PROMOTION=true   # Enable passkey promotion (default: false)
```

When disabled:
- Promotion routes are not registered
- `passkey_promotion.js` is not served
- All existing behavior is completely unchanged

### Compatibility

- Works with both `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true` and `false`
- Credential lookup is by `UserId` (not `UserHandle`), so all credentials are found
- Existing "Add New Passkey" on account page is unaffected (no `excludeCredentials`)

## Impact on Existing Code

| Component | Impact |
|-----------|--------|
| `oauth2_passkey/` (core library) | **None** |
| `oauth2_passkey_axum/src/passkey.rs` (existing handlers) | **None** |
| `oauth2_passkey_axum/static/passkey.js` | **None** |
| `oauth2_passkey_axum/static/oauth2.js` | **None** |
| `oauth2_passkey_axum/src/router.rs` | Conditional route addition only |

## New Files

- `oauth2_passkey_axum/src/passkey_promotion.rs` -- New handler + route
- `oauth2_passkey_axum/static/passkey_promotion.js` -- Promotion UI + registration logic

## Related Files (read-only reference)

- `oauth2_passkey/src/coordination/passkey.rs` -- `handle_start_registration_core()`,
  `list_credentials_core()` (called by new handler)
- `oauth2_passkey/src/passkey/main/types.rs` -- `RegistrationOptions` (serialized, not modified)
- `oauth2_passkey_axum/static/passkey.js` -- Reference for registration patterns
- `oauth2_passkey_axum/static/oauth2.js` -- Reference for postMessage handling

## References

- https://developer.chrome.com/docs/identity/webauthn-conditional-create
- https://github.com/w3c/webauthn/wiki/Explainer:-Conditional-Create
- https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-excludecredentials

## Implementation Tasks

- [x] Add env var `O2P_PASSKEY_PROMOTION` config
- [x] Create `passkey_promotion.rs` with new handler wrapping existing core function
- [x] Add conditional route registration in router
- [x] Create `passkey_promotion.js` with promotion UI, registration, and sessionStorage logic
- [x] Add handler to serve `passkey_promotion.js` (conditional on env var)
- [x] Add tests for new handler
- [x] Update `dot.env.example` with new env var
- [x] Server: Add `promotion_check` endpoint with UA + AAGUID heuristic
- [x] Server: Add `is_credential_likely_available()` platform matching function
- [x] Client: Call check endpoint before showing modal in `passkey_promotion.js`
- [x] Server: Add unit tests for platform matching heuristic
- [x] Change `O2P_PASSKEY_PROMOTION` from bool to enum (`ask`/`force`/disabled)
- [x] Add `force` mode: skip modal, go directly to WebAuthn registration
- [ ] Refactor to intermediate redirect page (eliminate demo app changes)
- [ ] Simplify `passkey_promotion.js` to redirect-only script
- [ ] Create `promotion_redirect.j2` template with inline promotion logic
- [ ] Add `GET /promotion/redirect` handler in `passkey_promotion.rs`
- [ ] Re-export `is_passkey_promotion_enabled` public helper
- [ ] Revert all demo-both promotion changes

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-01-30: Initial design

- Context: Need to encourage passkey adoption after OAuth2 login
- Considered two approaches: Explicit Promotion (modal after login) vs
  WebAuthn Conditional Creation (`mediation: "conditional"`)
- Decision: Prioritize Explicit Promotion (Approach 1)
- Reason: Conditional Creation only works with password authentication,
  not OAuth2/identity federation which is the primary auth method in this library

### 2026-02-09: Revised to excludeCredentials-based approach

- Context: Original plan assumed server-side `has_passkey` / `suggest_passkey`
  flags in login response, but server cannot determine per-device passkey availability
- Investigated alternatives: AAGUID matching (no client API to get device AAGUID),
  Conditional Creation (not applicable to OAuth2), signalAllAcceptedCredentials
  (for cleanup, not detection), excludeCredentials (for duplicate prevention)
- Decision: Use WebAuthn `excludeCredentials` in registration options
- Reason: Authenticator itself detects duplicates via `InvalidStateError`,
  eliminating server-side per-device detection entirely

### 2026-02-09: Zero-modification constraint for existing code

- Context: Adding `excludeCredentials` to existing `RegistrationOptions` struct
  would change AddToUser behavior -- re-registration on same authenticator would
  be blocked (`InvalidStateError`) instead of triggering server-side credential
  replacement via `prepare_registration_storage()`
- Decision: Create new endpoint + new JS file instead of modifying existing code;
  add `O2P_PASSKEY_PROMOTION` env var to toggle the feature (default: false)
- Reason: Preserves backward compatibility of existing passkey registration flow;
  experimental feature should be opt-in and fully isolated

### 2026-02-09: UA + AAGUID heuristic for modal control

- Context: Promotion modal always appears even when user already has passkeys
  registered on the current device, leading to poor UX
- Investigated: Pure `excludeCredentials`-only approach works for duplicate prevention
  but doesn't prevent the modal from showing unnecessarily
- Decision: Add server-side heuristic using User-Agent + AAGUID/AuthenticatorInfo
  to determine whether the user likely has a passkey accessible on the current platform
- Approach: New `GET /passkey/promotion/check` endpoint checks user's credential
  AAGUIDs against AuthenticatorInfo names, matches against UA platform family
- Rationale: Separates modal control (best-effort heuristic) from registration safety
  (`excludeCredentials` as safety net). Not perfect but significantly reduces
  unnecessary prompts. Cross-platform password managers (1Password, Bitwarden, etc.)
  always suppress the modal. Platform-specific authenticators (iCloud Keychain,
  Google PM, Windows Hello) are matched against the UA's OS/browser.

### 2026-02-09: Force mode -- skip modal, direct WebAuthn registration

- Context: User wants option to bypass the confirmation modal and go directly
  to `navigator.credentials.create()` (browser's native biometric/PIN dialog)
- Decision: Change `O2P_PASSKEY_PROMOTION` from boolean to three-state enum:
  `false` (disabled), `ask` (modal), `force` (skip modal)
- Approach: Check endpoint returns `mode` field; client dispatches accordingly
- Rationale: `force` mode is useful when the site operator wants maximum passkey
  adoption without requiring user opt-in. The WebAuthn dialog itself is the
  user interaction point. Cancel behavior is graceful (sessionStorage flag
  already consumed; no re-prompt until next OAuth2 login)

### 2026-02-09: Intermediate redirect page -- eliminate demo app changes

- Context: The current design requires demo/consumer apps to include `passkey_promotion.js`
  on their destination pages and provide JS globals (`csrfToken`, `O2P_ROUTE_PREFIX`).
  This forces app-level template changes for a library feature.
- Investigated: Whether the entire promotion flow could be handled within the library
  without any consumer app changes
- Decision: Use a library-controlled intermediate redirect page at
  `/passkey/promotion/redirect` between OAuth2 login and the final app redirect
- Approach: `passkey_promotion.js` on the login page intercepts `auth_complete` and
  redirects to the library's promotion page (cancelling `oauth2.js`'s reload).
  The promotion page handles check + modal/registration + redirect to
  `O2P_DEFAULT_REDIRECT`. All promotion logic is inline in the Askama template.
- Rationale: Zero consumer app changes needed. The library is fully self-contained.
  The sessionStorage flag pattern is eliminated. Trade-off: an extra redirect hop
  when `should_promote: false` (immediately redirects to default), but this is
  brief and acceptable for the cleaner architecture.

### 2026-02-09: Popup-based promotion -- replace intermediate redirect page

- Context: The intermediate redirect page approach requires `passkey_promotion.js`
  on the login page to intercept `auth_complete` and redirect, causing a race condition
  with `oauth2.js`'s `window.location.reload()`. Required `stopImmediatePropagation()`
  as a workaround. Also causes a visible redirect flash on the parent page.
- Investigated: Using the OAuth2 popup window itself for promotion. The popup is already
  a library-controlled context with a valid session cookie.
- Decision: Do passkey promotion inside the OAuth2 popup, after the callback and before
  sending `postMessage('auth_complete')` to the parent.
- Approach: OAuth2 callback handler conditionally redirects to `/passkey/promotion/popup`
  (instead of `/oauth2/popup_close`) when `O2P_PASSKEY_PROMOTION` is enabled. The promotion
  popup page handles check + modal/registration, then sends `postMessage('auth_complete')`
  and closes. No JS needed on the login page. No race conditions.
- Rationale: Cleaner than both previous approaches. Single coupling point (conditional
  redirect in `oauth2.rs`). No `passkey_promotion.js` on login page. No
  `stopImmediatePropagation`. No visible redirect on parent page. The parent page
  (login or account) just receives `auth_complete` as before.

## Resolution

