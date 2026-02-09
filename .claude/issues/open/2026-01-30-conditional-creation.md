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

### Architecture: Popup-Based Promotion

The promotion flow runs inside the OAuth2 popup window itself. After the OAuth2
callback, instead of redirecting to `popup_close.j2`, the callback conditionally
redirects to `/passkey/promotion/popup` which handles the entire promotion flow,
then sends `postMessage('auth_complete')` and closes the popup.

```
OAuth2 popup: Google auth -> callback -> [promotion enabled?]
  -> YES: /passkey/promotion/popup?message=... -> check + register -> postMessage + close
  -> NO:  /oauth2/popup_close?message=...      -> postMessage + close (existing behavior)
```

The parent page (login page or account page) never needs to know about promotion.
No extra JS on the login page. No race conditions. Single coupling point in `oauth2.rs`.

### Server-Side Endpoints

**Registration start** wraps the existing core function and appends `excludeCredentials`:

```
Existing flow (unchanged):
  POST /passkey/register/start  -> handle_start_registration (existing handler)
  POST /passkey/register/finish -> handle_finish_registration (existing handler)

Promotion flow (only when O2P_PASSKEY_PROMOTION is set):
  GET  /passkey/promotion/popup          -> promotion popup page (Askama template)
  GET  /passkey/promotion/check          -> UA + AAGUID heuristic check
  POST /passkey/promotion/register/start -> registration with excludeCredentials
  POST /passkey/register/finish          -> existing handler (reused)
```

**UA + AAGUID heuristic** (`GET /promotion/check`): Before showing the modal or
starting registration, the popup page calls this endpoint. It checks the user's
existing credential AAGUIDs against AuthenticatorInfo names, matches against the
User-Agent platform family, and returns `{ "should_promote": bool, "mode": "ask"|"force" }`.

### Client-Side: Inline in Askama Template (promotion_popup.j2)

All promotion logic is inline in the `promotion_popup.j2` template (no separate JS file).
The template handles:

1. localStorage opt-out check -- immediately close popup if dismissed
2. Call `GET /promotion/check` -- skip if heuristic says not needed
3. Modal (ask mode) or direct WebAuthn registration (force mode)
4. `postMessage('auth_complete')` + `window.close()` on completion

### Environment Variable

```
O2P_PASSKEY_PROMOTION=ask    # Show confirmation modal
O2P_PASSKEY_PROMOTION=force  # Skip modal, direct WebAuthn registration
# unset or false -> disabled (default)
```

When disabled:
- Promotion routes are still registered (merged into passkey router) but popup is unreachable
- OAuth2 callback redirects to `popup_close` as before
- All existing behavior is completely unchanged

### Compatibility

- Works with both `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true` and `false`
- Credential lookup is by `UserId` (not `UserHandle`), so all credentials are found
- Existing "Add New Passkey" on account page is unaffected (no `excludeCredentials`)
- No consumer app changes required -- the library handles everything internally

## Impact on Existing Code

| Component | Impact |
|-----------|--------|
| `oauth2_passkey/` (core library) | **None** |
| `oauth2_passkey_axum/src/passkey.rs` (existing handlers) | **None** |
| `oauth2_passkey_axum/static/passkey.js` | **None** |
| `oauth2_passkey_axum/static/oauth2.js` | **None** |
| `oauth2_passkey_axum/src/oauth2.rs` | Conditional redirect in callback handlers |
| `oauth2_passkey_axum/src/router.rs` | Conditional route merging |
| `oauth2_passkey_axum/src/config.rs` | `PasskeyPromotionMode` enum + `is_passkey_promotion_enabled()` |

## New Files

- `oauth2_passkey_axum/src/passkey_promotion.rs` -- Handlers, routes, UA+AAGUID heuristic
- `oauth2_passkey_axum/src/passkey_promotion/tests.rs` -- Unit tests for heuristic
- `oauth2_passkey_axum/templates/promotion_popup.j2` -- Popup page with inline promotion logic

## Related Files (read-only reference)

- `oauth2_passkey/src/coordination/passkey.rs` -- `handle_start_registration_core()`,
  `list_credentials_core()` (called by promotion handler)
- `oauth2_passkey/src/passkey/main/types.rs` -- `RegistrationOptions` (serialized, not modified)
- `oauth2_passkey_axum/templates/popup_close.j2` -- Reference for postMessage + close pattern
- `oauth2_passkey_axum/src/oauth2.rs` -- OAuth2 callback redirect (coupling point)

## References

- https://developer.chrome.com/docs/identity/webauthn-conditional-create
- https://github.com/w3c/webauthn/wiki/Explainer:-Conditional-Create
- https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-excludecredentials

## Implementation Tasks

- [x] Add env var `O2P_PASSKEY_PROMOTION` config (`ask`/`force`/disabled)
- [x] Create `passkey_promotion.rs` with registration handler wrapping existing core
- [x] Add conditional route merging in router
- [x] Add `promotion_check` endpoint with UA + AAGUID heuristic
- [x] Add `is_credential_likely_available()` platform matching function
- [x] Add unit tests for platform matching heuristic
- [x] Update `dot.env.example` with new env var
- [x] Change `O2P_PASSKEY_PROMOTION` from bool to enum
- [x] Add `force` mode: skip modal, direct WebAuthn registration
- [x] Re-export `is_passkey_promotion_enabled()` public helper
- [x] Refactor to popup-based approach (promotion inside OAuth2 popup)
- [x] Create `promotion_popup.j2` template with inline promotion logic
- [x] Add `GET /promotion/popup` handler
- [x] Conditional redirect in `oauth2.rs` callback handlers
- [x] Remove `passkey_promotion_enabled` from login template
- [x] Revert demo-both promotion changes (no longer needed)
- [ ] End-to-end manual testing with `ask` and `force` modes

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

