# Issue: Improve OAuth2 Popup Error Handling UX

## Table of Contents

- [Description](#description)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 2026-02-09-02

## Closed: 2026-02-13

## Status: completed

## Priority: medium

## Difficulty: medium

## Description

When an OAuth2 operation fails in the popup window (e.g., user tries to log in but
is not registered, or tries to create an account that already exists), the error
handling is poor:

1. **Raw HTTP error text** is shown in the popup instead of a user-friendly page
2. **Popup does not close** -- `postMessage('auth_complete')` is never sent
3. **Parent page is stuck** -- no reload, popup remains open
4. **Wrong HTTP status** -- `Conflict` errors return 500 (Internal Server Error)
   instead of 409

### Error Scenarios

| Scenario | Error Type | Current Message |
|----------|-----------|-----------------|
| Login mode, account not found | `Conflict` | "Conflict: This OAuth2 account is not registered" |
| CreateUser mode, account exists | `Conflict` | "Conflict: This OAuth2 account is already registered" |
| Invalid mode/state combination | `InvalidState` | "Invalid combination of mode..." |
| CSRF verification failure | Various | Various |
| OAuth2 provider errors | `OAuth2Error` | Various |

## Approach

### Core Idea: Redirect to popup_close on Error

Instead of returning `Err(...)` from the handler (which renders a raw error page),
catch the error and redirect to `popup_close` with the error message. This ensures
the popup always shows a styled page, sends `postMessage`, and closes.

### Handler Changes (oauth2.rs)

In `get_authorized` and `post_authorized`, replace the `?` error propagation with
match-based error handling:

```rust
async fn get_authorized(...) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let redirect_url = match get_authorized_core(&query, &cookies, &headers).await {
        Ok((response_headers, message)) => {
            // Success: promotion popup or popup_close (existing logic)
            ...
        }
        Err(e) => {
            // Error: redirect to popup_close with error message
            format!(
                "{}/oauth2/popup_close?message={}",
                O2P_ROUTE_PREFIX.as_str(),
                urlencoding::encode(&e.to_string())
            )
        }
    };
    ...
}
```

### Error Message Improvement

Make error messages user-friendly by mapping `CoordinationError` variants:

| Error | User-Friendly Message |
|-------|----------------------|
| `Conflict("...not registered")` | "This account is not registered. Please create an account first." |
| `Conflict("...already registered")` | "This account already exists. Please sign in instead." |
| Other errors | Pass through the error message |

### Error Status Code Fix (error.rs)

Add explicit mapping for `Conflict` in `IntoResponseError`:

```rust
CoordinationError::Conflict(_) => StatusCode::CONFLICT, // 409
```

### popup_close.j2 Enhancement (Optional)

Consider differentiating error display in the popup:
- Pass `error=true` query param to style the message differently (e.g., red text)
- Add a brief delay before auto-close so the user can read the error
- Or: always close quickly, let the parent page show the error via postMessage data

## Related Files

- `oauth2_passkey_axum/src/oauth2.rs` -- Handler changes (catch errors, redirect)
- `oauth2_passkey_axum/src/error.rs` -- Add `Conflict` -> 409 mapping
- `oauth2_passkey/src/coordination/oauth2.rs` -- Error message source (read-only)
- `oauth2_passkey_axum/templates/popup_close.j2` -- Optional: error styling
- `oauth2_passkey_axum/static/oauth2.js` -- Optional: error-aware postMessage handling

## Implementation Tasks

- [x] Fix `Conflict` error mapping to 409 in `error.rs`
- [x] Catch errors in `get_authorized` and redirect to `popup_close` with message
- [x] Catch errors in `post_authorized` and redirect to `popup_close` with message
- [x] Improve error messages to be user-friendly
- [x] Differentiate error/success display in popup_close.j2 (login-card style, color, Close button)
- [x] Skip postMessage on error (avoid unnecessary parent reload)
- [x] Update security tests (BadRequest -> RedirectWithError)

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-09: Initial design -- redirect to popup_close on error

- Context: OAuth2 errors in popup show raw HTTP error text and popup never closes
- Considered: (1) Error-specific popup template, (2) Redirect to popup_close with error,
  (3) postMessage-based error passing to parent
- Decision: Redirect to popup_close with error message (simplest, addresses core issue)
- Reason: popup_close already handles postMessage + close. Minimal changes needed.
  More sophisticated error display (parent-side) can be added later.

### 2026-02-13: Skip postMessage on error, use login-card styling

- Context: Error popup was sending postMessage('auth_complete') to parent, causing
  unnecessary page reload even when authentication failed
- Decision: Only send postMessage on success; on error, show styled message with Close button
- Reason: No session is created on error, so parent reload is pointless and causes
  visual flicker while user is reading the error message

## Resolution

Implemented OAuth2 popup error handling with the following changes:

1. **error.rs**: Added `Conflict` -> 409 status code mapping (was falling through to 500)
2. **oauth2.rs**: Refactored `get_authorized`/`post_authorized` from `Result<...>` to
   infallible handlers using `match`. Errors redirect to `popup_close` with user-friendly
   messages via `friendly_error_message()` helper
3. **popup_close.j2**: Redesigned with `login-card` styling. Error shows red message +
   Close button. Success shows message + auto-close description. postMessage only sent
   on success to avoid unnecessary parent reload
4. **Security tests**: Updated `ExpectedSecurityError::BadRequest` -> `RedirectWithError`
   for all OAuth2 callback tests (13 in oauth2_security.rs, 1 in cross_flow_security.rs)

Branch: `dev-20260209-0902`, commits: `ac43e38`, `a83aae8`
