# Passkey Registration Session Protection

## Overview

This document covers how the library preserves session identity across the passkey credential registration flow — from the moment the user's account page is rendered to the moment a new passkey credential is registered. Two distinct session-boundary attacks are possible during that window; the library handles each in a separate phase of the flow with its own mechanism:

| Phase | Window | Mechanism | Purpose |
|-------|--------|-----------|---------|
| Phase 1 | Page render → "Add New Passkey" click | `X-CSRF-Token` header (standard CSRF) | Detect session changes before `register/start` |
| Phase 2 | `register/start` → `register/finish` | `user_handle`-keyed `SessionInfo` + ID check at finish | Maintain user identity across the authenticator round-trip |

Each phase is detailed below, preceded by the attack scenarios it addresses. The protection structure parallels [OAuth2 Linking Session Protection](oauth2-linking-protection.md); see the [Comparison with OAuth2 Linking](#comparison-with-oauth2-linking) section for the side-by-side view.

## Session Boundary Attacks

Modern web applications face two common session-boundary problems during multi-step authentication flows:

### Page-to-Request Desynchronization

A user loads a page while logged in as Account A. Later, they log in as Account B in another tab or window. If they return to the original page and perform an action, that action may be executed as Account B — potentially registering a credential to the wrong user.

**Concrete Scenario:**

1. A user views their account page (User A) with an "Add New Passkey" button
2. The user opens another tab and logs in as a different user (User B)
3. The user returns to the first tab (still showing User A's page)
4. The user clicks "Add New Passkey", expecting to register the credential to User A
5. Without protection, the passkey credential would be registered to User B instead, because that is the active session

### Process Start-to-Completion Desynchronization

The passkey registration flow is inherently multi-step: the server returns a challenge from `register/start`, the browser communicates with the authenticator (which can take seconds to minutes — biometric prompt, security key tap, etc.), and only then submits the assertion to `register/finish`. If the user's session changes during that window, the assertion submitted at `register/finish` would otherwise be processed under the new session, registering the credential to the wrong user.

## Phase 1: X-CSRF-Token Header

Phase 1 protects the window between rendering the user's account page and the click that initiates passkey registration.

Because passkey registration is initiated by a `fetch` POST (not a navigation), the standard `X-CSRF-Token` header rides along with the request. The library's CSRF middleware verifies this header against the current session's CSRF token automatically; if the session changed between page render and click, the stale token is rejected with 403 before any registration state is created.

### How It Works

1. When rendering the user's account page, the server's CSRF token for the current session is exposed via the standard mechanism (template variable, the `/auth/user/csrf_token` endpoint, or a response header).
2. The client's JavaScript stores this CSRF token at page render time.
3. When the user clicks "Add New Passkey", the client issues a POST to `/passkey/register/start` with `X-CSRF-Token: <token>` in the request headers:

   ```javascript
   // oauth2_passkey_axum/static/passkey.js (in startRegistration)
   startResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/register/start', {
       method: 'POST',
       headers: {
           'X-CSRF-Token': `${csrfToken}`,
           'Content-Type': 'application/json',
       },
       credentials: 'same-origin',
       body: JSON.stringify(request)
   });
   ```

4. The middleware compares the header value against the current session's CSRF token. If they don't match, the request is rejected with 403 before any handler logic runs.

The mechanism naturally detects session changes: the JS-held CSRF token was bound to the session at page render time, and a new session has a new CSRF token, so the comparison fails.

### Why No Page Session Token Here

Unlike OAuth2 linking, passkey registration starts with a `fetch` POST rather than a `window.open(...)` navigation. POST requests can carry custom headers, so the CSRF token can travel directly in the `X-CSRF-Token` header — no HMAC obfuscation is needed, and the token never appears in a URL (and therefore not in Referer headers, server access logs, or browser history).

See [CSRF Protection](csrf.md) for the underlying header-based CSRF mechanism.

## Phase 2: user_handle-Keyed SessionInfo

Phase 2 protects the window between the server returning a registration challenge (`register/start`) and the client submitting the credential assertion (`register/finish`). The browser is communicating with the authenticator during this window; if the session cookie changes (e.g. the user logs out and back in as a different account in another tab), the assertion submitted at `register/finish` would otherwise be processed under the new session, registering the credential to the wrong user.

### How It Works

**1. Storing the registration's user context at start.**

At `register/start`, the server stores a `SessionInfo { user }` entry in the cache, keyed by the generated `user_handle`:

```rust
// oauth2_passkey/src/passkey/main/register.rs (in start_registration)
let session_info = SessionInfo { user: u.clone() };
store_cache_keyed::<_, PasskeyError>(
    CachePrefix::session_info(),
    cache_key,           // built from user_handle
    session_info,
    (*PASSKEY_CHALLENGE_TIMEOUT).into(),
).await?;
```

The `user_handle` is included in the `RegistrationOptions` sent to the browser.

**2. Browser-authenticator round-trip.**

The browser invokes `navigator.credentials.create()` with the challenge, the user interacts with the authenticator (biometric, security key, etc.), and the resulting assertion (including the `user_handle`) is POSTed to `register/finish`.

**3. Verifying user identity at finish.**

At `register/finish`, the server retrieves the `SessionInfo` stored under that `user_handle` and explicitly compares the stored user ID to the current session's user ID:

```rust
// oauth2_passkey/src/passkey/main/register.rs
// (in verify_session_then_finish_registration)
if session_user.id != session_info.user.id {
    return Err(PasskeyError::Format("User ID mismatch".to_string()));
}
```

If the session has changed since `register/start`, the IDs don't match and the registration is rejected before the credential is persisted.

### Why This Works

The `user_handle` is generated server-side at `register/start` and is unique per registration attempt. It serves as a single-use binding between the start and finish steps. The current session at `register/finish` is compared not against a generic CSRF token but against the specific user who initiated the registration, ensuring continuity regardless of intermediate session changes.

The stored `SessionInfo` entry is also removed at the end of `verify_session_then_finish_registration`, so a replayed `register/finish` request cannot re-use it.

## Comparison with OAuth2 Linking

The same two session-boundary attacks are protected against in both flows, but with mechanisms suited to each flow's transport:

| Phase | OAuth2 Linking | Passkey Registration |
|-------|----------------|----------------------|
| Phase 1 | `page_session_token` (HMAC of session CSRF) embedded in URL | `X-CSRF-Token` header on `fetch` POST |
| Phase 2 | `misc_session`: random `misc_id`, referenced via OAuth2 state parameter | `SessionInfo`: keyed by generated `user_handle` |

The key difference is the transport at Phase 1: OAuth2 linking is initiated by a `window.open(...)` navigation, which cannot carry custom headers, so Phase 1 has to ride in the URL with HMAC obfuscation to avoid leaking the session CSRF token. Passkey registration is initiated by a `fetch` POST, which can carry custom headers, so the CSRF token flows directly without obfuscation.

For OAuth2-specific details see [OAuth2 Linking Session Protection](oauth2-linking-protection.md).

## Implementation Notes

### Early Detection

Both phases catch problems at the earliest possible point:

- Phase 1 rejects with 403 before any registration challenge is issued
- Phase 2 rejects before the credential is persisted

### Minimal Implementation

- Phase 1 reuses the existing CSRF middleware — no passkey-specific mechanism
- Phase 2 leverages the cache store already in use for registration challenges
- No additional database tables or schema changes

## Testing Session Protection

### Phase 1: Page-to-Request Detection

1. Log in as User A and open their account page
2. In another tab, log out and log in as User B
3. Return to User A's account page and click "Add New Passkey"
4. The POST to `/passkey/register/start` is rejected with 403
5. No registration challenge is issued; no state is mutated

### Phase 2: Registration Round-trip Continuity

1. Log in as User A and trigger passkey registration (`register/start` succeeds, an authenticator prompt appears)
2. Before responding to the authenticator prompt, log out and log in as User B in another tab
3. Complete the authenticator prompt and submit `register/finish`
4. The server rejects with "User ID mismatch"
5. No credential is stored

These tests confirm both phases of the protection work as designed.
