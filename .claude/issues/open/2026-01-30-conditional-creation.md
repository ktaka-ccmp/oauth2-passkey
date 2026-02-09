# Issue: Passkey Registration Promotion After Login

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

### Approaches Considered but Rejected

1. **Server-side `has_passkey` flag**: Cannot determine per-device availability
2. **AAGUID matching**: No client-side API to get current device's AAGUID
3. **WebAuthn Conditional Creation** (`mediation: "conditional"`): Only works with
   password authentication, not OAuth2/identity federation
4. **User preferences API** (`/api/user/preferences`): Requires new storage layer;
   `localStorage` is simpler for "don't ask again" functionality
5. **Modifying existing RegistrationOptions struct**: Would change existing Passkey
   flow behavior; rejected in favor of JSON-level augmentation in new handler

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

- [ ] Add env var `O2P_PASSKEY_PROMOTION` config
- [ ] Create `passkey_promotion.rs` with new handler wrapping existing core function
- [ ] Add conditional route registration in router
- [ ] Create `passkey_promotion.js` with promotion UI, registration, and sessionStorage logic
- [ ] Add handler to serve `passkey_promotion.js` (conditional on env var)
- [ ] Add tests for new handler
- [ ] Update `dot.env.example` with new env var

## Resolution

