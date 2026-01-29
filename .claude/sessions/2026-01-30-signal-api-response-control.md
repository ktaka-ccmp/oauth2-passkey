# Session Snapshot: Signal API Response Control

## Status: COMPLETED

## Summary

Removed `signalApiMode` variable from client-side (JS/templates) entirely and implemented server response-controlled Signal API behavior.

## Changes Made

### Server-Side (Rust)

**`oauth2_passkey_axum/src/passkey.rs`**:
- `handle_finish_authentication()`: Returns `signal_api_mode` in all responses
- `delete_passkey_credential()`: Returns `signal_api_mode` in all responses
- When mode includes `sync`: Also includes `credential_ids` and `user_handle`

```rust
let mut response = serde_json::json!({
    "name": auth_data.name,
    "signal_api_mode": PASSKEY_SIGNAL_API_MODE.as_str(),
});

if PASSKEY_SIGNAL_API_MODE.contains("sync") {
    response["user_handle"] = serde_json::json!(auth_data.user_handle);
    response["credential_ids"] = serde_json::json!(auth_data.credential_ids);
}
```

### Client-Side (JavaScript)

**`oauth2_passkey_axum/static/account.js`**:
- `deletePasskeyCredential()`: Checks `signal_api_mode` before calling `signalUnknownCredential`

```javascript
const mode = data.signal_api_mode || "direct";
if (mode.includes("direct")) {
    synchronizeCredentialsWithSignalUnknown(credentialId);
}
if (data.remaining_credential_ids) {
    synchronizeCredentials(data.user_handle, data.remaining_credential_ids);
}
```

**`oauth2_passkey_axum/static/passkey.js`** and **`conditional_ui.js`**:
- Auth failure: Always calls `signalUnknownCredential` (credential doesn't exist on server)
- Auth success: Calls `signalAllAcceptedCredentials` only if `credential_ids` present

### Templates

Removed `signalApiMode` variable from:
- `oauth2_passkey_axum/templates/login.j2`
- `oauth2_passkey_axum/templates/user_account.j2`
- `oauth2_passkey_axum/templates/conditional_ui.j2`

Removed `signal_api_mode` field from Rust template structs:
- `oauth2_passkey_axum/src/user/optional.rs` - `LoginTemplate`, `UserAccountTemplate`

### Documentation

Updated `docs/src/webauthn/user-handle-and-signal-api.md`:
- Added `signal_api_mode` field descriptions to response examples
- Updated client-side code examples

## Signal API Mode Behavior

| Mode | APIs Called | Use Case |
|------|-------------|----------|
| `direct` (default) | `signalUnknownCredential` only | Production |
| `sync` | `signalAllAcceptedCredentials` only | Testing |
| `direct+sync` | Both APIs | Future compatibility |

## Key Design Decisions

1. **Server controls client behavior via response content** - No client-side configuration needed
2. **Pure `sync` mode works correctly** - Only calls `signalAllAcceptedCredentials`
3. **Auth failure always calls `signalUnknownCredential`** - Credential genuinely doesn't exist

## Commits

- `d145ecc` - refactor(passkey): control Signal API via server response signal_api_mode
- `5d90fc6` - docs: add session snapshots for Signal API improvements

## Related Files

- `docs/src/webauthn/user-handle-and-signal-api.md` - Detailed documentation
- `dot.env.example` - Configuration example
