# Session Snapshot: Signal API Response Control

## Current Task

Remove `signalApiMode` variable from client-side (JS/templates) entirely and control Signal API calls via server response instead.

### Background

Requiring custom page developers to define `signalApiMode` in their templates is poor developer experience. Adopted approach: control `signalAllAcceptedCredentials` calls by whether `credential_ids` is included in server response (Option 6).

## Files Modified (This Session - Uncommitted)

The following files were modified in the previous session but will be **rolled back** due to Option 6 adoption:

- `demo-custom-login/src/main.rs` - Added `signal_api_mode` field (to be removed)
- `demo-custom-login/templates/login.j2` - Added `signalApiMode` variable (to be removed)
- `demo-custom-login/templates/account.j2` - Added `signalApiMode` variable (to be removed)

## Key Decisions

### Option 6 Adopted: Server Response Control

All 6 options considered:

| Option | Summary | Adopted |
|--------|---------|---------|
| 1 | Embed config at JS serve time | ✗ Cache issues |
| 2 | Remove mode, hardcode direct | ✗ No future flexibility |
| 3 | Fetch from /o2p/config endpoint | ✗ Extra request needed |
| 4 | Serve separate config.js | ✗ Requires extra script tag |
| 5 | Use default value in JS | ✗ Global variable dependency |
| **6** | **Server response control** | **✓ Adopted** |

### Option 6 Design

```javascript
// Client-side - no signalApiMode needed
if (data.credential_ids && data.user_handle) {
    signalAllAcceptedCredentials({...});
}
```

```rust
// Server-side - include credential_ids based on mode
if PASSKEY_SIGNAL_API_MODE.contains("sync") {
    Json(json!({ "name": name, "user_handle": handle, "credential_ids": ids }))
} else {
    Json(json!({ "name": name }))
}
```

## Next Steps

See detailed plan at `.claude/plans/signal-api-response-control.md`.

1. **Step 1**: Conditional server response control
   - `oauth2_passkey_axum/src/passkey.rs` - Modify `handle_finish_authentication()`

2. **Step 2**: Remove signalApiMode from JS
   - Modify `passkey.js`, `conditional_ui.js`

3. **Step 3**: Remove signalApiMode from templates
   - Library templates (login.j2, account.j2, conditional_ui.j2)
   - Rust template structs

4. **Step 4**: Fix demo-custom-login
   - Remove signalApiMode added in previous session

5. **Step 5**: Clean up re-exports
   - Remove `PASSKEY_SIGNAL_API_MODE` re-export

## Context

### PASSKEY_SIGNAL_API_MODE

- `direct` (default): `signalUnknownCredential` only - **the only working API**
- `sync`: `signalAllAcceptedCredentials` only - currently has no effect
- `direct+sync`: Both - for future compatibility testing

### Related Commits (Previous Session)

- `f2dd947` - Fix CHANGELOG (move Signal API docs to Added section)
- `1e628dc` - Fix outdated paths in demo-custom-login README

### Reference Documentation

- `docs/src/webauthn/user-handle-and-signal-api.md` - Signal API detailed documentation
