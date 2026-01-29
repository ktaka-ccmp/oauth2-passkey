# Session Snapshot: Signal API Credential Synchronization Improvement

**Date**: 2026-01-28
**Topic**: WebAuthn Signal API credential synchronization improvement

## Current Task

Improving credential synchronization between server and authenticator using WebAuthn Signal API. Documentation complete, implementation of dual approach pending.

## Completed Work

### 1. Signal API Implementation (Steps 1-4 from plan)

All 4 steps from the plan (`transient-wibbling-turtle.md`) have been implemented but **not yet committed**:

- **Step 1**: DELETE endpoint returns JSON with `remaining_credential_ids` and `user_handle` (was `StatusCode::NO_CONTENT`)
- **Step 2**: `account.js` deletion uses `signalAllAcceptedCredentials` with remaining IDs (was `signalUnknownCredential` only)
- **Step 3**: Login success calls `signalAllAcceptedCredentials` + `signalCurrentUserDetails` in `passkey.js` and `conditional_ui.js` (was no Signal API calls). Auth finish endpoint returns JSON with `name`, `user_handle`, `credential_ids` (was plain text name)
- **Step 4**: Login failure calls `signalUnknownCredential` in `passkey.js` and `conditional_ui.js` (was no Signal API calls)

### 2. Documentation

Created comprehensive documentation at `docs/src/webauthn/user-handle-and-signal-api.md`:
- How `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` works (true vs false)
- Signal API behavior analysis for each mode
- Dual approach strategy (combining `signalUnknownCredential` + `signalAllAcceptedCredentials` for deletion)
- Added to SUMMARY.md in Part 6: Reference

### 3. Analysis: User Handle Strategy Impact on Signal API

Key finding: Signal API effectiveness depends on user handle strategy:
- `signalAllAcceptedCredentials` and `signalCurrentUserDetails` operate per-userId (user_handle) -> only effective when `false` (shared handle)
- `signalUnknownCredential` operates per-credentialId -> works in both modes
- Dual approach for deletion (both APIs) provides optimal results regardless of mode

## Files Modified (Uncommitted)

### Rust (Server-side)
- `oauth2_passkey/src/coordination/passkey.rs` - `DeleteCredentialResponse`, `AuthenticationResponse` structs; changed return types
- `oauth2_passkey/src/coordination/mod.rs` - re-exports
- `oauth2_passkey/src/lib.rs` - re-exports
- `oauth2_passkey/src/passkey/main/auth.rs` - `finish_authentication()` now returns `user_handle`
- `oauth2_passkey_axum/src/passkey.rs` - JSON responses for delete and auth handlers
- `oauth2_passkey_axum/src/admin/default.rs` - `|_|` fix for new return type

### JavaScript (Client-side)
- `oauth2_passkey_axum/static/account.js` - `synchronizeCredentials()` accepts `remainingCredentialIds` param
- `oauth2_passkey_axum/static/passkey.js` - `signalAfterLogin()`, `signalUnknownCredential` on failure
- `oauth2_passkey_axum/static/conditional_ui.js` - Signal API for login success/failure

### Documentation
- `docs/src/webauthn/user-handle-and-signal-api.md` (NEW)
- `docs/src/SUMMARY.md` - added link

## Next Steps

1. **Implement dual approach**: Add `signalUnknownCredential` call before `signalAllAcceptedCredentials` in `deletePasskeyCredential()` in `account.js` (1 line change)
2. **Commit all changes**: Signal API implementation + documentation
3. **Manual testing**: Test deletion and login flows in browser with DevTools Console

## Key Decisions

1. Use dual approach (both `signalUnknownCredential` + `signalAllAcceptedCredentials`) for deletion to work optimally in both `true` and `false` modes
2. `signalUnknownCredential` called first (direct targeting), then `signalAllAcceptedCredentials` (comprehensive sync)
3. Login flow: no change needed (current APIs are appropriate)

## Context

- `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` defaults to `true`
- Signal API browser support: Chrome 132+, Edge 132+, Safari 26+, Firefox not supported
- All Signal API calls are fire-and-forget, non-critical, with feature detection
- `cargo fmt && cargo clippy && cargo test` all pass
