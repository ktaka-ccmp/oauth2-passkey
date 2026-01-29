# Issue: WebAuthn Signal API Implementation

## ID: 2026-01-28-01

## Status: completed

## Priority: medium

## Description

Implement WebAuthn Signal API integration for credential synchronization between server and authenticators. Includes `signalUnknownCredential`, `signalAllAcceptedCredentials`, and `signalCurrentUserDetails` API support with configurable mode.

## Related Files

- `oauth2_passkey/src/env_var.rs` - PASSKEY_SIGNAL_API_MODE configuration
- `oauth2_passkey/src/coordination/passkey.rs` - Response structs with credential data
- `oauth2_passkey_axum/src/passkey.rs` - JSON responses with signal_api_mode
- `oauth2_passkey_axum/static/account.js` - Deletion Signal API calls
- `oauth2_passkey_axum/static/passkey.js` - Login Signal API calls
- `oauth2_passkey_axum/static/conditional_ui.js` - Conditional UI Signal API calls
- `docs/src/webauthn/user-handle-and-signal-api.md` - Documentation

## Notes

**Implementation Timeline**:
- 2026-01-28: Initial implementation plan and code changes
- 2026-01-29: Testing, PASSKEY_SIGNAL_API_MODE config plan, remaining_credentials filter consideration
- 2026-01-30: Server response-controlled behavior, cleanup, documentation

**Key Features**:
1. Server controls client Signal API behavior via `signal_api_mode` in responses
2. Three modes: `direct` (default), `sync`, `direct+sync`
3. Auth failure always calls `signalUnknownCredential` regardless of mode
4. Deletion returns `remaining_credential_ids` and `user_handle` for sync

**Testing Results** (Chrome + Google Password Manager):
- `signalUnknownCredential`: Works for credential removal
- `signalAllAcceptedCredentials`: No visible effect (kept for future compatibility)

**Commits**:
- `d145ecc` - refactor(passkey): control Signal API via server response signal_api_mode
- Earlier commits for initial implementation

## Resolution

Completed 2026-01-30. Signal API fully integrated with configurable mode support.
