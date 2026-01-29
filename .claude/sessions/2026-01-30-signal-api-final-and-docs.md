# Session Snapshot: Signal API Final Implementation & Documentation Updates

## Current Task

Completed Signal API server-controlled behavior implementation and updated various documentation files.

## Files Modified (This Session)

### Signal API Implementation
- `oauth2_passkey_axum/src/passkey.rs` - Added `signal_api_mode` to all responses
- `oauth2_passkey_axum/static/account.js` - Check `signal_api_mode` before calling `signalUnknownCredential`
- `oauth2_passkey_axum/static/passkey.js` - Updated comments for auth failure behavior
- `oauth2_passkey_axum/static/conditional_ui.js` - Updated comments for auth failure behavior
- `oauth2_passkey_axum/src/user/optional.rs` - Removed `signal_api_mode` from templates
- `oauth2_passkey_axum/templates/login.j2` - Removed `signalApiMode` variable
- `oauth2_passkey_axum/templates/user_account.j2` - Removed `signalApiMode` variable
- `oauth2_passkey_axum/templates/conditional_ui.j2` - Removed `signalApiMode` variable
- `dot.env.example` - Updated comments

### Documentation
- `docs/src/webauthn/user-handle-and-signal-api.md` - Updated with new response format
- `docs/src/getting-started/architecture.md` - Added demo-profile, demo-todo, test_utils

### Session Snapshots
- `.claude/sessions/2026-01-30-signal-api-response-control.md` - Updated to COMPLETED status

## Key Decisions

1. **Server-controlled Signal API behavior**
   - Server includes `signal_api_mode` in all responses
   - Client checks `signal_api_mode` before calling `signalUnknownCredential`
   - Pure `sync` mode now works correctly (only calls `signalAllAcceptedCredentials`)

2. **Auth failure always calls signalUnknownCredential**
   - Regardless of `PASSKEY_SIGNAL_API_MODE` setting
   - Because the credential genuinely doesn't exist on the server

3. **Mode behavior**
   | Mode | APIs Called |
   |------|-------------|
   | `direct` (default) | `signalUnknownCredential` only |
   | `sync` | `signalAllAcceptedCredentials` only |
   | `direct+sync` | Both APIs |

## Commits Made

- `d145ecc` - refactor(passkey): control Signal API via server response signal_api_mode
- `5d90fc6` - docs: add session snapshots for Signal API improvements
- `82aa0d6` - docs: update session snapshot for completed Signal API work
- `6035d14` - docs: update architecture with new demo apps and modules

### Workflow Tools Implementation

Created a reusable workflow system for session snapshots and issue tracking:

- `.claude/issues/` - Issue tracking directory with README
- `.claude/commands/issue.md` - Create/update issues
- `.claude/commands/backlog.md` - View open issues
- `CLAUDE.md` - Added workflow documentation

## Open Issues

Moved pending tasks to issue tracking system:
- `.claude/issues/2026-01-30-move-info-csrf-endpoints.md` - Move /info and /csrf_token to default.rs

## Context

- Branch: `dev-signalapi`
- Signal API work is complete
- Workflow tools implemented for reusable session/issue management
