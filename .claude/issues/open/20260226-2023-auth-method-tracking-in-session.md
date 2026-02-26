# Issue: Authentication Method Tracking in Session

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2023

## Created: 2026-02-26

## Closed:

## Status: open

## Priority: low

## Difficulty: small

## Description

Record how a user authenticated (OAuth2 vs Passkey) in the session storage (`StoredSession`), making it available to the application at runtime.

Currently, login history records the authentication method, but the active session itself does not expose this information. Adding `auth_method` to `StoredSession` would enable:

- **Conditional UI/UX** based on authentication method
- **Security audit trails** and logging
- **Different user flows** per authentication method (e.g., step-up authentication)
- **Passkey promotion** logic (already partially implemented via login history)

### Proposed Change

```rust
enum AuthenticationMethod {
    OAuth2 { provider: String },
    Passkey,
}

struct StoredSession {
    // ... existing fields ...
    auth_method: AuthenticationMethod,
}
```

### Backwards Compatibility

Existing sessions in cache will not have `auth_method`. Deserialization must handle missing field gracefully (default to `None` or `Unknown`).

## Related Issues

None

## Approach

1. Add `AuthenticationMethod` enum to session types
2. Set `auth_method` during session creation in OAuth2 and Passkey coordination modules
3. Expose via `AuthUser` for use in handlers
4. Handle backwards compatibility for existing sessions

## Related Files

- `oauth2_passkey/src/session/` - Session types and management
- `oauth2_passkey/src/coordination/oauth2.rs` - OAuth2 session creation
- `oauth2_passkey/src/coordination/passkey.rs` - Passkey session creation
- `oauth2_passkey_axum/src/middleware.rs` - AuthUser construction

## Implementation Tasks

- [ ] Add `AuthenticationMethod` enum
- [ ] Add `auth_method` field to `StoredSession`
- [ ] Update session creation in OAuth2 coordination
- [ ] Update session creation in Passkey coordination
- [ ] Expose `auth_method` in `AuthUser`
- [ ] Handle backwards compatibility (missing field deserialization)
- [ ] Add unit tests
- [ ] Update documentation

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as low-priority, small-difficulty issue
- Reason: Low risk, straightforward implementation, but no immediate demand

## Resolution
