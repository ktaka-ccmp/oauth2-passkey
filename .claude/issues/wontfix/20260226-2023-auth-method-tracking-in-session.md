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

## Closed: 2026-03-03

## Status: wontfix

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

### 2026-03-03: Closed as wontfix (YAGNI)

Reviewed all proposed use cases and found none are actionable:

1. **Step-up authentication**: Not applicable. Both OAuth2 and Passkey rely on password managers as trust anchors, so there is no meaningful difference in authentication strength. Requiring one method after the other adds friction without improving security.

2. **Conditional UI/UX based on auth method**: No concrete scenario identified where the UI should differ based on how the user logged in. Account management pages are the same regardless.

3. **Security audit trails**: Already covered by login history (`LoginHistoryEntry` records `AuthMethod` for every login). Adding it to the session would be redundant.

4. **Passkey promotion**: The current implementation works without session-level auth method tracking. The OAuth2 popup flow context itself implicitly identifies OAuth2 logins, and the `promotion_check` endpoint uses UA + AAGUID heuristics to decide whether to prompt. No need for `auth_method` in `StoredSession`.

- Decision: Wontfix -- no real use case justifies the added complexity
- Principle: YAGNI (You Aren't Gonna Need It)

## Resolution

Closed as wontfix. All proposed use cases were reviewed and none require `auth_method` in the session. Step-up authentication is not meaningful when both auth methods share the same trust anchor (password managers). Audit logging is already handled by login history. Passkey promotion works via OAuth2 popup flow context without session-level tracking.
