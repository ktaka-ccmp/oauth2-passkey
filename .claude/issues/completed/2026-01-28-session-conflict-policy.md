# Issue: Session Conflict Policy Implementation

## ID: 2026-01-28-02

## Status: completed

## Priority: medium

## Description

Implement session conflict policy feature to control behavior when a user logs in with an existing session.

## Related Files

- `oauth2_passkey/src/session/main/user_sessions.rs` - Mapping CRUD + lazy cleanup
- `oauth2_passkey/src/session/config.rs` - SessionConflictPolicy enum, O2P_SESSION_CONFLICT_POLICY
- `oauth2_passkey/src/session/errors.rs` - SessionConflictRejected variant
- `oauth2_passkey/src/session/main/session.rs` - Policy enforcement
- `dot.env.example` - Documentation

## Notes

Policy options:
- `allow` (default) - Multiple concurrent sessions permitted
- `replace` - Old sessions invalidated on new login
- `reject` - Login denied if session exists

Implementation details:
- JSON array approach for user->session mapping using existing CacheStore trait
- 30-day TTL for mapping entries (lazy cleanup handles stale sessions)
- Mapping always maintained regardless of policy value

## Resolution

Completed 2026-01-28. Commit: 5c6d8d9.
