# Session Snapshot: Session Conflict Policy Design

**Date**: 2026-01-28
**Status**: Design complete, implementation pending

## Current Task

Design a session conflict policy feature that:
1. Always maintains a `user_id -> session_id[]` mapping in cache
2. Controls behavior when a user logs in while already having active sessions
3. Provides an environment variable to select the conflict resolution policy

## Key Decisions

### Approach: JSON Array in Existing Cache (Approach A)

Store a JSON-serialized array of session IDs under a per-user cache key:

- **Key**: `cache:user_sessions:{user_id}`
- **Value**: `["session_id_1", "session_id_2", ...]` (JSON array)
- **Operations**: Use existing `CacheStore` trait (`put`, `get`, `remove`) -- no trait extension needed

### Environment Variable

- **Name**: `O2P_SESSION_CONFLICT_POLICY`
- **Values**:
  - `allow` (default) -- permit multiple concurrent sessions
  - `replace` -- invalidate all existing sessions, create new one
  - `reject` -- deny login if active session exists (return error)

### Mapping is Always Maintained

Regardless of the policy value, the user_id -> session_id mapping is always maintained. The env var only controls what happens when an existing session is found during new login.

### Lazy Cleanup for Expired Sessions

Sessions expire via TTL (Redis auto-expires; memory backend checks on access). The mapping may contain stale session IDs. Solution:

- When reading the mapping, verify each session_id still exists in cache
- Remove stale entries (sessions that no longer exist)
- Write back the cleaned mapping
- This avoids needing a background cleanup task or cache expiry callbacks

## Operation Flow

### Login (OAuth2 or Passkey)

1. Read mapping for user_id
2. Lazy cleanup: verify each session_id exists, prune stale ones
3. Apply policy:
   - `allow`: proceed to create new session
   - `replace`: delete all existing sessions, then create new session
   - `reject`: if active sessions remain after cleanup, return error
4. Create new session
5. Append new session_id to mapping, write back

### Logout

1. Delete session from cache
2. Read mapping for user_id
3. Remove the session_id from the array
4. Write back (or remove key if array is empty)

## Files to Modify

| File | Change |
|------|--------|
| `oauth2_passkey/src/session/config.rs` | Add `O2P_SESSION_CONFLICT_POLICY` env var and enum |
| `oauth2_passkey/src/session/main/session.rs` | Modify `create_new_session_with_uid()` to check mapping and apply policy; add mapping CRUD helpers |
| `oauth2_passkey/src/storage/cache_operations.rs` | Add user session mapping helpers (get/put/update JSON array) |
| `oauth2_passkey/src/session/main/session.rs` (logout) | Remove session_id from mapping on logout/session deletion |

## Architecture Context

### Current Session Flow
- Sessions stored as `cache:session:{random_id}` -> `StoredSession { user_id, csrf_token, expires_at, ttl }`
- No existing user_id -> session_id reverse index
- Session creation: `create_new_session_with_uid()` in `session/main/session.rs`
- Login paths: `coordination/oauth2.rs` and `coordination/passkey.rs` both call `new_session_header()`
- Cache backends: Memory (no TTL enforcement) and Redis (TTL via EXPIRE)

### Key Files (read-only reference)
- `oauth2_passkey/src/session/config.rs` -- session cookie config
- `oauth2_passkey/src/session/main/session.rs` -- session CRUD operations
- `oauth2_passkey/src/session/types.rs` -- `StoredSession` struct
- `oauth2_passkey/src/storage/cache_store/types.rs` -- `CacheStore` trait
- `oauth2_passkey/src/storage/cache_store/memory.rs` -- in-memory cache
- `oauth2_passkey/src/storage/cache_store/redis.rs` -- Redis cache
- `oauth2_passkey/src/storage/cache_operations.rs` -- cache helpers
- `oauth2_passkey/src/coordination/oauth2.rs` -- OAuth2 login flow
- `oauth2_passkey/src/coordination/passkey.rs` -- Passkey login flow

## Other Changes in This Session

- **Committed** (`14e1594`): Replaced `#N` numbering with `@YYYYMMDD` date suffix in passkey registration username prefill (`passkey.js`, `user/optional.rs`)

## Next Steps

1. Implement the session conflict policy feature following the design above
2. Add unit tests for mapping CRUD and policy enforcement
3. Test with both Memory and Redis cache backends
4. Update documentation/env example files
