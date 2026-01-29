# Session Conflict Policy

When a user logs in while already having one or more active sessions, the library needs to decide what to do. The **session conflict policy** controls this behavior.

This is configured via a single environment variable and requires no code changes.

---

## Policies

| Policy | Env Value | Behavior |
|--------|-----------|----------|
| **Allow** | `allow` (default) | Permit multiple concurrent sessions. Each login creates a new session without affecting existing ones. |
| **Replace** | `replace` | Invalidate all existing sessions for the user before creating a new one. Only the most recent session remains active. |
| **Reject** | `reject` | Deny the login attempt if an active session already exists. The user must log out first. |

### Configuration

```bash
# In your .env or environment
SESSION_CONFLICT_POLICY=allow    # default
SESSION_CONFLICT_POLICY=replace
SESSION_CONFLICT_POLICY=reject
```

---

## When to Use Each Policy

### Allow (default)

Suitable for most applications. Users can be logged in from multiple devices or browsers simultaneously.

- Desktop and mobile access at the same time
- Multiple browser tabs or profiles
- Shared accounts where concurrent access is expected

### Replace

Useful when you want to ensure only one active session per user. The previous session is silently invalidated when a new login occurs.

- Security-sensitive applications (banking, admin panels)
- Licensing or seat-based restrictions
- Preventing session accumulation

When a session is replaced, the previous device/browser will see an "unauthenticated" state on its next request. No explicit notification is sent.

### Reject

Strictest policy. The login attempt itself fails if the user already has an active session. The user must explicitly log out before logging in again (or wait for the existing session to expire).

- High-security environments requiring explicit session lifecycle control
- Preventing account sharing
- Environments where session state must be deterministic

When rejected, the login handler returns a `SessionConflictRejected` error (HTTP 409 Conflict in the default Axum integration).

---

## How It Works

### User-to-Session Mapping

The library maintains a reverse index mapping each user ID to their active session IDs, stored in the cache (Redis or in-memory) under the `user_sessions` prefix:

```
cache key:   user_sessions:{user_id}
cache value: ["session_id_1", "session_id_2", ...]
```

This mapping is **always maintained** regardless of which policy is configured. It enables the library to look up all sessions for a given user without scanning the entire session store.

### Login Flow

When a user logs in, the following steps occur:

1. **Lazy cleanup** -- The library reads the user's session mapping and checks whether each listed session still exists in the cache. Expired or deleted sessions are pruned from the mapping.
2. **Policy evaluation** -- If active sessions remain after cleanup:
   - `allow`: Proceed to create a new session.
   - `replace`: Delete each existing session, then create a new session.
   - `reject`: Return an error without creating a session.
3. **Session creation** -- A new session is created and added to the user's mapping.

### Logout and Session Deletion

When a session is deleted (via logout or the `replace` policy), the library:

1. Reads the session data to obtain the `user_id`
2. Removes the session ID from the user's mapping
3. Deletes the session from the cache

This ensures the mapping stays consistent with the actual session state.

### Mapping TTL

The user-to-session mapping has a 30-day TTL in the cache. Since individual sessions expire independently (via `SESSION_COOKIE_MAX_AGE`), the mapping may temporarily contain references to expired sessions. These stale entries are cleaned up lazily on the next login attempt, so no background job is needed.

---

## Related Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_CONFLICT_POLICY` | `allow` | Session conflict policy (`allow`, `replace`, `reject`) |
| `SESSION_COOKIE_MAX_AGE` | `600` | Session lifetime in seconds (affects when sessions expire naturally) |

---

## Related Docs

- [Session Cookies](session.md)
- [Configuration Reference](../integration/configuration.md)
- [Production Deployment](production.md)
