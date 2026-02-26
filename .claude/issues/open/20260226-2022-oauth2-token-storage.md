# Issue: OAuth2 Token Storage

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2022

## Created: 2026-02-26

## Closed:

## Status: open

## Priority: low

## Difficulty: large

## Description

Currently OAuth2 tokens (access, refresh, ID) are discarded after authentication. This means the backend cannot make Google API calls on behalf of the user after login. Storing tokens would enable use cases like accessing user's Google Calendar, Drive, etc.

### Security Risk: High

Stored tokens represent direct access to user's external accounts. Implementation requires:

- **Field-level encryption** for all tokens at rest
- **Secure key management** with proper rotation
- **Automatic token refresh** background jobs
- **Comprehensive audit logging** of all token access
- **Secure token deletion** on user request
- **Minimal scope principle** -- only store tokens with required permissions

### Alternative Approaches (Lower Risk)

- **Session-scoped tokens**: Discard on logout (simpler, lower risk)
- **On-demand re-authentication**: Re-authenticate when API access needed
- **API proxy pattern**: Backend makes calls without storing user tokens

### Proposed Schema

```sql
CREATE TABLE oauth2_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    provider TEXT NOT NULL,
    access_token TEXT NOT NULL,        -- Must be encrypted
    refresh_token TEXT,                -- Must be encrypted
    id_token TEXT,
    token_type TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
```

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (token storage becomes more valuable with multiple providers)

## Approach

Defer until there is concrete demand. The security complexity is high and the feature is only useful when the application needs to make API calls to OAuth2 providers on behalf of users. Consider starting with the session-scoped approach as a lower-risk alternative.

## Related Files

- `oauth2_passkey/src/oauth2/` - OAuth2 implementation
- `oauth2_passkey/src/coordination/oauth2.rs` - OAuth2 coordination
- `oauth2_passkey/src/storage/data_store/` - Database storage

## Implementation Tasks

- [ ] Decide on approach (persistent vs session-scoped vs on-demand)
- [ ] Design encryption strategy for tokens at rest
- [ ] Implement token storage schema and migrations
- [ ] Implement token CRUD operations with encryption
- [ ] Add automatic token refresh mechanism
- [ ] Add audit logging for token access
- [ ] Implement secure token deletion
- [ ] Add integration tests
- [ ] Update documentation

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as low-priority issue due to high security complexity
- Reason: High value but high risk; requires careful security design. No concrete demand yet

## Resolution

