# Issue: Filter remaining_credential_ids by user_handle

## Status: open

## Priority: low

## Description

Filter `remaining_credential_ids` in deletion response to only include credentials with the same `user_handle` as the deleted credential. Currently returns all credentials by `user_id`, which is semantically incorrect for `signalAllAcceptedCredentials`.

## Related Files

- `oauth2_passkey/src/coordination/passkey.rs` - Add filter (lines 358-367)
- `docs/src/webauthn/user-handle-and-signal-api.md` - Update documentation

## Notes

From session 2026-01-29:

**Current Code**:
```rust
let remaining = list_credentials_core(user_id).await?;
let remaining_credential_ids = remaining.iter().map(|c| c.credential_id.clone()).collect();
```

**Proposed Change**:
```rust
let remaining = list_credentials_core(user_id).await?;
let remaining_credential_ids = remaining
    .iter()
    .filter(|c| c.user.user_handle == user_handle)
    .map(|c| c.credential_id.clone())
    .collect();
```

**Expected Behavior**:
| Mode | Before | After |
|------|--------|-------|
| `true` (unique) | All credential IDs | Empty list |
| `false` (shared) | All credential IDs | Same (all share handle) |

**Impact**: No breaking changes. Cleaner semantics, minor optimization for `true` mode.

## Resolution

