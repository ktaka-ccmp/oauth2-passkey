# Session Snapshot: Filter remaining_credential_ids by user_handle

**Date**: 2026-01-29
**Topic**: Filter `remaining_credential_ids` to only include credentials with the same `user_handle`

## Background

Currently, `remaining_credential_ids` in the deletion response is queried by `user_id` (app's DB ID), which may include credentials with different `user_handle` values when `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true`.

While this doesn't cause actual harm (authenticator ignores IDs with different user_handle), it's semantically incorrect and adds unnecessary noise to the response.

## Current Code

**File**: `oauth2_passkey/src/coordination/passkey.rs` (lines 358-367)

```rust
// Retrieve remaining credentials for authenticator synchronization
let remaining = list_credentials_core(user_id).await?;
let remaining_credential_ids = remaining.iter().map(|c| c.credential_id.clone()).collect();

Ok(DeleteCredentialResponse {
    remaining_credential_ids,
    user_handle,
})
```

## Proposed Change

Filter `remaining_credential_ids` to only include credentials with the same `user_handle` as the deleted credential:

```rust
// Retrieve remaining credentials for authenticator synchronization
let remaining = list_credentials_core(user_id).await?;

// Filter to only include credentials with the same user_handle
// This is semantically correct for signalAllAcceptedCredentials which is scoped by userId
let remaining_credential_ids = remaining
    .iter()
    .filter(|c| c.user.user_handle == user_handle)
    .map(|c| c.credential_id.clone())
    .collect();

Ok(DeleteCredentialResponse {
    remaining_credential_ids,
    user_handle,
})
```

## Expected Behavior After Change

| Mode | Before | After |
|------|--------|-------|
| `true` (unique) | All credential IDs (different handles) | Empty list (only deleted credential had that handle) |
| `false` (shared) | All credential IDs (same handle) | Same - all credential IDs (same handle) |

## Documentation Update

**File**: `docs/src/webauthn/user-handle-and-signal-api.md`

Update the "Credential Deletion Response" section (around line 493):

### Before:
```markdown
- `remaining_credential_ids`: All credential IDs still registered for this user
```

### After:
```markdown
- `remaining_credential_ids`: Credential IDs sharing the same `user_handle` as the deleted credential (for `signalAllAcceptedCredentials` which is scoped by userId)
```

Also update the JSON example comment if needed.

## Implementation Steps

1. **Modify `oauth2_passkey/src/coordination/passkey.rs`**:
   - Add filter to `remaining_credential_ids` collection
   - Add comment explaining the filtering rationale

2. **Update documentation**:
   - Update `docs/src/webauthn/user-handle-and-signal-api.md` "Credential Deletion Response" section

3. **Test**:
   - `cargo test`
   - Manual testing with both `true` and `false` modes

4. **Commit**:
   - Single commit with code change and documentation update

## Impact

- **`true` mode**: Response will have empty `remaining_credential_ids` (minor optimization, clearer semantics)
- **`false` mode**: No change in behavior
- **No breaking changes**: Client-side code already handles any credential list correctly
