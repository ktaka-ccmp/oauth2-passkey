# Session Snapshot: Default Mode Consideration

**Date**: 2026-01-29
**Topic**: Should `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` default to `false`?

## Current State

Default is `true` (unique per credential).

## Comparison

| Aspect                         | `true` (current default)           | `false` (proposed)                  |
|--------------------------------|------------------------------------|-------------------------------------|
| Credentials per authenticator  | Unlimited                          | One                                 |
| Signal API effectiveness       | Limited                            | Full                                |
| WebAuthn spec alignment        | Non-standard                       | Aligned (one-handle-per-user)       |
| Password manager compatibility | Works around restrictions          | Native compatibility                |
| Credential cleanup on register | None                               | Old credential deleted              |

## Arguments for `false` as Default

1. **WebAuthn spec alignment**: The spec and Signal API assume one-user-handle-per-user
2. **Signal API works fully**: All sync APIs (`signalAllAcceptedCredentials`, `signalCurrentUserDetails`) work as intended
3. **Password manager friendly**: Native behavior matches PM expectations
4. **Simpler mental model**: "One passkey per device type per account"
5. **Security**: Fewer credentials means smaller attack surface

## Arguments for Keeping `true` as Default

1. **Flexibility**: Users can register multiple credentials from same authenticator
2. **No data loss**: Registration doesn't delete existing credentials
3. **Breaking change**: Existing deployments might rely on current behavior
4. **Development convenience**: Easier to test with multiple credentials

## Recommendation

**Change default to `false`** for the following reasons:

1. Aligns with WebAuthn specification intent
2. Signal API (which we just implemented) works optimally
3. Most real-world use cases don't need multiple credentials from same authenticator
4. Users who need `true` behavior can explicitly set it

## Implementation Plan

### Step 1: Change Default Value

**File**: `oauth2_passkey/src/config.rs` (or wherever the config is defined)

```rust
// Before
pub static PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL: Lazy<bool> =
    Lazy::new(|| env_var_bool("PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL", true));

// After
pub static PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL: Lazy<bool> =
    Lazy::new(|| env_var_bool("PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL", false));
```

### Step 2: Update Documentation

**File**: `docs/src/webauthn/user-handle-and-signal-api.md`

```markdown
| Value   | `user_handle`         | Credentials per authenticator |
|---------|-----------------------|-------------------------------|
| `true`  | Unique per credential | Unlimited                     |
| `false` (default) | Shared per user | One                       |
```

Also update:
- Configuration section to show `false` as default
- "Choosing the Right Strategy" section to reflect new default
- Any examples that assume `true` behavior

### Step 3: Update Example Configs

**Files**: `dot.env.example`, demo app configs

```bash
# Uncomment to allow multiple credentials per authenticator type
# PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true
```

### Step 4: Add Migration Note

Add to CHANGELOG or release notes:
- Breaking change notice
- Migration guidance for users who want to keep `true` behavior

## Risks

1. **Breaking change**: Users upgrading may experience different behavior
2. **Credential deletion**: Users might be surprised when old credentials are replaced
3. **Development friction**: Developers testing locally may need to set `true` explicitly

## Mitigation

- Clear documentation of the change
- Migration guide in release notes
- Prominent warning in configuration docs about credential replacement behavior

## Decision Required

Should we proceed with changing the default from `true` to `false`?

- If yes: Implement the plan above
- If no: Keep current default, document `false` as recommended for production
