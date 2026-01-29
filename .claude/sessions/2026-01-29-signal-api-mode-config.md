# Session Snapshot: PASSKEY_SIGNAL_API_MODE Configuration

**Date**: 2026-01-29
**Topic**: Add environment variable to control which Signal APIs are called
**Status**: 📋 Plan

---

## Overview

Add `PASSKEY_SIGNAL_API_MODE` environment variable to control which Signal APIs are used for credential deletion and login sync.

| Value | Description | APIs Called |
|-------|-------------|-------------|
| `direct` | Direct targeting only (default) | `signalUnknownCredential` |
| `sync` | Sync-based only | `signalAllAcceptedCredentials` |
| `direct+sync` | Both APIs | Both |

**Default**: `direct` (the only API that currently works with Google Password Manager)

---

## Detailed Implementation Plan

### Step 1: Add Environment Variable Definition

**File**: `oauth2_passkey/src/env_var.rs`

Add after other `PASSKEY_*` variables (around line 50):

```rust
/// Signal API mode for credential synchronization with authenticators.
/// - "direct": signalUnknownCredential only (default, currently the only working API)
/// - "sync": signalAllAcceptedCredentials only
/// - "direct+sync": both APIs
pub static PASSKEY_SIGNAL_API_MODE: Lazy<String> = Lazy::new(|| {
    let mode = std::env::var("PASSKEY_SIGNAL_API_MODE").unwrap_or_else(|_| "direct".to_string());
    let valid_modes = ["direct", "sync", "direct+sync"];
    if !valid_modes.contains(&mode.as_str()) {
        tracing::warn!(
            "Invalid PASSKEY_SIGNAL_API_MODE '{}', valid values are: {:?}. Using 'direct'.",
            mode,
            valid_modes
        );
        "direct".to_string()
    } else {
        mode
    }
});
```

### Step 2: Export from Library

**File**: `oauth2_passkey/src/lib.rs`

Ensure `PASSKEY_SIGNAL_API_MODE` is exported (if not already re-exporting all from env_var):

```rust
pub use env_var::PASSKEY_SIGNAL_API_MODE;
```

### Step 3: Pass to Account Page Template

**File**: `oauth2_passkey_axum/src/user.rs`

Find `my_account()` function (around line 200-250). Update template context:

**Before**:
```rust
context.insert("csrf_token", &csrf_token);
context.insert("user_id", &user_id);
// ... other context
```

**After**:
```rust
use oauth2_passkey::PASSKEY_SIGNAL_API_MODE;

context.insert("csrf_token", &csrf_token);
context.insert("user_id", &user_id);
context.insert("signal_api_mode", &*PASSKEY_SIGNAL_API_MODE);
// ... other context
```

### Step 4: Expose to JavaScript in Template

**File**: `oauth2_passkey_axum/src/templates/account.html`

Find the `<script>` section where other JS variables are defined (around line 20-40):

**Before**:
```html
<script>
    const csrfToken = "{{ csrf_token }}";
    const userId = "{{ user_id }}";
    const accountName = "{{ account }}";
</script>
```

**After**:
```html
<script>
    const csrfToken = "{{ csrf_token }}";
    const userId = "{{ user_id }}";
    const accountName = "{{ account }}";
    const signalApiMode = "{{ signal_api_mode }}";
</script>
```

### Step 5: Update account.js - Deletion Logic

**File**: `oauth2_passkey_axum/static/account.js`

Find `deletePasskeyCredential()` function (around line 312-354).

**Before** (lines 326-336):
```javascript
const data = await response.json();
// DUAL APPROACH: Use both Signal APIs for maximum compatibility
// Both are fire-and-forget (no await) to avoid blocking page reload
// Step 1: signalUnknownCredential - directly targets the deleted credential
// Works for both user_handle modes (unique or shared)
synchronizeCredentialsWithSignalUnknown(credentialId);
// Step 2: signalAllAcceptedCredentials - syncs remaining credentials
// Effective when user_handle is shared, harmless when unique
synchronizeCredentials(
    data.user_handle || userHandle,
    data.remaining_credential_ids
);
```

**After**:
```javascript
const data = await response.json();
// Signal API calls based on PASSKEY_SIGNAL_API_MODE
// Both are fire-and-forget (no await) to avoid blocking page reload

// signalUnknownCredential: directly targets the deleted credential
// Currently the only API that works with Google Password Manager
if (signalApiMode === 'direct' || signalApiMode === 'direct+sync') {
    synchronizeCredentialsWithSignalUnknown(credentialId);
}

// signalAllAcceptedCredentials: syncs remaining credentials
// Currently has no effect on Google Password Manager, kept for future compatibility
if (signalApiMode === 'sync' || signalApiMode === 'direct+sync') {
    synchronizeCredentials(
        data.user_handle || userHandle,
        data.remaining_credential_ids
    );
}
```

### Step 6: Update account.js - Account Deletion Logic

**File**: `oauth2_passkey_axum/static/account.js`

Find `DeleteAccount()` function (around line 59-122).

**Before** (lines 97-103):
```javascript
credentialIds.forEach((credentialId) => {
    notificationChain = notificationChain.then(() => {
        return synchronizeCredentialsWithSignalUnknown(
            credentialId
        );
    });
});
```

**After**:
```javascript
// Only call signalUnknownCredential if mode includes 'direct'
if (signalApiMode === 'direct' || signalApiMode === 'direct+sync') {
    credentialIds.forEach((credentialId) => {
        notificationChain = notificationChain.then(() => {
            return synchronizeCredentialsWithSignalUnknown(
                credentialId
            );
        });
    });
}
```

### Step 7: Update passkey.js - Login Success

**File**: `oauth2_passkey_axum/static/passkey.js`

First, need to pass `signalApiMode` to this file. Check how it's loaded and if it has access to the variable.

If `passkey.js` is loaded on login page, need to also pass the mode there.

**File**: `oauth2_passkey_axum/src/templates/login.html` (or wherever passkey.js is included)

Add:
```html
<script>
    const signalApiMode = "{{ signal_api_mode }}";
</script>
```

**File**: `oauth2_passkey_axum/src/passkey.rs`

Update login page handler to include `signal_api_mode` in context.

**File**: `oauth2_passkey_axum/static/passkey.js`

Find `signalAfterLogin()` or similar function. Update to check mode:

```javascript
// Only call signalAllAcceptedCredentials if mode includes 'sync'
if (typeof signalApiMode !== 'undefined' &&
    (signalApiMode === 'sync' || signalApiMode === 'direct+sync')) {
    synchronizeCredentials(data.user_handle, data.credential_ids);
}
```

### Step 8: Update conditional_ui.js - Login Success

**File**: `oauth2_passkey_axum/static/conditional_ui.js`

Similar update as passkey.js for conditional UI login flow.

### Step 9: Update Documentation

**File**: `docs/src/webauthn/user-handle-and-signal-api.md`

Add section after "Current Browser Behavior":

```markdown
### Signal API Mode Configuration

The `PASSKEY_SIGNAL_API_MODE` environment variable controls which Signal APIs are called:

| Value | APIs Called | Description |
|-------|-------------|-------------|
| `direct` (default) | `signalUnknownCredential` | Direct targeting - the only API currently working with Google Password Manager |
| `sync` | `signalAllAcceptedCredentials` | Sync-based - currently no effect on Chrome, may work with other authenticators |
| `direct+sync` | Both | Call both APIs for maximum compatibility |

**Recommendation**: Use `direct` (default) for production. Use `direct+sync` for testing future browser support.
```

**File**: `docs/src/integration/configuration.md`

Add to configuration table:

```markdown
| `PASSKEY_SIGNAL_API_MODE` | `direct` | Signal API mode: `direct`, `sync`, or `direct+sync` |
```

### Step 10: Update dot.env.example

**File**: `dot.env.example`

Add:

```bash
# Signal API mode for credential synchronization with authenticators
# - direct: signalUnknownCredential only (default, currently working)
# - sync: signalAllAcceptedCredentials only (currently no effect on Chrome)
# - direct+sync: both APIs (for testing future compatibility)
# PASSKEY_SIGNAL_API_MODE=direct
```

---

## Files Summary

| File | Changes | Lines |
|------|---------|-------|
| `oauth2_passkey/src/env_var.rs` | Add PASSKEY_SIGNAL_API_MODE variable | +15 |
| `oauth2_passkey/src/lib.rs` | Export if needed | +1 |
| `oauth2_passkey_axum/src/user.rs` | Pass mode to account template | +2 |
| `oauth2_passkey_axum/src/passkey.rs` | Pass mode to login templates | +2 |
| `oauth2_passkey_axum/src/templates/account.html` | Expose signalApiMode to JS | +1 |
| `oauth2_passkey_axum/src/templates/login.html` | Expose signalApiMode to JS | +1 |
| `oauth2_passkey_axum/static/account.js` | Conditional API calls | +15 |
| `oauth2_passkey_axum/static/passkey.js` | Conditional API calls | +5 |
| `oauth2_passkey_axum/static/conditional_ui.js` | Conditional API calls | +5 |
| `docs/src/webauthn/user-handle-and-signal-api.md` | Document the option | +20 |
| `docs/src/integration/configuration.md` | Add to config reference | +1 |
| `dot.env.example` | Add example | +5 |

**Total**: ~70 lines across 12 files

---

## Testing Checklist

### Test 1: Default mode (`direct`)

```bash
# Unset or don't set PASSKEY_SIGNAL_API_MODE
```

- [ ] Delete credential → Console shows only `signalUnknownCredential` call
- [ ] Credential removed from Google Password Manager
- [ ] Login → No `signalAllAcceptedCredentials` call

### Test 2: Sync mode (`sync`)

```bash
PASSKEY_SIGNAL_API_MODE=sync
```

- [ ] Delete credential → Console shows only `signalAllAcceptedCredentials` call
- [ ] Credential NOT removed from Google Password Manager (expected, current Chrome behavior)
- [ ] Login → `signalAllAcceptedCredentials` called

### Test 3: Both mode (`direct+sync`)

```bash
PASSKEY_SIGNAL_API_MODE=direct+sync
```

- [ ] Delete credential → Console shows BOTH API calls
- [ ] Credential removed from Google Password Manager
- [ ] Login → `signalAllAcceptedCredentials` called

### Test 4: Invalid value

```bash
PASSKEY_SIGNAL_API_MODE=invalid
```

- [ ] Server logs warning about invalid value
- [ ] Falls back to `direct` mode
- [ ] Functions correctly as `direct` mode

---

## Rollback Plan

If issues are found:
1. Set `PASSKEY_SIGNAL_API_MODE=direct+sync` to restore original behavior
2. Or revert the code changes

No database changes required.
