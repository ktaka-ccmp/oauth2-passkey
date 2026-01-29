# Session Snapshot: WebAuthn Signal API Testing Results

**Date**: 2026-01-29
**Topic**: Testing effectiveness of `signalAllAcceptedCredentials` vs `signalUnknownCredential`
**Environment**: Chrome + Google Password Manager

---

## Summary

| API | Deletion (`true` mode) | Deletion (`false` mode) | Login sync |
|-----|------------------------|-------------------------|------------|
| `signalUnknownCredential` | ✅ Works | ✅ Works | N/A |
| `signalAllAcceptedCredentials` | ❌ No effect | ❌ No effect | ❌ No effect |

**Key Finding**: `signalAllAcceptedCredentials` has **no visible effect** on Google Password Manager (Chrome) as of 2026-01. Only `signalUnknownCredential` actually removes credentials.

---

## Test 1: `signalAllAcceptedCredentials` Only (Deletion)

### Hypothesis

`signalUnknownCredential` might be redundant because `signalAllAcceptedCredentials` should handle deletion by excluding the deleted credential from the list.

### Test Setup

Commented out `synchronizeCredentialsWithSignalUnknown(credentialId)` in `deletePasskeyCredential()`.

### Results

**`true` mode (unique user_handle)**:
- Console: `Successfully signaled accepted credentials to authenticator. remaining: 0`
- Result: ❌ Credential NOT removed
- Passkey dialog: Credential still appeared

**`false` mode (shared user_handle)**:
- Console: `Successfully signaled accepted credentials to authenticator. remaining: N`
- Result: ❌ Credential NOT removed
- Passkey dialog: Credential still appeared

---

## Test 2: `signalUnknownCredential` Only (Deletion)

### Test Setup

Commented out `synchronizeCredentials()` (signalAllAcceptedCredentials) in `deletePasskeyCredential()`.

### Results

**`true` mode**: ✅ Credential removed from authenticator
**`false` mode**: ✅ Credential removed from authenticator

---

## Test 3: Login Sync with `signalAllAcceptedCredentials`

### Test Setup

After successful login, `signalAllAcceptedCredentials` is called with all valid credential IDs.

### Result

❌ No visible effect - deleted credentials on server still appear in passkey selection dialog.

---

## Root Cause Analysis

According to [Chrome's documentation](https://developer.chrome.com/docs/identity/webauthn-signal-api):
- `signalAllAcceptedCredentials` should "hide" credentials not in the list
- Hidden credentials should not appear in sign-in UI

**Actual behavior** (Google Password Manager, Chrome, 2026-01):
- API call succeeds without error
- Credentials are NOT hidden
- Credentials are NOT removed
- No visible effect whatsoever

**Possible explanations**:
- Google Password Manager hasn't fully implemented this API yet
- Implementation only marks internal state without UI effect
- Timing/propagation delay (but tested multiple times with no change)
- Spec vs implementation gap

---

## Conclusions

### For Credential Deletion

`signalUnknownCredential` is **necessary and sufficient** for both user_handle modes.

`signalAllAcceptedCredentials` currently has no effect, but:
- Keeping it is harmless (fire-and-forget, no performance impact)
- May work in future Chrome updates
- May work with other authenticators (iCloud Keychain, etc.)

### For Login Sync

`signalAllAcceptedCredentials` currently has no effect on Google Password Manager.
Credentials deleted server-side will still appear in passkey selection until:
- User manually removes them from Google Password Manager
- `signalUnknownCredential` is called for each orphaned credential

### Recommendation

**Keep both APIs** in the current "Dual Approach" for future-proofing, but document that:
- `signalUnknownCredential` is the only API that currently works
- `signalAllAcceptedCredentials` is called for spec compliance and future compatibility

---

## References

- [Chrome Developers: WebAuthn Signal API](https://developer.chrome.com/docs/identity/webauthn-signal-api)
- [MDN: signalAllAcceptedCredentials](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalAllAcceptedCredentials_static)
- [W3C Explainer: WebAuthn Signal API](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Signal-API-explainer)
