# Issue: Add getClientCapabilities Feature Detection

## ID: 2026-01-30-05

## Status: completed

## Priority: medium

## Difficulty: small

## Description

Add `PublicKeyCredential.getClientCapabilities()` support to detect browser WebAuthn feature support before using them.

## Related Files

- `oauth2_passkey_axum/static/passkey.js` - Main passkey JS
- `oauth2_passkey_axum/static/conditional_ui.js` - Conditional UI JS
- `oauth2_passkey_axum/static/account.js` - Account management JS

## Notes

**What is getClientCapabilities?**

A new WebAuthn API that returns which features the browser supports:

```javascript
const capabilities = await PublicKeyCredential.getClientCapabilities();
// Returns:
// {
//   conditionalCreate: true/false,
//   conditionalGet: true/false,
//   signalAllAcceptedCredentials: true/false,
//   signalCurrentUserDetails: true/false,
//   signalUnknownCredential: true/false,
//   userVerifyingPlatformAuthenticator: true/false,
//   ...
// }
```

**Benefits**:
- Check Signal API support before calling (avoid errors on unsupported browsers)
- Enable/disable UI features based on browser capabilities
- Better error handling and fallback behavior

**Browser Support**:
- Chrome 131+ (December 2024)
- Other browsers: TBD

## Resolution

Added capability detection with caching to all three JS files:

**New functions added:**

1. `initPasskeyCapabilities()` - Initialize and cache capabilities on page load
2. `hasSignalCapability(capabilityName)` - Check if a Signal API is supported

**Implementation details:**

- Capabilities are cached in `_passkeyCapabilities` (null = not fetched, undefined = not supported)
- `hasSignalCapability()` checks cached capabilities first, falls back to `typeof` check
- All Signal API calls now use `hasSignalCapability()` instead of inline `typeof` checks

**Updated Signal API calls:**

- `account.js`:
  - `synchronizeCredentials()` - uses `hasSignalCapability('signalAllAcceptedCredentials')`
  - `synchronizeCredentialsWithSignalUnknown()` - uses `hasSignalCapability('signalUnknownCredential')`
  - `signalCurrentUserDetails()` - uses `hasSignalCapability('signalCurrentUserDetails')`

- `conditional_ui.js`:
  - `signalUnknownCredential` call - uses `hasSignalCapability('signalUnknownCredential')`
  - `signalAllAcceptedCredentials` call - uses `hasSignalCapability('signalAllAcceptedCredentials')`

**Benefits:**

- Cleaner, more consistent capability checking
- Single source of truth for capability detection
- Better debugging via capability logging on page load
- Backward compatible with browsers that don't support getClientCapabilities
