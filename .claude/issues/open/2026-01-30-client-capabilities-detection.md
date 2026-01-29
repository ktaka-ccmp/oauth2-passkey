# Issue: Add getClientCapabilities Feature Detection

## ID: 2026-01-30-05

## Status: open

## Priority: medium

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

**Implementation**:

1. Create utility function in common JS:
```javascript
async function getPasskeyCapabilities() {
    if (typeof PublicKeyCredential?.getClientCapabilities === 'function') {
        return await PublicKeyCredential.getClientCapabilities();
    }
    return null; // Not supported
}
```

2. Use before Signal API calls:
```javascript
const caps = await getPasskeyCapabilities();
if (caps?.signalAllAcceptedCredentials) {
    await signalAllAcceptedCredentials(...);
}
```

**Browser Support**:
- Chrome 131+ (December 2024)
- Other browsers: TBD

**Reference**:
- https://blog.agektmr.com/ja/2025/12/passkey-keywords.html
- https://w3c.github.io/webauthn/#sctn-getClientCapabilities

## Resolution

