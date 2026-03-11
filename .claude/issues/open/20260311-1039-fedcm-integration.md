# Issue: FedCM (Federated Credential Management) Integration

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260311-1039

## Created: 2026-03-11-10-39

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

Introduce FedCM (Federated Credential Management API) support to the Google OAuth2 authentication flow.

### Background

FedCM is a W3C browser API (`navigator.credentials.get({ identity: { providers: [...] } })`) that provides a browser-native UI for federated authentication, eliminating the need for redirects or popups. It is designed to maintain federated identity flows after third-party cookie deprecation.

Google has mandated FedCM for Google Identity Services (GIS) SDK users as of August 2025. This project does NOT use GIS SDK - it uses direct OAuth2 Authorization Code Flow + PKCE, which is the more standards-compliant approach. Google's FedCM mandate does not directly apply to this project.

### Browser Support (as of March 2026)

- Chrome 108+, Edge 136+, Opera 108+: Supported
- Safari: Not implemented (focusing on Passkeys)
- Firefox: WG participant but implementation paused (since August 2025)

**Fallback to the existing popup-based Authorization Code Flow is mandatory for Safari/Firefox.**

### Key Investigation Findings

#### 1. GIS SDK Is NOT Required

The FedCM API is a browser-native API. `navigator.credentials.get()` can be called directly without loading any SDK. The browser handles all communication with Google's FedCM endpoints:

```javascript
const credential = await navigator.credentials.get({
  identity: {
    providers: [{
      configURL: 'https://accounts.google.com/gsi/fedcm.json',
      clientId: 'YOUR_CLIENT_ID',
      nonce: 'server-generated-nonce'
    }]
  }
});
// credential.token = JWT ID token
```

Google's FedCM endpoints (defined in the config):

| Endpoint | URL |
|----------|-----|
| `id_assertion_endpoint` | `https://accounts.google.com/gsi/fedcm/issue` |
| `accounts_endpoint` | `https://accounts.google.com/gsi/fedcm/listaccounts` |
| `client_metadata_endpoint` | `https://accounts.google.com/gsi/fedcm/clientmetadata` |
| `revocation_endpoint` | `https://accounts.google.com/gsi/fedcm/revoke` |

The browser sends all necessary headers (`Sec-Fetch-Dest: webidentity`) and cookies automatically. No SDK mediation needed.

#### 2. Google Returns JWT ID Token (NOT Authorization Code)

Google's `/gsi/fedcm/issue` endpoint returns a JWT ID token directly. This is confirmed by Google's GIS JS Reference which documents `CredentialResponse.credential` as "the ID token as a base64-encoded JSON Web Token (JWT) string" with FedCM-specific `select_by` values (`"fedcm"`, `"fedcm_auto"`).

This means:
- **The OAuth FedCM Profile (Aaron Parecki) does NOT apply to Google.** That profile returns an authorization code; Google returns an ID token.
- **Code exchange is bypassed.** No token endpoint call, no PKCE, no client_secret.
- **The existing `idtoken.rs` JWT validation code is directly reusable.** Same JWT format, same JWKS-based signature verification.

Other IdPs (Seznam, IndieAuth) return authorization codes via FedCM, but Google does not.

#### 3. Security Model: Different from Current Flow

Current Authorization Code Flow + PKCE:
```
User click -> Popup -> Google auth -> Redirect with code
  -> Backend exchanges code with client_secret (server-to-server) -> ID token -> Validate -> Session
```

FedCM with Google:
```
navigator.credentials.get() -> Browser-native UI -> JWT ID token returned to JS
  -> JS POSTs token to backend -> Validate JWT signature + claims -> Session
```

Key security differences:

| Aspect | Current (Auth Code + PKCE) | FedCM |
|--------|---------------------------|-------|
| Token passes through JS? | Auth code in browser navigation (URL/POST body), not directly in JS runtime | ID token returned as JS variable |
| client_secret RP authentication | Yes (code exchange) | No (eliminated) |
| Token authenticity guarantee | server-to-server + client_secret | JWT signature verification (JWKS) |
| XSS token exposure | Auth code briefly in popup URL (same-origin accessible in theory) | ID token explicitly in JS variable |

Note: The security difference is **incremental, not fundamental**. In the current flow, the authorization code also passes through the browser (via redirect URL or form POST). The code exchange step adds client_secret authentication, but JWT signature verification (aud, iss, exp, nonce) also provides strong authenticity guarantees. This is the same model used by GIS SDK's One Tap sign-in, which is widely deployed.

#### 4. Existing Code Reuse

| Component | Status |
|-----------|--------|
| JWT signature verification | Reuse `idtoken.rs` |
| JWKS fetch/cache | Reuse OIDC Discovery infrastructure |
| Claims validation (iss, aud, exp, nonce) | Reuse `idtoken.rs` |
| User creation / account linking | Reuse `coordination/oauth2.rs` |
| Session creation | Reuse existing session handling |
| Frontend JS | **New** (~30 lines) |
| Backend ID token endpoint | **New** (1 endpoint) |

#### 5. Risks

1. **Google does not officially support direct FedCM usage.** All Google documentation routes through GIS SDK. Direct usage is undocumented and could break without notice.
2. **Endpoint change history**: Google changed from `/o/fedcm/authorization` to `/gsi/fedcm/issue`, breaking direct users.
3. **Spec evolution**: Chrome 143 moved nonce to `params`, Chrome 125 added CORS requirements. GIS SDK absorbs these changes transparently; direct callers must track them.
4. **Zero public examples**: No confirmed public implementation uses Google FedCM without GIS SDK.

#### 6. Primary Benefit

Browser-native account chooser UI instead of popup window. No security improvement, no protocol simplification. Additional minor benefits: phishing resistance (browser-chrome UI cannot be spoofed), browser-level identity management.

### Reference Materials

- [FedCM W3C Spec](https://www.w3.org/TR/fedcm/)
- [MDN: FedCM API](https://developer.mozilla.org/en-US/docs/Web/API/FedCM_API)
- [MDN: RP Sign-in](https://developer.mozilla.org/en-US/docs/Web/API/FedCM_API/RP_sign-in)
- [Chrome: RP Implementation Guide](https://developer.chrome.com/docs/identity/fedcm/implement/relying-party)
- [Chrome: IdP Implementation Guide](https://developers.google.com/privacy-sandbox/cookies/fedcm-developer-guide)
- [Google: FedCM Migration Guide](https://developers.google.com/identity/gsi/web/guides/fedcm-migration)
- [Google: Verify ID Token](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
- [Google: GIS JS Reference](https://developers.google.com/identity/gsi/web/reference/js-reference)
- [OAuth FedCM Profile (Aaron Parecki)](https://github.com/aaronpk/oauth-fedcm-profile) - NOT applicable to Google
- [OAuth profile for FedCM - W3C FedID Issue #599](https://github.com/w3c-fedid/FedCM/issues/599)
- [GoogleChromeLabs FedCM Demo](https://github.com/GoogleChromeLabs/fedcm-demo) - custom IdP, not Google
- [Seznam FedCM Case Study](https://developer.chrome.com/blog/private-user-authentication-fedcm-seznam)
- [FedCM for IndieAuth](https://indieweb.org/FedCM_for_IndieAuth)

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (related: FedCM spec is provider-agnostic, but Google's implementation returns ID tokens while other IdPs may return authorization codes)

## Approach

### Phase 1: Proof of Concept

1. Minimal frontend JS calling `navigator.credentials.get()` with Google's configURL
2. Backend endpoint receiving JWT ID token and validating with existing `idtoken.rs`
3. Verify this works without GIS SDK in practice
4. Feature detection fallback to existing popup flow

### Phase 2: Production Implementation

1. Add `fedcm` feature flag to both crates
2. Implement frontend JS with feature detection and fallback
3. Add backend endpoint for direct ID token reception
4. Nonce generation and validation
5. Integration testing

### Phase 3: Documentation and Demo

1. Update demo applications to showcase FedCM
2. Document configuration, browser compatibility, and risks
3. Add usage examples

## Related Files

- `oauth2_passkey/src/oauth2/main/idtoken.rs` - ID token validation (reusable)
- `oauth2_passkey/src/oauth2/main/core.rs` - OAuth2 auth request preparation
- `oauth2_passkey/src/oauth2/main/google.rs` - Google token exchange (NOT used by FedCM)
- `oauth2_passkey/src/coordination/oauth2.rs` - Auth flow coordination (reusable)
- `oauth2_passkey_axum/src/oauth2.rs` - HTTP handlers
- `oauth2_passkey_axum/src/assets/oauth2.js` - Frontend OAuth2 logic

## Implementation Tasks

- [ ] PoC: Call `navigator.credentials.get()` with Google configURL without GIS SDK
- [ ] PoC: Verify JWT ID token validation with existing `idtoken.rs`
- [ ] Design frontend fallback strategy (FedCM -> popup flow)
- [ ] Add `fedcm` feature flag
- [ ] Implement frontend FedCM JS with feature detection
- [ ] Implement backend ID token reception endpoint
- [ ] Add nonce generation and validation for FedCM flow
- [ ] Integration tests
- [ ] Update demo applications
- [ ] Documentation

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-11: Issue created for investigation

- Context: Evaluating FedCM as an enhancement to existing Google OAuth2 flow
- Decision: Create as medium-priority, medium-difficulty issue
- Reason: The RP-side implementation is relatively lightweight since most backend logic (ID token validation, JWKS, session management) already exists. Browser support is limited (no Safari/Firefox), so fallback is mandatory and this is an enhancement rather than a replacement. Priority is medium because the current Authorization Code Flow works well and is not affected by third-party cookie deprecation. GIS SDK is NOT used by this project, so Google's FedCM mandate does not directly apply.

### 2026-03-11: Investigation findings - OAuth FedCM Profile assessment

- Context: Initial investigation assumed FedCM returns ID tokens directly; further research revealed the OAuth FedCM Profile (Aaron Parecki) which returns authorization codes instead
- Decision: Downgrade priority from medium to low; assume OAuth FedCM Profile as the implementation approach
- Reason: The OAuth FedCM Profile maintains the authorization code exchange + client_secret security model. However, the profile is not an official standard (author describes it as "implementation guide, not spec"), W3C FedID Issue #599 is still open, and no IETF RFC exists. The security model with FedCM is equivalent to the current flow (authorization code passes through the browser in both cases). Primary benefit is UX only (browser-native UI).

### 2026-03-11: Deep investigation - Google returns JWT, not authorization code

- Context: Thorough investigation revealed the OAuth FedCM Profile assessment was incorrect for Google
- Decision: Update approach to JWT ID token reception; maintain low priority
- Reason:
  1. **Google's FedCM endpoint (`/gsi/fedcm/issue`) returns a JWT ID token**, not an authorization code. The OAuth FedCM Profile does NOT apply to Google. Other IdPs (Seznam, IndieAuth) return authorization codes, but Google does not.
  2. **GIS SDK is NOT required.** The FedCM browser API (`navigator.credentials.get()`) can be called directly with Google's configURL. The browser handles all endpoint communication.
  3. **Existing `idtoken.rs` code is directly reusable** for JWT validation (signature, aud, iss, exp, nonce).
  4. **Implementation is simpler than initially thought**: ~30 lines of new JS + 1 new backend endpoint. No code exchange, no PKCE in the FedCM path.
  5. **Significant risks remain**: Google does not officially support direct FedCM usage (only via GIS SDK), endpoint URLs have changed before, spec is evolving with breaking changes, and zero public examples exist of Google FedCM without GIS SDK.
  6. **Security trade-off**: Eliminating code exchange removes client_secret RP authentication. JWT signature verification provides authenticity guarantees, but the security model is different from the current server-to-server code exchange. This is the same model used by GIS SDK One Tap (widely deployed).
  7. **Priority stays low**: Primary benefit is UX (browser-native UI). Risks from unsupported usage pattern and evolving spec outweigh the UX gain at this time. A PoC should be done first to verify feasibility before committing to full implementation.

## Resolution
