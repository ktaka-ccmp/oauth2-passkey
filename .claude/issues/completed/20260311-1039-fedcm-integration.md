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

## Closed: 2026-03-13-10-16

## Status: completed

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

**Important: XSS impact differs significantly.** In the current flow, even if an attacker steals the authorization code via XSS, it is useless without the `client_secret` (which only the backend knows). In FedCM, the ID token is a self-contained credential — if stolen via XSS, the attacker can directly use it to authenticate against the backend within the token's validity window. This is a meaningful security difference, not merely incremental.

That said, JWT signature verification (aud, iss, exp, nonce) provides strong authenticity guarantees, and this is the same model used by GIS SDK's One Tap sign-in, which is widely deployed. The risk is mitigated by short token lifetimes and nonce validation.

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
3. **Spec evolution**: Chrome 143 moved nonce to `params` (Chrome 145 removes old format). [Chrome 125 added CORS requirements](https://developers.google.com/privacy-sandbox/blog/fedcm-chrome-125-updates) for id_assertion_endpoint and changed SameSite cookie handling. GIS SDK absorbs these changes transparently; direct callers must track them.
4. **No confirmed public examples**: No confirmed public implementation uses Google FedCM without GIS SDK. Google's documentation recommends IdPs provide SDKs and discourages RPs from self-hosting IdP interactions.

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

- [x] PoC: Call `navigator.credentials.get()` with Google configURL without GIS SDK
- [x] PoC: Verify JWT ID token validation with existing `idtoken.rs`
- [x] Design frontend fallback strategy (FedCM -> popup flow)
- [x] Add `O2P_FEDCM` environment variable toggle (runtime, not compile-time feature flag)
- [x] Implement frontend FedCM JS with feature detection and fallback
- [x] Implement backend FedCM nonce and callback endpoints
- [x] Add nonce generation and validation for FedCM flow
- [x] Extract shared coordination logic (`process_authenticated_oauth2_user`)
- [x] Passkey promotion support after FedCM login
- [x] Integration tests
- [x] Update demo applications
- [x] Documentation (dot.env.example, CHANGELOG, docs/)

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

### 2026-03-11: Implementation complete

- Context: Full implementation completed and tested on Chrome 145 with demo-live
- Decision: Ship as experimental feature behind `O2P_FEDCM` env var
- Key findings during implementation:
  1. **Google's FedCM requires undocumented params**: `response_type: 'id_token'`, `scope: 'email profile openid'`, `ss_domain: location.origin` must be passed via the `params` object. Discovered by reverse-engineering Google's GIS library.
  2. **Nonce moved to `params`**: Chrome 145 deprecated top-level nonce; must be inside `params` object.
  3. **`mode: 'active'` placement**: ~~Must be inside the provider object, not the identity object.~~ **WRONG** - see 2026-03-11 entry below.
  4. **Google returns JSON-wrapped JWT**: `credential.token` is `{"token":"eyJ..."}` not a raw JWT. JS must parse before sending to backend.
  5. **Coordination layer refactored**: Extracted `process_authenticated_oauth2_user()` from `process_oauth2_authorization()` so both OAuth2 callback and FedCM callback share user processing logic.
  6. **FedCM config injection**: Done via `serve_oauth2_js()` prepending constants, not template injection. Works for all pages that load `oauth2.js`, including custom login pages.
  7. **Passkey promotion**: FedCM callback returns `promotion_url` in JSON response; JS opens promotion popup after successful FedCM auth.
- Files added: `oauth2_passkey/src/oauth2/main/fedcm.rs`
- Files modified: 12 files (see commits `8ad18e7`, `7ca9d0d`)
- Remaining: integration tests, demo app updates

### 2026-03-11: FedCM mode placement bug - root cause of Chrome cooldown

- Context: After FedCM cancel, Chrome permanently added the site to the FedCM block list (`chrome://settings/content/federatedIdentityApi`) with message "User declined or dismissed prompt. API exponential cool down triggered." This contradicted Chromium source code which explicitly guards against embargo in active mode: `should_embargo &= rp_mode_ == RpMode::kPassive;` (request_service.cc:1619, 1679).
- Root cause: **`mode: 'active'` was placed inside the provider object instead of at the `identity` level.**
  - Wrong: `identity: { providers: [{ mode: 'active', ... }] }`
  - Correct: `identity: { providers: [{ ... }], mode: 'active' }`
  - Chrome silently ignores the unrecognized `mode` field inside the provider, defaulting to **passive mode**.
  - In passive mode, the `should_embargo` guard passes through, recording the dismiss embargo.
  - Chromium source: `webid_utils.cc` `GetConsoleErrorMessageFromResult()` maps `kShouldEmbargo` -> "User declined or dismissed prompt. API exponential cool down triggered."
  - Embargo thresholds: `kFederatedIdentityApiDismissalsBeforeBlock = 1` (one dismiss triggers embargo), with exponential durations: 2h, 1d, 7d, 28d.
- Fix: Moved `mode: 'active'` to the `identity` object level in `oauth2.js`.
- Lesson: FedCM API `mode` is a property of `IdentityCredentialRequestOptions` (the `identity` object), NOT of individual providers. MDN and Chrome RP docs clearly show this. The FedCM account chooser UI appears in both active and passive modes, making the mode misplacement hard to detect from behavior alone.
- References:
  - [MDN: CredentialsContainer.get()](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get)
  - [Chrome: RP Implementation Guide](https://developer.chrome.com/docs/identity/fedcm/implement/relying-party)
  - [Chromium webid_utils.cc](https://blametest.sesse.net/content/browser/webid/webid_utils.cc.html)
  - [Chromium request_service.cc embargo guard](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/content/browser/webid/request_service.cc)

### 2026-03-13: Integration tests and demo updates completed

- Context: Remaining tasks from implementation phase
- Changes:
  1. **Integration tests**: Added 7 core-level FedCM tests in `coordination/oauth2/tests.rs` with `drive_fedcm_flow()` helper. Tests cover: login (existing/nonexistent), create_user, create_user_or_login, add_to_user rejection, nonce replay protection, nonce mismatch.
  2. **Docs fix**: Updated `docs/src/integration/fedcm.md` API Endpoints section -- removed stale `mode_id` references (leftover from pre-refactoring), removed non-existent `mode` query parameter from GET endpoint, added `mode` field to POST callback request.
  3. **Config bug fix**: `demo-live/env.cloud-run.yaml` had `O2P_FEDCM: "active"` but code only recognizes `"true"` or `"enabled"`. FedCM was silently disabled in production. Fixed to `"true"`.
  4. **Demo READMEs**: Added optional FedCM config and "Authorized JavaScript origins" instructions to demo-both and demo-oauth2 READMEs.

## Resolution

FedCM integration fully implemented and tested as an experimental feature behind `O2P_FEDCM` env var. All implementation tasks completed: PoC, frontend JS with fallback, backend endpoints, nonce validation, coordination layer refactoring, passkey promotion support, integration tests (7 core-level tests), demo app updates, and documentation. Key discoveries during implementation: Google requires undocumented `params` fields, `mode: 'active'` must be at identity level (not provider), and Google returns JSON-wrapped JWT.
