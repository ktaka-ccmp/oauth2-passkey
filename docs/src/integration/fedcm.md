# FedCM (Federated Credential Management)

> **Status**: Experimental. Disabled by default. Enable with `O2P_FEDCM=true`.

FedCM is a W3C browser API that provides a browser-native account chooser for federated authentication, eliminating the need for popup windows or redirects. When enabled, oauth2-passkey uses FedCM for Google OAuth2 login with automatic fallback to the traditional popup flow.

## Overview

### Flow Comparison

```
Authorization Code Flow + PKCE (current):
  User click -> Popup -> Google auth -> Redirect with code
    -> Backend exchanges code with client_secret (server-to-server)
    -> ID token -> Validate -> Session

FedCM flow (browser-native):
  User click -> navigator.credentials.get() -> Browser account chooser
    -> JWT ID token returned to JS
    -> JS POSTs token to backend -> Validate JWT signature + claims -> Session
```

With FedCM, the browser displays a native account chooser instead of a popup window. The browser communicates directly with Google's FedCM endpoints and returns a JWT ID token to JavaScript, which then sends it to the backend for validation and session establishment.

If FedCM is unavailable (unsupported browser, user dismissal, or error), the existing popup flow activates automatically.

### Browser Support

| Browser | Support |
|---------|---------|
| Chrome 108+ | Supported |
| Edge 136+ | Supported |
| Opera 108+ | Supported |
| Safari | Not supported (fallback to popup) |
| Firefox | Not supported (fallback to popup) |

### Quick Navigation

- **Just want to enable it?** → See [Quick Start](#quick-start)
- **Want to understand how it works?** → See [How It Works](#how-it-works)
- **Security concerns?** → See [Security & Compliance](#security--compliance)

## Quick Start

### Setup

#### 1. Environment Variable

```bash
O2P_FEDCM=true
```

This is the only configuration needed on the oauth2-passkey side. FedCM is disabled by default.

#### 2. Google Cloud Console

In addition to the standard OAuth2 setup (Authorized Redirect URIs), FedCM requires your origin in **Authorized JavaScript Origins**:

1. Go to [Google Cloud Console](https://console.cloud.google.com/) -> APIs & Services -> Credentials
2. Select your OAuth 2.0 Client ID
3. Under **Authorized JavaScript origins**, add your origin (e.g., `https://your-domain.example.com`)
4. Save

> **Important**: This is separate from "Authorized redirect URIs" which is used by the traditional OAuth2 flow. FedCM requires both to be configured.

#### 3. No Frontend Changes Required

FedCM integration is handled entirely by the library's `oauth2.js`. When `O2P_FEDCM=true`, the served JavaScript automatically includes feature detection and FedCM logic. This works for both the built-in login page and custom login pages that load `oauth2.js`.

### Troubleshooting

#### FedCM dialog doesn't appear

- Verify `O2P_FEDCM=true` is set
- Check browser support (Chrome 108+)
- Ensure the page is served over HTTPS (or localhost for development)
- Check browser console for FedCM-related errors

#### "Error retrieving a token" in browser console

- Verify your origin is in Google Cloud Console's "Authorized JavaScript Origins"
- Check that `OAUTH2_GOOGLE_CLIENT_ID` is correctly set

#### FedCM works but falls back to popup

This is expected behavior for:
- Unsupported browsers (Safari, Firefox)
- User dismissing the FedCM dialog
- Any error during the FedCM flow

Check browser console for the specific fallback reason: `FedCM failed, falling back to popup: <reason>`.

#### FedCM stopped working after user dismissed the dialog

If using active mode correctly, dismissal should NOT cause cooldown. Check:

1. Verify `mode: 'active'` is at the `identity` level, not inside the provider (see [Active vs Passive Mode](#active-vs-passive-mode))
2. If already in cooldown state, the user can clear it at `chrome://settings/content/federatedIdentityApi` by removing the blocked entry
3. Chrome DevTools Protocol has `FedCm.resetCooldownTime` to reset cooldown during development

### Compatibility with Other Features

#### Passkey Promotion (`O2P_PASSKEY_PROMOTION`)

FedCM works with passkey promotion. After a successful FedCM login, the promotion popup opens automatically (same behavior as the traditional OAuth2 flow).

#### Custom Login Pages

FedCM works with custom login pages. The `serve_oauth2_js` handler injects `FEDCM_ENABLED` and `OAUTH2_CLIENT_ID` constants into the served JavaScript. Any page that loads `oauth2.js` and uses `oauth2.openPopup()` gets FedCM support automatically.

## How It Works

### Browser-Internal Flow Details

When `navigator.credentials.get()` is called, the browser executes several internal steps that are invisible to JavaScript:

```
User clicks "Sign in with Google"
  |
  v
JS calls navigator.credentials.get({ identity: { providers, mode, context } })
  |
  v
[Browser-internal: invisible to JS]
  |
  (1) Browser fetches configURL to discover endpoints
  |   GET https://accounts.google.com/gsi/fedcm.json
  |
  (2) Browser fetches accounts_endpoint with user's Google cookies
  |   GET https://accounts.google.com/gsi/fedcm/listaccounts
  |   Cookie: (Google session cookies, sent automatically)
  |   -> Returns list of logged-in Google accounts (name, email, picture)
  |
  (3) Browser shows native account chooser (populated from step 2)
  |   User selects an account
  |
  (4) Browser POSTs to id_assertion_endpoint
  |   POST https://accounts.google.com/gsi/fedcm/issue
  |   Body: account_id, client_id, nonce, params (response_type, scope, ...)
  |   -> Google validates and returns JWT ID token
  |
  v
[Back to JS]
  |
  credential.token returned to JS (the only data JS receives)
  |
  v
JS POSTs token to backend -> Validate JWT signature + claims -> Session
```

Key points:

- **All browser-internal requests include `Sec-Fetch-Dest: webidentity`** — this header identifies FedCM requests to the IdP
- **Google's cookies are sent automatically** — even under third-party cookie restrictions, the browser grants FedCM requests special cookie access to the IdP
- **The RP's JavaScript never sees the account list** — only the final `credential.token` is returned. This is a privacy improvement over popup flows where the RP could potentially observe user behavior in the popup
- **No SDK is involved** — the browser handles all endpoint discovery, account fetching, and token retrieval natively

### Frontend Implementation

The FedCM frontend implementation consists of four main steps:

#### 1. Obtaining a Nonce

First, obtain a nonce from the server. This nonce is a single-use value to prevent replay attacks.

```javascript
const nonceResponse = await fetch(`${O2P_ROUTE_PREFIX}/oauth2/fedcm/nonce`);
const nonceData = await nonceResponse.json();
// { nonce: "random string", nonce_id: "cache key" }
```

#### 2. Calling navigator.credentials.get()

Use the obtained nonce to call the FedCM API:

```javascript
const credential = await navigator.credentials.get({
    identity: {
        providers: [{
            configURL: 'https://accounts.google.com/gsi/fedcm.json',
            clientId: OAUTH2_CLIENT_ID,
            params: {
                nonce: nonceData.nonce,
                response_type: 'id_token',
                scope: 'email profile openid',
                ss_domain: window.location.origin,
            },
        }],
        mode: 'active',      // Must be at identity level (not inside provider)
        context: 'signin',
    },
    mediation: 'required',   // Prevent auto re-authn, always require user interaction
});
```

The browser displays a native account chooser and returns a JWT ID token in `credential.token`.

#### 3. Sending the Token to the Backend

Send the obtained ID token and nonce_id to the backend:

```javascript
const response = await fetch(`${O2P_ROUTE_PREFIX}/oauth2/fedcm/callback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        credential: credential.token,
        nonce_id: nonceData.nonce_id,
        mode: 'login'  // or 'create_user', 'create_user_or_login'
    })
});

if (response.ok) {
    // Login successful, session cookie set via Set-Cookie header
    window.location.reload();
}
```

The backend validates the JWT ID token, establishes a session, and returns a `Set-Cookie` header.

#### 4. OAuth2 Fallback

If FedCM fails (unsupported browser, user closes dialog, error, etc.), automatically fall back to the traditional OAuth2 popup flow:

```javascript
function openPopup() {
    if (isFedCMAvailable()) {
        fedcmLogin().catch(function(err) {
            console.log('FedCM failed, falling back to popup:', err.message);
            openPopupOAuth2();
        });
        return;
    }
    openPopupOAuth2();
}
```

The Promise's `.catch()` automatically initiates the popup flow when FedCM fails.

### No SDK Required

FedCM is a browser-native API. `navigator.credentials.get()` is called directly without loading Google's GIS SDK or any other library. The browser handles all communication with Google's FedCM endpoints:

| Endpoint | URL |
|----------|-----|
| Config | `https://accounts.google.com/gsi/fedcm.json` |
| `id_assertion_endpoint` | `https://accounts.google.com/gsi/fedcm/issue` |
| `accounts_endpoint` | `https://accounts.google.com/gsi/fedcm/listaccounts` |
| `client_metadata_endpoint` | `https://accounts.google.com/gsi/fedcm/clientmetadata` |

The browser sends all necessary headers (`Sec-Fetch-Dest: webidentity`) and cookies automatically.

> **Note**: Google's FedCM endpoint returns a **JWT ID token** directly, not an authorization code. This differs from other IdPs (e.g., Seznam, IndieAuth) that return authorization codes via FedCM. The [OAuth FedCM Profile](https://github.com/aaronpk/oauth-fedcm-profile) (authorization code approach) does not apply to Google.

### Modes

| OAuth2 Mode | FedCM | Fallback |
|-------------|-------|----------|
| `login` | Yes | Popup |
| `create_user` | Yes | Popup |
| `create_user_or_login` | Yes | Popup |
| `add_to_user` | Always popup | N/A |

The `add_to_user` mode (linking an additional OAuth2 account) always uses the traditional popup flow because it requires page session token verification.

## Security & Compliance

### Comparison with Authorization Code Flow

| Aspect | Authorization Code Flow + PKCE | FedCM |
|--------|--------------------------------|-------|
| ID token acquisition | Server exchanges authorization code | Browser obtains directly |
| JavaScript-accessible information | Authorization code (worthless) | JWT ID token (usable for authentication) |
| XSS attack risk | Authorization code alone cannot authenticate | Usable for authentication within validity period |

### Security Considerations

**JWT Signature Verification**: The backend validates the ID token using Google's JWKS (JSON Web Key Set). This verifies that the token was issued by Google and has not been tampered with. The following claims are checked:

- `iss` (issuer) - must be `accounts.google.com` or `https://accounts.google.com`
- `aud` (audience) - must match your `OAUTH2_GOOGLE_CLIENT_ID`
- `exp` (expiration) - token must not be expired
- `nonce` - must match the server-generated single-use nonce

**Front-Channel Token Delivery**: Unlike the Authorization Code Flow where the code is exchanged server-to-server with the client_secret, FedCM delivers the ID token directly to JavaScript. This is a meaningful security difference:

- In the Authorization Code Flow, even if an attacker steals the authorization code via XSS, it is **useless without the `client_secret`** (which only the backend knows)
- In FedCM, the ID token is a **self-contained credential** — if stolen via XSS, the attacker can directly use it to authenticate against the backend within the token's validity window
- The risk is mitigated by short token lifetimes and single-use nonce validation
- This is the same security model used by Google's One Tap sign-in (GIS SDK), which is widely deployed

**Nonce Protection**: Each FedCM login generates a unique server-side nonce that is:
- Stored in the cache with a 120-second TTL
- Included in the `navigator.credentials.get()` request
- Verified against the ID token's `nonce` claim
- Removed from cache after single use (replay protection)

### OIDC Principles Deviation

In traditional OpenID Connect (OIDC), the ID token is issued by the Identity Provider (IdP) directly to the Relying Party (RP) backend via server-to-server exchange. The OIDC specification states that an ID token's `aud` (audience) claim identifies the intended recipient, and the token should only be consumed by that entity—not forwarded through intermediaries.

FedCM's design deviates from this principle:

- **Traditional OIDC**: IdP → authorization code → browser → RP backend → exchanges code + client_secret → IdP → ID token → RP backend. **ID token never passes through JavaScript.**
- **FedCM**: IdP → ID token → browser (JavaScript) → **JavaScript forwards ID token to RP backend** → RP backend validates and consumes

JavaScript acts as an intermediary that receives and forwards the ID token, contradicting the traditional OIDC principle.

**Why This Design**: The W3C FedCM specification explicitly designs the API to return credentials to JavaScript to enable browser-native UI, deviating from traditional OIDC token handling principles. Google's official implementation (One Tap via GIS SDK) uses the same pattern.

### Recommendation

FedCM provides a better user experience but has a different security trade-off than the Authorization Code Flow. Benefits include:

- **Browser-native UI** — no popup windows or redirects
- **Phishing resistance** — the browser-chrome account chooser cannot be spoofed by an attacker, unlike popup-based flows where the URL bar can be faked
- **Browser-level identity management** — the browser tracks which IdP accounts are used on which sites

For applications where these UX benefits are valuable and the XSS risk profile is acceptable, FedCM is a good choice. For applications requiring the strongest possible RP authentication, the traditional flow with client_secret exchange may be preferred.

Both flows can coexist: FedCM is used when available, with automatic fallback to the popup flow.

## Advanced Topics

### Active Mode and Chrome Cooldown

#### Active vs Passive Mode

FedCM has two UI modes controlled by the `mode` property on the `identity` object (not on individual providers). In the [implementation example above](#2-calling-navigatorcredentialsget), `mode: 'active'` is placed at the `identity` level.

| | Active Mode | Passive Mode (default) |
|---|---|---|
| User gesture required | Yes (button click) | No |
| IdP login state | Works even if logged out of IdP | Requires logged-in state |
| Cooldown on dismiss | No | Yes (exponential) |
| Popup after completion | Allowed (user activation preserved) | Blocked by popup blocker |
| Chrome version | 132+ | 108+ |

oauth2-passkey uses **active mode** because it is triggered by a button click and the no-cooldown behavior is essential for a good user experience.

> **Warning**: Placing `mode: 'active'` inside the provider object instead of at the `identity` level causes Chrome to silently default to passive mode. The account chooser UI still appears in both modes, making this mistake hard to detect. **Consequence**: In passive mode, when a user dismisses the FedCM dialog, a cooldown occurs, preventing FedCM from being used for 2 hours to a maximum of 4 weeks. If the placement is wrong, FedCM becomes unusable for a long period just because the user closed the dialog once.

#### Chrome Cooldown (Passive Mode Only)

When a user dismisses the FedCM dialog in **passive mode**, Chrome applies an exponential cooldown:

| Consecutive dismissals | Cooldown duration |
|---|---|
| 1st | 2 hours |
| 2nd | 1 day |
| 3rd | 1 week |
| 4th+ | 4 weeks |

During cooldown, `navigator.credentials.get()` rejects immediately with the console message: *"FedCM was disabled either temporarily based on previous user action or permanently via site settings."*

The cooldown is recorded per-origin at `chrome://settings/content/federatedIdentityApi`. Users can manually remove entries to reset the cooldown.

**Active mode is exempt from cooldown.** Chromium source (`request_service.cc`) explicitly guards: `should_embargo &= rp_mode_ == RpMode::kPassive;` — the embargo is only recorded for passive mode.

### Known Limitations

1. **Unsupported by Google officially**: Google documents FedCM usage only through the GIS SDK. Direct usage of `navigator.credentials.get()` with Google's FedCM endpoints is undocumented and could break without notice.

2. **Endpoint instability**: Google has changed FedCM endpoint URLs in the past (from `/o/fedcm/authorization` to `/gsi/fedcm/issue`). The GIS SDK absorbs these changes transparently; direct callers must track them.

3. **Spec evolution**: The FedCM specification is actively evolving. Chrome 143 moved nonce to the `params` object (Chrome 145 removes old format). Future spec changes may require code updates.

4. **Google-specific params**: Google's FedCM endpoint requires the following parameters in the `params` object. These are not part of the FedCM spec and are Google-specific:

| Field | Value | Description |
|-------|-------|-------------|
| `response_type` | `'id_token'` | Required for Google to return JWT |
| `scope` | `'email profile openid'` | Requested scopes |
| `ss_domain` | `window.location.origin` | RP's origin |

5. **JSON-wrapped token**: Google's FedCM endpoint returns the JWT wrapped in JSON (`{"token":"eyJ..."}`). The library handles this automatically.

### API Endpoints

When `O2P_FEDCM=true`, two additional endpoints are registered:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth2/fedcm/nonce` | GET | Generates a nonce for `navigator.credentials.get()` |
| `/oauth2/fedcm/callback` | POST | Validates the JWT ID token and establishes a session |

#### GET `/oauth2/fedcm/nonce`

Response:
```json
{
  "nonce": "random-nonce-value",
  "nonce_id": "cache-key-for-nonce"
}
```

#### POST `/oauth2/fedcm/callback`

Request body:
```json
{
  "credential": "eyJhbGciOiJSUzI1NiIs...",
  "nonce_id": "cache-key-for-nonce",
  "mode": "login"
}
```

The `mode` field is optional. Valid values: `login`, `create_user`, `create_user_or_login`.
The `add_to_user` mode is not supported by FedCM (always uses popup flow).

Response (success):
```json
{
  "message": "Successfully logged in"
}
```

The response includes a `Set-Cookie` header with the session cookie.

## Appendix

### Intended Use Case

**Question**: Was FedCM designed for the browser to POST the ID token to the backend, or was it intended for browser-only validation?

**Answer**: FedCM was designed with backend validation in mind, not for pure browser-only use cases.

According to MDN and Chrome documentation:
- The FedCM workflow explicitly includes "Send the token to your backend: Pass the token from your frontend JavaScript to your backend server"
- The ID assertion endpoint returns "a validation token that the RP can use to validate the authentication"
- "The RP needs to follow the instructions provided by the IdP to make sure they are using it correctly"

No documentation was found describing pure client-side (browser-only) validation use cases for FedCM. All official documentation assumes the RP will validate tokens on the backend server.

**Why JavaScript Receives the Token**: The specification returns credentials to JavaScript to enable browser-native UI (no popups or redirects), not to enable client-side validation. This design choice inherently conflicts with traditional OIDC principles where tokens should go directly to the intended recipient.

**References**:
- [MDN: Relying party federated sign-in](https://developer.mozilla.org/en-US/docs/Web/API/FedCM_API/RP_sign-in) — describes sending token to backend for validation
- [MDN: Identity provider integration](https://developer.mozilla.org/en-US/docs/Web/API/FedCM_API/IDP_integration) — ID assertion endpoint returns validation token for RP backend
- [W3C FedCM Specification](https://www.w3.org/TR/fedcm/) — API explicitly designed to return credentials to JavaScript

**Implications**:

- **Security**: JavaScript has access to the ID token before the backend, increasing exposure to XSS attacks compared to the Authorization Code Flow where only an unusable authorization code is exposed to JavaScript.
- **Compliance**: Applications with strict security requirements or compliance obligations may need to evaluate whether this deviation from traditional OIDC principles is acceptable in their threat model.
- **Adoption Decision**: Organizations should assess the trade-off between improved UX (browser-native UI, no popups/redirects) and the security implications of front-channel ID token delivery when deciding whether to enable FedCM.

### References

#### Specifications and Browser Documentation

- [FedCM W3C Spec](https://www.w3.org/TR/fedcm/)
- [MDN: FedCM API](https://developer.mozilla.org/en-US/docs/Web/API/FedCM_API)
- [MDN: RP Sign-in Guide](https://developer.mozilla.org/en-US/docs/Web/API/FedCM_API/RP_sign-in)
- [Chrome: RP Implementation Guide](https://developer.chrome.com/docs/identity/fedcm/implement/relying-party)

#### Google-Specific

- [Google: FedCM Migration Guide](https://developers.google.com/identity/gsi/web/guides/fedcm-migration)
- [Google: Verify ID Token](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
- [Google: GIS JS Reference](https://developers.google.com/identity/gsi/web/reference/js-reference) — documents `CredentialResponse.credential` and FedCM `select_by` values

#### Related Projects and Case Studies

- [OAuth FedCM Profile (Aaron Parecki)](https://github.com/aaronpk/oauth-fedcm-profile) — authorization code approach, NOT applicable to Google
- [OAuth profile for FedCM - W3C FedID Issue #599](https://github.com/w3c-fedid/FedCM/issues/599)
- [Seznam FedCM Case Study](https://developer.chrome.com/blog/private-user-authentication-fedcm-seznam)
- [FedCM for IndieAuth](https://indieweb.org/FedCM_for_IndieAuth)
