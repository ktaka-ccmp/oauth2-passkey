# FedCM (Federated Credential Management)

> **Status**: Experimental. Disabled by default. Enable with `O2P_FEDCM=true`.

FedCM is a W3C browser API that provides a browser-native account chooser for federated authentication, eliminating the need for popup windows or redirects. When enabled, oauth2-passkey uses FedCM for Google OAuth2 login with automatic fallback to the traditional popup flow.

## Overview

### How It Works

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

With FedCM enabled, the login flow changes from a popup-based redirect to a browser-native UI:

1. User clicks "Sign in with Google"
2. Browser shows a native account chooser (no popup window)
3. User selects an account
4. Browser obtains a JWT ID token from Google's FedCM endpoint
5. JavaScript sends the token to the backend for validation
6. Backend validates JWT signature, audience, issuer, expiration, and nonce
7. Session is established

For details on what happens inside the browser during steps 2-4, see [Browser-Internal Flow Details](#browser-internal-flow-details).

If FedCM is unavailable (unsupported browser, user dismissal, or error), the existing popup flow activates automatically.

### Browser Support

| Browser | Support |
|---------|---------|
| Chrome 108+ | Supported |
| Edge 136+ | Supported |
| Opera 108+ | Supported |
| Safari | Not supported (fallback to popup) |
| Firefox | Not supported (fallback to popup) |

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

## Setup

### 1. Environment Variable

```bash
O2P_FEDCM=true
```

This is the only configuration needed on the oauth2-passkey side. FedCM is disabled by default.

### 2. Google Cloud Console

In addition to the standard OAuth2 setup (Authorized Redirect URIs), FedCM requires your origin in **Authorized JavaScript Origins**:

1. Go to [Google Cloud Console](https://console.cloud.google.com/) -> APIs & Services -> Credentials
2. Select your OAuth 2.0 Client ID
3. Under **Authorized JavaScript origins**, add your origin (e.g., `https://your-domain.example.com`)
4. Save

> **Important**: This is separate from "Authorized redirect URIs" which is used by the traditional OAuth2 flow. FedCM requires both to be configured.

### 3. No Frontend Changes Required

FedCM integration is handled entirely by the library's `oauth2.js`. When `O2P_FEDCM=true`, the served JavaScript automatically includes feature detection and FedCM logic. This works for both the built-in login page and custom login pages that load `oauth2.js`.

## Security Model

### Comparison with Authorization Code Flow

| Aspect | Authorization Code Flow + PKCE | FedCM |
|--------|-------------------------------|-------|
| Token type in browser | Authorization code (URL/form) | JWT ID token (JS variable) |
| Server-to-server exchange | Yes (code + client_secret) | No |
| RP authentication | client_secret | None (JWT signature only) |
| Token authenticity | Code exchange + client_secret | JWT signature verification (JWKS) |
| XSS token exposure | Code unusable without client_secret | ID token usable within validity window |

### Key Considerations

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

### Recommendation

FedCM provides a better user experience but has a different security trade-off than the Authorization Code Flow. Benefits include:

- **Browser-native UI** — no popup windows or redirects
- **Phishing resistance** — the browser-chrome account chooser cannot be spoofed by an attacker, unlike popup-based flows where the URL bar can be faked
- **Browser-level identity management** — the browser tracks which IdP accounts are used on which sites

For applications where these UX benefits are valuable and the XSS risk profile is acceptable, FedCM is a good choice. For applications requiring the strongest possible RP authentication, the traditional flow with client_secret exchange may be preferred.

Both flows can coexist: FedCM is used when available, with automatic fallback to the popup flow.

## Compatibility with Other Features

### Passkey Promotion (`O2P_PASSKEY_PROMOTION`)

FedCM works with passkey promotion. After a successful FedCM login, the promotion popup opens automatically (same behavior as the traditional OAuth2 flow).

### Custom Login Pages

FedCM works with custom login pages. The `serve_oauth2_js` handler injects `FEDCM_ENABLED` and `OAUTH2_CLIENT_ID` constants into the served JavaScript. Any page that loads `oauth2.js` and uses `oauth2.openPopup()` gets FedCM support automatically.

## Active Mode and Chrome Cooldown

### Active vs Passive Mode

FedCM has two UI modes controlled by the `mode` property on the `identity` object (not on individual providers):

```javascript
const credential = await navigator.credentials.get({
  identity: {
    providers: [{
      configURL: 'https://accounts.google.com/gsi/fedcm.json',
      clientId: 'YOUR_CLIENT_ID',
      params: {
        nonce: 'server-generated-nonce',
        response_type: 'id_token',
        scope: 'email profile openid',
        ss_domain: window.location.origin,
      },
    }],
    mode: 'active',      // <-- must be here, at the identity level
    context: 'signin',
  },
  mediation: 'required', // Prevent auto re-authn, always require user interaction
});
```

| | Active Mode | Passive Mode (default) |
|---|---|---|
| User gesture required | Yes (button click) | No |
| IdP login state | Works even if logged out of IdP | Requires logged-in state |
| Cooldown on dismiss | No | Yes (exponential) |
| Popup after completion | Allowed (user activation preserved) | Blocked by popup blocker |
| Chrome version | 132+ | 108+ |

oauth2-passkey uses **active mode** because it is triggered by a button click and the no-cooldown behavior is essential for a good user experience.

> **Warning**: Placing `mode: 'active'` inside the provider object instead of at the `identity` level causes Chrome to silently default to passive mode. The account chooser UI still appears in both modes, making this mistake hard to detect.

### Chrome Cooldown (Passive Mode Only)

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

## Known Limitations

1. **Unsupported by Google officially**: Google documents FedCM usage only through the GIS SDK. Direct usage of `navigator.credentials.get()` with Google's FedCM endpoints is undocumented and could break without notice.

2. **Endpoint instability**: Google has changed FedCM endpoint URLs in the past (from `/o/fedcm/authorization` to `/gsi/fedcm/issue`). The GIS SDK absorbs these changes transparently; direct callers must track them.

3. **Spec evolution**: The FedCM specification is actively evolving. Chrome 143 moved nonce to the `params` object (Chrome 145 removes old format). Future spec changes may require code updates.

4. **Google-specific params**: Google's FedCM endpoint requires `response_type: 'id_token'`, `scope`, and `ss_domain` in the `params` object. These are not part of the FedCM spec and are Google-specific.

5. **JSON-wrapped token**: Google's FedCM endpoint returns the JWT wrapped in JSON (`{"token":"eyJ..."}`). The library handles this automatically.

## Troubleshooting

### FedCM dialog doesn't appear

- Verify `O2P_FEDCM=true` is set
- Check browser support (Chrome 108+)
- Ensure the page is served over HTTPS (or localhost for development)
- Check browser console for FedCM-related errors

### "Error retrieving a token" in browser console

- Verify your origin is in Google Cloud Console's "Authorized JavaScript Origins"
- Check that `OAUTH2_GOOGLE_CLIENT_ID` is correctly set

### FedCM works but falls back to popup

This is expected behavior for:
- Unsupported browsers (Safari, Firefox)
- User dismissing the FedCM dialog
- Any error during the FedCM flow

Check browser console for the specific fallback reason: `FedCM failed, falling back to popup: <reason>`.

### FedCM stopped working after user dismissed the dialog

If using active mode correctly, dismissal should NOT cause cooldown. Check:

1. Verify `mode: 'active'` is at the `identity` level, not inside the provider (see [Active vs Passive Mode](#active-vs-passive-mode))
2. If already in cooldown state, the user can clear it at `chrome://settings/content/federatedIdentityApi` by removing the blocked entry
3. Chrome DevTools Protocol has `FedCm.resetCooldownTime` to reset cooldown during development

## API Endpoints

When `O2P_FEDCM=true`, two additional endpoints are registered:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth2/fedcm/nonce` | GET | Generates a nonce for `navigator.credentials.get()` |
| `/oauth2/fedcm/callback` | POST | Validates the JWT ID token and establishes a session |

### GET `/oauth2/fedcm/nonce`

Response:
```json
{
  "nonce": "random-nonce-value",
  "nonce_id": "cache-key-for-nonce"
}
```

### POST `/oauth2/fedcm/callback`

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

## Browser-Internal Flow Details

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

## References

### Specifications and Browser Documentation

- [FedCM W3C Spec](https://www.w3.org/TR/fedcm/)
- [MDN: FedCM API](https://developer.mozilla.org/en-US/docs/Web/API/FedCM_API)
- [MDN: RP Sign-in Guide](https://developer.mozilla.org/en-US/docs/Web/API/FedCM_API/RP_sign-in)
- [Chrome: RP Implementation Guide](https://developer.chrome.com/docs/identity/fedcm/implement/relying-party)

### Google-Specific

- [Google: FedCM Migration Guide](https://developers.google.com/identity/gsi/web/guides/fedcm-migration)
- [Google: Verify ID Token](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
- [Google: GIS JS Reference](https://developers.google.com/identity/gsi/web/reference/js-reference) — documents `CredentialResponse.credential` and FedCM `select_by` values

### Related Projects and Case Studies

- [OAuth FedCM Profile (Aaron Parecki)](https://github.com/aaronpk/oauth-fedcm-profile) — authorization code approach, NOT applicable to Google
- [OAuth profile for FedCM - W3C FedID Issue #599](https://github.com/w3c-fedid/FedCM/issues/599)
- [Seznam FedCM Case Study](https://developer.chrome.com/blog/private-user-authentication-fedcm-seznam)
- [FedCM for IndieAuth](https://indieweb.org/FedCM_for_IndieAuth)
