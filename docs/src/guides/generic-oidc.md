# Generic OIDC Provider Setup

oauth2-passkey ships with four "Custom" OIDC slots (`Custom1` through
`Custom4`) that let operators enable any standards-compliant OpenID Connect
provider via environment variables alone — no code change required.

Use these slots for providers without dedicated built-in support, such as
Okta, AWS Cognito, Zitadel, Ory Hydra, Dex, Authelia, and similar
self-hosted or hosted OIDC stacks.

## When to Use Custom Slots vs Named Providers

| Provider | Use |
|----------|-----|
| Google | Built-in (always on when `OAUTH2_GOOGLE_CLIENT_ID` is set) |
| Auth0, Keycloak, Microsoft Entra ID | Dedicated guide — enable via `OAUTH2_{NAME}_*` env vars |
| Okta, AWS Cognito, Zitadel, Ory Hydra, Dex, Authelia, any other OIDC IdP | A Custom slot |

The custom slots go through the exact same OIDC code path as the named
providers. The only constraint is that the IdP must implement standard OIDC
Discovery at `{issuer}/.well-known/openid-configuration`.

## Required Environment Variables

For each enabled slot `N` (1, 2, 3, or 4):

```bash
OAUTH2_CUSTOM{N}_CLIENT_ID='your-client-id'
OAUTH2_CUSTOM{N}_CLIENT_SECRET='your-client-secret'
OAUTH2_CUSTOM{N}_ISSUER_URL='https://idp.example.com'
OAUTH2_CUSTOM{N}_DISPLAY_NAME='My SSO'
OAUTH2_CUSTOM{N}_PATH_SEGMENT='my-sso'
```

- `ISSUER_URL`: the base URL from which oauth2-passkey fetches
  `/.well-known/openid-configuration`. No trailing slash.
- `DISPLAY_NAME`: the label shown on the login button ("Continue with
  `{DISPLAY_NAME}`").
- `PATH_SEGMENT`: the URL segment used in routes
  (`/o2p/oauth2/{PATH_SEGMENT}`) and stored in the database `provider`
  column. Must match `[a-z0-9_-]+` and must not collide with the named
  providers (`google`, `auth0`, `keycloak`, `entra`) or the reserved
  literals `authorized`, `accounts`, `fedcm`, `popup_close`, `oauth2.js`,
  `select`.

The redirect URI you register at the IdP is:

```
{ORIGIN}/o2p/oauth2/{PATH_SEGMENT}/authorized
```

## Optional Environment Variables

Defaults shown:

```bash
OAUTH2_CUSTOM{N}_RESPONSE_MODE='form_post'     # form_post or query
OAUTH2_CUSTOM{N}_SCOPE='openid+email+profile'
OAUTH2_CUSTOM{N}_BUTTON_COLOR='#6b7280'        # neutral gray
OAUTH2_CUSTOM{N}_BUTTON_HOVER_COLOR='#4b5563'
```

Button colors are injected as CSS variables in the login template and drive
the `.btn-custom{N}` background color declared in the base stylesheet.

## Verified IdPs

The following IdPs have been validated end-to-end against a custom slot:

| IdP | Issuer URL pattern |
|-----|--------------------|
| Zitadel | `https://{instance}.zitadel.cloud` (cloud) or `https://{host}` (self-host) |
| Ory Hydra | `https://{host}` (the public URL of Hydra's public endpoints) |
| Okta | `https://{tenant}.okta.com/oauth2/default` (Custom Authorization Server, default) |

Any OIDC-compliant IdP should work. The sections below walk through the two
verified self-host options.

---

## Zitadel (Self-Hosted)

### Step 1: Bring Up Zitadel

```bash
docker run -d --name zitadel \
  -p 8080:8080 \
  ghcr.io/zitadel/zitadel:latest \
  start-from-init --masterkey "MasterkeyNeedsToHave32Characters" --tlsMode disabled
```

Open `http://localhost:8080/ui/console` and complete the first-run wizard.

### Step 2: Register an Application

1. Log into the Zitadel console
2. Open the **Default** project (or create one) → **New** → **Application**
3. Choose **Web** and **Code** grant type
4. Set **Redirect URI**: `{ORIGIN}/o2p/oauth2/zitadel/authorized`
5. Finish the wizard and copy the **Client ID** and **Client Secret**

### Step 3: Configure oauth2-passkey

```bash
OAUTH2_CUSTOM1_CLIENT_ID='<client-id-from-zitadel>'
OAUTH2_CUSTOM1_CLIENT_SECRET='<client-secret-from-zitadel>'
OAUTH2_CUSTOM1_ISSUER_URL='http://localhost:8080'
OAUTH2_CUSTOM1_DISPLAY_NAME='Zitadel'
OAUTH2_CUSTOM1_PATH_SEGMENT='zitadel'
OAUTH2_CUSTOM1_RESPONSE_MODE='query'
```

> **Zitadel v4** (separate `zitadel-login` Next.js service) requires
> `OAUTH2_CUSTOM1_RESPONSE_MODE=query`. Zitadel v2 (embedded V1 login,
> e.g. `v2.71.x`) handles `form_post` natively and can omit the line.
> See **Troubleshooting → Zitadel returns `Invalid response mode: GET
> is not allowed for form_post`** below for the root cause.

Restart oauth2-passkey. A **Continue with Zitadel** button appears on the
login page alongside Google.

---

## Ory Hydra (Self-Hosted)

### Step 1: Bring Up Hydra

Use Hydra's quickstart docker-compose:

```bash
git clone https://github.com/ory/hydra.git
cd hydra
docker compose -f quickstart.yml up -d
```

This launches Hydra on `http://localhost:4444` (public) and
`http://localhost:4445` (admin).

### Step 2: Register an OAuth2 Client

Use the admin API to create a client:

```bash
docker compose exec hydra hydra create client \
  --endpoint http://localhost:4445 \
  --grant-type authorization_code,refresh_token \
  --response-type code,id_token \
  --scope 'openid email profile' \
  --redirect-uri '{ORIGIN}/o2p/oauth2/hydra/authorized' \
  --token-endpoint-auth-method client_secret_post
```

Two Hydra-specific requirements:

- **`--token-endpoint-auth-method client_secret_post`**: oauth2-passkey
  sends client credentials in the request body. Hydra defaults to
  `client_secret_basic` (HTTP Basic), which will fail with `401 Unauthorized`
  at token exchange.
- **`--redirect-uri` must exactly match** what the library sends —
  `{ORIGIN}/o2p/oauth2/{PATH_SEGMENT}/authorized` — or Hydra rejects the
  authorization request with `invalid_request`.

Copy the returned `client_id` and `client_secret` (Hydra only shows the
secret once).

### Step 3: Configure oauth2-passkey

```bash
OAUTH2_CUSTOM2_CLIENT_ID='<client-id-from-hydra>'
OAUTH2_CUSTOM2_CLIENT_SECRET='<client-secret-from-hydra>'
OAUTH2_CUSTOM2_ISSUER_URL='http://localhost:4444'
OAUTH2_CUSTOM2_DISPLAY_NAME='Ory Hydra'
OAUTH2_CUSTOM2_PATH_SEGMENT='hydra'
```

### Step 4: Login / Consent App

Hydra does not bundle a user database — you must run a separate
login/consent UI. The Ory reference app
(`oryd/hydra-login-consent-node`) is a minimal starting point, but **by
default it emits an ID token with only `sub`** (the claim-injection points
in `src/routes/consent.ts` are commented out). oauth2-passkey requires at
least `email` or `preferred_username` in the userinfo response, so the
login fails with:

```text
OIDC userinfo from 'hydra' is missing both `email` and `preferred_username` claims
```

For demo / testing, the reference app has a built-in shortcut — set
`CONFORMITY_FAKE_CLAIMS=1` on the consent container and it will emit fake
`email=foo@bar.com` + `preferred_username=robot` whenever the matching
scope is granted. **Demo use only**; all users map to the same synthetic
account.

Note: the fake `profile` scope also sets `picture` to a hardcoded GitHub
raw URL that upstream has since moved — the link returns `404`, so the
account avatar renders as a broken image. Cosmetic only; it does not
affect authentication.

```yaml
consent:
  image: oryd/hydra-login-consent-node:v2.2.0
  environment:
    HYDRA_ADMIN_URL: http://hydra:4445
    CONFORMITY_FAKE_CLAIMS: "1"   # demo only
```

For real multi-user setups, fork the reference consent app and populate
`session.id_token` from your user store in the accept-consent call.

---

## Okta (Cloud, Developer Edition)

Okta's Developer tenant is free and its OIDC defaults are standards-
compliant, but the setup is split across **two layers of policies** that
both need to be configured. Most first-time setups stall on the second
layer. Walk through the steps in order.

### Step 1: Tenant and application

1. Sign up at `developer.okta.com`. Your admin URL is
   `https://<tenant>-admin.okta.com`; the public OIDC host (used for
   discovery and redirects) is `https://<tenant>.okta.com`.
2. Admin console -> **Applications -> Create App Integration**.
   - **Sign-in method**: `OIDC - OpenID Connect`
   - **Application type**: `Web Application`
   - **Grant type**: `Authorization Code`
   - **Sign-in redirect URIs**: exactly
     `{ORIGIN}/o2p/oauth2/{PATH_SEGMENT}/authorized`
   - **Controlled access**: pick **Allow everyone in your organization**
     for fastest setup.

Copy **Client ID** and **Client Secret**.

### Step 2: Record the issuer URL

```bash
curl -s https://<tenant>.okta.com/oauth2/default/.well-known/openid-configuration | jq .issuer
```

Use the exact string it returns for `OAUTH2_CUSTOM{N}_ISSUER_URL`.

### Step 3: Configure oauth2-passkey

```bash
OAUTH2_CUSTOM{N}_CLIENT_ID='<Client ID from Okta>'
OAUTH2_CUSTOM{N}_CLIENT_SECRET='<Client Secret from Okta>'
OAUTH2_CUSTOM{N}_ISSUER_URL='https://<tenant>.okta.com/oauth2/default'
OAUTH2_CUSTOM{N}_DISPLAY_NAME='Okta'
OAUTH2_CUSTOM{N}_PATH_SEGMENT='okta'
```

### Step 4: Assign users

**Applications -> [your app] -> Assignments -> Assign** ->
**Assign to Groups -> Everyone**, or pick specific users.

Skipping this step produces **"You don't have access to this app.
Contact your administrator."** Super-admin accounts appear to bypass
this check during admin console navigation but **not** during an OAuth2
token grant, so it's easy to miss. Assign explicitly.

### Step 5: Relax the Application Sign-On Policy

**Applications -> [your app] -> Sign On** tab -> the **Authentication
Policy** panel shows which policy is attached. New apps default to
**"Any two factor types/IdPs"**, which requires the user's current Okta
session to have already completed two different factor types.

If only a password is enrolled, OAuth2 login fails immediately with
**"Policy evaluation failed"**. Fixes, in order of practicality:

- Edit the attached policy's catch-all rule: **Security ->
  Authentication Policies** -> open the policy -> rule -> **User must
  authenticate with**: `Password / IdP`.
- Enroll a second factor (Okta Verify is easiest) and sign into Okta
  with it at least once before starting the OAuth2 flow.
- Assign a different, looser policy to the app.

### Step 6: Add an Access Policy on the Authorization Server

The one that trips up most people. Okta Custom Authorization Servers
enforce their **own Access Policies** on top of the application's Sign-On
policy. Without a matching rule the token endpoint returns
`FAILURE: no_matching_policy` (visible in System Log) and the browser
sees `400 access_denied`.

**Security -> API -> Authorization Servers -> default -> Access
Policies** tab:

1. If there is no policy, **Add New Access Policy**:
   - Name: `Demo Access Policy`
   - **Assign to**: `The following clients` -> select your app (or
     `All clients`).
2. Inside the policy, **Add Rule**:
   - **IF Grant type is**: check `Authorization Code`.
   - **AND User is**: `Any user assigned the app`.
   - **AND Scopes requested**: `Any scopes` (or list `openid`, `email`,
     `profile`).
3. Save.

### Debugging via System Log

**Reports -> System Log** is the authoritative source when something
fails. Filter by the application name or look for the failing timestamp.
The rows matter in this order:

| Row                               | What's being checked                     |
|-----------------------------------|------------------------------------------|
| `User single sign on to app`      | App assignment + app-level access        |
| `Evaluation of sign-on policy`    | Application Authentication Policy        |
| `OAuth2 authorization request`    | Authorization Server Access Policy       |
| `OIDC access/id token is granted` | Final success signal                     |

`OAuth2 authorization request` -> `FAILURE: no_matching_policy` maps to
Step 6. `Evaluation of sign-on policy` -> `DENY` maps to Step 5.
No entry for your app at all = the request never reached Okta; check
`redirect_uri` and `client_id` in the browser's Network tab.

---

## Troubleshooting

### Issuer mismatch error

oauth2-passkey performs strict issuer validation: the `iss` claim on the
returned ID token must match the IdP's published `issuer` from the
discovery document, which in turn must match your configured
`OAUTH2_CUSTOM{N}_ISSUER_URL`. If they differ:

- Verify `OAUTH2_CUSTOM{N}_ISSUER_URL` points at the exact URL the IdP
  advertises in its discovery document's `issuer` field
- Some IdPs (e.g. Keycloak behind a reverse proxy) require setting a
  `hostname` or `frontendUrl` so the advertised issuer matches the
  public URL

### `validate_custom_slots` rejects `PATH_SEGMENT` at startup

Possible causes:

- The segment contains characters outside `[a-z0-9_-]` (uppercase,
  slashes, spaces)
- The segment collides with a named provider (`google`, `auth0`, ...) or
  a reserved route (`authorized`, `accounts`, `fedcm`, `popup_close`,
  `oauth2.js`, `select`)
- Two different custom slots declare the same `PATH_SEGMENT`

The error message names the offending env var.

### Zitadel returns `Invalid response mode: GET is not allowed for form_post`

Zitadel v4 silently downgrades `response_mode=form_post` to a `query`
redirect, which oauth2-passkey then rejects because the authorization
request explicitly asked for `form_post`.

**Root cause** (upstream, not fixable from oauth2-passkey):

- v4's login flow is a separate Next.js service (`zitadel-login`) that
  calls the API's Connect-RPC `CreateCallback` to finish the request.
- `CreateCallback` returns only a `CallbackUrl` string — there is no
  field for the HTML body that `form_post` requires.
- The underlying `zitadel/oidc` helper `AuthResponseURL` has branches
  for `ResponseModeQuery` and `ResponseModeFragment` but **no
  `ResponseModeFormPost` branch**, so a `form_post` request falls
  through to query encoding.

**Fix**: set `OAUTH2_CUSTOM{N}_RESPONSE_MODE=query` (see Zitadel Step 3
above).

Zitadel v2.71.x (embedded V1 login) does not hit this path — it calls
`AuthResponseFormPost` directly and emits the HTML form correctly.

### JWKS fetch failures

oauth2-passkey fetches the IdP's JSON Web Key Set from the `jwks_uri`
advertised by the discovery document. For self-hosted IdPs on HTTP, make
sure the URL is reachable from the oauth2-passkey process. For IdPs
behind corporate firewalls, confirm egress is allowed.

### IdP signs the user in without prompting

After a first successful login, subsequent OAuth2 sign-ins complete
without the IdP showing a password or account-picker screen. The IdP
silently reuses the existing session.

This is expected OIDC behavior: oauth2-passkey sends `prompt=consent`
on every authorization request (hardcoded in `oauth2/provider.rs` for
every provider, named and Custom), and per OIDC Core 1.0 that only
asks the IdP to redisplay the *consent* screen — it does not force
re-authentication or account selection. IdPs are therefore free to
reuse an existing authenticated session.

The difference between IdPs is how visibly they honor this:

- Google and Auth0 typically show at least a consent prompt
- Zitadel v4's login-v2 is aggressive about skipping straight through
  when a session exists
- Zitadel v2's V1 login often inserts an account-picker step

If the IdP's admin console shares the browser with the demo, the
console login creates a session the OAuth2 flow will reuse on the next
demo sign-in.

Practical workarounds for end-to-end testing:

- Use a **private browsing window** for the demo and close it between
  runs
- Call the IdP's `end_session_endpoint`
  (e.g. `http://localhost:8080/oidc/v1/end_session` for Zitadel) to
  drop the IdP-side session
- Avoid signing into the IdP admin console in the same browser profile
  you test the demo with

A permanent configuration knob for the `prompt` value
(`OAUTH2_CUSTOM{N}_PROMPT=login|select_account|consent|none`) would
give operators control over this but is not yet implemented; track as
a separate issue if the behavior is problematic for your deployment.
