# Generic OIDC Provider Setup

oauth2-passkey ships with eight "Custom" OIDC slots (`Custom1` through
`Custom8`) that let operators enable any standards-compliant OpenID Connect
provider via environment variables alone — no code change required.

Use these slots for providers without dedicated built-in support, such as
Okta, AWS Cognito, Zitadel, Ory Hydra, Authentik, Dex, Authelia, and
similar self-hosted or hosted OIDC stacks. A Custom slot can also be
used to register a *second* instance of a named provider (e.g. a
second Keycloak realm) — see **Using a Custom slot for a named
provider** at the bottom of this page.

> **ORIGIN in the examples below.** The `demo-*` apps in this
> repository listen on port `3001`. Every redirect URI in this guide
> uses `http://localhost:3001` as the concrete ORIGIN to match that
> default. If your deployment uses a different origin, substitute
> accordingly — the library reads `ORIGIN` from the environment at
> startup and the redirect URI follows the shape
> `{ORIGIN}/o2p/oauth2/{NAME}/authorized`.

## When to Use Custom Slots vs Named Providers

| Provider | Use |
|----------|-----|
| Google | Built-in (always on when `OAUTH2_GOOGLE_CLIENT_ID` is set) |
| Auth0, Keycloak, Microsoft Entra ID, Zitadel, Okta, Authentik | Custom slot with `OAUTH2_CUSTOM{N}_PRESET=auth0\|keycloak\|entra\|zitadel\|okta\|authentik` — see each provider's dedicated guide for the IdP-side steps |
| AWS Cognito, Ory Hydra, Dex, Authelia, any other OIDC IdP | A Custom slot without a preset |
| A second instance of any of the above (e.g. extra Keycloak realm) | A Custom slot with a distinct `NAME` |

The custom slots go through the exact same OIDC code path as Google. The
only constraint is that the IdP must implement standard OIDC Discovery at
`{issuer}/.well-known/openid-configuration`.

## Presets for built-in vendors

Set `OAUTH2_CUSTOM{N}_PRESET` to one of:

| Preset | `NAME` default | `DISPLAY_NAME` default | `ICON_SLUG` | Brand color | Library-side quirks applied |
|--------|----------------|------------------------|-------------|-------------|------------------------------|
| `auth0` | `auth0` | `Auth0` | `auth0` | Auth0 orange (#eb5424) | — |
| `keycloak` | `keycloak` | `Keycloak` | `keycloak` | dark gray (#4d4d4d) | — |
| `entra` | `entra` | `Microsoft` | `entra` | Microsoft blue (#0078D4) | `login.live.com` added to allowed origins (required for personal MS accounts) |
| `zitadel` | `zitadel` | `Zitadel` | `zitadel` | near-black (#333333) | — |
| `okta` | `okta` | `Okta` | `okta` | Okta blue (#007dc1) | — |
| `authentik` | `authentik` | `Authentik` | `authentik` | red-orange (#fd4b2d) | — |

A preset supplies defaults for `DISPLAY_NAME`, `NAME`, `ICON_SLUG`,
`BUTTON_COLOR`, `BUTTON_HOVER_COLOR`, and any additional allowed origins.
Any field can still be overridden by the matching `OAUTH2_CUSTOM{N}_*`
env var — the env var wins.

A preset-driven slot needs only four env vars:

```bash
OAUTH2_CUSTOM1_PRESET=auth0
OAUTH2_CUSTOM1_CLIENT_ID='your-client-id'
OAUTH2_CUSTOM1_CLIENT_SECRET='your-client-secret'
OAUTH2_CUSTOM1_ISSUER_URL='https://your-tenant.auth0.com'
```

For Entra, the preset adds `https://login.live.com` to the allowed origin
list so personal Microsoft accounts (which route credential entry through
that host) do not fail origin validation on the `form_post` callback. There
is no env var to override this list — it is a library-level invariant.

## Required Environment Variables

For each enabled slot `N` (1..8):

```bash
OAUTH2_CUSTOM{N}_CLIENT_ID='your-client-id'
OAUTH2_CUSTOM{N}_CLIENT_SECRET='your-client-secret'
OAUTH2_CUSTOM{N}_ISSUER_URL='https://idp.example.com'
OAUTH2_CUSTOM{N}_DISPLAY_NAME='My SSO'
OAUTH2_CUSTOM{N}_NAME='my-sso'
```

- `ISSUER_URL`: the base URL from which oauth2-passkey fetches
  `/.well-known/openid-configuration`. No trailing slash.
- `DISPLAY_NAME`: the label shown on the login button ("Continue with
  `{DISPLAY_NAME}`"). Optional when `PRESET` is set.
- `NAME`: the URL segment used in routes
  (`/o2p/oauth2/{NAME}`) and stored in the database `provider`
  column. Must match `[a-z0-9_-]+` and must not collide with `google` or
  the reserved literals `authorized`, `accounts`, `fedcm`, `popup_close`,
  `oauth2.js`, `select`. Optional when `PRESET` is set — the preset
  supplies `auth0`, `keycloak`, or `entra` as the default.

The redirect URI you register at the IdP is:

```
{ORIGIN}/o2p/oauth2/{NAME}/authorized
```

## Optional Environment Variables

Defaults shown:

```bash
OAUTH2_CUSTOM{N}_PRESET=                        # unset | auth0 | keycloak | entra
OAUTH2_CUSTOM{N}_ICON_SLUG='openid'             # SVG basename at /o2p/icons/{slug}.svg
OAUTH2_CUSTOM{N}_RESPONSE_MODE='form_post'      # form_post or query
OAUTH2_CUSTOM{N}_SCOPE='openid+email+profile'
OAUTH2_CUSTOM{N}_PROMPT='consent'               # none | login | consent | select_account | "" (omit)
OAUTH2_CUSTOM{N}_BUTTON_COLOR='#6b7280'         # neutral gray
OAUTH2_CUSTOM{N}_BUTTON_HOVER_COLOR='#4b5563'
OAUTH2_CUSTOM{N}_STRICT_DISPLAY_CLAIMS=true     # see "Claim mismatch" troubleshooting
```

When `PRESET` is set, the preset supplies defaults for `ICON_SLUG`,
`BUTTON_COLOR`, `BUTTON_HOVER_COLOR`, and (for `entra`) an additional
allowed origin. Each field is still overridable by the corresponding env
var. See [Presets for built-in vendors](#presets-for-built-in-vendors).

Button colors are injected as CSS variables in the login template and drive
the `.btn-custom{N}` background color declared in the base stylesheet.

`ICON_SLUG` names an SVG basename served by the axum crate's built-in icon
router. Built-in slugs: `auth0`, `keycloak`, `entra`, `google`, and `openid`
(the neutral fallback). The slug must match `[a-z0-9_-]+`; slugs pointing
at non-existent SVGs will 404 at icon fetch time.

`STRICT_DISPLAY_CLAIMS` controls how the library reacts when display-tier
claims (`name`, `picture`, `family_name`, `given_name`) differ between the
verified ID token and the `/userinfo` response: `true` (default) rejects
the flow; `false` emits a `tracing::warn!` log and uses the id_token
value. Identity-tier claims (`email`, `email_verified`,
`preferred_username`, `hd`) are always rejected on mismatch — this flag
does **not** affect them. See the
[Claim mismatch between id_token and /userinfo](#claim-mismatch-between-id_token-and-userinfo)
troubleshooting entry for when this fires in practice.

## Verification Status and Caveats

The table below summarizes the IdPs that have been exercised
end-to-end against `demo-live` / `demo-both`, plus the quirks worth
knowing before you connect them. Named providers are included for
completeness — they have their own dedicated guides, but the OIDC
code path is shared with Custom slots.

| IdP | Slot type | Verified | Key caveats |
|-----|-----------|----------|-------------|
| Google | Named (`OAUTH2_GOOGLE_*`) | ✅ | None. Standard OIDC compliant. |
| Auth0 | Named (`OAUTH2_AUTH0_*`) | ✅ | `sub` contains `\|` (`auth0\|{id}`) — accepted by the library's `ProviderUserId` type. Cross-origin `form_post` sends `Origin: null`; the library falls back to `Referer` automatically. |
| Keycloak | Named (`OAUTH2_KEYCLOAK_*`) | ✅ | Behind a reverse proxy, set `hostname` / `frontendUrl` so the advertised issuer matches the public URL — strict issuer validation fails otherwise. Can also be run via a Custom slot (see *Using a Custom slot for a named provider*). |
| Microsoft Entra ID | Named (`OAUTH2_ENTRA_*`) | ✅ | Single-tenant issuer only (`https://login.microsoftonline.com/{tenant}/v2.0`); multi-tenant `common` / `organizations` endpoints are not supported. Personal MS accounts route credential entry through `login.live.com` — handled via `additional_allowed_origins` in the provider config. `email` often absent from the ID token for personal accounts; `preferred_username` is the fallback. |
| Zitadel v2 (`v2.71.x`, embedded V1 login) | Custom | ✅ | Standard OIDC; `form_post` works natively. `email` absent from id_token; `/userinfo` carries it. |
| Zitadel v4 (`zitadel-login` Next.js service) | Custom | ✅ | **Requires `RESPONSE_MODE=query`** — v4's login service has no `form_post` branch and silently downgrades to `query`. `email` absent from id_token, same as v2. See [Zitadel (Self-Hosted)](#zitadel-self-hosted). |
| Ory Hydra | Custom | ✅ | Client must be registered with `--token-endpoint-auth-method client_secret_post` (library sends credentials in the form body, not HTTP Basic). No bundled user store — needs a separate login/consent app. Reference consent app emits only `sub` by default; use `CONFORMITY_FAKE_CLAIMS=1` for demo setups. See [Ory Hydra (Self-Hosted)](#ory-hydra-self-hosted). |
| Authentik | Custom | ✅ | Trailing slash on `ISSUER_URL` must match what Authentik's discovery document reports (`http://localhost:9000/application/o/{slug}/`). Otherwise clean OIDC defaults — no response-mode downgrade, no auth-method mismatch. See [Authentik (Self-Hosted)](#authentik-self-hosted). |
| Okta (Developer Edition) | Custom | ✅ | Two-layer policy model — both the app's Authentication Policy **and** the Custom Authorization Server's Access Policy must allow the grant. Users must be **assigned** to the app explicitly (super-admin appears to bypass in admin UI but fails at token grant). See [Okta (Cloud, Developer Edition)](#okta-cloud-developer-edition). |
| AWS Cognito | Custom | ❌ Not tested | Expected to work per OIDC spec; user-pool issuer shape is `https://cognito-idp.{region}.amazonaws.com/{user-pool-id}`. |
| Dex, Authelia, Salesforce, GitLab, Ping, etc. | Custom | ❌ Not tested | OIDC-compliant; expected to work. File an issue if you try one and need adjustments. |

Any OIDC-compliant IdP should work. The sections below walk through
each verified self-host / cloud setup in detail.

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
4. Set **Redirect URI**: `http://localhost:3001/o2p/oauth2/zitadel/authorized`
5. Finish the wizard and copy the **Client ID** and **Client Secret**

### Step 3: Configure oauth2-passkey

```bash
OAUTH2_CUSTOM1_CLIENT_ID='<client-id-from-zitadel>'
OAUTH2_CUSTOM1_CLIENT_SECRET='<client-secret-from-zitadel>'
OAUTH2_CUSTOM1_ISSUER_URL='http://localhost:8080'
OAUTH2_CUSTOM1_DISPLAY_NAME='Zitadel'
OAUTH2_CUSTOM1_NAME='zitadel'
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
  --redirect-uri 'http://localhost:3001/o2p/oauth2/hydra/authorized' \
  --token-endpoint-auth-method client_secret_post
```

Two Hydra-specific requirements:

- **`--token-endpoint-auth-method client_secret_post`**: oauth2-passkey
  sends client credentials in the request body. Hydra defaults to
  `client_secret_basic` (HTTP Basic), which will fail with `401 Unauthorized`
  at token exchange.
- **`--redirect-uri` must exactly match** what the library sends —
  `http://localhost:3001/o2p/oauth2/{NAME}/authorized` — or
  Hydra rejects the authorization request with `invalid_request`.

Copy the returned `client_id` and `client_secret` (Hydra only shows the
secret once).

### Step 3: Configure oauth2-passkey

```bash
OAUTH2_CUSTOM2_CLIENT_ID='<client-id-from-hydra>'
OAUTH2_CUSTOM2_CLIENT_SECRET='<client-secret-from-hydra>'
OAUTH2_CUSTOM2_ISSUER_URL='http://localhost:4444'
OAUTH2_CUSTOM2_DISPLAY_NAME='Ory Hydra'
OAUTH2_CUSTOM2_NAME='hydra'
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

## Authentik (Self-Hosted)

Authentik is a full-featured self-hosted IdP (admin UI, flows,
policies) similar in scope to Keycloak or Zitadel, but with sensible
OIDC defaults — no response-mode downgrade, no token-endpoint-auth-
method mismatch, no fake-claim workarounds. This makes it a clean
reference point for the Custom slot code path.

### Step 1: Bring Up Authentik

A ready-to-go docker-compose is provided under `idp/authentik/`:

```bash
cd idp/authentik
cp .env.example .env
# Generate AUTHENTIK_SECRET_KEY and set AUTHENTIK_BOOTSTRAP_PASSWORD:
openssl rand -base64 60 | tr -d '\n'
$EDITOR .env

docker compose up -d
docker compose logs -f server
```

Wait until the server log shows `Starting main process`. First boot
runs migrations and creates the default admin user.

Services exposed on host:

| Service           | Port  |
|-------------------|-------|
| HTTP (admin UI + OIDC endpoints) | `9000` |
| HTTPS (self-signed)              | `9443` |
| Postgres / Redis                 | not exposed |

### Step 2: Create the OAuth2/OIDC Provider

1. Open `http://localhost:9000/if/flow/initial-setup/` and log in as
   `akadmin` (or the email from `AUTHENTIK_BOOTSTRAP_EMAIL`) with
   the password from `.env`.
2. Admin interface → **Applications → Providers → Create →
   OAuth2/OpenID Provider**. Key fields:
   - **Name**: `oauth2-passkey-demo`
   - **Authorization flow**:
     `default-provider-authorization-explicit-consent` (or
     `-implicit-consent` to skip the consent screen while testing)
   - **Client type**: `Confidential`
   - **Client ID** / **Client Secret**: leave auto-generated; copy
     them out for Step 3
   - **Redirect URIs**:
     `http://localhost:3001/o2p/oauth2/authentik/authorized`
     (regex mode **off**; exact match)
   - **Signing Key**: `authentik Self-signed Certificate`
   - **Scopes**: keep defaults (`openid`, `email`, `profile`)
3. Save.
4. **Applications → Applications → Create**:
   - **Name**: `oauth2-passkey-demo`
   - **Slug**: `oauth2-passkey-demo` (this forms the issuer URL)
   - **Provider**: the provider you just created
5. Save.

The issuer URL is `http://localhost:9000/application/o/{slug}/`.
Verify:

```bash
curl -s http://localhost:9000/application/o/oauth2-passkey-demo/.well-known/openid-configuration | jq .issuer
# -> "http://localhost:9000/application/o/oauth2-passkey-demo/"
```

### Step 3: Configure oauth2-passkey

```bash
OAUTH2_CUSTOM{N}_CLIENT_ID='<from Authentik provider>'
OAUTH2_CUSTOM{N}_CLIENT_SECRET='<from Authentik provider>'
OAUTH2_CUSTOM{N}_ISSUER_URL='http://localhost:9000/application/o/oauth2-passkey-demo/'
OAUTH2_CUSTOM{N}_DISPLAY_NAME='Authentik'
OAUTH2_CUSTOM{N}_NAME='authentik'
OAUTH2_CUSTOM{N}_BUTTON_COLOR='#fd4b2d'
OAUTH2_CUSTOM{N}_BUTTON_HOVER_COLOR='#e03d1f'
```

The **trailing slash** on `ISSUER_URL` must match exactly what
Authentik's discovery document reports under `"issuer"`, or strict
ID-token validation will reject the response.

Restart oauth2-passkey. A **Continue with Authentik** button appears
on the login page.

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
     `http://localhost:3001/o2p/oauth2/{NAME}/authorized`
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
OAUTH2_CUSTOM{N}_NAME='okta'
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

## Using a Custom slot for a named provider

The Custom slot code path is identical to the named-provider code
path — the same `ProviderConfig`, the same OIDC discovery cache, the
same token validation. Any named provider can therefore be
configured via a Custom slot, which is useful when you need:

- Two instances of the same provider type (e.g. two Keycloak realms
  with different branding)
- A named provider with a custom display name, button color, or
  URL segment that the named slot does not expose
- To experiment with a provider before deciding whether it deserves
  a dedicated guide

### Example: Keycloak as a Custom slot

Suppose you already have Keycloak running at
`http://localhost:8180/realms/o2p`. To expose it as `keycloak2`
alongside (or instead of) the named Keycloak slot:

```bash
OAUTH2_CUSTOM{N}_CLIENT_ID='o2p'
OAUTH2_CUSTOM{N}_CLIENT_SECRET='<client-secret-from-keycloak>'
OAUTH2_CUSTOM{N}_ISSUER_URL='http://localhost:8180/realms/o2p'
OAUTH2_CUSTOM{N}_DISPLAY_NAME='Keycloak2'
OAUTH2_CUSTOM{N}_NAME='keycloak2'
OAUTH2_CUSTOM{N}_BUTTON_COLOR='#fd4b2d'
OAUTH2_CUSTOM{N}_BUTTON_HOVER_COLOR='#e03d1f'
```

Register a matching redirect URI in the Keycloak client config:

```
http://localhost:3001/o2p/oauth2/keycloak2/authorized
```

You now get a **Continue with Keycloak2** button that resolves
through the same realm as the named Keycloak slot but via a
different URL path, different DB `provider` column value
(`keycloak2`), and different branding. The two are independent
accounts in oauth2-passkey even when they share the backing realm.

The same pattern works for Auth0 and Microsoft Entra ID — set
`OAUTH2_CUSTOM{N}_CLIENT_ID` / `_SECRET` / `_ISSUER_URL` to the
values from the IdP, pick a distinct `NAME`, and you have a
second instance. Google is slightly less interesting because its
single OIDC tenant does not benefit from multiple client slots, but
it works the same way if needed.

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

### `validate_custom_slots` rejects `NAME` at startup

Possible causes:

- The segment contains characters outside `[a-z0-9_-]` (uppercase,
  slashes, spaces)
- The segment collides with a named provider (`google`, `auth0`, ...) or
  a reserved route (`authorized`, `accounts`, `fedcm`, `popup_close`,
  `oauth2.js`, `select`)
- Two different custom slots declare the same `NAME`

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

This is expected OIDC behavior: per OIDC Core 1.0, `prompt=consent`
only asks the IdP to redisplay the *consent* screen — it does not force
re-authentication or account selection. IdPs are therefore free to
reuse an existing authenticated session.

The difference between IdPs is how visibly they honor this:

- Google and Auth0 typically show at least a consent prompt
- Zitadel v4's login-v2 is aggressive about skipping straight through
  when a session exists
- Zitadel v2's V1 login often inserts an account-picker step

**Fix**: set `OAUTH2_CUSTOM{N}_PROMPT` (or `OAUTH2_GOOGLE_PROMPT` for
Google) to change the OIDC `prompt` parameter:

```bash
# Force the account-picker on every sign-in:
OAUTH2_CUSTOM1_PROMPT=select_account

# Force re-authentication on every sign-in:
OAUTH2_CUSTOM1_PROMPT=login

# Omit the prompt parameter entirely (let the IdP decide):
OAUTH2_CUSTOM1_PROMPT=
```

Valid values: `none`, `login`, `consent`, `select_account`, or empty
string (omits the parameter). Default is `consent`. An invalid value
causes startup failure with a descriptive error.

If the IdP's admin console shares the browser with the demo, the
console login creates a session the OAuth2 flow will reuse on the next
demo sign-in. Other testing workarounds:

- Use a **private browsing window** for the demo and close it between
  runs
- Call the IdP's `end_session_endpoint`
  (e.g. `http://localhost:8080/oidc/v1/end_session` for Zitadel) to
  drop the IdP-side session
- Avoid signing into the IdP admin console in the same browser profile
  you test the demo with

### Claim mismatch between id_token and /userinfo

Sign-in fails with an error whose message starts with

```
OAuth2 claim mismatch for provider '<name>': `<field>` differs between
id_token ('<idinfo value>') and userinfo ('<userinfo value>')
```

The library cross-checks claims that both the verified ID token and
the `/userinfo` response populate. Because both are fetched within
milliseconds of each other in a single OAuth2 flow and reflect the
same user snapshot, any field-level divergence is anomalous rather
than legitimate drift.

Two tiers are enforced:

- **Tier 1 — identity-critical** (`email`, `email_verified`,
  `preferred_username`, `hd`): always rejected on mismatch. These drive
  authn/authz decisions, so silent divergence is a security concern.
  Not configurable.
- **Tier 2 — display/metadata** (`name`, `picture`, `family_name`,
  `given_name`): rejected by default; can be downgraded to a warning
  per provider by setting
  `OAUTH2_<PROVIDER>_STRICT_DISPLAY_CLAIMS=false`
  (`OAUTH2_GOOGLE_STRICT_DISPLAY_CLAIMS`, `OAUTH2_CUSTOM1_STRICT_DISPLAY_CLAIMS`, etc.).

A mismatch fires only when **both sides populate the field with
different values**. A one-sided `None` (e.g. Zitadel asserts `email`
only in `/userinfo` and omits it from the ID token) is the normal merge
case and is silently allowed.

Typical triggers in practice:

- A Keycloak realm with a custom **Token Mapper** that rewrites a
  display claim only in the ID token (or only in `/userinfo`)
- An Authentik custom **Scope Mapping** that transforms one side
- Operator-level claim transformations at any OIDC IdP

Remediation:

- **Preferred**: reconcile the IdP mappings so both sources emit the
  same value. This is a configuration bug at the IdP layer.
- If the divergence is intentional and limited to Tier 2, set
  `OAUTH2_<PROVIDER>_STRICT_DISPLAY_CLAIMS=false` and watch the
  `tracing::warn!` logs for the
  `security_event = "oauth2_claim_mismatch"` structured field.
- Tier 1 divergence never has an escape hatch — resolve at the IdP.
