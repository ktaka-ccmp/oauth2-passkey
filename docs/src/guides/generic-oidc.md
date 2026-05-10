# Generic OIDC Provider Setup

oauth2-passkey supports any standards-compliant OpenID Connect provider
through one of two paths: the built-in **Google** named provider
(`OAUTH2_GOOGLE_*`) or one of the eight **Custom slots**
(`OAUTH2_CUSTOM1_*` through `OAUTH2_CUSTOM8_*`). Custom slots can
optionally apply a **preset** that pre-fills the display name, URL
segment, icon, and brand colors for popular vendors. No code change is
required to enable any OIDC provider.

This page is the **reference / catalog** — concepts, preset table,
env-var documentation, verification status, end-to-end check, and a
shared troubleshooting catalog. For per-provider walkthroughs, see the
dedicated guide for that provider in this section of the book.

> **ORIGIN in the examples below.** The `demo-*` apps in this
> repository listen on port `3001`. Every redirect URI in this guide
> uses `http://localhost:3001` as the concrete ORIGIN to match that
> default. If your deployment uses a different origin, substitute
> accordingly — the library reads `ORIGIN` from the environment at
> startup and the redirect URI follows the shape
> `{ORIGIN}/o2p/oauth2/{NAME}/authorized`.

## Choosing the right path

| Use case | Path |
|---|---|
| Google | Built-in (set `OAUTH2_GOOGLE_CLIENT_ID` / `OAUTH2_GOOGLE_CLIENT_SECRET`). |
| Auth0, Keycloak, Microsoft Entra ID, Zitadel, Okta, Authentik, LINE, Apple | Custom slot with the matching preset (`OAUTH2_CUSTOM{N}_PRESET=auth0` etc.). See the dedicated guide for that provider. |
| AWS Cognito, Ory Hydra, Dex, Authelia, or any other OIDC-compliant IdP | Custom slot without a preset. Set `DISPLAY_NAME`, `NAME`, and (optionally) `BUTTON_COLOR` / `ICON_SLUG` explicitly. |
| Multiple instances of the same provider (e.g. two Keycloak realms, two Auth0 tenants) | One Custom slot per instance, each with a distinct `NAME`. Each slot is an independent account-binding in the database. |

Custom slots share the same OIDC code path as Google. The only
constraint is that the IdP implements standard OIDC Discovery at
`{issuer}/.well-known/openid-configuration`.

## Presets

Set `OAUTH2_CUSTOM{N}_PRESET` to one of:

| Preset | `NAME` default | `DISPLAY_NAME` default | `ICON_SLUG` | Brand color | Library-side quirks applied |
|--------|----------------|------------------------|-------------|-------------|------------------------------|
| `auth0` | `auth0` | `Auth0` | `auth0` | Auth0 orange (#eb5424) | — |
| `keycloak` | `keycloak` | `Keycloak` | `keycloak` | dark gray (#4d4d4d) | — |
| `entra` | `entra` | `Microsoft` | `entra` | Microsoft blue (#0078D4) | `login.live.com` added to allowed origins (required for personal MS accounts) |
| `zitadel` | `zitadel` | `Zitadel` | `zitadel` | near-black (#333333) | — |
| `okta` | `okta` | `Okta` | `okta` | Okta blue (#007dc1) | — |
| `authentik` | `authentik` | `Authentik` | `authentik` | red-orange (#fd4b2d) | — |
| `line` | `line` | `LINE` | `line` | LINE green (#06C755) | — |
| `apple` | `apple` | `Apple` | `apple` | black (#000000) | — |

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
  `oauth2.js`, `select`. Optional when `PRESET` is set — the preset's
  default `NAME` is used (see the preset table above).

The redirect URI you register at the IdP is:

```
{ORIGIN}/o2p/oauth2/{NAME}/authorized
```

## Optional Environment Variables

Defaults shown:

```bash
OAUTH2_CUSTOM{N}_PRESET=                        # unset | auth0 | keycloak | entra | zitadel | okta | authentik | line | apple
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
var. See [Presets](#presets).

Button colors are injected as CSS variables in the login template and drive
the `.btn-custom{N}` background color declared in the base stylesheet.

`ICON_SLUG` names an SVG basename served by the axum crate's built-in icon
router. Built-in slugs: `google`, `auth0`, `keycloak`, `entra`, `zitadel`,
`okta`, `authentik`, `line`, `apple`, and `openid` (the neutral
fallback). The slug must match `[a-z0-9_-]+`; slugs pointing at
non-existent SVGs will 404 at icon fetch time.

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

The table below summarizes the IdPs exercised end-to-end against
`demo-live` / `demo-both`, plus the quirks worth knowing before you
connect them. Each provider with a dedicated guide links to it; refer
to that guide for the full setup walkthrough.

| IdP | Path | Verified | Guide | Key caveats |
|-----|------|----------|-------|-------------|
| Google | Named (`OAUTH2_GOOGLE_*`) | ✅ | (built-in; see top-level README) | None. Standard OIDC compliant. |
| Auth0 | Custom (`PRESET=auth0`) | ✅ | [Auth0](./auth0.md) | `sub` contains `\|` (`auth0\|{id}`) — accepted by the library's `ProviderUserId` type. Cross-origin `form_post` sends `Origin: null`; the library falls back to `Referer` automatically. |
| Keycloak | Custom (`PRESET=keycloak`) | ✅ | [Keycloak](./keycloak.md) | Behind a reverse proxy, set `hostname` / `frontendUrl` so the advertised issuer matches the public URL — strict issuer validation fails otherwise. |
| Microsoft Entra ID | Custom (`PRESET=entra`) | ✅ | [Entra](./entra.md) | Single-tenant issuer only (`https://login.microsoftonline.com/{tenant}/v2.0`); multi-tenant `common` / `organizations` endpoints are not yet supported (tracked in issue `20260505-1416`). Personal MS accounts route credential entry through `login.live.com` — handled via `additional_allowed_origins` in the preset. `email` often absent from the ID token for personal accounts; `preferred_username` is the fallback. |
| Zitadel v2 (`v2.71.x`, embedded V1 login) | Custom (`PRESET=zitadel`) | ✅ | [Zitadel](./zitadel.md) | Standard OIDC; `form_post` works natively. `email` absent from id_token; `/userinfo` carries it. |
| Zitadel v4 (`zitadel-login` Next.js service) | Custom (`PRESET=zitadel`) | ✅ | [Zitadel](./zitadel.md) | **Requires `RESPONSE_MODE=query`** — v4's login service has no `form_post` branch and silently downgrades to `query`. `email` absent from id_token, same as v2. |
| Ory Hydra | Custom (no preset) | ✅ | [Ory Hydra](./ory-hydra.md) | Client must be registered with `--token-endpoint-auth-method client_secret_post` (library sends credentials in the form body, not HTTP Basic). No bundled user store — needs a separate login/consent app. Reference consent app emits only `sub` by default; use `CONFORMITY_FAKE_CLAIMS=1` for demo setups. |
| Authentik | Custom (`PRESET=authentik`) | ✅ | [Authentik](./authentik.md) | Trailing slash on `ISSUER_URL` must match what Authentik's discovery document reports (`http://localhost:9000/application/o/{slug}/`). Otherwise clean OIDC defaults — no response-mode downgrade, no auth-method mismatch. |
| Okta (Developer Edition) | Custom (`PRESET=okta`) | ✅ | [Okta](./okta.md) | Two-layer policy model — both the app's Authentication Policy **and** the Custom Authorization Server's Access Policy must allow the grant. Users must be **assigned** to the app explicitly (super-admin appears to bypass in admin UI but fails at token grant). |
| LINE Login | Custom (`PRESET=line`) | ✅ | [LINE](./line.md) | Web login uses **HS256** (channel secret as HMAC key, no `kid` header) — supported since v0.5.1. `email` scope requires explicit approval in the LINE Developer Console; without it, login fails with a clean validation error. Discovery advertises ES256 but web login always returns HS256. |
| Apple (Sign in with Apple) | Custom (`PRESET=apple`) | ❌ Not tested | [Apple](./apple.md) | OIDC-compliant, expected to work. Requires a **pre-generated client_secret JWT** (ES256-signed, max 6-month validity) instead of a static secret — generate externally and pass as `CLIENT_SECRET`. `name` claim is only returned on first authorization. Verification blocked on Apple Developer Program subscription. |
| AWS Cognito | Custom (no preset) | ❌ Not tested | — | Expected to work per OIDC spec; user-pool issuer shape is `https://cognito-idp.{region}.amazonaws.com/{user-pool-id}`. |
| Dex, Authelia, Salesforce, GitLab, Ping, etc. | Custom (no preset) | ❌ Not tested | — | OIDC-compliant; expected to work. File an issue if you try one and need adjustments. |
| GitHub | — | ❌ Not supported | — | GitHub does not implement OIDC for end-user login. Its `/login/oauth/.well-known/openid-configuration` endpoint is for Actions workflow federation only (no authorization_endpoint, no user-identity claims). GitHub OAuth2 requires a proprietary REST flow that this library does not support. |

Any OIDC-compliant IdP should work via a Custom slot, with or without
a preset. If you bring up a new IdP successfully, please file an issue
or PR so its caveats can be added here.

---

## Multiple instances of the same provider

Each Custom slot is an independent registration in oauth2-passkey.
Pointing two slots at the same backing IdP — for example, two Keycloak
realms or two Auth0 tenants — gives you two independent **Continue
with…** buttons, two distinct `provider` values in the `oauth2_accounts`
DB table, and two independent account-binding lifecycles. This is the
canonical way to support multi-tenant or multi-environment setups.

### Example: a second Keycloak realm

Suppose you already have a `Continue with Keycloak` button driven by
slot 1 with `PRESET=keycloak`. To add a second Keycloak realm with
distinct branding:

```bash
OAUTH2_CUSTOM2_PRESET=keycloak
OAUTH2_CUSTOM2_CLIENT_ID='<client-id-in-second-realm>'
OAUTH2_CUSTOM2_CLIENT_SECRET='<client-secret-in-second-realm>'
OAUTH2_CUSTOM2_ISSUER_URL='http://localhost:8180/realms/second-realm'
OAUTH2_CUSTOM2_NAME='keycloak2'         # override preset's "keycloak"
OAUTH2_CUSTOM2_DISPLAY_NAME='Keycloak (Realm 2)'
OAUTH2_CUSTOM2_BUTTON_COLOR='#1a73e8'   # override preset's color
```

Register a matching redirect URI in the second realm's Keycloak client:

```
http://localhost:3001/o2p/oauth2/keycloak2/authorized
```

The two slots produce independent **Continue with Keycloak** and
**Continue with Keycloak (Realm 2)** buttons, with separate DB rows
under `provider='keycloak'` vs `provider='keycloak2'`.

The same pattern works for any provider — Auth0, Entra, Zitadel,
Okta, etc. Pick a distinct `NAME` for each slot; the `PRESET=` is
optional and reusable across slots.

### Custom slot for an OIDC IdP without a preset

If your IdP isn't covered by a preset, drop `OAUTH2_CUSTOM{N}_PRESET`
and set `DISPLAY_NAME` and `NAME` explicitly:

```bash
OAUTH2_CUSTOM{N}_CLIENT_ID='<client-id>'
OAUTH2_CUSTOM{N}_CLIENT_SECRET='<client-secret>'
OAUTH2_CUSTOM{N}_ISSUER_URL='https://idp.example.com'
OAUTH2_CUSTOM{N}_DISPLAY_NAME='My IdP'
OAUTH2_CUSTOM{N}_NAME='my-idp'
# Optional visual overrides:
OAUTH2_CUSTOM{N}_BUTTON_COLOR='#6b7280'
OAUTH2_CUSTOM{N}_BUTTON_HOVER_COLOR='#4b5563'
OAUTH2_CUSTOM{N}_ICON_SLUG='openid'   # neutral fallback
```

The button shows the configured `DISPLAY_NAME` with the neutral
OpenID icon (or any built-in slug — see the Optional Environment
Variables section above).

---

## End-to-End Verification

Once a Custom slot is configured:

1. Start a demo app:
   ```bash
   cd demo-both
   cargo run
   ```
2. Open `http://localhost:3001/` in a browser.
3. Click **Continue with {DISPLAY_NAME}**.
4. Authenticate at the IdP (use the admin account you created during
   registration; for Hydra with `CONFORMITY_FAKE_CLAIMS=1`, any
   credentials are accepted).
5. Grant consent when prompted.
6. You should be redirected back to the demo landing page as an
   authenticated user.
7. Verify the account row was written:
   ```bash
   sqlite3 demo-both/data/auth.db \
       "SELECT provider, provider_user_id, email FROM oauth2_accounts;"
   ```
   You should see a row with `provider` matching `OAUTH2_CUSTOM{N}_NAME`.

### Regression checks

After verifying a Custom slot, sign out and confirm:

- Google (the only built-in named provider) still works.
- The **Choose a provider** screen at `/o2p/oauth2/select` renders every
  enabled provider button, with the colors from each slot's
  `BUTTON_COLOR` (or the preset's defaults).
- The admin user-detail page renders the correct display name and icon
  for the new provider.

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
- The segment collides with the built-in `google` named provider or a
  reserved route literal (`authorized`, `accounts`, `fedcm`,
  `popup_close`, `oauth2.js`, `select`)
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

**Ory Hydra** exhibits the same constraint with a more explicit error
message: it returns `invalid_request: response_mode form_post not
supported` because Hydra only supports `query` and `fragment`. Same
fix: set `OAUTH2_CUSTOM{N}_RESPONSE_MODE=query`.

### JWKS fetch failures

oauth2-passkey fetches the IdP's JSON Web Key Set from the `jwks_uri`
advertised by the discovery document. For self-hosted IdPs on HTTP, make
sure the URL is reachable from the oauth2-passkey process. For IdPs
behind corporate firewalls, confirm egress is allowed.

### JWKS stale after switching IdP versions on the same host

If you test against multiple versions of the same IdP on the same host
(e.g. Zitadel v2 and v4 both bound to `:8080`), they advertise the same
`jwks_uri`. oauth2-passkey caches JWKS in the configured cache backend
(Redis by default) for 10 minutes keyed by URL, so after switching
stacks the app still returns the previous instance's keys and ID-token
verification fails with:

```
Authentication failed: OAuth2 error: Id token error: No matching key
found in JWKS
```

Flush just the stale entry:

```bash
docker exec <redis-container> redis-cli \
    DEL 'cache:jwks:http://localhost:8080/oauth/v2/keys'
```

(or `FLUSHDB` if you don't mind wiping the entire cache). In-memory
caches clear on demo-app restart and do not need manual intervention.

### Login loops after consent (self-hosted IdPs)

Repeatedly redirected back to the IdP login screen after granting
consent — usually a stale session cookie for the IdP from an earlier
run. Clear cookies for the IdP host (e.g. `localhost:8080` for Zitadel)
and try again. If the loop persists, `docker compose down -v` on the
IdP stack to wipe state fully and re-register the application.

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
