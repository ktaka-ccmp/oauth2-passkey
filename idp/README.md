# Generic OIDC Provider — End-to-End Verification

This directory holds `docker compose` definitions for self-hosted OIDC
providers used to verify the **Custom1..Custom8** generic slots added by
`oauth2_passkey`.

Each stack is self-contained: bring it up, register a client, plug the
credentials into `OAUTH2_CUSTOM{N}_*` env vars, and run one of the demo
apps.

| Stack        | Directory          | Issuer URL                 | Admin / UI                           |
|--------------|--------------------|----------------------------|--------------------------------------|
| Zitadel v2   | `idp/zitadel/`     | `http://localhost:8080`    | Console at `http://localhost:8080/ui/console` |
| Zitadel v4   | `idp/zitadel-v4/`  | `http://localhost:8080`    | Console at `http://localhost:8080/ui/console` |
| Ory Hydra    | `idp/ory-hydra/`   | `http://localhost:4444`    | Admin API at `http://localhost:4445` |
| Keycloak     | `idp/keycloak/`    | `http://localhost:8180/realms/{realm}` | Admin console at `http://localhost:8180` |

`idp/zitadel/` (v2.71.x, embedded V1 login) and `idp/zitadel-v4/` (v4.x, separate
`zitadel-login` Next.js service) both bind to `:8080` and are mutually exclusive —
bring one down before bringing the other up. v4 is the official upstream compose
and is closer to what cloud-hosted Zitadel runs today; v2 is kept because its
single-container setup is simpler and it supports `response_mode=form_post`
natively (see §1.5).

Ports are bound to `127.0.0.1` only. Named Docker volumes persist
state so you can `down` and bring the stack back up without losing data.

---

## Prerequisites

- Docker Engine 20.10+ with Compose v2
- One of the demo apps in this repo running (e.g. `demo-both`)
- `ORIGIN` set to a URL reachable by your browser — typically
  `http://localhost:3001` for the demos

Redirect URI format for every Custom slot is:

```
{ORIGIN}/o2p/oauth2/{OAUTH2_CUSTOM{N}_NAME}/authorized
```

e.g. with `ORIGIN=http://localhost:3001` and `OAUTH2_CUSTOM1_NAME=zitadel`:

```
http://localhost:3001/o2p/oauth2/zitadel/authorized
```

---

## 1. Zitadel

Zitadel is a full-featured OIDC/OAuth2 identity platform. It provisions
a Postgres backend on first boot, runs initial migrations, and starts
the server on `:8080`.

### 1.1 Bring up the stack

```bash
cd idp/zitadel
docker compose up -d
docker compose logs -f zitadel   # wait for "server is listening on [::]:8080"
```

First start takes ~30-60 seconds (init + setup + start). Subsequent
boots are near-instant.

> **Why v2.71.x and not `latest`?**
> Zitadel v3 redirects `/ui/console` to a separate Next.js login UI
> (`zitadel-login`) that is **not** bundled with the main container.
> Using `latest` causes `/ui/v2/login/login?...` to return
> `{"code":5,"message":"Not Found"}` because the login service is
> missing. v2.71.x still ships the embedded V1 login UI and works
> standalone, which is what this verification stack needs. If you
> want to test against v3+, add a `zitadel-login` service per
> Zitadel's official multi-service compose example.

### 1.2 First-time Zitadel setup

1. Open `http://localhost:8080/ui/console`.
2. Log in with the default IAM owner credentials printed by
   `docker compose logs zitadel | grep -A2 "IAM Owner"`:
   - Username: `zitadel-admin@zitadel.localhost`
   - Password: check the log line `setup step 4 ... password: ...`
     (or use the default: `Password1!` — Zitadel then prompts a reset).
3. Change the password when prompted.
4. In the console: **Projects -> Create Project** (e.g. `oauth2-passkey-demo`).
5. Inside the project: **New -> Application** -> **WEB**.
   - Name: `demo`
   - **Authentication Method: `CODE`** (required — this is what issues a
     client secret. Do **not** pick `PKCE`: PKCE makes it a public client
     with no secret, which oauth2-passkey does not use.)
   - Redirect URI: `http://localhost:3001/o2p/oauth2/zitadel/authorized`
   - Post Logout URI: `http://localhost:3001/`
6. On the final wizard page, copy:
   - **ClientID** -> `OAUTH2_CUSTOM1_CLIENT_ID`
   - **ClientSecret** -> `OAUTH2_CUSTOM1_CLIENT_SECRET`
     (shown **once only** — if you miss it, regenerate via
     [the app's detail page → "Client Secret" section → "New"]).
7. If you accidentally created the app as `PKCE`: open the app,
   change **Authentication Method** to `CODE`, save, then regenerate
   a secret from the **Client Secret** section.
7. (Optional) In the project **General** tab, enable **Assert Roles On
   Authentication** if you want role claims in the ID token.

### 1.3 Wire up oauth2-passkey

Add to your `.env`:

```dotenv
OAUTH2_CUSTOM1_CLIENT_ID=<paste from Zitadel>
OAUTH2_CUSTOM1_CLIENT_SECRET=<paste from Zitadel>
OAUTH2_CUSTOM1_ISSUER_URL=http://localhost:8080
OAUTH2_CUSTOM1_DISPLAY_NAME=Zitadel
OAUTH2_CUSTOM1_NAME=zitadel
OAUTH2_CUSTOM1_BUTTON_COLOR=#000000
OAUTH2_CUSTOM1_BUTTON_HOVER_COLOR=#1a1a1a
OAUTH2_CUSTOM1_RESPONSE_MODE=query
```

> **v4 only**: `OAUTH2_CUSTOM1_RESPONSE_MODE=query` is required for the
> v4 stack (`idp/zitadel-v4/`). v4's separate login service calls the
> API's `CreateCallback` RPC, whose response carries only a
> `CallbackUrl` string — so `form_post` cannot be emitted and the
> request silently downgrades to a GET redirect. The demo then
> rejects the response with `Invalid response mode: GET is not allowed
> for form_post`. The v2 stack (`idp/zitadel/`) ships the embedded V1
> login UI which builds the callback directly and supports
> `form_post`, so the mode line can be omitted there.

Restart the demo app. A **Continue with Zitadel** button should appear
on the login page.

### 1.4 Tear down

```bash
cd idp/zitadel
docker compose down          # keeps the named volume (data persists)
docker compose down -v       # wipes everything
```

---

## 2. Ory Hydra

Hydra is a headless OAuth2/OIDC server: it provides the protocol but
delegates login and consent UI to an external app. This compose stack
runs the reference `hydra-login-consent-node` alongside Hydra so the
flow works out of the box.

Services exposed:

| Service       | Purpose                              | Port (host)   |
|---------------|--------------------------------------|---------------|
| Hydra public  | `/oauth2/auth`, `/oauth2/token`, etc.| `4444`        |
| Hydra admin   | Client registration, introspection   | `4445`        |
| Consent node  | Login + consent UI                   | `3100`        |
| Postgres      | Hydra backend                        | (not exposed) |

### 2.1 Bring up the stack

```bash
cd idp/ory-hydra
docker compose up -d
docker compose logs -f hydra
```

`hydra-migrate` runs once to apply the SQL schema, then exits. `hydra`
starts serving after migration completes.

Verify:

```bash
curl -s http://localhost:4444/.well-known/openid-configuration | jq .issuer
# -> "http://localhost:4444"
```

### 2.2 Register an OAuth2 client

Hydra has no admin UI; clients are created via the admin API. The
simplest way is to `exec` into the Hydra container:

```bash
docker compose exec hydra \
    hydra create client \
        --endpoint http://127.0.0.1:4445 \
        --name "oauth2-passkey demo" \
        --grant-type authorization_code,refresh_token \
        --response-type code,id_token \
        --scope openid,email,profile \
        --redirect-uri http://localhost:3001/o2p/oauth2/hydra/authorized \
        --token-endpoint-auth-method client_secret_post \
        --format json
```

`--token-endpoint-auth-method client_secret_post` is required:
oauth2-passkey sends credentials in the request body. Hydra's default
(`client_secret_basic`) expects HTTP Basic and will fail token exchange
with `401 Unauthorized`.

The response is JSON. Copy:

- `client_id` -> `OAUTH2_CUSTOM2_CLIENT_ID`
- `client_secret` -> `OAUTH2_CUSTOM2_CLIENT_SECRET` (Hydra shows this
  only at creation time)

> The bundled consent container runs with `CONFORMITY_FAKE_CLAIMS=1`,
> which makes the reference consent app emit fake `email=foo@bar.com`
> and `preferred_username=robot` claims. This is demo-only behavior; for
> real multi-user deployments, fork `hydra-login-consent-node` and
> populate `session.id_token` from your user store.

### 2.3 Wire up oauth2-passkey

Add to your `.env`:

```dotenv
OAUTH2_CUSTOM2_CLIENT_ID=<paste from Hydra>
OAUTH2_CUSTOM2_CLIENT_SECRET=<paste from Hydra>
OAUTH2_CUSTOM2_ISSUER_URL=http://localhost:4444
OAUTH2_CUSTOM2_DISPLAY_NAME=Ory Hydra
OAUTH2_CUSTOM2_NAME=hydra
OAUTH2_CUSTOM2_BUTTON_COLOR=#5528ff
OAUTH2_CUSTOM2_BUTTON_HOVER_COLOR=#3d1bcc
OAUTH2_CUSTOM2_RESPONSE_MODE=query
```

> `OAUTH2_CUSTOM2_RESPONSE_MODE=query` is important: Hydra supports
> `query` and `fragment`, not `form_post`. The default `form_post` will
> fail at discovery time.

Restart the demo app. A **Continue with Ory Hydra** button should
appear.

### 2.4 Tear down

```bash
cd idp/ory-hydra
docker compose down
docker compose down -v       # wipes Postgres volume
```

---

## 3. Authentik

Authentik is a full-featured self-hosted IdP (admin UI, flows, policies)
similar in scope to Keycloak / Zitadel, but with sensible defaults — no
response-mode downgrade, no token-endpoint-auth-method mismatch, no fake
claim workarounds. A clean reference point for the Custom slot code path.

Services exposed:

| Service       | Purpose                              | Port (host)   |
|---------------|--------------------------------------|---------------|
| Server        | HTTP (admin UI + OIDC endpoints)     | `9000`        |
| Server (TLS)  | HTTPS (self-signed)                  | `9443`        |
| Postgres      | Authentik backend                    | (not exposed) |
| Redis         | Cache / task queue                   | (not exposed) |

### 3.1 Bring up the stack

```bash
cd idp/authentik
cp .env.example .env
# Generate AUTHENTIK_SECRET_KEY and set AUTHENTIK_BOOTSTRAP_PASSWORD in .env
openssl rand -base64 60 | tr -d '\n'
$EDITOR .env

docker compose up -d
docker compose logs -f server
```

Wait until the server log shows `Starting main process`. First boot runs
migrations + creates the default admin user.

Verify discovery is reachable (the exact slug is created in the next
step; for now just confirm the server is alive):

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:9000/-/health/live/
# -> 204
```

### 3.2 Log in and create the OAuth2/OIDC provider

1. Open `http://localhost:9000/if/flow/initial-setup/` in a browser.
2. Log in as `akadmin` (or the email from `AUTHENTIK_BOOTSTRAP_EMAIL`)
   with the password from `.env`.
3. Admin interface -> **Applications -> Providers -> Create**.
4. Select **OAuth2/OpenID Provider**. Key fields:
   - **Name**: `oauth2-passkey-demo`
   - **Authorization flow**: `default-provider-authorization-explicit-consent`
     (or `-implicit-consent` to skip the consent screen during testing)
   - **Client type**: `Confidential`
   - **Client ID** / **Client Secret**: leave auto-generated; copy them
   - **Redirect URIs**: one entry,
     `http://localhost:3001/o2p/oauth2/authentik/authorized`
     (regex mode off; exact match)
   - **Signing Key**: `authentik Self-signed Certificate`
   - **Scopes**: keep defaults (`openid`, `email`, `profile`)
5. Save.
6. **Applications -> Applications -> Create**:
   - **Name**: `oauth2-passkey-demo`
   - **Slug**: `oauth2-passkey-demo` (this forms the issuer URL)
   - **Provider**: the provider you just created
7. Save.

The issuer URL is `http://localhost:9000/application/o/{slug}/`.
Verify:

```bash
curl -s http://localhost:9000/application/o/oauth2-passkey-demo/.well-known/openid-configuration | jq .issuer
# -> "http://localhost:9000/application/o/oauth2-passkey-demo/"
```

### 3.3 Wire up oauth2-passkey

Add to your `.env`:

```dotenv
OAUTH2_CUSTOM3_CLIENT_ID=<from Authentik provider>
OAUTH2_CUSTOM3_CLIENT_SECRET=<from Authentik provider>
OAUTH2_CUSTOM3_ISSUER_URL=http://localhost:9000/application/o/oauth2-passkey-demo/
OAUTH2_CUSTOM3_DISPLAY_NAME=Authentik
OAUTH2_CUSTOM3_NAME=authentik
OAUTH2_CUSTOM3_BUTTON_COLOR='#fd4b2d'
OAUTH2_CUSTOM3_BUTTON_HOVER_COLOR='#e03d1f'
```

The trailing slash on `ISSUER_URL` must match what Authentik's discovery
document reports under `"issuer"`, or strict ID-token validation will
reject the response.

Restart the demo app. A **Continue with Authentik** button should appear.

### 3.4 Tear down

```bash
cd idp/authentik
docker compose down
docker compose down -v       # wipes Postgres + Redis volumes
```

---

## 4. Okta (Cloud, Developer Edition)

Okta is the one cloud-hosted IdP in this list — no Docker. Free
Developer tenant, well-behaved OIDC defaults, but **two layers of
policy** need to be configured, which is where most setup attempts
stall.

### 4.1 Create a Developer tenant

1. Sign up at `developer.okta.com`. Confirm the email.
2. Your admin URL is `https://<your-tenant>-admin.okta.com`.
   The public OIDC host (used for discovery / login redirects) is
   `https://<your-tenant>.okta.com`.

### 4.2 Create the OIDC application

Admin console -> **Applications -> Applications -> Create App Integration**.

- **Sign-in method**: `OIDC - OpenID Connect`
- **Application type**: `Web Application`
- **Grant type**: `Authorization Code` (default)
- **Sign-in redirect URIs**: exactly
  `http://localhost:3001/o2p/oauth2/okta/authorized` (adjust `ORIGIN`
  and `NAME` as needed)
- **Controlled access**: pick `Allow everyone in your organization` for
  fastest setup (can tighten later). If you skip assignment here, you
  must come back in 4.4.

Save. Copy **Client ID** and **Client Secret** from the detail page.

### 4.3 Record the issuer URL

Two authorization-server choices in Okta:

| Auth server                 | Issuer URL                                             |
|-----------------------------|--------------------------------------------------------|
| Custom Authorization Server | `https://<tenant>.okta.com/oauth2/default`             |
| Org Authorization Server    | `https://<tenant>.okta.com`                            |

Developer tenants default to the Custom Authorization Server (`default`).
Verify:

```bash
curl -s https://<tenant>.okta.com/oauth2/default/.well-known/openid-configuration | jq .issuer
# -> "https://<tenant>.okta.com/oauth2/default"
```

Use the exact string it returns (including / excluding trailing slash)
for `OAUTH2_CUSTOM{N}_ISSUER_URL` — the library does strict issuer
comparison on the returned ID token.

### 4.4 Assign users

Admin console -> **Applications -> [your app] -> Assignments** ->
**Assign**:

- **Assign to Groups -> Everyone** is simplest for a single-developer
  tenant.
- Or **Assign to People** to pick specific users.

Without this step the login returns **"You don't have access to this
app. Contact your administrator."** — note that *super admin accounts
appear to bypass this check* during normal navigation but NOT during
OAuth2 token grant, which can produce confusing "works in browser, fails
via OAuth2" symptoms. Always assign explicitly.

### 4.5 Loosen the application's authentication policy (if needed)

Admin console -> **Applications -> [your app] -> Sign On** tab -> the
**Authentication Policy** panel shows which policy is attached.

By default new apps get **"Any two factor types/IdPs"**, which requires
the user's *current session* to have completed two different factor
types. If only a password factor is on file, OAuth2 login fails
immediately with **"Policy evaluation failed"** even for admin accounts.

Three fixes, in order of practicality:

1. **Edit the attached policy's Catch-all rule**: go to **Security ->
   Authentication Policies**, click the attached policy, open the rule
   -> set **User must authenticate with** to `Password / IdP`.
2. **Enroll a second factor** on your user (Okta Verify is easiest) and
   log into Okta with it at least once before starting the OAuth2 flow.
3. Attach a different policy (e.g. one you create with a one-factor
   catch-all rule).

### 4.6 Add an Access Policy on the Authorization Server

This is the step most often missed. Custom Authorization Servers enforce
their own **Access Policies** independently of the application's Sign-On
policy. If no policy matches the client, Okta returns
`FAILURE: no_matching_policy` in System Log with a `400 access_denied`
response to the browser.

Admin console -> **Security -> API -> Authorization Servers -> default**
-> **Access Policies** tab:

1. If there is no policy: **Add New Access Policy**
   - Name: `Demo Access Policy`
   - **Assign to**: `The following clients` -> select your OIDC
     application (or `All clients`).
2. Open the policy -> **Add Rule**:
   - Rule Name: `Allow OIDC grants`
   - **IF Grant type is**: check `Authorization Code`.
   - **AND User is**: `Any user assigned the app`.
   - **AND Scopes requested**: `Any scopes`, or explicitly list `openid`,
     `email`, `profile`, `offline_access`.
3. Save.

### 4.7 Wire up oauth2-passkey

```dotenv
OAUTH2_CUSTOM5_CLIENT_ID=<Client ID from Okta>
OAUTH2_CUSTOM5_CLIENT_SECRET=<Client Secret from Okta>
OAUTH2_CUSTOM5_ISSUER_URL=https://<tenant>.okta.com/oauth2/default
OAUTH2_CUSTOM5_DISPLAY_NAME=Okta
OAUTH2_CUSTOM5_NAME=okta
OAUTH2_CUSTOM5_BUTTON_COLOR='#000000'
OAUTH2_CUSTOM5_BUTTON_HOVER_COLOR='#333333'
```

Restart the demo app; a **Continue with Okta** button should appear.

### 4.8 Debugging via System Log

When anything fails, **Reports -> System Log** is authoritative. Filter
by the application name or search for the failing timestamp. The key
rows to look at:

| Row                             | What it means                               |
|---------------------------------|---------------------------------------------|
| `User single sign on to app`    | App-level access (assignments + app policy) |
| `Evaluation of sign-on policy`  | Result of the application's Authentication Policy |
| `OAuth2 authorization request`  | Authorization Server's Access Policy evaluation |
| `OIDC access/id token is granted` | Final success signal |

If the `OAuth2 authorization request` row shows `FAILURE: no_matching_policy`
you are at step 4.6. If `Evaluation of sign-on policy` shows `DENY` you
are at step 4.5. If you see no entry at all for your app, the request
never reached Okta — check `redirect_uri` / `client_id` in the browser's
Network tab.

---

## 5. End-to-End Test Procedure

Once a stack is configured:

1. Start the demo app:
   ```bash
   cd demo-both
   cargo run
   ```
2. Open `http://localhost:3001/` in a browser.
3. Click **Continue with {display_name}**.
4. Authenticate at the IdP (for Zitadel: use the admin account you
   created; for Hydra: use the consent-node test credentials).
5. Grant consent when prompted.
6. You should be redirected back to the demo landing page as an
   authenticated user.
7. Verify the account was linked by checking the user row:
   ```bash
   # SQLite (default demo DB)
   sqlite3 demo-both/data/auth.db \
       "SELECT provider, provider_user_id, email FROM oauth2_accounts;"
   ```
   You should see a row with `provider` matching your
   `OAUTH2_CUSTOM{N}_NAME`.

### Regression checks

After verifying a Custom slot, sign out and confirm that:

- Google (and any other named providers you have configured) still
  work.
- The **Choose a provider** screen on `/o2p/oauth2/select` renders every
  enabled provider button, with distinct colors from each slot's
  `BUTTON_COLOR`.
- The admin user-detail page renders the correct display name and icon
  for the new provider (custom slots fall back to the generic `openid`
  icon).

---

## 6. Troubleshooting

### `validate_custom_slots` refuses to start

The init routine fails fast if:

- `OAUTH2_CUSTOM{N}_NAME` is invalid (must match
  `[a-z0-9_-]+`, so lowercase only, no slashes).
- Two enabled slots share the same `NAME`.
- A slot collides with a reserved route (`google`, `auth0`,
  `keycloak`, `entra`, `authorized`, `accounts`, `fedcm`,
  `popup_close`, `oauth2.js`, `select`).

Fix the offending env var and restart.

### Issuer mismatch

```
validation error: id_token issuer "http://localhost:8080" did not match
expected issuer "http://zitadel:8080"
```

The `iss` claim in the ID token must exactly match
`OAUTH2_CUSTOM{N}_ISSUER_URL`. For Zitadel, always use the external
URL you set via `ZITADEL_EXTERNALDOMAIN` + `ZITADEL_EXTERNALPORT`
(here, `http://localhost:8080`).

### JWKS fetch fails

The demo app calls `{ISSUER}/.well-known/openid-configuration` at
discovery time, then fetches `jwks_uri`. If that fails:

1. Confirm the IdP is reachable from *inside* the demo app container
   (not just the browser). If both run on the host, `localhost` works.
   If the demo runs in Docker, you need `host.docker.internal` or a
   shared network.
2. Inspect the discovery document:
   ```bash
   curl -s http://localhost:4444/.well-known/openid-configuration | jq
   ```

### Hydra returns `invalid_request: response_mode form_post not supported`

Set `OAUTH2_CUSTOM{N}_RESPONSE_MODE=query`. Hydra only supports `query`
and `fragment`.

### Zitadel login loops after consent

Usually caused by a stale session cookie for an earlier run. Clear
cookies for `localhost:8080` and try again. If the problem persists,
`docker compose down -v` on the `idp/zitadel` stack to reset state
fully.

### Zitadel signs the user in without prompting

After a first successful login, repeated clicks on **Continue with
Zitadel** redirect back to the demo without showing a password or
account-picker screen — Zitadel reuses the previous session silently.

This is Zitadel's SSO behavior working as specified: oauth2-passkey
sends `prompt=consent` (which is hardcoded across all providers in
`oauth2/provider.rs`), and per OIDC Core that only asks the IdP to
redisplay the *consent* screen — it does **not** force
re-authentication or account selection. v4's login-v2 service takes
this literally and skips straight to consent (often auto-granted),
while v2's V1 login historically tended to show an account picker
even with an active session, which is why the difference is
noticeable.

If the Zitadel console shares the browser with the demo, logging into
`/ui/console` creates a session that the OAuth2 flow will then reuse
on the next sign-in (we hit this with `zitadel-admin@zitadel.localhost`
during setup).

Workarounds while testing:

- Use a **private browsing window** for the demo and close it between
  runs
- Hit Zitadel's `end_session_endpoint`
  (`http://localhost:8080/oidc/v1/end_session`) to drop the Zitadel-side
  session
- Avoid logging into `/ui/console` with the same browser you use for
  the demo; create a separate test user and sign in only via the demo

A permanent fix would require making `prompt` configurable per slot
(e.g. `OAUTH2_CUSTOM{N}_PROMPT=login|select_account|consent|none`); this
is out of scope for the generic-OIDC slot work and should be tracked
as a separate issue if needed.

### JWKS stale after switching Zitadel v2 <-> v4

The two Zitadel stacks bind to the same port (`:8080`) and advertise
the same `jwks_uri`. oauth2-passkey caches JWKS in the configured
cache backend (Redis by default) for 10 minutes keyed by URL, so after
switching stacks the app still returns the previous instance's keys
and ID-token verification fails with:

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
