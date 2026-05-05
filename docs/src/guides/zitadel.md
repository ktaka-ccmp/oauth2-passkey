# Zitadel Provider Setup

Zitadel runs through a Custom OIDC slot with `OAUTH2_CUSTOM{N}_PRESET=zitadel`
— the preset supplies the display name, URL segment (`zitadel`), icon, and
brand colors. Setting the preset is equivalent to configuring a bespoke
"Zitadel" provider; no code change is required.

Zitadel is a full-featured OIDC/OAuth2 identity platform. It provisions a
PostgreSQL backend on first boot, runs initial migrations, and starts the
server on `:8080`.

## Prerequisites

- Docker and Docker Compose
- A running oauth2-passkey application

## Step 1: Bring Up Zitadel

A `docker-compose.yaml` is provided in `idp/zitadel/` (v2.71.x, embedded V1
login) and `idp/zitadel-v4/` (v4.x, separate `zitadel-login` Next.js
service). The two stacks are mutually exclusive — both bind to `:8080`.

```bash
cd idp/zitadel
docker compose up -d
docker compose logs -f zitadel   # wait for "server is listening on [::]:8080"
```

First start takes ~30-60 seconds (init + setup + start). Subsequent boots
are near-instant.

Open `http://localhost:8080/ui/console` to access the admin console.

> **Why v2.71.x and not `latest`?** Zitadel v3+ redirects `/ui/console` to
> the separate `zitadel-login` Next.js service, which is not bundled with
> the main container. v2.71.x still ships the embedded V1 login UI and
> works standalone. Use the v4 stack to test the multi-service setup.
> See [`idp/README.md`](../../../idp/README.md) for stack details.

## Step 2: Register an Application

1. Log into the Zitadel console (default IAM owner credentials are
   `zitadel-admin@zitadel.localhost` / `Password1!` — Zitadel prompts a
   password reset on first login). The actual password is also printed in
   the container logs:
   ```bash
   docker compose logs zitadel | grep -A2 "IAM Owner"
   ```
2. Open the **Default** project (or create one) → **New** → **Application**.
3. Choose **Web**.
4. **Authentication Method**: pick **`CODE`** — this is what issues a
   client secret. Do **not** pick `PKCE`: PKCE makes Zitadel treat the app
   as a public client with no secret, which oauth2-passkey does not use.
   If you picked `PKCE` by accident, open the app, switch
   **Authentication Method** to `CODE`, save, then regenerate a secret
   from the **Client Secret** section.
5. Set **Redirect URI**:
   `http://localhost:3001/o2p/oauth2/zitadel/authorized`
6. Finish the wizard and copy the **Client ID** and **Client Secret**.
   The secret is shown **once only** — if you miss it, regenerate it from
   the app's detail page → **Client Secret** section.

## Step 3: Configure Environment Variables

Add the following to your `.env` file. This example uses slot 1; any of
slots 1..8 works (each slot is independent).

```bash
OAUTH2_CUSTOM1_PRESET=zitadel
OAUTH2_CUSTOM1_CLIENT_ID='<client-id-from-zitadel>'
OAUTH2_CUSTOM1_CLIENT_SECRET='<client-secret-from-zitadel>'
OAUTH2_CUSTOM1_ISSUER_URL='http://localhost:8080'
OAUTH2_CUSTOM1_RESPONSE_MODE='query'
```

The preset (`PRESET=zitadel`) fills in defaults for `DISPLAY_NAME`, `NAME`
(which becomes the `zitadel` URL segment), `ICON_SLUG`, and button colors.

> **`RESPONSE_MODE=query` for Zitadel v4**: v4's separate `zitadel-login`
> Next.js service silently downgrades `response_mode=form_post` to a query
> redirect, which oauth2-passkey then rejects. Set
> `OAUTH2_CUSTOM1_RESPONSE_MODE=query` for v4. v2 (embedded V1 login,
> `v2.71.x`) handles `form_post` natively and the line can be omitted —
> but setting it explicitly is harmless and keeps the env file portable
> across versions. See the
> [Zitadel form_post troubleshooting entry](./generic-oidc.md#zitadel-returns-invalid-response-mode-get-is-not-allowed-for-form_post)
> for the upstream root cause.

Optional overrides (defaults shown):

```bash
# Default: 'openid+email+profile'
#OAUTH2_CUSTOM1_SCOPE='openid+email+profile'

# Override any preset field:
#OAUTH2_CUSTOM1_NAME='zitadel-prod'
#OAUTH2_CUSTOM1_DISPLAY_NAME='Zitadel Production'
```

## Step 4: Verify

Start your application and navigate to the login page. A **Zitadel** button
should appear alongside Google.

After logging in via Zitadel, verify the database row:

```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"

# SQLite
sqlite3 db/sqlite/data/data.db "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"
```

Expected output:

```
 provider |              provider_user_id              |      email
----------+--------------------------------------------+------------------
 zitadel  | zitadel_322481474651946242                 | user@example.com
```

## Notes

- The `provider_user_id` format is `zitadel_{sub}` where `sub` is the
  Zitadel user identifier.
- `email` is absent from the ID token; oauth2-passkey reads it from the
  `/userinfo` endpoint.
- Zitadel v2 vs v4 share the same `:8080` port and `jwks_uri`. If you
  switch versions on the same host, see
  [JWKS stale after switching IdP versions](./generic-oidc.md#jwks-stale-after-switching-idp-versions-on-the-same-host).
- If sign-in skips the password / account-picker screen on subsequent
  logins (Zitadel's SSO behavior), see
  [IdP signs the user in without prompting](./generic-oidc.md#idp-signs-the-user-in-without-prompting).
- See [Generic OIDC Provider Setup](./generic-oidc.md) for the full Custom
  slot reference, including how presets and env-var overrides compose.
