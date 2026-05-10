# Authentik Provider Setup

Authentik runs through a Custom OIDC slot with `OAUTH2_CUSTOM{N}_PRESET=authentik`
— the preset supplies the display name, URL segment (`authentik`), icon,
and brand colors. Setting the preset is equivalent to configuring a bespoke
"Authentik" provider; no code change is required.

Authentik is a full-featured self-hosted IdP (admin UI, flows, policies)
similar in scope to Keycloak or Zitadel, but with sensible OIDC defaults —
no response-mode downgrade, no token-endpoint-auth-method mismatch, no
fake-claim workarounds.

## Prerequisites

- Docker and Docker Compose
- A running oauth2-passkey application

## Step 1: Bring Up Authentik

A `docker-compose.yaml` is provided in `idp/authentik/`:

```bash
cd idp/authentik
cp .env.example .env

# Generate AUTHENTIK_SECRET_KEY and set AUTHENTIK_BOOTSTRAP_PASSWORD:
openssl rand -base64 60 | tr -d '\n'
$EDITOR .env

docker compose up -d
docker compose logs -f server
```

Wait until the server log shows `Starting main process`. First boot runs
migrations and creates the default admin user.

Services exposed on host:

| Service           | Port  |
|-------------------|-------|
| HTTP (admin UI + OIDC endpoints) | `9000` |
| HTTPS (self-signed)              | `9443` |
| Postgres / Redis                 | not exposed |

Health check:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:9000/-/health/live/
# -> 204
```

## Step 2: Create the OAuth2/OIDC Provider

1. Open `http://localhost:9000/if/flow/initial-setup/` and log in as
   `akadmin` (or the email from `AUTHENTIK_BOOTSTRAP_EMAIL`) with the
   password from `.env`.
2. Admin interface → **Applications → Providers → Create →
   OAuth2/OpenID Provider**. Key fields:
   - **Name**: `oauth2-passkey-demo`
   - **Authorization flow**:
     `default-provider-authorization-explicit-consent` (or
     `-implicit-consent` to skip the consent screen while testing)
   - **Client type**: `Confidential`
   - **Client ID** / **Client Secret**: leave auto-generated; copy them
     out for Step 3
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

The issuer URL is `http://localhost:9000/application/o/{slug}/`. Verify:

```bash
curl -s http://localhost:9000/application/o/oauth2-passkey-demo/.well-known/openid-configuration | jq .issuer
# -> "http://localhost:9000/application/o/oauth2-passkey-demo/"
```

## Step 3: Configure Environment Variables

Add the following to your `.env` file. This example uses slot 1; any of
slots 1..8 works (each slot is independent).

```bash
OAUTH2_CUSTOM1_PRESET=authentik
OAUTH2_CUSTOM1_CLIENT_ID='<from Authentik provider>'
OAUTH2_CUSTOM1_CLIENT_SECRET='<from Authentik provider>'
OAUTH2_CUSTOM1_ISSUER_URL='http://localhost:9000/application/o/oauth2-passkey-demo/'
```

The preset (`PRESET=authentik`) fills in defaults for `DISPLAY_NAME`,
`NAME` (which becomes the `authentik` URL segment), `ICON_SLUG`, and
button colors.

The **trailing slash** on `ISSUER_URL` must match exactly what Authentik's
discovery document reports under `"issuer"`, or strict ID-token validation
will reject the response.

Optional overrides (defaults shown):

```bash
# Default: 'form_post'
#OAUTH2_CUSTOM1_RESPONSE_MODE='form_post'

# Default: 'openid+email+profile'
#OAUTH2_CUSTOM1_SCOPE='openid+email+profile'
```

## Step 4: Verify

Start your application and navigate to the login page. An **Authentik**
button should appear alongside Google.

After logging in via Authentik, verify the database row:

```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"

# SQLite
sqlite3 db/sqlite/data/data.db "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"
```

Expected output:

```
 provider  |              provider_user_id              |      email
-----------+--------------------------------------------+------------------
 authentik | authentik_<sub-from-authentik>             | user@example.com
```

## Notes

- The `provider_user_id` format is `authentik_{sub}` where `sub` is the
  Authentik user identifier.
- To stop Authentik: `docker compose down`. To wipe Postgres + Redis
  volumes: `docker compose down -v`.
- See [Generic OIDC Provider Setup](./generic-oidc.md) for the full Custom
  slot reference, including how presets and env-var overrides compose.
