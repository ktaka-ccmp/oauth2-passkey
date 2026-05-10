# Ory Hydra Provider Setup

Ory Hydra runs through a Custom OIDC slot **without a preset** — Hydra is
not in the built-in preset list because it is typically deployed as a
custom self-hosted stack. Set the slot's display name, URL segment, and
brand colors explicitly.

Hydra is a headless OAuth2/OIDC server: it provides the protocol but
delegates login and consent UI to an external app. The bundled Docker stack
in `idp/ory-hydra/` runs the reference `hydra-login-consent-node` alongside
Hydra so the flow works out of the box for testing.

## Prerequisites

- Docker and Docker Compose
- A running oauth2-passkey application

## Step 1: Bring Up Hydra

A `docker-compose.yaml` is provided in `idp/ory-hydra/`:

```bash
cd idp/ory-hydra
docker compose up -d
docker compose logs -f hydra
```

`hydra-migrate` runs once to apply the SQL schema, then exits. `hydra`
starts serving after migration completes.

Services exposed:

| Service       | Purpose                              | Port (host)   |
|---------------|--------------------------------------|---------------|
| Hydra public  | `/oauth2/auth`, `/oauth2/token`, etc.| `4444`        |
| Hydra admin   | Client registration, introspection   | `4445`        |
| Consent node  | Login + consent UI                   | `3100`        |
| Postgres      | Hydra backend                        | (not exposed) |

Verify:

```bash
curl -s http://localhost:4444/.well-known/openid-configuration | jq .issuer
# -> "http://localhost:4444"
```

## Step 2: Register an OAuth2 Client

Hydra has no admin UI; clients are created via the admin API. The simplest
way is to `exec` into the Hydra container:

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

Two Hydra-specific requirements:

- **`--token-endpoint-auth-method client_secret_post`** is required:
  oauth2-passkey sends client credentials in the request body. Hydra's
  default (`client_secret_basic`) expects HTTP Basic and will fail token
  exchange with `401 Unauthorized`.
- **`--redirect-uri` must exactly match** what the library sends —
  `http://localhost:3001/o2p/oauth2/{NAME}/authorized` — or Hydra rejects
  the authorization request with `invalid_request`.

The response is JSON. Copy:

- `client_id` → `OAUTH2_CUSTOM{N}_CLIENT_ID`
- `client_secret` → `OAUTH2_CUSTOM{N}_CLIENT_SECRET` (Hydra shows this only
  at creation time)

## Step 3: Login / Consent App (demo-only fake claims)

The bundled consent container (`oryd/hydra-login-consent-node`) emits an ID
token with **only `sub`** by default. oauth2-passkey requires at least
`email` or `preferred_username` in the userinfo response, so the login
fails with:

```text
OIDC userinfo from 'hydra' is missing both `email` and `preferred_username` claims
```

For demo / testing, set `CONFORMITY_FAKE_CLAIMS=1` on the consent container
to emit fake `email=foo@bar.com` + `preferred_username=robot` claims
whenever the matching scope is granted. **Demo use only**; all users map to
the same synthetic account. The `idp/ory-hydra/docker-compose.yaml`
already sets this:

```yaml
consent:
  image: oryd/hydra-login-consent-node:v2.2.0
  environment:
    HYDRA_ADMIN_URL: http://hydra:4445
    CONFORMITY_FAKE_CLAIMS: "1"   # demo only
```

For real multi-user setups, fork the reference consent app and populate
`session.id_token` from your user store in the accept-consent call.

## Step 4: Configure Environment Variables

Add the following to your `.env` file. This example uses slot 1; any of
slots 1..8 works (each slot is independent).

```bash
OAUTH2_CUSTOM1_CLIENT_ID='<client-id-from-hydra>'
OAUTH2_CUSTOM1_CLIENT_SECRET='<client-secret-from-hydra>'
OAUTH2_CUSTOM1_ISSUER_URL='http://localhost:4444'
OAUTH2_CUSTOM1_DISPLAY_NAME='Ory Hydra'
OAUTH2_CUSTOM1_NAME='hydra'
OAUTH2_CUSTOM1_RESPONSE_MODE='query'
```

`OAUTH2_CUSTOM1_RESPONSE_MODE=query` is required: Hydra supports `query`
and `fragment` only, not `form_post`. The library's default `form_post`
fails with `invalid_request: response_mode form_post not supported`.

Optional overrides for the visual bits (no preset, so default colors apply
unless overridden):

```bash
#OAUTH2_CUSTOM1_BUTTON_COLOR='#5528ff'
#OAUTH2_CUSTOM1_BUTTON_HOVER_COLOR='#3d1bcc'
#OAUTH2_CUSTOM1_ICON_SLUG='openid'   # default neutral fallback
```

## Step 5: Verify

Start your application and navigate to the login page. An **Ory Hydra**
button should appear alongside Google.

After logging in (any credentials work with `CONFORMITY_FAKE_CLAIMS=1`),
verify the database row:

```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"

# SQLite
sqlite3 db/sqlite/data/data.db "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"
```

Expected output (with fake claims):

```
 provider |        provider_user_id        |     email
----------+--------------------------------+-------------
 hydra    | hydra_<sub-from-consent-app>   | foo@bar.com
```

## Notes

- The fake `profile` scope sets `picture` to a hardcoded GitHub raw URL
  that upstream has since moved — the link returns `404`, so the account
  avatar renders as a broken image. Cosmetic only; does not affect
  authentication.
- To stop Hydra: `docker compose down`. To wipe the Postgres volume:
  `docker compose down -v`.
- See [Generic OIDC Provider Setup](./generic-oidc.md) for the full Custom
  slot reference, including how to register a Custom slot without a preset.
