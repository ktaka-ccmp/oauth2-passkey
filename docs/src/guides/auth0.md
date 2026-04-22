# Auth0 Provider Setup

Auth0 runs through a Custom OIDC slot with `OAUTH2_CUSTOM{N}_PRESET=auth0`
— the preset supplies the display name, URL segment (`auth0`), icon, and
brand colors. Setting the preset is equivalent to configuring a bespoke
"Auth0" provider; no code change is required.

## Prerequisites

- An Auth0 account ([auth0.com](https://auth0.com) — free tier is sufficient)
- A running oauth2-passkey application

## Step 1: Create an Application in Auth0

1. Log in to the [Auth0 Dashboard](https://manage.auth0.com/)
2. Navigate to **Applications → Applications**
3. Click **Create Application**
4. Enter a name (e.g. `oauth2-passkey-demo`)
5. Select **Regular Web Applications**
6. Click **Create**

## Step 2: Configure the Callback URL

1. In your new application, go to the **Settings** tab
2. Under **Application URIs**, add to **Allowed Callback URLs**:

```
https://your-domain.example.com/o2p/oauth2/auth0/authorized
```

Replace `https://your-domain.example.com` with your actual `ORIGIN` value.
For local development over HTTP, use `http://localhost:3001`. The URL
segment is `auth0` because that is the preset's default `provider_name`;
override it via `OAUTH2_CUSTOM{N}_NAME=...` if you need a different segment.

3. Click **Save Changes**

## Step 3: Get Your Credentials

From the **Settings** tab, copy:

- **Domain** → used to build the issuer URL (e.g. `your-tenant.auth0.com`)
- **Client ID**
- **Client Secret**

## Step 4: Configure Environment Variables

Add the following to your `.env` file. This example uses slot 1; any of
slots 1..8 works (each slot is independent).

```bash
OAUTH2_CUSTOM1_PRESET=auth0
OAUTH2_CUSTOM1_CLIENT_ID='your-client-id'
OAUTH2_CUSTOM1_CLIENT_SECRET='your-client-secret'
# Issuer URL: https://{your-tenant}.auth0.com  (no trailing slash)
OAUTH2_CUSTOM1_ISSUER_URL='https://your-tenant.auth0.com'
```

The preset (`PRESET=auth0`) fills in defaults for `DISPLAY_NAME`, `NAME`
(which becomes the `auth0` URL segment), `ICON_SLUG`, and button colors.

Optional overrides (defaults shown):

```bash
# Default: 'form_post'
#OAUTH2_CUSTOM1_RESPONSE_MODE='form_post'

# Default: 'openid+email+profile'
#OAUTH2_CUSTOM1_SCOPE='openid+email+profile'

# Override any preset field:
#OAUTH2_CUSTOM1_NAME='company-sso'
#OAUTH2_CUSTOM1_DISPLAY_NAME='Company SSO'
#OAUTH2_CUSTOM1_BUTTON_COLOR='#ff0000'
```

## Step 5: Verify

Start your application and navigate to the login page. An **Auth0** button
should appear alongside Google.

After logging in via Auth0, verify the database row:

```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"

# SQLite
sqlite3 db/sqlite/data/data.db "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"
```

Expected output:

```
 provider |          provider_user_id           |      email
----------+-------------------------------------+------------------
 auth0    | auth0_auth0|6abc...                 | user@example.com
```

## Notes

- The `provider_user_id` format is `auth0_{sub}` where `sub` is the Auth0 user identifier (e.g. `auth0|6abc123...` for database connections, `google-oauth2|123...` for social connections).
- Auth0 social connection logins (e.g. "Continue with Google" inside the Auth0 dialog) are stored as `provider="auth0"`, not `provider="google"`, because the token is issued by Auth0.
- `OAUTH2_CUSTOM{N}_RESPONSE_MODE=form_post` (the default) works on both HTTP localhost and HTTPS production.
- See [Generic OIDC Provider Setup](./generic-oidc.md) for the full Custom slot reference, including how presets and env-var overrides compose.
