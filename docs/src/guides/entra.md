# Microsoft Entra ID Provider Setup

This guide walks through configuring Microsoft Entra ID (formerly Azure Active Directory)
as an OAuth2/OIDC provider for oauth2-passkey.

## Prerequisites

- A Microsoft Azure account with an active subscription (free tier works)
- A running oauth2-passkey application

> **Single-tenant only**: This guide covers single-tenant app registrations.
> Multi-tenant endpoints (`common`, `organizations`) are not supported because
> the discovery document returns a `{tenantid}` placeholder that fails the
> library's issuer validation.

## Step 1: Register an Application

1. Go to the [Azure Portal](https://portal.azure.com/) and navigate to
   **Microsoft Entra ID → App registrations → New registration**
2. Set:
   - **Name**: `oauth2-passkey-demo` (or any name)
   - **Supported account types**: **Accounts in this organizational directory only
     (Single tenant)**
3. Leave **Redirect URI** blank for now
4. Click **Register**

After registration, note your:
- **Application (client) ID** — this is `OAUTH2_ENTRA_CLIENT_ID`
- **Directory (tenant) ID** — used to build `OAUTH2_ENTRA_ISSUER_URL`

## Step 2: Set the Redirect URI

1. On the app's overview page, click **Add a Redirect URI** (or go to
   **Authentication → Add a platform → Web**)
2. Enter: `http://localhost:3001/o2p/oauth2/entra/authorized`
3. Replace `http://localhost:3001` with your actual `ORIGIN`
4. Click **Configure**, then **Save**

## Step 3: Create a Client Secret

1. Navigate to **Certificates & secrets → Client secrets → New client secret**
2. Enter a **Description** and choose an **Expiry** period
3. Click **Add**
4. **Copy the secret value immediately** — it will not be shown again

This value is `OAUTH2_ENTRA_CLIENT_SECRET`.

## Step 4: Enable the Email Claim (Work Accounts)

By default, Entra ID does not include the `email` claim in tokens for some
work/school accounts even when the `email` scope is requested. To ensure email
is always available:

1. Navigate to **Token configuration → Add optional claim**
2. Select **Token type: ID** and check **email**
3. Click **Add**

> **Personal Microsoft accounts**: For personal accounts (e.g. `@outlook.com`,
> `@hotmail.com`), the library automatically falls back to the `preferred_username`
> claim when `email` is absent. No extra configuration is needed, but
> `preferred_username` is used as the email value in the database.

## Step 5: Configure Environment Variables

Add the following to your `.env` file:

```bash
OAUTH2_ENTRA_CLIENT_ID='your-application-client-id'
OAUTH2_ENTRA_CLIENT_SECRET='your-client-secret-value'
# IMPORTANT: Must end with /v2.0 — the v1 endpoint (without /v2.0) uses a different
# issuer format (sts.windows.net) that will cause issuer validation to fail.
OAUTH2_ENTRA_ISSUER_URL='https://login.microsoftonline.com/your-tenant-id/v2.0'
```

Optional overrides (defaults shown):

```bash
# Default: 'form_post'
#OAUTH2_ENTRA_RESPONSE_MODE='form_post'

# Default: 'openid+email+profile'
#OAUTH2_ENTRA_SCOPE='openid+email+profile'
```

## Step 6: Verify

Start your application and navigate to the login page. A **Microsoft** button should
appear alongside Google and other configured providers.

After logging in, verify the database row:

```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"

# SQLite
sqlite3 db/sqlite/data/data.db "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"
```

Expected output:

```
 provider |             provider_user_id              |       email
----------+-------------------------------------------+--------------------
 entra    | entra_00000000-0000-0000-0000-000000000000 | user@example.com
```

> A consent screen will appear on every login because `prompt=consent` is
> included in the authorization request. This is expected behavior.

## Notes

- **Single-tenant only**: The `OAUTH2_ENTRA_ISSUER_URL` must contain a specific
  tenant ID (e.g. `https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/v2.0`).
  Using `common` or `organizations` as the tenant segment will cause issuer
  validation to fail.

- **Email claim fallback**: When the `email` claim is absent (e.g. personal
  Microsoft accounts), the library uses `preferred_username` as the email value.
  For work accounts, enable the `email` optional claim (Step 4) to ensure
  consistent behavior.

- **`provider_user_id` format**: `entra_{sub}` where `sub` is the Entra object ID
  (a UUID) of the user. This is stable across sessions and unique within your tenant.

- **Client secret expiry**: Azure client secrets expire (max 24 months). Rotate the
  secret before expiry and update `OAUTH2_ENTRA_CLIENT_SECRET` in your environment.
