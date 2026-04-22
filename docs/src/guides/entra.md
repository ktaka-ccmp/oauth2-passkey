# Microsoft Entra ID Provider Setup

Microsoft Entra ID (formerly Azure AD) runs through a Custom OIDC slot with
`OAUTH2_CUSTOM{N}_PRESET=entra`. The preset supplies the display name
("Microsoft"), URL segment (`entra`), icon, brand colors, and — crucially —
the additional allowed origin `login.live.com` needed for personal
Microsoft accounts (which route credential entry through that host). Setting
the preset is equivalent to configuring a bespoke "Entra" provider; no code
change is required.

The examples below use slot 1. Any of slots 1..8 works.

## Which Setup to Choose

| Use case | Account type | Section |
|----------|--------------|---------|
| B2C consumer web app (anyone with a Microsoft account can sign up) | Personal Microsoft accounts | [Personal Account Setup](#personal-microsoft-account-setup-b2c) |
| B2B / internal tool (restrict to a specific organization) | Work/school accounts | [Work/School Account Setup](#workschool-account-setup-b2b) |

> **Not supported**: A single app registration serving both personal and
> work/school accounts (multi-tenant with `common` / `organizations` endpoints)
> is **not supported**. See [Notes](#notes).

## Prerequisites

- A Microsoft Azure account (free tier works)
- A running oauth2-passkey application

---

## Personal Microsoft Account Setup (B2C)

Use this path to let anyone with a personal Microsoft account
(`@outlook.com`, `@hotmail.com`, `@live.com`, etc.) sign up for your app.

> **Warning**: Anyone in the world with a Microsoft account will be able to
> register. Azure does not provide email or domain allowlisting for personal
> accounts because consumer accounts are not centrally managed. If you need
> to restrict access, see [Restricting Access](#restricting-access) below.

### Step 1: Register an Application

1. Go to the [Azure Portal](https://portal.azure.com/) and navigate to
   **Microsoft Entra ID → App registrations → New registration**
2. Set:
   - **Name**: `oauth2-passkey-demo-personal` (or any name)
   - **Supported account types**: **Personal Microsoft accounts only**
3. Leave **Redirect URI** blank for now
4. Click **Register**

After registration, note your **Application (client) ID** — this is
`OAUTH2_CUSTOM1_CLIENT_ID`.

### Step 2: Set the Redirect URI

1. On the app's overview page, click **Add a Redirect URI** (or go to
   **Authentication → Add a platform → Web**)
2. Enter: `http://localhost:3001/o2p/oauth2/entra/authorized`
3. Replace `http://localhost:3001` with your actual `ORIGIN`
4. Click **Configure**, then **Save**

### Step 3: Create a Client Secret

1. Navigate to **Certificates & secrets → Client secrets → New client secret**
2. Enter a **Description** and choose an **Expiry** period
3. Click **Add**
4. **Copy the secret value immediately** — it will not be shown again

This value is `OAUTH2_CUSTOM1_CLIENT_SECRET`.

### Step 4: Configure Environment Variables

Add the following to your `.env` file:

```bash
OAUTH2_CUSTOM1_PRESET=entra
OAUTH2_CUSTOM1_CLIENT_ID='your-application-client-id'
OAUTH2_CUSTOM1_CLIENT_SECRET='your-client-secret-value'
# Microsoft's fixed tenant ID for personal (consumer) accounts.
# This UUID is NOT your tenant — it's a well-known constant.
OAUTH2_CUSTOM1_ISSUER_URL='https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0'
```

The preset (`PRESET=entra`) fills in defaults for `DISPLAY_NAME`, `NAME`
(which becomes the `entra` URL segment), `ICON_SLUG`, button colors, and the
`login.live.com` additional allowed origin.

> **Why this specific UUID?** The `consumers` endpoint alias
> (`https://login.microsoftonline.com/consumers/v2.0`) returns a discovery
> document whose `issuer` field is the fixed UUID above. Because
> oauth2-passkey performs strict issuer validation, you must configure the
> UUID directly — using the `consumers` alias will fail with an issuer
> mismatch error.

Optional overrides (defaults shown):

```bash
# Default: 'form_post'
#OAUTH2_CUSTOM1_RESPONSE_MODE='form_post'

# Default: 'openid+email+profile'
#OAUTH2_CUSTOM1_SCOPE='openid+email+profile'
```

### Step 5: Verify

Start your application and navigate to the login page. A **Microsoft** button
should appear alongside Google and other configured providers.

After logging in with a personal Microsoft account, verify the database row:

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
 entra    | entra_00000000-0000-0000-0000-000000000000 | user@outlook.com
```

For personal accounts, the `email` column is populated from the
`preferred_username` claim because Microsoft does not issue a standard
`email` claim for consumer accounts.

### Restricting Access

Since Azure cannot restrict which personal Microsoft accounts can sign up,
access control is the application's responsibility. Two practical options:

1. **Application-layer email allowlist** — After oauth2-passkey creates the
   account, your handler/middleware checks the email against an allowlist
   and rejects unknown addresses.

2. **Admin approval flow** — oauth2-passkey's built-in behavior makes the
   first registered user an admin. Let new users register, then review them
   in your admin UI and delete unwanted accounts.

---

## Work/School Account Setup (B2B)

Use this path to restrict login to users within a specific organization's
Entra ID tenant.

### Step 1: Register an Application

1. Go to the [Azure Portal](https://portal.azure.com/) and navigate to
   **Microsoft Entra ID → App registrations → New registration**
2. Set:
   - **Name**: `oauth2-passkey-demo` (or any name)
   - **Supported account types**: **Accounts in this organizational directory
     only (Single tenant)**
3. Leave **Redirect URI** blank for now
4. Click **Register**

After registration, note your:
- **Application (client) ID** — this is `OAUTH2_CUSTOM1_CLIENT_ID`
- **Directory (tenant) ID** — used to build `OAUTH2_CUSTOM1_ISSUER_URL`

### Step 2: Set the Redirect URI

1. On the app's overview page, click **Add a Redirect URI** (or go to
   **Authentication → Add a platform → Web**)
2. Enter: `http://localhost:3001/o2p/oauth2/entra/authorized`
3. Replace `http://localhost:3001` with your actual `ORIGIN`
4. Click **Configure**, then **Save**

### Step 3: Create a Client Secret

1. Navigate to **Certificates & secrets → Client secrets → New client secret**
2. Enter a **Description** and choose an **Expiry** period
3. Click **Add**
4. **Copy the secret value immediately** — it will not be shown again

This value is `OAUTH2_CUSTOM1_CLIENT_SECRET`.

### Step 4: Enable the Email Claim

By default, Entra ID does not include the `email` claim in tokens for some
work/school accounts even when the `email` scope is requested. To ensure
email is always available:

1. Navigate to **Token configuration → Add optional claim**
2. Select **Token type: ID** and check **email**
3. Click **Add**

If `email` is still absent (e.g. the user has no email attribute set), the
library falls back to the `preferred_username` claim (typically the UPN).

### Step 5: Configure Environment Variables

Add the following to your `.env` file:

```bash
OAUTH2_CUSTOM1_PRESET=entra
OAUTH2_CUSTOM1_CLIENT_ID='your-application-client-id'
OAUTH2_CUSTOM1_CLIENT_SECRET='your-client-secret-value'
# IMPORTANT: Must end with /v2.0 — the v1 endpoint (without /v2.0) uses a
# different issuer format (sts.windows.net) that will cause issuer
# validation to fail.
OAUTH2_CUSTOM1_ISSUER_URL='https://login.microsoftonline.com/your-tenant-id/v2.0'
```

Optional overrides (defaults shown):

```bash
# Default: 'form_post'
#OAUTH2_CUSTOM1_RESPONSE_MODE='form_post'

# Default: 'openid+email+profile'
#OAUTH2_CUSTOM1_SCOPE='openid+email+profile'
```

### Step 6: Verify

Start your application and navigate to the login page. A **Microsoft** button
should appear alongside Google and other configured providers.

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

---

## Notes

- **Single-tenant only** (per app registration): The `OAUTH2_CUSTOM1_ISSUER_URL`
  must resolve to a specific tenant — either your organization's tenant
  (work/school) or Microsoft's fixed consumer tenant UUID (personal). Using
  `common` or `organizations` aliases will fail issuer validation because
  their discovery documents contain a `{tenantid}` placeholder.

- **Mixed (work + personal) not supported**: Supporting both account types
  with one app registration requires multi-tenant issuer validation, which
  is not implemented. The workaround is to register two separate
  applications (one personal, one work/school) — however, oauth2-passkey
  currently supports only one Entra provider instance per deployment.

- **Consent screen on every login**: A consent screen appears on every login
  because `prompt=consent` is included in the authorization request. This
  is expected behavior.

- **`provider_user_id` format**: `entra_{sub}` where `sub` is the Entra
  object ID (a UUID) of the user. This is stable across sessions and
  unique within the issuing tenant.

- **Client secret expiry**: Azure client secrets expire (max 24 months).
  Rotate the secret before expiry and update `OAUTH2_CUSTOM1_CLIENT_SECRET`
  in your environment.
