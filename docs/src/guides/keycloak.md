# Keycloak Provider Setup

This guide walks through configuring Keycloak as an OAuth2/OIDC provider for oauth2-passkey.

## Prerequisites

- Docker and Docker Compose
- A running oauth2-passkey application

## Step 1: Start Keycloak

A `docker-compose.yaml` is provided in `idp/keycloak/`:

```bash
cd idp/keycloak
docker compose up -d
```

This starts Keycloak on port `8180` with data persisted in a named Docker volume.

Wait for startup to complete (takes ~15–30 seconds):

```bash
docker compose logs -f
```

Look for a line like:
```
Keycloak 26.x.x on JVM (powered by Quarkus ...) started in ...
```

The Admin Console is available at `http://localhost:8180` (credentials: `admin` / `admin`).

## Step 2: Create a Realm

1. Log in to the Admin Console at `http://localhost:8180`
2. Click the dropdown in the top-left (shows **Keycloak** by default)
3. Click **Create realm**
4. Enter a **Realm name** (e.g. `myrealm`)
5. Click **Create**

## Step 3: Create a Client

1. In your new realm, navigate to **Clients → Create client**
2. Set:
   - **Client type**: `OpenID Connect`
   - **Client ID**: `oauth2-passkey-demo` (or any name)
3. Click **Next**
4. Enable **Client authentication** (this makes it a confidential client)
5. Click **Next**, then **Save**

### Set the Redirect URI

On the client's **Settings** tab, under **Access settings**:

- **Valid redirect URIs**: `http://localhost:3001/o2p/oauth2/keycloak/authorized`

Replace `http://localhost:3001` with your actual `ORIGIN`.

Click **Save**.

### Copy the Client Secret

Go to the **Credentials** tab and copy the **Client secret**.

## Step 4: Create a Test User

1. Navigate to **Users → Create new user**
2. Enter a **Username** (e.g. `testuser`)
3. Set **Email** and **First/Last name** as desired
4. Click **Create**
5. Go to the **Credentials** tab → **Set password**
6. Enter a password, disable **Temporary**, click **Save**

## Step 5: Configure Environment Variables

Add the following to your `.env` file:

```bash
OAUTH2_KEYCLOAK_CLIENT_ID='oauth2-passkey-demo'
OAUTH2_KEYCLOAK_CLIENT_SECRET='your-client-secret'
# Issuer URL: http(s)://{host}/realms/{realm-name}  (no trailing slash)
OAUTH2_KEYCLOAK_ISSUER_URL='http://localhost:8180/realms/myrealm'
```

Optional overrides (defaults shown):

```bash
# Default: 'form_post'
#OAUTH2_KEYCLOAK_RESPONSE_MODE='form_post'

# Default: 'openid+email+profile'
#OAUTH2_KEYCLOAK_SCOPE='openid+email+profile'
```

## Step 6: Verify

Start your application and navigate to the login page. A **Keycloak** button should appear alongside Google and Auth0.

After logging in, verify the database row:

```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"

# SQLite
sqlite3 db/sqlite/data/data.db "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"
```

Expected output:

```
 provider |               provider_user_id                |      email
----------+-----------------------------------------------+------------------
 keycloak | keycloak_17fc7f79-be73-4562-b72c-69e511a76c75 | test@example.com
```

## Notes

- The `provider_user_id` format is `keycloak_{sub}` where `sub` is the Keycloak user UUID.
- The issuer URL must include the realm name and must not have a trailing slash: `http://localhost:8180/realms/myrealm`.
- `OAUTH2_KEYCLOAK_RESPONSE_MODE=form_post` (the default) works on both HTTP localhost and HTTPS production.
- To stop Keycloak while preserving data: `docker compose stop`. To remove the container but keep data: `docker compose down`. To remove everything including data: `docker compose down -v`.
