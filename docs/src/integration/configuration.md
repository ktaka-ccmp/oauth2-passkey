# Chapter 5: Configuration

## Overview

The oauth2-passkey library uses environment variables for configuration. This approach provides flexibility for different deployment scenarios and keeps sensitive credentials out of source code.

Configuration is loaded at application startup. All variables can be set via:
- Environment variables directly
- A `.env` file in the project root (using the `dotenvy` crate)

## Required Variables

These variables must be set for the library to function.

### ORIGIN

The base URL of your application. This is used for:
- Constructing OAuth2 callback URLs
- Setting the WebAuthn Relying Party ID
- Validating request origins

```bash
ORIGIN='https://your-domain.example.com'
```

**Important**: No trailing slash.

### OAUTH2_GOOGLE_CLIENT_ID

Your Google OAuth2 client ID obtained from the Google Cloud Console.

```bash
OAUTH2_GOOGLE_CLIENT_ID='your-client-id.apps.googleusercontent.com'
```

### OAUTH2_GOOGLE_CLIENT_SECRET

Your Google OAuth2 client secret obtained from the Google Cloud Console.

```bash
OAUTH2_GOOGLE_CLIENT_SECRET='your-client-secret'
```

### OAUTH2_ISSUER_URL

The OIDC (OpenID Connect) issuer URL. The library uses OIDC Discovery to automatically fetch endpoint configurations from the `.well-known/openid-configuration` URL.

```bash
OAUTH2_ISSUER_URL='https://accounts.google.com'
```

For Google authentication, use `https://accounts.google.com`.

## Database Configuration

### GENERIC_DATA_STORE_TYPE

Specifies the database backend for persistent storage.

| Value | Description |
|-------|-------------|
| `sqlite` | SQLite database (development/testing) |
| `postgres` | PostgreSQL database (production) |

```bash
GENERIC_DATA_STORE_TYPE=postgres
```

### GENERIC_DATA_STORE_URL

Connection URL for the database.

**PostgreSQL format:**
```bash
GENERIC_DATA_STORE_URL='postgresql://user:password@host:port/database'
```

**SQLite formats:**
```bash
# File-based SQLite
GENERIC_DATA_STORE_URL='sqlite:/path/to/database.db'
GENERIC_DATA_STORE_URL='sqlite:./db/sqlite/data/data.db'

# In-memory SQLite (useful for testing)
GENERIC_DATA_STORE_URL='sqlite:file:memdb1?mode=memory&cache=shared'
GENERIC_DATA_STORE_URL=':memory:'
```

## Cache Configuration

### GENERIC_CACHE_STORE_TYPE

Specifies the cache backend for temporary data (sessions, challenges, CSRF tokens).

| Value | Description |
|-------|-------------|
| `memory` | In-memory cache (development/single instance) |
| `redis` | Redis cache (production/multi-instance) |

```bash
GENERIC_CACHE_STORE_TYPE=redis
```

### GENERIC_CACHE_STORE_URL

Connection URL for Redis (only required when using Redis cache).

```bash
GENERIC_CACHE_STORE_URL='redis://localhost:6379'
```

## Optional Variables

### Route Configuration

#### O2P_ROUTE_PREFIX

Main route prefix for all authentication endpoints.

- **Default**: `/o2p`
- **Endpoints affected**: OAuth2, passkey, login, logout, summary pages

```bash
O2P_ROUTE_PREFIX='/o2p'
```

#### O2P_DEFAULT_REDIRECT

Default redirect URL for authentication flows. Used when:
- Unauthenticated users access protected routes
- Authenticated users visit the login page
- After logout

- **Default**: `/`

```bash
O2P_DEFAULT_REDIRECT='/'
```

#### O2P_LOGIN_URL

URL path for the login page.

- **Default**: `/o2p/user/login`

```bash
O2P_LOGIN_URL='/o2p/user/login'
```

#### O2P_ACCOUNT_URL

URL path for the user account management page.

- **Default**: `/o2p/user/account`

```bash
O2P_ACCOUNT_URL='/o2p/user/account'
```

#### O2P_RESPOND_WITH_X_CSRF_TOKEN

Controls whether the `X-CSRF-Token` header is included in responses.

- **Default**: `true`
- **Values**: `true`, `false`

```bash
O2P_RESPOND_WITH_X_CSRF_TOKEN=false
```

### WebAuthn Configuration

#### WEBAUTHN_ADDITIONAL_ORIGINS

Additional origins allowed to use WebAuthn credentials (for multi-domain support).

```bash
WEBAUTHN_ADDITIONAL_ORIGINS='https://example.com'
```

**Important**: No trailing slash in URLs.

#### PASSKEY_RP_NAME

The Relying Party name displayed to users during passkey registration.

- **Default**: Same as ORIGIN

```bash
PASSKEY_RP_NAME='My Application'
```

#### PASSKEY_TIMEOUT

Client-side timeout (in seconds) sent to the authenticator.

- **Default**: `60`

```bash
PASSKEY_TIMEOUT=60
```

#### PASSKEY_CHALLENGE_TIMEOUT

Server-side timeout (in seconds) for challenge validity.

- **Default**: `60`

```bash
PASSKEY_CHALLENGE_TIMEOUT=60
```

#### PASSKEY_AUTHENTICATOR_ATTACHMENT

Specifies which type of authenticator to allow.

| Value | Description |
|-------|-------------|
| `platform` | Built-in authenticators (Touch ID, Face ID, Windows Hello, password managers) |
| `cross-platform` | Removable authenticators (YubiKey, security keys) |
| `None` | Allow any type |

- **Default**: `platform`

```bash
PASSKEY_AUTHENTICATOR_ATTACHMENT='platform'
```

#### PASSKEY_RESIDENT_KEY

Controls resident key (discoverable credential) requirement.

| Value | Description |
|-------|-------------|
| `required` | Credential must be discoverable |
| `preferred` | Prefer discoverable, but allow non-discoverable |
| `discouraged` | Prefer non-discoverable credentials |

- **Default**: `required`

```bash
PASSKEY_RESIDENT_KEY='required'
```

#### PASSKEY_REQUIRE_RESIDENT_KEY

Whether to require resident key support.

- **Default**: `true`
- **Values**: `true`, `false`

```bash
PASSKEY_REQUIRE_RESIDENT_KEY=true
```

#### PASSKEY_USER_VERIFICATION

User verification requirement during authentication.

| Value | Description |
|-------|-------------|
| `required` | Always require user verification (PIN, biometric) |
| `preferred` | Request verification if available |
| `discouraged` | Skip verification if possible |

- **Default**: `discouraged`

```bash
PASSKEY_USER_VERIFICATION='discouraged'
```

#### PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL

Controls user handle generation strategy.

| Value | Behavior |
|-------|----------|
| `true` | Generate unique user_handle per credential (allows multiple credentials per user per site) |
| `false` | Use single user_handle for all credentials for a user (limits to one credential per user per site) |

- **Default**: `true`

```bash
PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true
```

**Note**: Password managers typically allow only one credential per user identifier. Set to `true` if users need multiple passkeys.

### OAuth2 Advanced Configuration

#### OAUTH2_AUTH_URL

Override the authorization endpoint (normally discovered from issuer).

```bash
OAUTH2_AUTH_URL='https://accounts.google.com/o/oauth2/v2/auth'
```

#### OAUTH2_TOKEN_URL

Override the token endpoint (normally discovered from issuer).

```bash
OAUTH2_TOKEN_URL='https://oauth2.googleapis.com/token'
```

#### OAUTH2_SCOPE

OAuth2 scopes to request.

- **Default**: `openid+email+profile`

```bash
OAUTH2_SCOPE='openid+email+profile'
```

#### OAUTH2_RESPONSE_MODE

How the authorization response is returned.

| Value | Description |
|-------|-------------|
| `form_post` | Response via POST to callback (uses SameSite=None for CSRF cookies) |
| `query` | Response via query parameters (uses SameSite=Lax for CSRF cookies) |

- **Default**: `form_post`

```bash
OAUTH2_RESPONSE_MODE='form_post'
```

#### OAUTH2_RESPONSE_TYPE

OAuth2 response type.

- **Default**: `code`
- **Note**: Only the authorization code flow is supported.

```bash
OAUTH2_RESPONSE_TYPE='code'
```

### Cookie Configuration

#### OAUTH2_CSRF_COOKIE_NAME

Name of the CSRF protection cookie for OAuth2 flows.

- **Default**: `__Host-CsrfId`

```bash
OAUTH2_CSRF_COOKIE_NAME='__Host-CsrfId'
```

#### OAUTH2_CSRF_COOKIE_MAX_AGE

Maximum age (in seconds) for the CSRF cookie.

- **Default**: `60`

```bash
OAUTH2_CSRF_COOKIE_MAX_AGE=60
```

#### SESSION_COOKIE_NAME

Name of the session cookie.

- **Default**: `__Host-SessionId`

```bash
SESSION_COOKIE_NAME='__Host-SessionId'
```

#### SESSION_COOKIE_MAX_AGE

Maximum age (in seconds) for the session cookie.

- **Default**: `600`

```bash
SESSION_COOKIE_MAX_AGE=600
```

### User Field Mapping

These settings control how user fields are mapped between authentication providers and the internal user model.

#### OAUTH2_USER_ACCOUNT_FIELD

OAuth2 claim to use for User.account.

- **Default**: `email`

```bash
OAUTH2_USER_ACCOUNT_FIELD='email'
```

#### OAUTH2_USER_LABEL_FIELD

OAuth2 claim to use for User.label.

- **Default**: `name`

```bash
OAUTH2_USER_LABEL_FIELD='name'
```

#### PASSKEY_USER_ACCOUNT_FIELD

Passkey field to use for User.account.

- **Default**: `name`

```bash
PASSKEY_USER_ACCOUNT_FIELD='name'
```

#### PASSKEY_USER_LABEL_FIELD

Passkey field to use for User.label.

- **Default**: `display_name`

```bash
PASSKEY_USER_LABEL_FIELD='display_name'
```

### Security Configuration

#### AUTH_SERVER_SECRET

Secret key used for token signing.

- **Default**: `default_secret_key_change_in_production`

```bash
AUTH_SERVER_SECRET='your-secret-key-here'
```

**Warning**: Always change this value in production environments. Use a cryptographically secure random string.

### Database Table Configuration

#### DB_TABLE_PREFIX

Prefix for all database tables created by the library.

- **Default**: `o2p_`

```bash
DB_TABLE_PREFIX='o2p_'
```

#### DB_TABLE_USERS

Custom name for the users table.

- **Default**: `{prefix}users` (e.g., `o2p_users`)

```bash
DB_TABLE_USERS='o2p_users'
```

#### DB_TABLE_PASSKEY_CREDENTIALS

Custom name for the passkey credentials table.

- **Default**: `{prefix}passkey_credentials` (e.g., `o2p_passkey_credentials`)

```bash
DB_TABLE_PASSKEY_CREDENTIALS='o2p_passkey_credentials'
```

#### DB_TABLE_OAUTH2_ACCOUNTS

Custom name for the OAuth2 accounts table.

- **Default**: `{prefix}oauth2_accounts` (e.g., `o2p_oauth2_accounts`)

```bash
DB_TABLE_OAUTH2_ACCOUNTS='o2p_oauth2_accounts'
```

## Configuration Examples

### Development (SQLite + Memory)

Minimal configuration for local development:

```bash
# Required
ORIGIN='http://localhost:3000'
OAUTH2_GOOGLE_CLIENT_ID='your-dev-client-id.apps.googleusercontent.com'
OAUTH2_GOOGLE_CLIENT_SECRET='your-dev-client-secret'
OAUTH2_ISSUER_URL='https://accounts.google.com'

# Storage - lightweight options for development
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:./dev.db'
GENERIC_CACHE_STORE_TYPE=memory
```

For testing with in-memory storage:

```bash
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL=':memory:'
GENERIC_CACHE_STORE_TYPE=memory
```

### Production (PostgreSQL + Redis)

Recommended configuration for production deployments:

```bash
# Required
ORIGIN='https://your-domain.example.com'
OAUTH2_GOOGLE_CLIENT_ID='your-prod-client-id.apps.googleusercontent.com'
OAUTH2_GOOGLE_CLIENT_SECRET='your-prod-client-secret'
OAUTH2_ISSUER_URL='https://accounts.google.com'

# Production storage
GENERIC_DATA_STORE_TYPE=postgres
GENERIC_DATA_STORE_URL='postgresql://user:password@db-host:5432/production_db'
GENERIC_CACHE_STORE_TYPE=redis
GENERIC_CACHE_STORE_URL='redis://redis-host:6379'

# Security - CHANGE THIS!
AUTH_SERVER_SECRET='your-cryptographically-secure-random-string'

# Optional: Customize routes
O2P_ROUTE_PREFIX='/auth'

# Optional: Extend session duration (1 hour)
SESSION_COOKIE_MAX_AGE=3600
```

### Multi-Domain Setup

For applications serving multiple domains:

```bash
ORIGIN='https://primary-domain.example.com'
WEBAUTHN_ADDITIONAL_ORIGINS='https://secondary-domain.example.com'
```

### Custom Table Names

For integrating with existing database schemas:

```bash
DB_TABLE_PREFIX='myapp_auth_'
DB_TABLE_USERS='myapp_auth_users'
DB_TABLE_PASSKEY_CREDENTIALS='myapp_auth_passkeys'
DB_TABLE_OAUTH2_ACCOUNTS='myapp_auth_oauth2'
```
