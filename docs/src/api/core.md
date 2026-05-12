# Core Library API (oauth2-passkey)

## Overview

The `oauth2-passkey` crate provides the core authentication functionality for OAuth2 and WebAuthn/Passkey authentication. It is framework-agnostic and can be used directly or through integration crates like `oauth2-passkey-axum`.

**Full API Documentation**: [https://docs.rs/oauth2-passkey](https://docs.rs/oauth2-passkey)

## Main Modules

### coordination

Authentication flow orchestration module. Provides high-level functions that coordinate between different authentication mechanisms (OAuth2, Passkey) and user management.

**Submodules**:
- `admin` - Admin-specific operations (user management, credential administration)
- `oauth2` - OAuth2 authentication flow coordination
- `passkey` - WebAuthn/Passkey authentication flow coordination
- `user` - User account management operations

### oauth2

OAuth2 authentication module supporting Google OAuth2/OpenID Connect. Handles the authentication flow, token validation, and user profile retrieval.

### passkey

WebAuthn/Passkey authentication implementation. Provides capabilities for creating and using passkeys for authentication, following W3C WebAuthn Level 3 specification and FIDO2 standards.

### session

Session management components for authentication and user state persistence. Implements secure session cookies with CSRF protection.

### storage

Database and cache abstraction layer. Supports:
- **Databases**: SQLite, PostgreSQL
- **Caches**: In-memory, Redis

### userdb

User account management module for storing, retrieving, updating, and deleting user accounts.

## Initialization

```rust,ignore
use oauth2_passkey::init;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize authentication (reads configuration from environment variables)
    init().await?;
    Ok(())
}
```

## Key Functions

### Coordination Functions

#### Passkey Authentication
- `handle_start_registration_core` - Start passkey registration flow
- `handle_finish_registration_core` - Complete passkey registration
- `handle_start_authentication_core` - Start passkey authentication flow
- `handle_finish_authentication_core` - Complete passkey authentication
- `list_credentials_core` - List user's passkey credentials
- `update_passkey_credential_core` - Update credential name/display name
- `delete_passkey_credential_core` - Delete a passkey credential

#### OAuth2 Authentication
- `prepare_oauth2_auth_request` - Prepare OAuth2 authorization request
- `get_authorized_core` - Handle OAuth2 callback (GET)
- `post_authorized_core` - Handle OAuth2 callback (POST)
- `list_accounts_core` - List user's OAuth2 accounts
- `delete_oauth2_account_core` - Delete an OAuth2 account link

#### User Management
- `get_user` - Get a specific user by ID
- `get_all_users` - Get all users (admin)
- `update_user_account` - Update user account details
- `delete_user_account` - Delete user account
- `update_user_admin_status` - Update user's admin status

#### Admin Functions
- `delete_user_account_admin` - Admin: delete any user account
- `delete_oauth2_account_admin` - Admin: delete any OAuth2 account
- `delete_passkey_credential_admin` - Admin: delete any passkey credential

### Session Functions

#### Authentication Verification
- `is_authenticated_basic` - Basic session validation
- `is_authenticated_basic_then_csrf` - Basic validation + CSRF check
- `is_authenticated_basic_then_user_and_csrf` - Basic validation + user extraction + CSRF
- `is_authenticated_strict` - Strict session validation
- `is_authenticated_strict_then_csrf` - Strict validation + CSRF check

#### Session Data Access
- `get_user_from_session` - Extract user from session
- `get_csrf_token_from_session` - Get CSRF token from session
- `get_user_and_csrf_token_from_session` - Get both user and CSRF token

#### Session Management
- `prepare_logout_response` - Create logout response with cleared session

#### Page Session Tokens
- `generate_page_session_token` - Generate token for sensitive operations
- `verify_page_session_token` - Verify page session token

### Passkey Functions

- `get_authenticator_info` - Get info about a single authenticator by AAGUID
- `get_authenticator_info_batch` - Get info for multiple authenticators
- `get_related_origin_json` - Get WebAuthn related origins configuration

## Key Types

### User Identification

| Type | Description |
|------|-------------|
| `UserId` | Unique user identifier (newtype wrapper) |
| `SessionId` | Session identifier |
| `SessionCookie` | Typed session cookie value |
| `SessionUser` (alias: `User`) | User information stored in session |
| `DbUser` | User as stored in database |

### Session Types

| Type | Description |
|------|-------------|
| `CsrfToken` | CSRF protection token |
| `CsrfHeaderVerified` | Marker indicating CSRF was verified via header |
| `AuthenticationStatus` | Whether user is authenticated |
| `SessionError` | Session-related errors |

### OAuth2 Types

| Type | Description |
|------|-------------|
| `OAuth2Account` | OAuth2 account linked to a user |
| `AuthResponse` | OAuth2 authorization response |
| `OAuth2Mode` | Authentication mode (Login, Register, Link) |
| `OAuth2State` | OAuth2 state parameter |
| `Provider` | OAuth2 provider identifier |
| `ProviderUserId` | User ID from OAuth2 provider |

### Passkey Types

| Type | Description |
|------|-------------|
| `PasskeyCredential` | Stored passkey credential |
| `CredentialId` | Unique credential identifier |
| `ChallengeId` | WebAuthn challenge identifier |
| `ChallengeType` | Type of WebAuthn challenge |
| `AuthenticationOptions` | Options for authentication ceremony |
| `RegistrationOptions` | Options for registration ceremony |
| `AuthenticatorResponse` | Response from authenticator |
| `RegisterCredential` | Credential data for registration |
| `AuthenticatorInfo` | Information about an authenticator device |
| `RegistrationStartRequest` | Request to start passkey registration |

### Error Types

| Type | Description |
|------|-------------|
| `CoordinationError` | Errors from coordination layer |
| `SessionError` | Session management errors |

## Constants

| Constant | Description |
|----------|-------------|
| `O2P_ROUTE_PREFIX` | Route prefix for auth endpoints (default: `/o2p`) |
| `SESSION_COOKIE_NAME` | Name of the session cookie |

## Environment Variables

### Required

- `ORIGIN` - Base URL of your application (e.g., `https://example.com`)

### Storage Configuration

- `GENERIC_DATA_STORE_TYPE` - Database type: `sqlite` or `postgres`
- `GENERIC_DATA_STORE_URL` - Database connection string
- `GENERIC_CACHE_STORE_TYPE` - Cache type: `memory` or `redis`
- `GENERIC_CACHE_STORE_URL` - Cache connection string (for Redis)

### OAuth2 Configuration

- `OAUTH2_GOOGLE_CLIENT_ID` - Google OAuth2 client ID
- `OAUTH2_GOOGLE_CLIENT_SECRET` - Google OAuth2 client secret

See `dot.env.example` in the repository for complete configuration options.
