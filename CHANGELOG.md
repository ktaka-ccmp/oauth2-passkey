# Changelog

All notable changes to oauth2-passkey will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-02-16

### Added

- Login history tracking for users and administrators
  - `GET /o2p/admin/audit` - Cross-user audit page with date filtering
  - `GET /o2p/admin/user/{user_id}/login_history` - Per-user login history
  - Records IP address, user agent, authentication method, and credential details
  - Failed passkey authentication attempts also recorded for security monitoring
- Passkey promotion: prompt users to register a passkey after OAuth2 login
  - `O2P_PASSKEY_PROMOTION` env var with `ask` (confirmation modal) and `force` (always prompt) modes
  - UA + AAGUID heuristic detects whether the user's platform authenticator is likely available
  - Popup-based registration flow integrated with OAuth2 login redirect
- Admin safeguards to prevent admin lockout
  - Prevent deleting or demoting the last admin user
  - First-user (seq=1) demotion guard
  - Self-deletion protection for admin accounts
- `O2P_DEMO_MODE` for public demo deployments
  - All new users automatically receive admin privileges
  - Admin pages mask other users' sensitive data (email, name, IDs, IP addresses)
  - Placeholder user occupies seq=1 so no real user gets first-user admin treatment
  - `O2P_LOGIN_URL` env var redirects unauthenticated users to a custom login page
- Admin Force Logout feature: administrators can terminate all active sessions for a user
  - Session status indicator in Admin Panel user list
  - "Active Sessions" count and "Force Logout" button in user detail page
  - New API endpoints: `GET /o2p/admin/sessions`, `POST /o2p/admin/user/{user_id}/logout`
  - New coordination functions: `get_all_active_sessions()`, `force_logout_user()`
- `SESSION_CONFLICT_POLICY` env var (`allow`/`replace`/`reject`) to control login behavior when a user already has active sessions
- User-to-session reverse index (`user_sessions` cache mapping) with lazy cleanup of stale entries
- `PASSKEY_SIGNAL_API_MODE` env var to control WebAuthn Signal API behavior (`direct`/`sync`/`direct+sync`)
  - `direct` (default): Uses `signalUnknownCredential` only - the only working API with Google Password Manager
  - `sync`: Uses `signalAllAcceptedCredentials` only - currently no effect on Chrome
  - `direct+sync`: Uses both APIs for future compatibility testing
- `SESSION_COOKIE_DOMAIN` env var for cross-origin session cookie support with CORS
- `bundled-tls` feature flag to bundle Mozilla root certificates via `webpki-roots` for minimal container deployments (scratch/alpine Docker images without system `ca-certificates`)
- Built-in CSS theme system with 9 pre-built themes: Zinc, Slate, Blue, Violet, Rose, Neumorphism, Material, Eco, SaaS
- `O2P_CUSTOM_CSS_URL` environment variable for custom CSS theme loading
- Theme CSS files served at `{O2P_ROUTE_PREFIX}/themes/` (e.g., `/o2p/themes/theme-zinc.css`)
- `oauth2_passkey_full_router()` unified router that automatically includes `/.well-known/webauthn` when multi-origin is configured
- `admin-ui` and `user-ui` feature flags for selectively disabling built-in UI components
- Admin page customization support for framework integrations
- Responsive mobile layout for admin user list
- Public re-exports of types needed for custom page implementations (`AuthUser`, template types)
- `rp_id` field in `PasskeyCredential` to store and display the Relying Party ID used during registration
- `getClientCapabilities()` JavaScript helper for WebAuthn feature detection

### Fixed

- JWKS cache deadlock with in-memory backend: `tokio::sync::Mutex` guard held across `if let` body caused re-acquisition to deadlock after 600s TTL expiry. Refactored to scope each lock independently.
- SQLite in-memory database tables disappearing after ~30 minutes of low traffic. Root cause: connection pool eviction destroyed the in-memory database. Fixed with `min_connections(1)`, `idle_timeout(None)`, `max_lifetime(None)`.
- `credential_id` not recorded on successful passkey login, causing login history entries to lack credential details
- OAuth2 popup errors now redirect to styled close page instead of showing raw error text
- ALPN protocol negotiation added to `bundled-tls` rustls configuration for proper TLS handshake
- WebAuthn Signal API calls changed to fire-and-forget to avoid blocking the authentication response
- `remaining_credential_ids` now filtered by `user_handle` for correct credential exclusion during registration
- TPM attestation verification failure with Windows Hello due to unsupported RS1 algorithm (`-65535`). Fixed by using proper `i128`-based conversion and adding RS1 signature verification.

### Changed

- **BREAKING**: Changed `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` default from `true` to `false`
  - New behavior: All credentials for the same user share a single `user_handle` (standard WebAuthn practice)
  - Old behavior: Each credential had a unique `user_handle`
  - Existing credentials are not affected; only newly registered credentials use the new default
- **BREAKING**: Renamed `O2P_REDIRECT_ANON` to `O2P_DEFAULT_REDIRECT` for clarity (env var, config, and template variable)
- **BREAKING**: Admin route renamed from `/admin/list_users` to `/admin/index` for clarity
- **BREAKING**: User account page renamed from `/user/summary` to `/user/account` for accuracy
  - Route: `/summary` -> `/account`
  - Env var: `O2P_SUMMARY_URL` -> `O2P_ACCOUNT_URL`
  - Handler: `summary()` -> `user_account()`
  - Template: `summary.j2` -> `user_account.j2`
  - Static files: `summary.js` -> `account.js`, `summary.css` -> `account.css`
- Signal API calls now conditionally execute based on `PASSKEY_SIGNAL_API_MODE` setting
- Passkey registration username prefill changed from `#N` sequential numbering to `@YYYYMMDD` date suffix
- `LoginContext` extraction moved from axum handlers into core crate for framework-agnostic login recording
- Admin page title changed from "User List" to "User Management"
- Admin link text in account page changed from "User List" to "Admin"

### Removed

- `signalCurrentUserDetails` removed from passkey login flow (not functional in current browsers)

## [0.2.0] - 2026-01-22

### Security

- **CRITICAL FIX**: Fixed passkey registration vulnerability where users were created before challenge validation, preventing orphaned user records on validation failures
- **BREAKING**: Enhanced admin function security by requiring session ID validation with fresh database lookups instead of trusting session data, preventing privilege escalation attacks
- **BREAKING**: Implemented comprehensive type-safe validation system to eliminate ID confusion vulnerabilities and parameter mixing attacks at compile-time
- **Error Handling**: Eliminated all `unwrap()` and `expect()` calls from production code, replacing them with proper error handling and HTTP status codes

### Changed

- **OIDC Discovery**: Automatic endpoint discovery from `/.well-known/openid-configuration`
- **OAuth2 endpoint configuration**: Replaced hardcoded Google URLs with dynamic discovery
- **Passkey Registration**: Refactored to validate challenges before user creation, eliminating double validation and optimizing cleanup timing
- **BREAKING**: `SessionUser.sequence_number` field changed from `i64` to `Option<i64>` for database consistency
- **Database**: Enhanced SQLite connection with WAL journaling, memory temp storage, and optimized pragmas for better performance
- **Template Safety**: Improved Jinja2 templates to use defensive pattern matching instead of `unwrap()` calls, preventing runtime panics

### Breaking Changes

- **Type-Safe Validation System**: Comprehensive implementation of compile-time type safety for all authentication operations:
  - **New Type Wrappers**: Added type-safe wrappers for all identifier types with validation (constructors now return `Result<T, Error>`):
    - `UserId` - Database user identifiers (already existed, now consistently used)
    - `CredentialId` - Passkey credential identifiers (already existed, now consistently used)
    - `Provider` - OAuth2 provider names (e.g., "google", "github")
    - `ProviderUserId` - External provider user identifiers
    - `AccountId` - OAuth2 account identifiers
    - `UserHandle` - WebAuthn user handles
    - `UserName` - Username identifiers
    - `DisplayName` - User display names
    - `Email` - Email addresses
    - `SessionCookie` - Session cookie identifiers
    - `OAuth2State` - OAuth2 state parameters
    - `ChallengeType` - WebAuthn challenge types
    - `ChallengeId` - WebAuthn challenge identifiers
  - **Core Function Signature Changes**: All core coordination functions now require typed parameters:
    - `delete_oauth2_account_core(UserId, Provider, ProviderUserId)` - was `delete_oauth2_account_core(user_id: &str, provider: &str, provider_user_id: &str)`
    - `list_accounts_core(UserId)` - was `list_accounts_core(user_id: &str)`
    - `delete_passkey_credential_core(UserId, CredentialId)` - was `delete_passkey_credential_core(user_id: &str, credential_id: &str)`
    - `list_credentials_core(UserId)` - was `list_credentials_core(user_id: &str)`
    - `update_passkey_credential_core(CredentialId, ...)` - was `update_passkey_credential_core(credential_id: &str, ...)`
  - **Session Management Functions**: All session functions now require typed session cookie parameter:
    - `get_user_from_session(&SessionCookie)` - was `get_user_from_session(session_cookie: &str)`
    - `get_csrf_token_from_session(&SessionCookie)` - was `get_csrf_token_from_session(session_cookie: &str)`
    - `get_user_and_csrf_token_from_session(&SessionCookie)` - was `get_user_and_csrf_token_from_session(session_cookie: &str)`
  - **Search Field Enums**: All database search operations now use typed search fields:
    - `CredentialSearchField::UserId(UserId)` - was `CredentialSearchField::UserId(String)`
    - `AccountSearchField::Provider(Provider)` - was `AccountSearchField::Provider(String)`
    - All search field variants now require appropriate typed wrappers instead of raw strings
  - **Migration Guide**: Replace string parameters with typed constructors:
    ```rust
    // Before:
    delete_oauth2_account_core("user123", "google", "google456")
    get_user_from_session("session_cookie_value")

    // After:
    delete_oauth2_account_core(
        UserId::new("user123".to_string())?,
        Provider::new("google".to_string())?,
        ProviderUserId::new("google456".to_string())?
    )
    get_user_from_session(&SessionCookie::new("session_cookie_value".to_string())?)
    ```

- **Coordination Functions**: All coordination functions now use type-safe wrapper types and require session validation:
  - **Admin Functions**: Now require `SessionId` parameter instead of `SessionUser` object and use typed identifiers:
    - `get_all_users(SessionId)` - was `get_all_users()`
    - `get_user(SessionId, UserId)` - was `get_user(user_id: &str)`
    - `delete_user_account_admin(SessionId, UserId)` - was `delete_user_account_admin(user_id: &str)`
    - `delete_passkey_credential_admin(SessionId, CredentialId)` - was `delete_passkey_credential_admin(user: &SessionUser, credential_id: &str)`
    - `delete_oauth2_account_admin(SessionId, String)` - was `delete_oauth2_account_admin(user: &SessionUser, provider_user_id: &str)`
    - `update_user_admin_status(SessionId, UserId, bool)` - was `update_user_admin_status(admin_user: &SessionUser, user_id: &str, is_admin: bool)`
  - **User Functions**: Now require `SessionId` parameter and use typed identifiers:
    - `update_user_account(SessionId, UserId, Option<String>, Option<String>)` - was `update_user_account(user_id: &str, account: Option<String>, label: Option<String>)`
    - `delete_user_account(SessionId, UserId)` - was `delete_user_account(user_id: &str)`
  - **Type-Safe Wrappers**: Use `SessionId::new(session_id)`, `UserId::new(user_id)`, `CredentialId::new(credential_id)` instead of raw strings

- **Type Changes**: `SessionUser.sequence_number` type changed from `i64` to `Option<i64>` to match database schema consistency

## [0.1.3] - 2025-07-12

### Security

- OpenID Connect compliant `at_hash` verification
- Support for multiple JWT signing algorithms (RS256/384/512, HS256/384/512, ES256/384)

## [0.1.2] - 2025-07-04

### Changed

- Minor modifications and clarifications in README.md files across the workspace for improved documentation and accuracy.

## [0.1.1] - 2025-06-23

### Fixed

- Fix session cookie extraction when multiple cookie headers are present

## [0.1.0] - 2025-06-20

### Added

- Complete OAuth2 and WebAuthn/Passkey authentication system
- Framework-agnostic core library (`oauth2-passkey`)
- Axum web framework integration (`oauth2-passkey-axum`)
- Support for Google OAuth2 authentication
- WebAuthn/FIDO2 passkey authentication
- Secure session management with Redis and in-memory storage
- SQLite and PostgreSQL database support
- CSRF protection with timing-attack resistance
- Admin and user management interfaces
- Comprehensive demo applications
- Security-focused design with `#![forbid(unsafe_code)]`
- Full API documentation and usage examples

### Security

- Cryptographically secure random number generation using `ring`
- Constant-time CSRF token comparison to prevent timing attacks
- Secure cookie handling with `Secure`, `HttpOnly`, `SameSite=Lax` attributes
- Host-locked cookies using `__Host-` prefix
- Complete OAuth2 PKCE implementation with S256
- Full WebAuthn specification compliance
- Comprehensive security documentation and best practices guide

[Unreleased]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ktaka-ccmp/oauth2-passkey/releases/tag/v0.1.0
