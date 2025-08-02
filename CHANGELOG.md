# Changelog

All notable changes to oauth2-passkey will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **CRITICAL FIX**: Fixed passkey registration vulnerability where users were created before challenge validation

### Changed

- **OIDC Discovery**: Automatic endpoint discovery from `/.well-known/openid-configuration`
- **Passkey Registration**: Refactored to validate challenges before user creation

### BREAKING CHANGES

- **Fixed Authorization Context in Core Admin Functions**: Enhanced admin functions with proper authorization context and layered security
  - **Migration**: Update all function calls to include authenticated SessionUser as first parameter
  - **Function signature changes**:
    - `get_all_users(auth_user: &SessionUser)` - Admin-only access
    - `get_user(auth_user: &SessionUser, user_id: &str)` - Admin or self-access
    - `delete_user_account(auth_user: &SessionUser, user_id: &str)` - Admin or self-access
    - `delete_user_account_admin(auth_user: &SessionUser, user_id: &str)` - Admin-only access
    - `update_user_account(auth_user: &SessionUser, user_id: &str, ...)` - Admin or self-access
    - `list_credentials_core(auth_user: &SessionUser, user_id: &str)` - Admin or self-access
    - `delete_passkey_credential_core(auth_user: &SessionUser, user_id: &str, credential_id: &str)` - Layered security with ownership verification
    - `list_accounts_core(auth_user: &SessionUser, user_id: &str)` - Admin or self-access
    - `delete_oauth2_account_core(auth_user: &SessionUser, user_id: &str, provider: &str, provider_user_id: &str)` - Layered security with ownership verification

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

[Unreleased]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ktaka-ccmp/oauth2-passkey/releases/tag/v0.1.0
