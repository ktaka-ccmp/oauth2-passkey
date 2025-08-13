# Changelog

All notable changes to oauth2-passkey will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **CRITICAL FIX**: Fixed passkey registration vulnerability where users were created before challenge validation, preventing orphaned user records on validation failures
- **BREAKING**: Enhanced admin function security by requiring session ID validation with fresh database lookups instead of trusting session data, preventing privilege escalation attacks

### Changed

- **OIDC Discovery**: Automatic endpoint discovery from `/.well-known/openid-configuration`
- **OAuth2 endpoint configuration**: Replaced hardcoded Google URLs with dynamic discovery
- **Passkey Registration**: Refactored to validate challenges before user creation, eliminating double validation and optimizing cleanup timing
- **BREAKING**: `SessionUser.sequence_number` field changed from `i64` to `Option<i64>` for database consistency
- **Database**: Enhanced SQLite connection with WAL journaling, memory temp storage, and optimized pragmas for better performance

### Breaking Changes

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

[Unreleased]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ktaka-ccmp/oauth2-passkey/releases/tag/v0.1.0
