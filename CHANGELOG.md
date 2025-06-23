# Changelog

All notable changes to oauth2-passkey will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Initial release preparation

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

[Unreleased]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ktaka-ccmp/oauth2-passkey/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ktaka-ccmp/oauth2-passkey/releases/tag/v0.1.0
