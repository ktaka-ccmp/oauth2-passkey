# Chapter 1: Introduction

## What is oauth2-passkey?

oauth2-passkey is a drop-in authentication library for Rust web applications. It enables you to add secure login functionality with Google OAuth2 and/or Passkeys in minutes.

The library provides a complete authentication solution where users authenticate with OAuth2 or Passkey, then receive a secure session cookie to maintain their login status.

### Key Features

- **"Sign in with Google"** - OAuth2/OIDC authentication that works out of the box
- **Passwordless login** - WebAuthn/Passkey support for modern devices
- **Account linking** - Users can add multiple login methods to one account
- **Security built-in** - Sessions, CSRF protection, secure cookies
- **Minimal setup** - Works with SQLite out of the box, scales to PostgreSQL + Redis

## Supported Authentication Methods

### OAuth2/OpenID Connect (Google)

The library provides full OAuth2/OIDC integration with Google, allowing users to authenticate using their existing Google accounts. This is the familiar "Sign in with Google" flow that users expect from modern web applications.

### WebAuthn/Passkey

WebAuthn (Web Authentication) enables passwordless authentication using passkeys. Users can register and authenticate using:

- Platform authenticators (Touch ID, Face ID, Windows Hello)
- Security keys (YubiKey, etc.)
- Cross-device authentication via smartphones

Both authentication methods can be used independently or together, giving users flexibility in how they access their accounts.

## Use Cases

### Web Application Authentication

Add secure authentication to any Rust web application built with the Axum framework. The library handles:

- User registration and login flows
- Session management
- Secure cookie handling

### Multiple Authentication Methods

Allow users to choose their preferred authentication method:

- First-time users can register with Google OAuth2 OR create a Passkey
- Existing users can add additional login methods to their account
- Authentication works with any linked method (OAuth2 or Passkey)

### Secure Session Management

The library provides built-in session management with:

- Secure session cookies
- CSRF protection
- Configurable session expiration
- Support for both development (in-memory) and production (Redis) session stores

### Account Administration

The first registered user is automatically promoted to admin, enabling account management capabilities for other users.

## Target Audience

### Rust Web Developers

This library is designed for Rust developers building web applications who need authentication functionality without implementing it from scratch. It provides:

- Clean, idiomatic Rust APIs
- Comprehensive error handling
- Minimal dependencies

### Axum Framework Users

The `oauth2-passkey-axum` crate provides seamless integration with the Axum web framework:

- Ready-to-use route handlers
- Built-in static assets (JS/CSS) for login UI
- HTML templates for authentication pages
- Extractors for accessing authenticated user information

## Why Choose oauth2-passkey?

- **Beginner-friendly** - Works out of the box with SQLite
- **Production-ready** - Scales to PostgreSQL + Redis
- **Modern auth methods** - OAuth2 + Passkeys in one package
- **Security built-in** - CSRF, secure sessions, minimal dependencies
- **Flexible** - Users can mix and match auth methods

## Next Steps

Continue to the next chapter to learn about the library architecture and how the components work together.
