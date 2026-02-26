# Introduction

## What is oauth2-passkey?

oauth2-passkey is a passwordless authentication library for Rust web applications. **Password authentication is fundamentally flawed** - even strong, unique passwords are vulnerable to phishing, brute-force attacks, and server-side breaches. This library avoids passwords entirely.

**Intended workflow:** Users register with Google OAuth2, then add a Passkey for fast, phishing-resistant daily login. OAuth2 remains as a backup if the device is lost. After authentication, the library issues a secure session cookie to maintain login state.

### Key Features

- **Passkey** - Phishing-resistant login with biometrics, inherently multi-factor (no 2FA needed)
- **Google OAuth2** - One-click registration and backup authentication
- **Account linking** - Users can add multiple login methods to one account
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

## Why OAuth2 + Passkey?

**Intended workflow:** Users create an account with Google OAuth2, then register a Passkey for daily login. OAuth2 serves as the initial registration method and backup.

### Password Authentication is Fundamentally Flawed

Password-based authentication has inherent design flaws that cannot be fixed by better implementation:

- **Weak passwords** - Users choose predictable passwords (123456, password, etc.). No amount of complexity rules can change human behavior.
- **Password reuse** - Users reuse passwords across sites, making credential stuffing attacks effective
- **Phishing vulnerability** - Users can be tricked into entering passwords on fake sites
- **2FA is a band-aid** - Two-factor authentication exists because passwords alone are insufficient. It adds complexity without addressing the root cause.

### Our Solution: OAuth2 for Registration, Passkey for Login

This library is designed for a specific workflow:

1. **Initial Registration with Google OAuth2**
   - Users sign up with one click using their Google account
   - No password to create or remember
   - Google handles the authentication security

2. **Register a Passkey**
   - After registration, prompt users to add a Passkey
   - Uses device biometrics (fingerprint, face) or security key
   - Stored securely on user's device

3. **Daily Login with Passkey**
   - Fast biometric authentication (1-2 seconds)
   - Phishing-resistant (bound to your domain)
   - Works offline from Google

4. **OAuth2 as Backup**
   - If device is lost, Google OAuth2 still works
   - User can register a new Passkey on new device

### Benefits

- **No password management** - You never store or validate passwords
- **No 2FA implementation needed** - Passkey is inherently multi-factor (device possession + biometrics)
- **Phishing resistant** - Passkeys are cryptographically bound to origin
- **Fast login** - Biometric authentication in seconds
- **Resilient** - Multiple auth methods provide fallback options
- **Reduced attack surface** - No password database to breach

### Technical Highlights

- **Beginner-friendly** - Works out of the box with SQLite
- **Production-ready** - Scales to PostgreSQL + Redis
- **Security built-in** - CSRF, secure sessions, `__Host-` cookie prefix
- **Minimal dependencies** - Careful dependency selection

## Next Steps

Continue to the next chapter to learn about the library architecture and how the components work together.
