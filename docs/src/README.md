# oauth2-passkey Documentation

Drop-in OAuth2 and Passkey authentication for Rust web applications.

## Why OAuth2 + Passkey?

**Password authentication is fundamentally flawed** - even strong, unique passwords are vulnerable to phishing, brute-force attacks, and server-side breaches. 2FA adds complexity without fixing the root cause.

**This library avoids passwords entirely:**

1. **Register with Google OAuth2** - One-click signup, no password to create
2. **Add a Passkey** - Register biometric authentication (fingerprint, face)
3. **Login with Passkey** - Fast, phishing-resistant daily authentication
4. **OAuth2 as backup** - Recovery option if device is lost

After authentication, the library issues a secure session cookie to maintain login state. No password management. No 2FA implementation. Better security.

## Getting Started

New to oauth2-passkey? Start here:

1. [Introduction](getting-started/introduction.md) - Why this approach works
2. [Quick Start](getting-started/quick-start.md) - Prerequisites and running demos
3. [Architecture](getting-started/architecture.md) - System components and data flow
