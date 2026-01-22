# oauth2-passkey Documentation

Welcome to the oauth2-passkey documentation. This library provides OAuth2 and WebAuthn/Passkey authentication for Rust web applications.

## Quick Links

- [Main README](../Readme.md) - Project overview
- [CHANGELOG](../CHANGELOG.md) - Release history
- [CONTRIBUTING](../CONTRIBUTING.md) - How to contribute

---

## Part 1: Getting Started

| Chapter | Description |
|---------|-------------|
| [1. Introduction](getting-started/introduction.md) | What is oauth2-passkey, use cases, target audience |
| [2. Quick Start](getting-started/quick-start.md) | Prerequisites, installation, running demos |
| [3. Architecture](getting-started/architecture.md) | System components, module structure, data flow |

## Part 2: Integration Guide

| Chapter | Description |
|---------|-------------|
| [4. Framework Integration](integration/framework.md) | Axum integration, routers, middleware |
| [5. Configuration](integration/configuration.md) | Environment variables, database, cache setup |
| [6. OAuth2 Implementation](integration/oauth2.md) | OAuth2 flow, provider config, account linking |
| [7. Passkey Implementation](integration/passkey.md) | WebAuthn registration, authentication, credentials |

## Part 3: Security

| Chapter | Description |
|---------|-------------|
| [8. Security Model](security/model.md) | Threat model, security architecture |
| [9. CSRF Protection](security/csrf.md) | Double Submit Cookie, token verification |
| [10. Session Security](security/session.md) | Cookie security, `__Host-` prefix |
| [11. Page Session Protection](security/page-session.md) | Session boundary attacks, page tokens |
| [12. OAuth2 Security](security/oauth2-security.md) | PKCE, state verification, nonce |
| [13. Authorization Patterns](security/authorization.md) | Admin security, role-based access |
| [14. Production Deployment](security/production.md) | HTTPS, security checklist |

## Part 4: WebAuthn Technical Reference

| Chapter | Description |
|---------|-------------|
| [15. Attestation Overview](webauthn/attestation-overview.md) | Attestation concepts, security implications |
| [16. None Attestation](webauthn/none.md) | "None" format specification and verification |
| [17. Packed Attestation](webauthn/packed.md) | "Packed" format, certificate validation |
| [18. TPM Attestation](webauthn/tpm.md) | TPM structures, AIK validation |

## Part 5: Platform Compatibility

| Chapter | Description |
|---------|-------------|
| [19. iOS Safari](compatibility/ios-safari.md) | ITP restrictions, popup fallback |

## Part 6: API Reference

| Chapter | Description |
|---------|-------------|
| [20. Core Library API](api/core.md) | oauth2-passkey modules and functions |
| [21. Axum Integration API](api/axum.md) | oauth2-passkey-axum routers and handlers |

## Part 7: Maintainer Guide

| Chapter | Description |
|---------|-------------|
| [22. Development](maintainer/development.md) | Testing strategy, test patterns |
| [23. Release Process](maintainer/release.md) | Version management, crates.io publishing |

## Appendices

| Appendix | Description |
|----------|-------------|
| [A. Security Advisories](appendix/security-advisories.md) | Known vulnerabilities and mitigations |
| [B. Type-Safe Validation](appendix/type-safe.md) | Type wrappers, validation patterns |
| [C. Troubleshooting](appendix/troubleshooting.md) | Common errors, debug tips |

---

## Demo Applications

Working examples to get started quickly:

- [demo-both](../demo-both/README.md) - Combined OAuth2 + Passkey authentication
- [demo-oauth2](../demo-oauth2/README.md) - OAuth2-only authentication
- [demo-passkey](../demo-passkey/README.md) - Passkey-only authentication

## Crate Documentation

- [oauth2-passkey](../oauth2_passkey/README.md) - Core library README
- [oauth2-passkey-axum](../oauth2_passkey_axum/README.md) - Axum integration README

## API Documentation (docs.rs)

- [docs.rs/oauth2-passkey](https://docs.rs/oauth2-passkey) - Core library API
- [docs.rs/oauth2-passkey-axum](https://docs.rs/oauth2-passkey-axum) - Axum integration API

---

## Archived Documents

Historical documents preserved for reference:

- [Checklists](archived/checklists/) - Completed publication checklists
- [Testing Assessments](archived/testing-assessments/) - Historical test quality assessments
- [Design Proposals](archived/design-proposals/) - Implemented design documents
