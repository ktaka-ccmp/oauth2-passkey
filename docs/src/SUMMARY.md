# Summary

[Introduction](README.md)

---

# Part 1: Getting Started

- [Introduction](getting-started/introduction.md)
- [Quick Start](getting-started/quick-start.md)
- [Architecture](getting-started/architecture.md)

---

# Part 2: Basic Integration

- [Basic Setup](integration/framework.md)
- [Route Protection](integration/route-protection.md)
- [CSRF Token Handling](integration/csrf-handling.md)
- [User Data Integration](integration/user-data.md)
- [Configuration](integration/configuration.md)
- [Multi-Origin Passkey Setup](integration/multi-origin.md)
- [Server Setup](integration/server-setup.md)
- [Deployment Patterns](integration/deployment-patterns.md)

---

# Part 3: Identity Providers

- [Generic OIDC Provider Setup](guides/generic-oidc.md)
  - [Auth0](guides/auth0.md)
  - [Authentik](guides/authentik.md)
  - [Keycloak](guides/keycloak.md)
  - [LINE Login](guides/line.md)
  - [Microsoft Entra ID](guides/entra.md)
  - [Okta](guides/okta.md)
  - [Ory Hydra](guides/ory-hydra.md)
  - [Sign in with Apple](guides/apple.md)
  - [Zitadel](guides/zitadel.md)

---

# Part 4: Customization

- [Built-in Themes](integration/themes.md)
- [Customizing CSS](integration/customizing-css.md)
- [Customizing Templates](integration/customizing-templates.md)
- [OAuth2 JavaScript API](integration/oauth2-js.md)
- [Passkey JavaScript API](integration/passkey-js.md)
- [Askama Templates](integration/templates.md)

---

# Part 5: Internals

- [OAuth2 Implementation](integration/oauth2.md)
- [FedCM (Experimental)](integration/fedcm.md)
- [Passkey Implementation](integration/passkey.md)
- [Development Tunneling](guides/tunneling.md)

---

# Part 6: Security

- [Security Model](security/model.md)
- [CSRF Protection](security/csrf.md)
- [Session Security](security/session.md)
- [Session Conflict Policy](security/session-conflict.md)
- [Page Session Protection](security/page-session.md)
- [OAuth2 Security](security/oauth2-security.md)
- [Authorization Patterns](security/authorization.md)
- [Production Deployment](security/production.md)

---

# Part 7: Reference

- [Core Library API](api/core.md)
- [Axum Integration API](api/axum.md)
- [iOS Safari Compatibility](compatibility/ios-safari.md)
- [WebAuthn Attestation]()
  - [Attestation Overview](webauthn/attestation-overview.md)
  - [None Attestation](webauthn/none.md)
  - [Packed Attestation](webauthn/packed.md)
  - [TPM Attestation](webauthn/tpm.md)
- [AAGUID and Metadata](webauthn/aaguid-metadata.md)
- [User Handle and Signal API](webauthn/user-handle-and-signal-api.md)

---

# Part 8: Maintainer Guide

- [Development](maintainer/development.md)
- [CI/CD](maintainer/ci-cd.md)
- [Release Process](maintainer/release.md)

---

# Appendices

- [Terminology and Glossary](appendix/terminology.md)
- [Security Advisories](appendix/security-advisories.md)
- [Type-Safe Validation](appendix/type-safe.md)
- [Storage Pattern](appendix/storage-pattern.md)
- [Troubleshooting](appendix/troubleshooting.md)
