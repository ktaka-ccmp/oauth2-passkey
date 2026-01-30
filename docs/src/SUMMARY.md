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

# Part 3: Customization

- [Built-in Themes](integration/themes.md)
- [Customizing CSS](integration/customizing-css.md)
- [Customizing Templates](integration/customizing-templates.md)
- [OAuth2 JavaScript API](integration/oauth2-js.md)
- [Passkey JavaScript API](integration/passkey-js.md)
- [Askama Templates](integration/templates.md)

---

# Part 4: Internals

- [OAuth2 Implementation](integration/oauth2.md)
- [Passkey Implementation](integration/passkey.md)
- [Development Tunneling](guides/tunneling.md)

---

# Part 5: Security

- [Security Model](security/model.md)
- [CSRF Protection](security/csrf.md)
- [Session Security](security/session.md)
- [Session Conflict Policy](security/session-conflict.md)
- [Page Session Protection](security/page-session.md)
- [OAuth2 Security](security/oauth2-security.md)
- [Authorization Patterns](security/authorization.md)
- [Production Deployment](security/production.md)

---

# Part 6: Reference

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

# Part 7: Maintainer Guide

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

---

# Archived Documents

- [Overview](archived/README.md)
  - [Checklists]()
    - [CHECKLIST oauth2_passkey](archived/checklists/CHECKLIST_oauth2_passkey.md)
    - [CHECKLIST oauth2_passkey_axum](archived/checklists/CHECKLIST_oauth2_passkey_axum.md)
    - [PUBLISH_CHECKLIST Version2](archived/checklists/PUBLISH_CHECKLIST_Version2.md)
  - [Testing Assessments]()
    - [Detailed Function Test Mapping](archived/testing-assessments/DETAILED_FUNCTION_TEST_MAPPING.md)
    - [Final Test Quality Analysis](archived/testing-assessments/FINAL_TEST_QUALITY_ANALYSIS.md)
    - [List of Functions](archived/testing-assessments/List_of_all_functions_oauth2_passkey.md)
    - [OAuth2 Test Assessment](archived/testing-assessments/OAuth2TestAssessment.md)
    - [OAuth2 Test Cleanup](archived/testing-assessments/OAuth2TestCleanupCompletion.md)
    - [Passkey Test Insight](archived/testing-assessments/PasskeyTestInsight.md)
    - [Unit Test Insight](archived/testing-assessments/UnitTestInsight.md)
    - [Assessment 202506]()
      - [README](archived/testing-assessments/assessment_202506/README.md)
      - [Comprehensive Assessment](archived/testing-assessments/assessment_202506/ComprehensiveAssessment.md)
      - [Axum Test Quality](archived/testing-assessments/assessment_202506/OAuth2PasskeyAxumTestQualityAssessment.md)
  - [Design Proposals]()
    - [Bearer Token Support](archived/design-proposals/bearer-token-support.md)
    - [Cache Expiration Simplification](archived/design-proposals/cache-expiration-system-simplification.md)
    - [Implementing Tracing](archived/design-proposals/implementing-tracing.md)
    - [Integration Testing Plan](archived/design-proposals/integration-testing-plan.md)
    - [OAuth2 Account Linking API](archived/design-proposals/oauth2-account-linking-api-simplification.md)
    - [Testing OIDC Discovery](archived/design-proposals/testing-oidc-discovery.md)
    - [Test Key Pair Generation](archived/design-proposals/TestKeyPairGeneration.md)
    - [Type-Safe Validation](archived/design-proposals/type-safe-validation.md)
