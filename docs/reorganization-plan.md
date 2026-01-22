# Documentation Reorganization Plan for oauth2-passkey

## Background

- 52 markdown files total (excluding target/)
- 32 orphan documents (no incoming references)
- docs/testing/ has 10 historical assessment files from June 2025
- Multiple completed publication checklists
- No documentation index - users don't know where to start

## Goals

1. Make it clear which documents users should read
2. Archive historical/completed documents
3. Consolidate overlapping content
4. Create a documentation index (docs/README.md)

## Approach Decision

**User selected: "両方検討" (Consider both approaches)**

1. **Phase A - Simple Reorganization (This Plan)**
   - Reorganize using directory structure with docs/README.md as index
   - Fast to implement, easy to maintain
   - No additional tooling required

2. **Phase B - mdbook Migration (Future Consideration)**
   - After simple reorganization is complete and verified
   - Evaluate if mdbook would provide additional value
   - mdbook provides: sidebar navigation, search, book-like structure
   - Decision to be made after Phase A is complete

---

## Proposed Directory Structure

```
docs/
  README.md                              # NEW: Documentation index

  guides/                                # User-facing guides
    security-best-practices.md
    csrf-protection.md
    oauth2-account-linking.md            # Consolidated
    ios-safari-compatibility.md
    framework-integrations.md

  reference/                             # Technical reference
    architecture.md
    security.md
    session-cookies-and-host-prefix.md
    page_session_protection.md           # Consolidated with session-boundary-solutions
    oauth2-user-verification.md
    SECURITY_ADVISORIES.md
    webauthn/
      passkey_attestation_none.md
      passkey_attestation_packed.md
      passkey_attestation_tpm.md

  maintainer/                            # Maintainer docs
    ReleaseHowTo.md
    testing-strategy.md                  # From root TestStrategy.md

  archived/                              # Historical documents
    checklists/
      CHECKLIST_oauth2_passkey.md
      CHECKLIST_oauth2_passkey_axum.md
      PUBLISH_CHECKLIST_Version2.md
    testing-assessments/
      (all docs/testing/* files)
    design-proposals/
      cache-expiration-system-simplification.md
      oauth2-account-linking-api-simplification.md
      type-safe-validation.md
      implementing-tracing.md
      integration-testing-plan.md
      testing-oidc-discovery.md
      TestKeyPairGeneration.md
```

---

## Document Actions

### KEEP at current location (root level)
- `Readme.md` - Main project entry
- `CLAUDE.md` - AI instructions
- `CONTRIBUTING.md` - Contributor guide
- `CHANGELOG.md` - Release history

### KEEP at current location (crate/demo READMEs)
- `oauth2_passkey/README.md`
- `oauth2_passkey_axum/README.md`
- `demo-both/README.md`
- `demo-oauth2/README.md`
- `demo-passkey/README.md`
- `db/Readme.md`
- `oauth2_passkey/tests-security/README.md`

### MOVE to docs/guides/
| From | To |
|------|-----|
| docs/security-best-practices.md | docs/guides/security-best-practices.md |
| docs/csrf-protection.md | docs/guides/csrf-protection.md |
| docs/ios-safari-compatibility.md | docs/guides/ios-safari-compatibility.md |
| docs/framework-integrations.md | docs/guides/framework-integrations.md |

### MOVE to docs/reference/
| From | To |
|------|-----|
| docs/architecture.md | docs/reference/architecture.md |
| docs/security.md | docs/reference/security.md |
| docs/session-cookies-and-host-prefix.md | docs/reference/session-cookies-and-host-prefix.md |
| docs/page_session_protection.md | docs/reference/page_session_protection.md |
| docs/oauth2-user-verification.md | docs/reference/oauth2-user-verification.md |
| docs/SECURITY_ADVISORIES.md | docs/reference/SECURITY_ADVISORIES.md |
| docs/passkey_attestation_*.md | docs/reference/webauthn/ |

### MOVE to docs/maintainer/
| From | To |
|------|-----|
| docs/ReleaseHowTo.md | docs/maintainer/ReleaseHowTo.md |
| TestStrategy.md | docs/maintainer/testing-strategy.md |

### MOVE to docs/archived/
| From | To |
|------|-----|
| docs/CHECKLIST_*.md | docs/archived/checklists/ |
| docs/PUBLISH_CHECKLIST_Version2.md | docs/archived/checklists/ |
| docs/testing/* | docs/archived/testing-assessments/ |
| docs/cache-expiration-system-simplification.md | docs/archived/design-proposals/ |
| docs/oauth2-account-linking-api-simplification.md | docs/archived/design-proposals/ |
| docs/type-safe-validation.md | docs/archived/design-proposals/ |
| docs/implementing-tracing.md | docs/archived/design-proposals/ |
| docs/integration-testing-plan.md | docs/archived/design-proposals/ |
| docs/testing-oidc-discovery.md | docs/archived/design-proposals/ |
| docs/TestKeyPairGeneration.md | docs/archived/design-proposals/ |

### CONSOLIDATE
| Source | Target | Action |
|--------|--------|--------|
| docs/oauth2-account-linking-implementation.md | docs/guides/oauth2-account-linking.md | Keep implementation, archive API simplification proposal |
| docs/session-boundary-solutions.md | docs/reference/page_session_protection.md | Merge relevant content |
| docs/authorization-security-patterns.md | docs/guides/security-best-practices.md | Merge, then archive original |

### KEEP (to be reviewed later)
| File | Reason |
|------|--------|
| ToDo.md | Contains unfinished tasks - keep for later review |

---

## Implementation Steps

### Phase 0: Setup Working Directory
1. Create working directory: `docs-staging/` (separate from docs/)
2. Copy this plan file to `docs-staging/reorganization-plan.md`

### Phase 1: Build New Structure in Staging
1. Within `docs-staging/`, create target structure:
   - `docs-staging/guides/`
   - `docs-staging/reference/`
   - `docs-staging/reference/webauthn/`
   - `docs-staging/maintainer/`
   - `docs-staging/archived/`
   - `docs-staging/archived/checklists/`
   - `docs-staging/archived/testing-assessments/`
   - `docs-staging/archived/design-proposals/`
2. Copy (not move) files from `docs/` to appropriate `docs-staging/` locations
3. Create new `docs-staging/README.md` index file
4. Review staged structure before finalizing

### Phase 2: Finalize (after user review)
1. Replace `docs/` contents with `docs-staging/` contents
2. Optionally keep `docs-staging/` for reference or delete it

### Phase 3: Copy Active Documents (to staging)
1. Copy user guides to `docs-staging/guides/`
2. Copy technical references to `docs-staging/reference/`
3. Copy maintainer docs to `docs-staging/maintainer/`
4. Copy `TestStrategy.md` to `docs-staging/maintainer/testing-strategy.md`

### Phase 4: Copy Historical Documents (to staging)
1. Copy checklists to `docs-staging/archived/checklists/`
2. Copy testing assessments to `docs-staging/archived/testing-assessments/`
3. Copy completed design proposals to `docs-staging/archived/design-proposals/`

### Phase 5: Consolidate (in staging)
1. Create `docs-staging/guides/oauth2-account-linking.md` from implementation doc
2. Merge session-boundary content into page_session_protection.md
3. Merge authorization patterns into security-best-practices.md

### Phase 6: Create Index (in staging)
1. Create `docs-staging/README.md` with navigation structure

### Phase 7: Update Cross-References (in staging)
1. Update all internal links to new paths within staging
2. Prepare links for main Readme.md and CONTRIBUTING.md

### Phase 8: User Review
1. User reviews `docs-staging/` structure
2. Make any requested adjustments

### Phase 9: Finalize
1. After user approval, replace `docs/` with `docs-staging/` contents
2. Update links in main Readme.md and CONTRIBUTING.md
3. Optionally remove or keep `docs-staging/`
4. Commit changes

---

## Verification

During staging review:
1. Verify `docs-staging/README.md` covers all active documents
2. Check internal links within staging
3. Ensure archived docs are accessible

After finalization:
1. Run link checker on all markdown files
2. Test that main Readme.md links work
3. Ensure no broken cross-references

---

## Files to Create

1. `docs-staging/reorganization-plan.md` - This plan file (for reference)
2. `docs-staging/README.md` - Documentation index
3. `docs-staging/guides/oauth2-account-linking.md` - Consolidated guide

## Estimated Changes

- ~15 files moved
- ~10 files archived
- ~3 files consolidated
- 1 new file created (docs/README.md)
- ~10 files need link updates

---

## Future: mdbook Consideration

After Phase A (simple reorganization) is complete:
1. Evaluate user experience with docs/README.md index
2. Consider mdbook if:
   - Users want better navigation (sidebar)
   - Search functionality is needed
   - Book-like reading experience desired
3. mdbook would use the same directory structure, just add:
   - `book.toml` configuration
   - `SUMMARY.md` for navigation
   - Build output to `docs/book/`

---

## Content Validation Results (2026-01-22)

### Summary

| Category | Status | Count |
|----------|--------|-------|
| CURRENT (no changes needed) | ✅ | 18 |
| NEEDS UPDATE (minor fixes) | ⚠️ | 4 |
| OBSOLETE (archive as-is) | 📦 | 14 |

### Guides (docs/guides/)

| File | Status | Notes |
|------|--------|-------|
| security-best-practices.md | ✅ CURRENT | All env vars, APIs verified |
| csrf-protection.md | ✅ CURRENT | All endpoints verified |
| ios-safari-compatibility.md | ✅ CURRENT | Recently updated Jan 2025 |
| framework-integrations.md | ✅ CURRENT | Architecture accurate |
| authorization-security-patterns.md | ✅ CURRENT | Helper pattern implemented |
| oauth2-account-linking-implementation.md | ⚠️ OUTDATED | Wrong function names: `oauth2_start_core` should be `prepare_oauth2_auth_request` |

### Reference (docs/reference/)

| File | Status | Notes |
|------|--------|-------|
| architecture.md | ⚠️ OUTDATED | Wrong demo name: "demo-integrated" should be "demo-both" |
| security.md | ✅ CURRENT | Content verified (dated June 2025) |
| session-cookies-and-host-prefix.md | ✅ CURRENT | All claims verified |
| page_session_protection.md | ✅ CURRENT | Implementation matches |
| oauth2-user-verification.md | ✅ CURRENT | All flows verified |
| session-boundary-solutions.md | ✅ CURRENT | Implementation matches |
| SECURITY_ADVISORIES.md | ✅ CURRENT | RUSTSEC-2023-0071 still valid |
| passkey_attestation_none.md | ✅ CURRENT | Implementation matches |
| passkey_attestation_packed.md | ✅ CURRENT | All verification procedures match |
| passkey_attestation_tpm.md | ✅ CURRENT | TPM structures verified |

### Maintainer (docs/maintainer/)

| File | Status | Notes |
|------|--------|-------|
| ReleaseHowTo.md | ⚠️ OUTDATED | References non-existent `release-manual.sh`, version numbers old |
| TestStrategy.md | ✅ CURRENT | Minor cleanup needed (conversational notes) |

### Design Proposals (to archive)

| File | Status | Notes |
|------|--------|-------|
| cache-expiration-system-simplification.md | 📦 IMPLEMENTED | `expires_at` removed, Redis TTL only |
| type-safe-validation.md | ✅ CURRENT | All type wrappers implemented |
| implementing-tracing.md | ✅ CURRENT | 352 tracing calls, #[instrument] in use |
| integration-testing-plan.md | ✅ CURRENT | 480+ unit tests, 29+ integration tests |
| testing-oidc-discovery.md | ✅ CURRENT | Port 9876 persistent server working |
| TestKeyPairGeneration.md | ✅ CURRENT | Technical reference accurate |
| oauth2-account-linking-api-simplification.md | 📦 PROPOSAL | Never implemented - design doc only |

### Checklists (to archive)

| File | Status | Notes |
|------|--------|-------|
| CHECKLIST_oauth2_passkey.md | 📦 OBSOLETE | v0.1.0 checklist; v0.2.0 now released |
| CHECKLIST_oauth2_passkey_axum.md | 📦 OBSOLETE | v0.1.0 checklist; v0.2.0 now released |
| PUBLISH_CHECKLIST_Version2.md | 📦 OBSOLETE | Publication completed Jan 22, 2026 |

### Testing Assessments (to archive)

| File | Status | Notes |
|------|--------|-------|
| testing/FINAL_TEST_QUALITY_ANALYSIS.md | 📦 OUTDATED | References 457 tests; now 512 |
| testing/DETAILED_FUNCTION_TEST_MAPPING.md | 📦 HISTORICAL | Reference document |
| testing/assessment_202506/*.md | 📦 HISTORICAL | June 2025 assessments |
| testing/OAuth2TestAssessment.md | 📦 HISTORICAL | December 2024 assessment |
| testing/PasskeyTestInsight.md | ✅ CURRENT | Technical reference - KEEP |
| testing/OAuth2TestCleanupCompletion.md | ✅ CURRENT | Technical reference - KEEP |
| testing/UnitTestInsight.md | ✅ CURRENT | Technical reference - KEEP |

---

## Required Updates Before Reorganization

### 1. architecture.md
- Change "demo-integrated" to "demo-both"
- Update timestamp from "March 2025"

### 2. oauth2-account-linking-implementation.md
- Replace `oauth2_start_core` with `prepare_oauth2_auth_request`
- Replace `oauth2_callback_core` with `get_authorized_core`/`post_authorized_core`

### 3. ReleaseHowTo.md
- Remove reference to non-existent `release-manual.sh`
- Update version examples from 0.1.2 to 0.2.x

---

## Book Structure - Topic Outline

一冊のBookとして再構成するためのトピック一覧。

### Part 1: Getting Started

1. **Introduction**
   - What is oauth2-passkey?
   - Supported authentication methods (OAuth2, WebAuthn/Passkey)
   - Use cases and target audience

2. **Quick Start**
   - Prerequisites
   - Installation
   - Running demo applications (demo-both, demo-oauth2, demo-passkey)
   - Basic configuration

3. **Architecture Overview**
   - System components
     - oauth2_passkey (core library)
     - oauth2_passkey_axum (Axum integration)
   - Module structure (coordination, oauth2, passkey, session, storage, userdb, config)
   - Data flow
   - Dependency relationships

### Part 2: Integration Guide

4. **Framework Integration**
   - Axum integration patterns
   - Router configuration
   - Middleware setup
   - Handler implementation
   - Static asset serving

5. **Configuration**
   - Environment variables
   - Database setup (SQLite, PostgreSQL)
   - Cache setup (Memory, Redis)
   - Route prefix customization

6. **OAuth2 Implementation**
   - OAuth2 flow overview
   - Provider configuration (Google)
   - Account linking implementation
     - Page session token usage
     - Client-side implementation (JavaScript)
     - Server-side handler implementation (Rust/Axum)
   - Complete example: User Settings Page

7. **Passkey/WebAuthn Implementation**
   - WebAuthn overview
   - Registration flow
   - Authentication flow
   - Credential management

### Part 3: Security

8. **Security Model**
   - Threat model
     - CSRF attacks
     - Session fixation
     - Replay attacks
     - Credential stuffing
   - Security architecture

9. **CSRF Protection**
   - Double Submit Cookie pattern
   - CSRF token generation
   - Header-based verification
   - Form-based verification
   - Integration with session management

10. **Session Security**
    - Session management
    - Cookie security (HttpOnly, Secure, SameSite)
    - `__Host-` cookie prefix
    - Cross-origin considerations
    - Browser compatibility

11. **Page Session Protection**
    - Session boundary attacks
    - Page session token mechanism
    - Token generation and verification
    - Integration with OAuth2 flows

12. **OAuth2 Security**
    - PKCE (Proof Key for Code Exchange)
    - State parameter verification
    - Nonce implementation
    - Token validation

13. **Authorization Patterns**
    - Admin function security
    - Authorization helper patterns
    - User verification methods
    - Role-based access control

14. **Production Deployment**
    - HTTPS requirements
    - Environment variable security
    - Database security
    - Security checklist

### Part 4: WebAuthn Technical Reference

15. **Attestation Formats**
    - Overview of attestation
    - Security implications

16. **None Attestation**
    - Specification
    - When to use
    - Verification procedures

17. **Packed Attestation**
    - Specification
    - Self-attestation verification
    - Basic attestation verification
    - Certificate chain validation
    - AAGUID verification

18. **TPM Attestation**
    - Specification
    - TPM structures (TPMS_ATTEST, TPMT_SIGNATURE)
    - Certificate verification
    - AIK (Attestation Identity Key) validation
    - TPM manufacturer verification

### Part 5: Platform Compatibility

19. **iOS Safari Compatibility**
    - ITP (Intelligent Tracking Prevention) restrictions
    - Third-party cookie limitations
    - Popup fallback strategy
    - Implementation patterns
    - Testing guidelines

### Part 6: API Reference

20. **Core Library API (oauth2-passkey)**
    - Coordination module
    - OAuth2 module
    - Passkey module
    - Session module
    - Storage module
    - UserDB module

21. **Axum Integration API (oauth2-passkey-axum)**
    - Routers
    - Handlers
    - Middleware
    - Extractors

### Part 7: Maintainer Guide

22. **Development**
    - Project structure
    - Testing strategy
    - Unit test patterns
    - Integration test patterns
    - Test utilities

23. **Release Process**
    - Version management
    - Automated release (utils/release.sh)
    - Manual release steps
    - Crates.io publishing
    - Git tagging
    - Troubleshooting

### Appendices

A. **Security Advisories**
   - RUSTSEC-2023-0071 (rsa crate)
   - Mitigation strategies

B. **Type-Safe Validation**
   - Type wrappers (UserId, SessionId, CredentialId, etc.)
   - Validation patterns
   - Error handling

C. **Troubleshooting**
   - Common errors
   - Debug tips

---

## Topic Coverage Mapping

| Book Chapter | Source Documents |
|--------------|------------------|
| 1-2. Introduction, Quick Start | Readme.md, demo READMEs |
| 3. Architecture | architecture.md |
| 4. Framework Integration | framework-integrations.md |
| 5. Configuration | dot.env.example, CLAUDE.md |
| 6. OAuth2 Implementation | oauth2-account-linking-implementation.md |
| 7. Passkey Implementation | (code documentation) |
| 8. Security Model | security.md |
| 9. CSRF Protection | csrf-protection.md |
| 10. Session Security | session-cookies-and-host-prefix.md |
| 11. Page Session Protection | page_session_protection.md, session-boundary-solutions.md |
| 12. OAuth2 Security | oauth2-user-verification.md |
| 13. Authorization Patterns | authorization-security-patterns.md |
| 14. Production Deployment | security-best-practices.md |
| 15-18. WebAuthn Reference | passkey_attestation_*.md |
| 19. iOS Safari | ios-safari-compatibility.md |
| 20-21. API Reference | (rustdoc) |
| 22-23. Maintainer Guide | TestStrategy.md, ReleaseHowTo.md |
| Appendix A | SECURITY_ADVISORIES.md |
| Appendix B | type-safe-validation.md |

---

## README.md Index Implementation Plan

### Directory Structure

```
docs/
  README.md                              # Main index (Book structure)

  getting-started/                       # Part 1
    introduction.md                      # Ch 1 (NEW from Readme.md)
    quick-start.md                       # Ch 2 (MERGE from demo READMEs)
    architecture.md                      # Ch 3 (COPY)

  integration/                           # Part 2
    framework.md                         # Ch 4 (COPY from framework-integrations.md)
    configuration.md                     # Ch 5 (NEW from dot.env.example)
    oauth2.md                            # Ch 6 (COPY from oauth2-account-linking-implementation.md)
    passkey.md                           # Ch 7 (NEW)

  security/                              # Part 3
    model.md                             # Ch 8 (ADAPT from security.md)
    csrf.md                              # Ch 9 (COPY from csrf-protection.md)
    session.md                           # Ch 10 (COPY from session-cookies-and-host-prefix.md)
    page-session.md                      # Ch 11 (MERGE page_session_protection + session-boundary-solutions)
    oauth2-security.md                   # Ch 12 (COPY from oauth2-user-verification.md)
    authorization.md                     # Ch 13 (COPY from authorization-security-patterns.md)
    production.md                        # Ch 14 (COPY from security-best-practices.md)

  webauthn/                              # Part 4
    attestation-overview.md              # Ch 15 (NEW)
    none.md                              # Ch 16 (COPY from passkey_attestation_none.md)
    packed.md                            # Ch 17 (COPY from passkey_attestation_packed.md)
    tpm.md                               # Ch 18 (COPY from passkey_attestation_tpm.md)

  compatibility/                         # Part 5
    ios-safari.md                        # Ch 19 (COPY from ios-safari-compatibility.md)

  api/                                   # Part 6
    core.md                              # Ch 20 (NEW - rustdoc links)
    axum.md                              # Ch 21 (NEW - rustdoc links)

  maintainer/                            # Part 7
    development.md                       # Ch 22 (ADAPT from TestStrategy.md)
    release.md                           # Ch 23 (COPY from ReleaseHowTo.md)

  appendix/                              # Appendices
    security-advisories.md               # A (COPY from SECURITY_ADVISORIES.md)
    type-safe.md                         # B (COPY from type-safe-validation.md)
    troubleshooting.md                   # C (MERGE from demo READMEs)

  archived/                              # Historical documents
    checklists/
    testing-assessments/
    design-proposals/
```

### Implementation Phases

#### Phase 1: Setup in docs-staging/
1. Create directory structure in `docs-staging/`
2. Create `docs-staging/README.md` as main index (DONE)
3. Verify structure before proceeding

#### Phase 2: COPY chapters (15 chapters - minimal work)
Copy existing docs with minor edits (chapter number prefix, navigation links):

| Target | Source |
|--------|--------|
| `getting-started/architecture.md` | docs/architecture.md |
| `integration/framework.md` | docs/framework-integrations.md |
| `integration/oauth2.md` | docs/oauth2-account-linking-implementation.md |
| `security/csrf.md` | docs/csrf-protection.md |
| `security/session.md` | docs/session-cookies-and-host-prefix.md |
| `security/oauth2-security.md` | docs/oauth2-user-verification.md |
| `security/authorization.md` | docs/authorization-security-patterns.md |
| `security/production.md` | docs/security-best-practices.md |
| `webauthn/none.md` | docs/passkey_attestation_none.md |
| `webauthn/packed.md` | docs/passkey_attestation_packed.md |
| `webauthn/tpm.md` | docs/passkey_attestation_tpm.md |
| `compatibility/ios-safari.md` | docs/ios-safari-compatibility.md |
| `maintainer/release.md` | docs/ReleaseHowTo.md |
| `appendix/security-advisories.md` | docs/SECURITY_ADVISORIES.md |
| `appendix/type-safe.md` | docs/type-safe-validation.md |

#### Phase 3: ADAPT chapters (4 chapters - moderate work)
Restructure existing docs for book format:

| Target | Source | Changes |
|--------|--------|---------|
| `getting-started/introduction.md` | Readme.md | Extract intro section, add use cases |
| `security/model.md` | docs/security.md | Restructure for book flow |
| `maintainer/development.md` | TestStrategy.md | Clean up, add structure |

#### Phase 4: MERGE chapters (3 chapters - moderate work)
Combine multiple docs into one:

| Target | Sources | Notes |
|--------|---------|-------|
| `getting-started/quick-start.md` | demo-*/README.md | Combine setup/run sections |
| `security/page-session.md` | page_session_protection.md + session-boundary-solutions.md | Consolidate |
| `appendix/troubleshooting.md` | demo-*/README.md troubleshooting | Combine all |

#### Phase 5: NEW chapters (5 chapters - significant work)
Write new content:

| Target | Source | Notes |
|--------|--------|-------|
| `integration/configuration.md` | dot.env.example | Document all env vars |
| `integration/passkey.md` | code docs | WebAuthn implementation guide |
| `webauthn/attestation-overview.md` | - | Summary of attestation formats |
| `api/core.md` | rustdoc | Links + overview |
| `api/axum.md` | rustdoc | Links + overview |

#### Phase 6: Archive historical documents
Move to `archived/`:

| Target | Sources |
|--------|---------|
| `archived/checklists/` | CHECKLIST_*.md, PUBLISH_CHECKLIST_Version2.md |
| `archived/testing-assessments/` | docs/testing/* |
| `archived/design-proposals/` | cache-expiration-*.md, type-safe-validation.md, implementing-tracing.md, etc. |

#### Phase 7: Finalize
1. User reviews `docs-staging/` structure
2. Replace `docs/` with `docs-staging/` contents
3. Update main Readme.md links
4. Verify all links work

### Content Strategy

| Action | Description |
|--------|-------------|
| COPY | Existing doc is already good, copy with minimal edits |
| ADAPT | Existing doc needs restructuring for book format |
| MERGE | Multiple docs combined into one chapter |
| NEW | Chapter needs to be written from scratch |

| Chapter | Action | Source |
|---------|--------|--------|
| 1. Introduction | ADAPT | Readme.md |
| 2. Quick Start | MERGE | demo-*/README.md |
| 3. Architecture | COPY | architecture.md |
| 4. Framework | COPY | framework-integrations.md |
| 5. Configuration | NEW | dot.env.example comments |
| 6. OAuth2 | COPY | oauth2-account-linking-implementation.md |
| 7. Passkey | NEW | code documentation |
| 8. Security Model | ADAPT | security.md |
| 9. CSRF | COPY | csrf-protection.md |
| 10. Session | COPY | session-cookies-and-host-prefix.md |
| 11. Page Session | MERGE | page_session_protection.md + session-boundary-solutions.md |
| 12. OAuth2 Security | COPY | oauth2-user-verification.md |
| 13. Authorization | COPY | authorization-security-patterns.md |
| 14. Production | COPY | security-best-practices.md |
| 15. Attestation Overview | NEW | summary of 16-18 |
| 16. None | COPY | passkey_attestation_none.md |
| 17. Packed | COPY | passkey_attestation_packed.md |
| 18. TPM | COPY | passkey_attestation_tpm.md |
| 19. iOS Safari | COPY | ios-safari-compatibility.md |
| 20. Core API | NEW | rustdoc links |
| 21. Axum API | NEW | rustdoc links |
| 22. Development | ADAPT | TestStrategy.md |
| 23. Release | COPY | ReleaseHowTo.md |
| A. Advisories | COPY | SECURITY_ADVISORIES.md |
| B. Type-Safe | COPY | type-safe-validation.md |
| C. Troubleshooting | MERGE | demo-*/README.md troubleshooting sections |

### Summary

- **Total chapters**: 23 + 3 appendices = 26
- **COPY (minimal work)**: 15 chapters
- **ADAPT (moderate work)**: 4 chapters
- **MERGE (moderate work)**: 3 chapters
- **NEW (significant work)**: 4 chapters

### Execution Order

1. **Setup** - Create directories in docs-staging/
2. **COPY chapters first** - Get bulk of content in place quickly (15 chapters)
3. **ADAPT chapters** - Restructure existing content (4 chapters)
4. **MERGE chapters** - Combine related docs (3 chapters)
5. **NEW chapters** - Write missing content (5 chapters)
6. **Archive** - Move historical docs to archived/
7. **Review** - User reviews docs-staging/
8. **Finalize** - Replace docs/ with docs-staging/, update links
