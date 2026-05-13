# Issue Tracking

This directory contains issue/task tracking files for the project.

## Current Issues

<!-- AUTO-UPDATED: Do not edit manually. Updated by /issue command. -->

### Open (10)

| ID | Priority | Difficulty | Title |
|----|----------|------------|-------|
| `20260226-2025` | high | large | [E2E Tests](open/20260226-2025-e2e-tests.md) |
| `20260226-1814` | high | large | [Device Bound Session Credentials (DBSC) Support](open/20260226-1814-device-bound-session-credentials.md) |
| `20260226-2019` | medium | large | [Finalize Public API for 1.0 Release](open/20260226-2019-finalize-public-api.md) |
| `2026-02-08-02` | medium | medium | [Login History DB Spam Risk from Brute-Force Attacks](open/2026-02-08-login-history-db-spam.md) |
| `20260226-2024` | medium | medium | [Rate Limiting](open/20260226-2024-rate-limiting.md) |
| `20260321-1245` | medium | medium | [Multi-Database Integration Tests](open/20260321-1245-multi-db-integration-tests.md) |
| `2026-01-24-01` | low | medium | [Documentation Improvement Planning](open/2026-01-24-docs-improvement-planning.md) |
| `20260323-1338` | low | medium | [Test Coverage Improvement for Non-DB Code Paths](open/20260323-1338-test-coverage-improvement.md) |
| `20260513-0544` | low | small | [Passkey register/finish falls through to create_user when auth is lost mid-flow](open/20260513-0544-passkey-register-finish-mode-confusion.md) |
| `20260513-1356` | low | small | [Reduce E2E pollution in demos (lib-side /test/reset + SQLite for demo-todo/profile)](open/20260513-1356-reduce-e2e-pollution-in-demos.md) |

### Completed (78)

| ID | Title |
|----|-------|
| `20260512-0457` | [Standardize Rust code block markers in mdBook docs to `rust,ignore`](completed/20260512-0457-standardize-rust-block-markers.md) |
| `20260512-0350` | [Use constant-time comparison in verify_page_session_token](completed/20260512-0350-constant-time-page-session-token.md) |
| `20260512-0351` | [Correct status labeling for archived design proposals](completed/20260512-0351-archived-design-proposals-status-labeling.md) |
| `20260511-0543` | [validate_origin starts_with subdomain confusion via Referer](completed/20260511-0543-validate-origin-subdomain-confusion.md) |
| `20260331-1517` | [PASSKEY_AUTHENTICATOR_ATTACHMENT=none sends non-standard string instead of omitting field](completed/20260331-1517-passkey-authenticator-attachment-none-serialization.md) |
| `20260420-0402` | [Admin unlink/delete fails in demo mode ("Invalid user ID")](completed/20260420-0402-admin-unlink-demo-mode.md) |
| `20260423-0136` | [Consolidate idp/README.md into docs/](completed/20260423-0136-idp-readme-docs-consolidation.md) |
| `20260226-2020` | [Expand OAuth2 Provider Support](completed/20260226-2020-expand-oauth2-providers.md) |
| `20260420-1456` | [Verify LINE Login as Custom OIDC Provider + Documentation](completed/20260420-1456-add-line-provider.md) |
| `20260421-0315` | [Configurable `prompt` parameter per OAuth2 provider](completed/20260421-0315-configurable-prompt-per-provider.md) |
| `20260422-2055` | [Introduce `ProviderName` newtype for stringly-typed provider identifiers](completed/20260422-2055-providername-newtype-typesafety.md) |
| `20260422-1636` | [Unify non-Google providers under Custom slot with presets](completed/20260422-1636-unify-non-google-providers-via-custom-slot-preset.md) |
| `20260422-1552` | [Detect claim mismatch between id_token and /userinfo](completed/20260422-1552-detect-claim-mismatch-idinfo-userinfo.md) |
| `20260421-0045` | [Make `expires_in` in OidcTokenResponse optional](completed/20260421-0045-oidc-token-response-expires-in-optional.md) |
| `20260421-0105` | [Merge `idinfo` and `userinfo` when building OAuth2Account](completed/20260421-0105-merge-idinfo-and-userinfo-for-account-build.md) |
| `20260420-1521` | [Remove `OAUTH2_GOOGLE_USER` Dead Code and `oauth2_account_from_userinfo`](completed/20260420-1521-remove-oauth2-google-user-dead-code.md) |
| `20260420-1511` | [Add Generic OIDC Provider Slots](completed/20260420-1511-add-generic-oidc-provider.md) |
| `20260420-1643` | [Show IDP Icon and Provider Name on OAuth2 Account Cards](completed/20260420-1643-oauth2-account-provider-icons.md) |
| `20260420-0552` | [Add Microsoft Entra ID as OAuth2 Provider](completed/20260420-0552-add-entra-provider.md) |
| `20260420-0307` | [Add Keycloak as OIDC Provider](completed/20260420-0307-add-keycloak-provider.md) |
| `20260322-0927` | [User Deletion Lacks Atomicity Across Multiple Stores](completed/20260322-0927-user-deletion-atomicity.md) |
| `20260321-1346` | [Review delete_old_entries Dead Code and Retention Policy](completed/20260321-1346-review-delete-old-entries-dead-code.md) |
| `20260322-0907` | [upsert_oauth2_account SELECT after COMMIT race condition](completed/20260322-0907-upsert-oauth2-account-post-tx-select-race.md) |
| `20260322-0926` | [Passkey Counter Verification TOCTOU Race Condition](completed/20260322-0926-passkey-counter-verification-race.md) |
| `20260322-1011` | [CI Performance Optimization](completed/20260322-1011-ci-performance-optimization.md) |
| `20260321-1234` | [SQLite last_insert_rowid() Potential Race Condition](completed/20260321-1234-sqlite-last-insert-rowid-race.md) |
| `20260226-2021` | [MySQL/MariaDB Database Support](completed/20260226-2021-mysql-mariadb-support.md) |
| `2026-01-31-01` | [Sequential Primary Keys Optimization](completed/2026-01-31-sequential-pkey-optimization.md) |
| `20260227-1703` | [Audit and Improve Silent Fallback Behavior for Optional Environment Variables](completed/20260227-1703-env-var-silent-fallback-audit.md) |
| `20260317-1500` | [Optimize Cloud Run Deployment Build Time](completed/20260317-1500-optimize-cloud-run-deploy-time.md) |
| `20260315-0348` | [Eliminate aws-lc-sys Dependency](completed/20260315-0348-eliminate-aws-lc-sys.md) |
| `20260314-0222` | [FedCM Auto Re-Authentication Rate Limit Error](completed/20260314-0222-fedcm-auto-reauthn-rate-limit.md) |
| `20260311-1039` | [FedCM (Federated Credential Management) Integration](completed/20260311-1039-fedcm-integration.md) |
| `20260311-0904` | [GitHub Actions Security Hardening](completed/20260311-0904-github-actions-security-hardening.md) |
| `20260226-2030` | [AAGUID-Based Credential Deletion Collision](completed/20260226-2030-aaguid-credential-deletion-collision.md) |
| `20260223-0027` | [Add Core Crate Functional-Layer Tests for _core() Functions](completed/20260223-0027-abstract-security-test-assertions.md) |
| `20260213-0145` | [Move All HTTP Integration Tests to Axum Crate](completed/20260213-0145-security-tests-crate-placement.md) |
| `20260222-2201` | [Early Evaluation of OAUTH2_RESPONSE_MODE at Startup](completed/20260222-2201-early-eval-oauth2-response-mode.md) |
| `20260222-1315` | [Make O2P_LOGIN_URL Functional in Middleware](completed/20260222-1315-make-login-url-functional.md) |
| `20260222-1316` | [user-ui Feature Flag Granularity](completed/20260222-1316-user-ui-feature-granularity.md) |
| `20260216-1500` | [O2P_LOGIN_URL Role Clarification and user-ui Feature Granularity](completed/20260216-1500-login-url-and-user-ui-cleanup.md) |
| `20260220-2357` | [Full Masking for Email and Name in Demo Mode](completed/20260220-2357-full-masking-email-name.md) |
| `20260220-2252` | [Add Informational Notice to Demo-Live Login Page](completed/20260220-2252-demo-login-page-notice.md) |
| `20260216-1730` | [Release v0.3.0](completed/20260216-1730-release-v030.md) |
| `2026-02-09-01` | [Update CHANGELOG.md for Changes Since v0.2.0](completed/2026-02-09-changelog-update.md) |
| `20260210-1935` | [Demo Site UI/UX Customizations](completed/20260210-1935-demo-site-ui-customizations.md) |
| `20260210-1930` | [Admin Deletion Safeguard (Prevent Deleting Last Admin)](completed/20260210-1930-admin-deletion-safeguard.md) |
| `2026-02-09-02` | [Improve OAuth2 Popup Error Handling UX](completed/2026-02-09-oauth2-popup-error-handling.md) |
| `20260210-0547` | [Enhance Login History with Auth-Method-Specific Details](completed/20260210-0547-login-history-detail-enhancement.md) |
| `20260212-1200` | [GitHub Actions Auto-Deploy for Cloud Run](completed/20260212-1200-github-actions-auto-deploy.md) |
| `20260212-1804` | [Separate demo-live from demo-both](completed/20260212-1804-separate-demo-live-from-demo-both.md) |
| `2026-01-30-08` | [Demo Site Deployment (Cloud Run)](completed/2026-01-30-demo-site-deployment.md) |
| `20260211-1742` | [OAuth2 Callback Deadlock on JWKS Cache Expiry](completed/20260211-1742-oauth2-callback-blocking.md) |
| `2026-01-30-07` | [Passkey Registration Promotion After Login](completed/2026-01-30-conditional-creation.md) |
| `2026-02-08-01` | [Audit Page Enhancement](completed/2026-02-08-audit-page-enhancement.md) |
| `2026-01-30-02` | [Admin Force Logout Feature](completed/2026-01-30-admin-force-logout.md) |
| `2026-01-30-03` | [Admin Login History View](completed/2026-01-30-admin-login-history.md) |
| `2026-02-07-01` | [Update README and Docs for Current API](completed/2026-02-07-readme-docs-update.md) |
| `2025-01-23-01` | [CI/CD Documentation](completed/2025-01-23-ci-cd-documentation.md) |
| `2026-01-29-01` | [Change PASSKEY_USER_HANDLE_UNIQUE default to false](completed/2026-01-29-change-user-handle-default.md) |
| `2026-01-29-03` | [Create Terminology/Glossary Document](completed/2026-01-29-terminology-document.md) |
| `2026-01-30-04` | [Update README.md with Links and Demo Info](completed/2026-01-30-readme-links-update.md) |
| `2026-01-30-05` | [getClientCapabilities Feature Detection](completed/2026-01-30-client-capabilities-detection.md) |
| `2025-01-23-02` | [CSRF Documentation & Snapshot System](completed/2025-01-23-csrf-docs-snapshot-system.md) |
| `2026-01-24-02` | [Demo Apps Implementation](completed/2026-01-24-demo-apps-implementation.md) |
| `2026-01-26-01` | [Demo Apps Database Configuration](completed/2026-01-26-demo-apps-db-config.md) |
| `2026-01-26-02` | [Documentation and Demo Cleanup](completed/2026-01-26-docs-and-demos-cleanup.md) |
| `2026-01-27-01` | [Admin Route Refactoring](completed/2026-01-27-admin-route-refactoring.md) |
| `2026-01-27-02` | [Unified Router API Design](completed/2026-01-27-unified-router-api.md) |
| `2026-01-27-03` | [Demo Cleanup & Unification](completed/2026-01-27-demo-cleanup-unification.md) |
| `2026-01-28-01` | [WebAuthn Signal API Implementation](completed/2026-01-28-signal-api-implementation.md) |
| `2026-01-28-02` | [Session Conflict Policy Implementation](completed/2026-01-28-session-conflict-policy.md) |
| `2026-01-28-03` | [Fix Windows Hello TPM Attestation (RS1)](completed/2026-01-28-tpm-rs1-attestation-fix.md) |
| `2026-01-29-02` | [Filter remaining_credential_ids by user_handle](completed/2026-01-29-filter-remaining-credentials.md) |
| `2026-01-29-04` | [Review SESSION_CONFLICT_POLICY Default](completed/2026-01-29-session-conflict-policy-review.md) |
| `2026-01-30-01` | [Move /info and /csrf_token to default.rs](completed/2026-01-30-move-info-csrf-endpoints.md) |
| `2026-01-30-09` | [Cross-Origin Same-Site Demo (Pattern 2)](completed/2026-01-30-cross-origin-same-site-demo.md) |
| `2026-01-31-02` | [Remove HTTPS Support from Demo Apps](completed/2026-01-31-demo-remove-https.md) |

### Wontfix (7)

| ID | Title |
|----|-------|
| `20260226-2018` | [Simplify OAuth2 Account Linking API](wontfix/20260226-2018-simplify-oauth2-account-linking-api.md) |
| `20260512-0335` | [POST-based OAuth2 account linking initiation (Alt 5B validation)](wontfix/20260512-0335-post-based-oauth2-linking-validation.md) |
| `20260420-1458` | [Add GitHub as OAuth2 Provider (non-OIDC)](wontfix/20260420-1458-add-github-provider.md) |
| `20260226-2023` | [Authentication Method Tracking in Session](wontfix/20260226-2023-auth-method-tracking-in-session.md) |
| `20260226-2026` | [UI Improvements](wontfix/20260226-2026-ui-improvements.md) |
| `20260212-0235` | [Standalone Demo Repository](wontfix/20260212-0235-standalone-demo-repository.md) |
| `20260213-1500` | [Remove seq=1 from has_admin_privileges()](wontfix/20260213-remove-seq1-from-has-admin-privileges.md) |

### Deferred (12)

| ID | Title |
|----|-------|
| `20260505-1416` | [Support Entra ID multi-tenant endpoints (common/organizations)](deferred/20260505-1416-entra-multi-tenant.md) |
| `20260420-1457` | [Add Sign in with Apple as OAuth2 Provider](deferred/20260420-1457-add-apple-provider.md) |
| `20260323-1505` | [DPoP (Demonstration of Proof-of-Possession) Support](deferred/20260323-1505-dpop-sender-constrained-tokens.md) |
| `20260320-1410` | [FedCM Cancel Fallback Popup Gets Blocked by Browser](deferred/20260320-1410-fedcm-fallback-popup-blocked.md) |
| `20260316-1630` | [FedCM Promise Hangs Indefinitely in Stale Tab](deferred/20260316-1630-fedcm-promise-hang-stale-tab.md) |
| `20260315-0349` | [Eliminate ring Dependency for Full RustCrypto Migration](deferred/20260315-0349-eliminate-ring-dependency.md) |
| `20260312-1948` | [Eliminate nonce_id from FedCM Flow](deferred/20260312-1948-fedcm-eliminate-nonce-id.md) |
| `20260303-0605` | [Adopt WebAuthn Level 3 JSON Serialization API](deferred/20260303-0605-webauthn-json-serialization-api.md) |
| `20260226-2022` | [OAuth2 Token Storage](deferred/20260226-2022-oauth2-token-storage.md) |
| `2026-01-23-01` | [Bearer Token Authentication Support](deferred/2026-01-23-bearer-token-support.md) |
| `2026-01-30-06` | [Passkey Endpoint (.well-known) Support](deferred/2026-01-30-passkey-endpoint-wellknown.md) |
| `20260226-2031` | [Attestation Certificate Chain Validation](deferred/20260226-2031-attestation-certificate-validation.md) |

<!-- END AUTO-UPDATED -->

## Directory Structure

```
.claude/issues/
├── open/           # Active issues
├── completed/      # Resolved issues
├── wontfix/        # Closed without implementation
├── deferred/       # Postponed issues
└── README.md       # This file
```

Issues are organized by status. When status changes, move the file to the appropriate directory.

## File Naming Convention

New issues use the timestamp-based format:

```text
YYYYMMDD-HHMM-<short-slug>.md
```

Example: `20260210-1430-login-history-enhancement.md`

**IMPORTANT**: Always run `date +%H%M` to get the actual current time before naming the file. Never guess or hardcode the time.

Legacy issues use `YYYY-MM-DD-<slug>.md` and are not renamed.

## Issue ID Format

New issues use a timestamp-based ID:

```text
YYYYMMDD-HHMM
```

- `YYYYMMDD`: Creation date
- `HHMM`: Creation time (24h format) — **must be obtained by running `date +%H%M`**

Example: `20260210-1430`, `20260210-1545`

Legacy issues retain their `YYYY-MM-DD-NN` IDs.

## Issue Template

```markdown
# Issue: <Title>

## Metadata

- ID: YYYYMMDD-HHMM
- Created: YYYY-MM-DD-HH-MM
- Closed:
- Status: open | completed | wontfix | deferred
- Priority: high | medium | low
- Difficulty: small | medium | large
- Related Issues:
  - `YYYYMMDD-HHMM` <Title> (relationship)

## Problem

<Symptom, mechanism, or feature gap as understood at issue creation.
This is the historical record of what prompted the issue. **Do not
edit, append, or correct after the issue is created** — even for
typos or factual errors. Corrections, refinements, and new
understanding go in the Timeline as new entries that respond to
the original Problem statement.>

## Timeline

<!--
APPEND-ONLY, time-ordered (oldest first). Each entry is a snapshot
of thinking, decisions, corrections, or research outcomes at a
point in time. Old plans, superseded approaches, decision rationale,
and Problem corrections all live here as entries. Never edit or
delete existing entries; always add new ones at the bottom.
-->

### YYYY-MM-DDTHH:MM — <Short headline>

<Body: discussion, decision rationale, corrections to earlier
sections, snapshot of an old Latest Plan that was just replaced, etc.>

### YYYY-MM-DDTHH:MM — <Next entry>

<...>

## Latest Plan

<!--
Mutable. Always reflects the *current* intended implementation.
When the plan changes substantively, copy the previous body into
the Timeline as a new entry (`### YYYY-MM-DDTHH:MM — Plan revision: <summary>`)
*before* overwriting this section, so no plan history is lost.
-->

<Concrete steps to implement, files to touch, etc. Includes the
Implementation Tasks checklist below.>

### Files

- `path/to/file.rs`

### Implementation Tasks

- [ ] <Task 1>
- [ ] <Task 2>

### Verification

<How to test end-to-end.>

## Resolution

<!--
Written once when status transitions to `completed`. Captures the
final commit hashes, summary of what was done, and verification
results. After this is filled in, the issue is sealed.
-->
```

## Section Update Rules

| Section | Update Rule |
|---------|------------|
| Metadata | Freely updatable. `Created` is written once at issue creation; `Closed` is written once when status moves to `completed`. |
| **Problem** | **Fully immutable after issue creation.** No edits, no appends, no typo fixes. Corrections go in Timeline as new entries. |
| **Timeline** | **Append-only, time-ordered (oldest first).** Never edit or delete existing entries. New entries go at the bottom with a `### YYYY-MM-DDTHH:MM — <headline>` subsection header. |
| **Latest Plan** | Freely overwritable, but every substantive revision must first copy the previous body into the Timeline as a new entry (`### YYYY-MM-DDTHH:MM — Plan revision: <summary>`). The Implementation Tasks checklist inside Latest Plan is freely tickable as work progresses. |
| Resolution | Written once when status moves to `completed`. After that, treat as sealed. |

The mental model mirrors GitHub Issues:

- **Problem** is the issue body (frozen at creation).
- **Timeline** is the comment thread (chronological, append-only).
- **Latest Plan** is a pinned summary at the bottom of the issue
  describing the current intended fix; revisions move into Timeline
  before the pinned summary is rewritten.
- **Resolution** is the closing comment that seals the work.

## Status Values

| Status | Directory | Description |
|--------|-----------|-------------|
| `open` | `open/` | New or in-progress |
| `completed` | `completed/` | Resolved and committed |
| `wontfix` | `wontfix/` | Closed without implementation |
| `deferred` | `deferred/` | Postponed for later |

## Commands

- `/issue` - Create or update an issue
- `/backlog` - View all open issues
- `/snapshot` - Create a session snapshot (different from issues)

## Workflow

1. **Run `date +%H%M` to get the current time** before naming the issue file or setting the ID
2. Create new issue in `open/` directory using the confirmed timestamp
3. **Update this README's "Current Issues" table** (increment count, add row)
4. Work on the issue
5. When resolved, update Resolution section and move to `completed/`
6. If postponed, move to `deferred/`

**Important**: Always update the README table when creating, completing, or moving issues.

## Difference from Sessions

- **Sessions** (`.claude/sessions/`): Work context snapshots for transferring between machines
- **Issues** (`.claude/issues/`): Task/bug tracking that persists across sessions
