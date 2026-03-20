# Development Journal

## Table of Contents

- [2026-03-21: Sequential primary keys for oauth2_accounts and passkey_credentials](#2026-03-21-sequential-primary-keys-for-oauth2_accounts-and-passkey_credentials)
- [2026-03-20: Env var silent fallback audit -- panic on invalid values](#2026-03-20-env-var-silent-fallback-audit----panic-on-invalid-values)
- [2026-03-20: FedCM GIS library analysis and hang investigation](#2026-03-20-fedcm-gis-library-analysis-and-hang-investigation)
- [2026-03-17: Cloud Run deploy optimization -- cargo-chef + BuildKit](#2026-03-17-cloud-run-deploy-optimization----cargo-chef--buildkit)
- [2026-03-17: FedCM stale tab hang issue deferred](#2026-03-17-fedcm-stale-tab-hang-issue-deferred)
- [2026-03-15: Eliminate aws-lc-sys dependency](#2026-03-15-eliminate-aws-lc-sys-dependency)
- [2026-03-14: FedCM auto re-authentication rate limit fix](#2026-03-14-fedcm-auto-re-authentication-rate-limit-fix)
- [2026-03-13: FedCM (Federated Credential Management) integration](#2026-03-13-fedcm-federated-credential-management-integration)
- [2026-03-11: GitHub Actions security hardening](#2026-03-11-github-actions-security-hardening)
- [2026-03-04: AAGUID collision fix -- replace server-side deletion with excludeCredentials](#2026-03-04-aaguid-collision-fix----replace-server-side-deletion-with-excludecredentials)
- [2026-03-03: Issue triage -- wontfix and deferral decisions](#2026-03-03-issue-triage----wontfix-and-deferral-decisions)
- [2026-02-27: Documentation cleanup, issue system migration, and tooling](#2026-02-27-documentation-cleanup-issue-system-migration-and-tooling)
- [2026-02-23: Core crate functional-layer tests for _core() functions](#2026-02-23-core-crate-functional-layer-tests-for-_core-functions)
- [2026-02-23: Security test crate placement correction](#2026-02-23-security-test-crate-placement-correction)
- [2026-02-22: Early evaluation of OAUTH2_RESPONSE_MODE at startup](#2026-02-22-early-evaluation-of-oauth2_response_mode-at-startup)
- [2026-02-22: user-ui feature flag granularity improvement](#2026-02-22-user-ui-feature-flag-granularity-improvement)
- [2026-02-22: Make O2P_LOGIN_URL functional in middleware](#2026-02-22-make-o2p_login_url-functional-in-middleware)
- [2026-02-22: O2P_LOGIN_URL role clarification and user-ui feature investigation](#2026-02-22-o2p_login_url-role-clarification-and-user-ui-feature-investigation)
- [2026-02-21: Full masking for email and name in demo mode](#2026-02-21-full-masking-for-email-and-name-in-demo-mode)
- [2026-02-20: Demo login page informational notice](#2026-02-20-demo-login-page-informational-notice)
- [2026-02-16: Release v0.3.0](#2026-02-16-release-v030)
- [2026-02-14: Demo site UI/UX customization with O2P_DEMO_MODE](#2026-02-14-demo-site-uiux-customization-with-o2p_demo_mode)
- [2026-02-13: OAuth2 popup error handling UX improvement](#2026-02-13-oauth2-popup-error-handling-ux-improvement)
- [2026-02-13: GitHub Actions auto-deploy for Cloud Run](#2026-02-13-github-actions-auto-deploy-for-cloud-run)
- [2026-02-13: Admin deletion safeguard -- prevent deleting the last admin](#2026-02-13-admin-deletion-safeguard----prevent-deleting-the-last-admin)
- [2026-02-12: Separate demo-live from demo-both](#2026-02-12-separate-demo-live-from-demo-both)
- [2026-02-12: Demo site deployment to Cloud Run](#2026-02-12-demo-site-deployment-to-cloud-run)
- [2026-02-11: OAuth2 callback deadlock fix (JWKS cache expiry)](#2026-02-11-oauth2-callback-deadlock-fix-jwks-cache-expiry)
- [2026-02-10: Login history auth-method-specific detail enhancement](#2026-02-10-login-history-auth-method-specific-detail-enhancement)
- [2026-02-10: Passkey registration promotion feature](#2026-02-10-passkey-registration-promotion-feature)
- [2026-02-09: CHANGELOG update (post v0.2.0)](#2026-02-09-changelog-update-post-v020)
- [2026-02-08: Audit page enhancement -- date filtering and security event logging](#2026-02-08-audit-page-enhancement----date-filtering-and-security-event-logging)
- [2026-02-07: README and documentation update for current API](#2026-02-07-readme-and-documentation-update-for-current-api)
- [2026-01-31: Remove HTTPS support from demo applications](#2026-01-31-remove-https-support-from-demo-applications)
- [2026-01-30: README links update](#2026-01-30-readme-links-update)
- [2026-01-30: Move /info and /csrf_token endpoints to default router](#2026-01-30-move-info-and-csrf_token-endpoints-to-default-router)
- [2026-01-30: Bearer token authentication demo (not merged / deferred)](#2026-01-30-bearer-token-authentication-demo-not-merged--deferred)
- [2026-01-30: Cross-origin same-site demo (Pattern 2)](#2026-01-30-cross-origin-same-site-demo-pattern-2)
- [2026-01-30: getClientCapabilities feature detection](#2026-01-30-getclientcapabilities-feature-detection)
- [2026-01-30: Login history view (admin + user)](#2026-01-30-login-history-view-admin--user)
- [2026-01-30: Admin force logout feature](#2026-01-30-admin-force-logout-feature)
- [2026-01-29: Terminology glossary document](#2026-01-29-terminology-glossary-document)
- [2026-01-29: SESSION_CONFLICT_POLICY default review](#2026-01-29-session_conflict_policy-default-review)
- [2026-01-29: Filter remaining_credential_ids by user_handle](#2026-01-29-filter-remaining_credential_ids-by-user_handle)
- [2026-01-29: Change PASSKEY_USER_HANDLE_UNIQUE default to false](#2026-01-29-change-passkey_user_handle_unique-default-to-false)
- [2026-01-28: Windows Hello TPM attestation fix (RS1 algorithm)](#2026-01-28-windows-hello-tpm-attestation-fix-rs1-algorithm)
- [2026-01-28: WebAuthn Signal API improvements](#2026-01-28-webauthn-signal-api-improvements)
- [2026-01-28: Session conflict policy implementation](#2026-01-28-session-conflict-policy-implementation)
- [2026-01-27: Demo application cleanup and unification](#2026-01-27-demo-application-cleanup-and-unification)
- [2026-01-27: Unified router API design](#2026-01-27-unified-router-api-design)
- [2026-01-27: Admin route refactoring](#2026-01-27-admin-route-refactoring)
- [2026-01-26: Documentation structure and demo configuration cleanup](#2026-01-26-documentation-structure-and-demo-configuration-cleanup)
- [2026-01-26: Demo app database configuration and documentation](#2026-01-26-demo-app-database-configuration-and-documentation)
- [2026-01-24: Demo applications for user data integration (demo-profile, demo-todo)](#2026-01-24-demo-applications-for-user-data-integration-demo-profile-demo-todo)
- [2026-01-23: CSRF documentation reorganization and session snapshot system](#2026-01-23-csrf-documentation-reorganization-and-session-snapshot-system)
- [2026-01-23: CI/CD pipeline documentation](#2026-01-23-cicd-pipeline-documentation)

## 2026-03-21: Sequential primary keys for oauth2_accounts and passkey_credentials

**Issue**: `2026-01-31-01` (completed) | **Priority**: low | **Difficulty**: medium

Database schema best practice alignment

### Motivation

The `users` table already used the recommended pattern of `sequence_number INTEGER PRIMARY KEY AUTOINCREMENT` with `id TEXT NOT NULL UNIQUE`. However, `oauth2_accounts` and `passkey_credentials` tables used TEXT columns (`id` and `credential_id` respectively) as primary keys directly. Sequential integer primary keys are a database design best practice for B-tree locality, space efficiency, and join performance -- regardless of current scale.

### User-facing impact

- **Before**: `oauth2_accounts` used `id TEXT PRIMARY KEY`, `passkey_credentials` used `credential_id TEXT PRIMARY KEY`
- **After**: Both tables use `sequence_number` as primary key with original TEXT identifiers as UNIQUE constraints

```sql
-- Before (oauth2_accounts):
id TEXT PRIMARY KEY NOT NULL,
user_id TEXT NOT NULL REFERENCES users(id),

-- After (oauth2_accounts):
sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,  -- SQLite
-- sequence_number BIGSERIAL PRIMARY KEY,            -- PostgreSQL
id TEXT NOT NULL UNIQUE,
user_id TEXT NOT NULL REFERENCES users(id),
```

**Breaking change**: Existing databases will need to be recreated (no migration provided). The `OAuth2Account` and `PasskeyCredential` structs now include `sequence_number: Option<i64>`.

Additionally, `sequence_number` is hidden from all JSON API responses via `#[serde(skip_serializing)]` on all three types (`User`, `OAuth2Account`, `PasskeyCredential`). The `User` type previously used `skip_serializing_if = "Option::is_none"` which leaked `sequence_number` in admin API responses -- investigation confirmed no JS or template code consumes this field from JSON.

### Design decisions

- **YAGNI does not apply**: Sequential integer primary keys are an established best practice, not a speculative feature. Deferring correct schema design is not the same as avoiding unnecessary features.
- **No migration**: This is a pre-1.0 library. Existing deployments can recreate tables. Migration complexity is not justified at this stage.
- **`Option<i64>` for sequence_number**: Matches the `users` table pattern. `None` when creating new records (database assigns the value), `Some(n)` when reading from database.
- **No query changes needed**: All queries use `SELECT *` with `FromRow` derive/impl, and INSERT statements don't specify `sequence_number` (auto-generated). The change is transparent to query logic.
- **No foreign key impact**: No other tables reference `oauth2_accounts.id` or `passkey_credentials.credential_id` via foreign keys. `login_history.credential_id` is denormalized without FK constraint.
- **`skip_serializing` over `skip_serializing_if`**: PR review identified that `sequence_number` was leaking to API responses. Investigation found: (1) admin templates use `TemplateUser.sequence_number` for first-user display -- this is server-side rendering, not JSON serialization; (2) `Json<Vec<DbUser>>` admin API is consumed by JS that only uses `user.id` and `user.account`; (3) `sequence_number` is an internal DB detail with no client-side use. Changed all three types to `skip_serializing` for consistency. Updated User's proptest roundtrip test to expect `None` after deserialization.
- **UNIQUE constraint provides index**: The original TEXT identifiers (`id`, `credential_id`) changed from PRIMARY KEY to UNIQUE constraint. Both SQLite and PostgreSQL automatically create an index for UNIQUE constraints, so no explicit `CREATE INDEX` is needed for these columns.

### Key files

`oauth2_passkey/src/oauth2/types.rs`, `oauth2_passkey/src/passkey/types.rs`, `oauth2_passkey/src/userdb/types.rs`, `oauth2_passkey/src/oauth2/storage/sqlite.rs`, `oauth2_passkey/src/oauth2/storage/postgres.rs`, `oauth2_passkey/src/passkey/storage/sqlite.rs`, `oauth2_passkey/src/passkey/storage/postgres.rs`

---

## 2026-03-20: Env var silent fallback audit -- panic on invalid values

**Issue**: `20260227-1703` (completed) | **Priority**: low | **Difficulty**: small

### Motivation

Optional environment variables using `.ok().and_then(|s| s.parse().ok()).unwrap_or()` silently fell back to defaults when set to unparseable values. Operators who set `SESSION_COOKIE_MAX_AGE=ten_minutes` would get the default 600 without any error or warning.

### What changed

Implemented Option B + C:
- **Option B**: 17 LazyLock env vars changed from silent fallback to panic on set-but-invalid values. Unset vars still use defaults.
- **Option C**: All optional config vars force-evaluated in `init()` functions, so invalid values are caught at startup, not on first request.
- **AUTH_SERVER_SECRET**: Replaced hardcoded default (`"default_secret_key_change_in_production"`) with random 32-byte key generation using `ring::rand::SystemRandom`.

| State | Behavior (before) | Behavior (after) |
|-------|-------------------|------------------|
| Env var not set | Default value | Default value (unchanged) |
| Set, valid value | That value | That value (unchanged) |
| Set, invalid value | Silent default | **Panic at startup** |

### Design decisions

- **B+C over A+C**: Option A (warn + continue) still hides the problem if operators don't read logs. Panic is consistent with required variables that already use `.expect()`.
- **`unwrap_or_else(\|e\| panic!(..., e))` over `expect(&format!(...))`**: clippy's `expect_fun_call` lint rejects `expect(&format!(...))` because `format!()` allocates even on the success path. `unwrap_or_else` only executes the closure on error, and we include the underlying parse error `e` in the message.
- **AUTH_SERVER_SECRET random default**: Single-process deployments work out of the box. Multi-process deployments must set the env var explicitly (documented).

### Key files

`oauth2_passkey/src/config.rs`, `oauth2_passkey/src/session/config.rs`, `oauth2_passkey/src/oauth2/config.rs`, `oauth2_passkey/src/passkey/config.rs`, `oauth2_passkey_axum/src/config.rs`, `oauth2_passkey_axum/src/cors.rs`, `oauth2_passkey/src/lib.rs`, `oauth2_passkey_axum/src/lib.rs`

---

## 2026-03-20: FedCM GIS library analysis and hang investigation

**Issue**: `20260316-1630` (deferred), `20260320-1410` (deferred)

### Motivation

FedCM `navigator.credentials.get()` hangs frequently on tabs open for a long time, causing the page to dim with no dialog and no recovery path. Reopened the deferred issue to investigate using Google's GIS library as a reference.

### What was done

1. **GIS library reverse engineering**: Fetched and beautified Google's GIS library (`accounts.google.com/gsi/client`, 254KB -> 7520 lines). Documented all FedCM-related functions, the abort mechanism, cooldown system, and error handling. Full analysis: `docs/src/archived/gis-fedcm-analysis.md`

2. **GIS alignment**: Aligned `credentials.get()` options with GIS -- added AbortController + signal, `federated` key (backward compat), `fields` property. These are kept in the codebase even though they don't fix the hang.

3. **Root cause investigation**: Explored multiple hypotheses:
   - Cooldown from prior FedCM cancel -- insufficient (hang occurs without prior cancel)
   - Login status mismatch -- Chrome's mismatch UI may fail to display ([Chromium #40070360](https://issues.chromium.org/issues/40070360))
   - Active mode error UI not implemented -- [Chromium #370796104](https://issues.chromium.org/issues/370796104)
   - **Tab count**: Closing excess browser tabs resolved the hang, suggesting Chrome resource constraints

4. **Timeout attempt**: Added 15s AbortController timeout, but reverted because the popup fallback gets blocked (User Activation expired after abort).

5. **New issue created**: `20260320-1410` for popup blocked on FedCM cancel fallback (User Activation timing problem). Also deferred.

### Design decisions

- **Deferred both issues**: Root cause still unclear (tab count? login status? Chrome resource limits?). Timeout reverted because no viable post-abort fallback exists yet.
- **GIS alignment kept**: Harmless improvements that match Google's own implementation.

### Key files

`oauth2_passkey_axum/static/oauth2.js`, `docs/src/archived/gis-fedcm-analysis.md`

---

## 2026-03-17: Cloud Run deploy optimization -- cargo-chef + BuildKit

**Issue**: `20260317-1500` | **Priority**: low | **Difficulty**: medium

Enhancement of CI/CD pipeline

### Motivation

Cloud Run deployment for passkey-demo.ccmp.jp took approximately 19-25 minutes per build. The bottleneck was full Rust compilation from scratch on every build -- Cloud Build's default machine (1 vCPU, 3.75 GB RAM) compiled all workspace dependencies (tokio, axum, sqlx, rustls, etc.) with zero caching because Docker layer caches don't persist between Cloud Build runs.

### User-facing impact

- **Before**: Every push to `dev` triggered a ~19 minute build via Cloud Build. No caching meant even a one-line `.rs` change required full recompilation of all dependencies.
- **After**: Cached builds complete in ~3.5 minutes (82% reduction). First build without cache takes ~11 minutes (still faster due to 4x CPU).

| Build | Method | Time |
|-------|--------|------|
| #30 | Cloud Build (old) | 19m 28s |
| #31 | BuildKit + cargo-chef (1st, no cache) | 11m 24s |
| #32 | BuildKit + cargo-chef (2nd, cached) | 3m 28s |

### Design decisions

**Option A (chosen): GitHub Actions BuildKit + cargo-chef**
- cargo-chef separates dependency compilation into its own Docker layer. When only `.rs` files change, the dependency layer cache hits and only the application code recompiles.
- BuildKit `type=gha` cache stores Docker layers in GitHub Actions cache storage, persisting across CI runs.
- `mode=max` caches all intermediate stages (not just final), which is essential for cargo-chef's dependency layer to be cached.

**Option B (rejected): Cloud Build with `--cache-from` + machine upgrade**
- `--cache-from` is image-level caching only -- intermediate stages (cargo-chef dependency layer) don't benefit.
- cargo-chef is incompatible with Kaniko (GoogleContainerTools/kaniko#1520), ruling out Cloud Build's best caching option.
- N1_HIGHCPU_8 upgrade would cost more and only improve to ~8-12 min.

**Workflow reordering**: Steps were grouped into two logical phases -- Docker build/push and Cloud Run deploy. GCP auth (`google-github-actions/auth`) moved closer to `gcloud` usage since `docker/login-action` authenticates independently via `_json_key` + SA key JSON.

**Cleanup**: Removed `demo-live/cloudbuild.yaml`, revoked unnecessary IAM roles (`cloudbuild.builds.editor`, `storage.admin`) from the GitHub Actions service account.

### Key files

`.github/workflows/deploy-demo.yml`, `demo-live/Dockerfile`, `demo-live/DEPLOY.md`

---

## 2026-03-17: FedCM stale tab hang issue deferred

**Issue**: `20260316-1630` | **Priority**: high | **Difficulty**: small

Not merged (deferred)

### Motivation

`navigator.credentials.get()` hangs indefinitely in stale tabs (likely from the passive mode era before `mode: 'active'` was added). The page dims but the FedCM account chooser never appears, the Promise never resolves or rejects, and the popup fallback never triggers. Only opening a new tab recovers.

### User-facing impact

- **Before**: Users in stale tabs see a dimmed, unresponsive page with no way to log in.
- **After**: No change (deferred). The issue remains for users with stale tabs, but these will naturally diminish over time as users open new tabs.

### Design decisions

**AbortController with 5-second timeout (rejected)**:
- Cannot distinguish between "FedCM UI hung" and "user is taking time to select an account". A user with multiple Google accounts who takes >5 seconds would be interrupted mid-selection and forced into the popup flow.

**Fallback link after delay (rejected)**:
- Showing a "Having trouble? Click here" link after a few seconds clutters the UI and is poor UX. Users may not notice it or understand what it means.

**Deferred because**:
- No way to programmatically detect whether the FedCM UI actually appeared (the browser API provides no such event or callback)
- The root cause is a Chrome bug (Promise should reject, not hang silently; active mode should not be subject to cooldown per Chrome's own docs)
- FedCM is still experimental support in this project
- Waiting for: error reproduction, Chrome improvements, or a novel detection approach

### Key files

`oauth2_passkey_axum/static/oauth2.js`

---

## 2026-03-15: Eliminate aws-lc-sys dependency

**Issue**: `20260315-0348` | **Priority**: high | **Difficulty**: small

Enhancement of build system -- dependency cleanup

### Motivation

The `aws-lc-sys` crate was pulled into the dependency tree by reqwest 0.13's default TLS configuration (`rustls` feature -> `aws-lc-rs` provider). This required CMake and a C++ compiler at build time, which broke `cargo build` on minimal environments, complicated cross-compilation, added significant build time, and was problematic for crates.io users who expect `cargo build` to just work.

The project already depended on `ring` directly (for WebAuthn signature verification), so switching rustls's crypto provider from aws-lc-rs to ring could eliminate aws-lc-sys without adding new dependencies.

### User-facing impact

- **Before**: `cargo build` failed on systems without CMake and a C++ compiler. aws-lc-sys pulled in ~20 transitive crates including cmake and quinn.
- **After**: `cargo build` works in minimal environments. No CMake or C++ compiler needed.

```toml
# Before: reqwest with default rustls (aws-lc-rs)
reqwest = { version = "0.13.2", features = ["rustls-tls"] }

# After: reqwest with ring-based rustls
reqwest = { version = "0.13.2", default-features = false, features = [
    "rustls-no-provider", "charset", "http2", "json", "cookies", "form", "system-proxy"
] }
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }
```

### Design decisions

**ring over RustCrypto for rustls provider**: ring was already a direct dependency (WebAuthn uses it). rustls-rustcrypto is experimental. Adding ring to rustls added no new dependencies.

**`rustls-no-provider` feature on reqwest**: reqwest 0.13 removed the `__rustls-ring` feature that 0.12 had. Only options were `rustls` (aws-lc-rs) or `rustls-no-provider`. This is the only way to avoid aws-lc-rs in reqwest 0.13.

**Explicit `install_default()` needed**: rustls 0.23 auto-detects aws_lc_rs as default but does NOT auto-detect ring (asymmetric design). Added `ensure_ring_provider()` that calls `install_default()` in `get_client()`. Used `builder_with_provider(ring)` in the bundled-tls path.

### Key files

`Cargo.toml`, `oauth2_passkey/Cargo.toml`, `oauth2_passkey/src/utils.rs`

---

## 2026-03-14: FedCM auto re-authentication rate limit fix

**Issue**: `20260314-0222` | **Priority**: high | **Difficulty**: small

Bug fix -- JavaScript frontend

### Motivation

When using FedCM for Google OAuth2 login, users occasionally encountered a critical UX failure: the browser window would become dimmed (grayed out) and completely unresponsive, with no FedCM account chooser UI appearing. The browser console showed the error: "Auto re-authn was previously triggered less than 10 minutes ago. Only one auto re-authn request can be made every 10 minutes."

The root cause was the browser's default `mediation: 'optional'` behavior, which allows automatic re-authentication attempts. When the 10-minute rate limit was hit, the FedCM API appeared to hang rather than rejecting cleanly, leaving the page in an unusable state with no recovery path except page reload.

### User-facing impact

- **Before**: On repeated FedCM login attempts within 10 minutes, the page would become unresponsive with a dimmed overlay. The FedCM UI would not appear, the fallback to popup flow would not trigger, and users were stuck requiring a manual page reload.
- **After**: FedCM login consistently shows the account chooser UI on every login attempt. The browser never attempts automatic re-authentication, preventing the rate limit error entirely.

```javascript
// Before: implicit mediation: 'optional' allows auto re-authn
const credential = await navigator.credentials.get({
  identity: {
    providers: [{ configURL, clientId, params: { nonce, ... } }],
    mode: 'active',
    context: 'signin',
  },
  // mediation defaults to 'optional' - triggers auto re-authn
});

// After: explicit mediation: 'required' prevents auto re-authn
const credential = await navigator.credentials.get({
  identity: {
    providers: [{ configURL, clientId, params: { nonce, ... } }],
    mode: 'active',
    context: 'signin',
  },
  mediation: 'required',  // Always require user interaction
});
```

### Design decisions

**Single-parameter solution (final)**: After initially implementing both `mediation: 'required'` (login) and `preventSilentAccess()` (logout) as defense-in-depth, testing revealed that `preventSilentAccess()` had no observable effect when `mediation: 'required'` was set. The architectural principle "behavior should be controlled by the mediation parameter" led to removing the logout helper entirely.

**Why simplicity won over defense-in-depth**:
- `mediation: 'required'` already prevents auto re-authn completely
- `preventSilentAccess()` adds no value when mediation is set to `'required'`
- Having two mechanisms for the same goal creates confusion about which controls behavior
- Ad-hoc template modifications (injecting logout handlers) don't work reliably with custom templates
- Single parameter (`mediation`) provides complete, unambiguous control

**Initial approach (rejected)**: Attempted to add a `logout()` helper function calling `navigator.credentials.preventSilentAccess()` before logout. Discovered this wouldn't be called by existing templates (e.g., `user_account.j2` uses its own `Logout()` function). This highlighted the brittleness of ad-hoc solutions that depend on templates adopting new patterns.

**Evolution of approach**:
1. Identified auto re-authn as root cause → added `mediation: 'required'`
2. Applied defense-in-depth → added `preventSilentAccess()` logout helper
3. Testing showed preventSilentAccess not being called (template incompatibility)
4. Architectural review questioned whether logout hook interferes with parameter control
5. Final decision: remove preventSilentAccess, rely solely on `mediation: 'required'`

The decision log in issue `20260314-0222` preserves this evolution for future reference.

### Key files

`oauth2_passkey_axum/static/oauth2.js`, `docs/src/integration/fedcm.md`

---

## 2026-03-13: FedCM (Federated Credential Management) integration

**Issue**: `20260311-1039` | **Priority**: low | **Difficulty**: medium

New feature -- Core library + Axum integration

### Motivation

FedCM is a W3C browser API (`navigator.credentials.get({ identity: { providers: [...] } })`) that provides a browser-native UI for federated authentication, eliminating the need for redirect-based popups. It is designed to maintain federated identity flows after third-party cookie deprecation.

While this project uses direct OAuth2 Authorization Code Flow + PKCE (not Google Identity Services SDK), FedCM offers an alternative login path with a better UX on supported browsers (Chrome 108+, Edge 136+). Safari and Firefox do not support FedCM, so fallback to the existing popup-based flow is mandatory.

The primary benefit is UX: a browser-native account chooser instead of a popup window. There is no security improvement -- in fact, the security model differs because FedCM receives a JWT ID token directly in JavaScript rather than exchanging an authorization code server-to-server with a client secret.

### User-facing impact

- **Before**: Google OAuth2 login always used a popup window with redirect-based Authorization Code Flow + PKCE.
- **After**: On supported browsers, a browser-native FedCM account chooser appears instead of a popup. On unsupported browsers, the existing popup flow is used automatically. FedCM is disabled by default and opt-in via `O2P_FEDCM=true` environment variable. Login history now distinguishes "FedCM" from "OAuth2" as the authentication method.

New environment variable:
```bash
# Enable FedCM (disabled by default)
O2P_FEDCM=true  # or "enabled"
```

The FedCM flow introduces two new endpoints:
```
GET  /o2p/oauth2/fedcm/nonce     -> { "nonce": "...", "nonce_id": "..." }
POST /o2p/oauth2/fedcm/callback  -> { "token": "...", "nonce_id": "...", "mode": "active"|"passive" }
```

Frontend JavaScript automatically detects FedCM support via `IdentityCredential` existence and `navigator.credentials.get` availability. No application code changes needed.

### Design decisions

**Google returns JWT, not authorization code**: Unlike the OAuth FedCM Profile (Aaron Parecki) which returns authorization codes, Google's FedCM endpoint (`/gsi/fedcm/issue`) returns a JWT ID token directly. This means PKCE and code exchange are bypassed entirely in the FedCM path. The existing `idtoken.rs` JWT signature verification (JWKS, aud, iss, exp, nonce) is directly reused.

**Runtime toggle, not compile-time feature flag**: FedCM is controlled by the `O2P_FEDCM` environment variable at runtime rather than a Cargo feature flag. This was chosen because FedCM shares most code with the existing OAuth2 flow and adds minimal overhead when disabled. The JS configuration is injected dynamically via `serve_oauth2_js()`.

**Coordination layer refactoring**: Extracted `process_authenticated_oauth2_user()` from the existing `process_oauth2_authorization()` so both the OAuth2 callback and FedCM callback share user creation/linking/session logic. This avoids duplicating ~50 lines of complex user processing.

**Shared nonce infrastructure**: Both OAuth2 and FedCM use the same nonce generation (`generate_store_token()`) and verification (`verify_and_consume_nonce()`) pattern. A follow-up issue (`20260312-1948`) analyzed whether FedCM's `nonce_id` could be eliminated since it lacks the CSRF-verified state binding that OAuth2 has, but this was deferred because it would reduce code sharing between the two flows.

**Undocumented Google params discovered**: Google's FedCM requires `response_type: 'id_token'`, `scope: 'email profile openid'`, and `ss_domain: location.origin` in the `params` object. These are not documented in any public API reference and were discovered by reverse-engineering Google's GIS library.

**`mode: 'active'` placement bug**: Initially placed `mode: 'active'` inside the provider object instead of at the `identity` level. Chrome silently ignored the unrecognized field, defaulting to passive mode. In passive mode, user dismissal triggers an exponential cooldown embargo (2h, 1d, 7d, 28d). Root cause was confirmed by reading Chromium source (`request_service.cc` embargo guard: `should_embargo &= rp_mode_ == RpMode::kPassive`). Fixed by moving `mode` to the correct level.

**Google returns JSON-wrapped JWT**: `credential.token` from Google is `{"token":"eyJ..."}`, not a raw JWT string. The JavaScript must parse this JSON before sending to the backend.

### Key files

`oauth2_passkey/src/oauth2/main/fedcm.rs`, `oauth2_passkey/src/coordination/oauth2.rs`, `oauth2_passkey/src/oauth2/types.rs`, `oauth2_passkey/src/oauth2/main/utils.rs`, `oauth2_passkey_axum/src/oauth2.rs`, `oauth2_passkey_axum/static/oauth2.js`, `oauth2_passkey/src/coordination/oauth2/tests.rs`, `docs/src/integration/fedcm.md`

---

## 2026-03-11: GitHub Actions security hardening

**Issue**: `20260311-0904` | **Priority**: low | **Difficulty**: easy

Enhancement (security) -- CI/CD infrastructure

### Motivation

Prompted by the "hackerbot-claw" AI-powered attack campaign (February 2026) that exploited GitHub Actions vulnerabilities in major OSS repositories. While this repository had no critical vulnerabilities (no `pull_request_target`, no external input in `run:` steps, no self-hosted runners), an audit identified three Warning-level issues requiring defense-in-depth hardening.

### User-facing impact

- **Before**: Three workflow files (`ci.yml`, `coverage.yml`, `deploy-demo.yml`) relied on repository default permissions. `deploy-demo.yml` used direct `${{ }}` expansion in `run:` steps for secrets and env vars.
- **After**: All workflows have explicit `permissions: contents: read`. `deploy-demo.yml` passes secrets through `env:` blocks instead of direct template expansion, and uses shell variable references (`$VAR`) instead of `${{ env.VAR }}` for proper escaping.

```yaml
# Before (deploy-demo.yml):
run: |
  gcloud run deploy $SERVICE \
    --image ${{ env.REGION }}-docker.pkg.dev/${{ secrets.GCP_PROJECT_ID }}/demo/${{ env.SERVICE }}

# After:
env:
  GCP_PROJECT_ID: ${{ secrets.GCP_PROJECT_ID }}
run: |
  gcloud run deploy "$SERVICE" \
    --image "${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/demo/${SERVICE}"
```

### Design decisions

**Explicit permissions over defaults**: Even though repository defaults were safe, explicit `permissions: contents: read` prevents privilege escalation if defaults are changed later. `docs.yml` already had explicit permissions and required no changes.

**Shell variable references over template expansion**: Direct `${{ }}` expansion in `run:` bypasses shell escaping, creating command injection surface. While GCP project IDs are alphanumeric (low risk), establishing the pattern prevents future secrets from being mishandled. Shell variables (`$VAR`) benefit from proper quoting.

### Key files

`.github/workflows/ci.yml`, `.github/workflows/coverage.yml`, `.github/workflows/deploy-demo.yml`

---

## 2026-03-04: AAGUID collision fix -- replace server-side deletion with excludeCredentials

**Issue**: `20260226-2030` | **Priority**: low | **Difficulty**: medium

Bug fix -- Core library + Axum integration

### Motivation

The passkey re-registration flow had a correctness bug: credentials were deleted based on AAGUID (Authenticator Attestation GUID) matching. AAGUID identifies the authenticator *type* (e.g., "Google Password Manager"), not individual instances. When a user had multiple instances of the same authenticator type (e.g., Google Password Manager on two different Google accounts), re-registering would incorrectly delete the other credential.

**Scenario**: User registers a passkey with Google PM (Account A), then registers another with Google PM (Account B). Step 2 deleted the credential from step 1 (same AAGUID match), silently losing access via Account A's Password Manager.

### User-facing impact

- **Before**: Re-registering a passkey with the same authenticator type (same AAGUID) silently deleted existing credentials from that authenticator type. Users could lose passkey access without realizing it.
- **After**: All credentials coexist regardless of AAGUID. The browser's `excludeCredentials` mechanism prevents true duplicates (authenticator returns `InvalidStateError` if the exact credential already exists). Users can manually delete unwanted credentials from the account management page.

The `excludeCredentials` field is now populated in all registration flows (not just passkey promotion), so the browser-native "credential already registered" error appears consistently.

### Design decisions

**Remove server-side AAGUID-based deletion entirely**: AAGUID-based deletion is fundamentally unsafe because the AAGUID is only revealed *after* registration completes (in the attestation response), so the server cannot pre-filter reliably. No major WebAuthn implementation recommends this approach.

**Stale credentials are harmless**: Old credentials remain in the database but the authenticator returns the correct (newest) credential during authentication. No data loss or security impact.

**Rejected alternatives**: (1) Login-credential-aware deletion -- fails when device's default Password Manager differs from the one used for login. (2) OAuth2 account tracking with passkey credentials -- unreliable because OAuth2 login account and device's active PM are independent.

**Unified excludeCredentials**: Removed duplicate `excludeCredentials` population code from the Axum promotion handler. The core library's `start_registration()` now handles it for all modes, providing a single source of truth.

### Key files

`oauth2_passkey/src/passkey/main/register.rs`, `oauth2_passkey/src/passkey/main/types.rs`, `oauth2_passkey_axum/src/passkey/promotion.rs`, `oauth2_passkey_axum/static/passkey.js`, `oauth2_passkey/src/passkey/main/register/tests.rs`

---

## 2026-03-03: Issue triage -- wontfix and deferral decisions

**Issue**: N/A (housekeeping) | **Priority**: N/A | **Difficulty**: N/A

Housekeeping -- Issue management

### Motivation

After migrating 11 issues from the legacy `ToDo.md` (see 2026-02-27 entry), the backlog needed triage to separate actionable work from speculative features. Three issues were evaluated against the YAGNI principle.

### User-facing impact

- **Before**: 3 open issues in the backlog with no clear resolution path.
- **After**: Backlog reduced by 3 issues. Two features explicitly decided against (wontfix), one deferred as out-of-scope. Decision rationale documented for future reference.

### Design decisions

**UI Improvements (20260226-2026) -> wontfix**: The built-in UI is a reference implementation; library users build their own frontends. The existing 9 CSS themes and custom CSS support are sufficient. Investing in toast notifications or polished UI is not justified for a library crate.

**Authentication Method Tracking in Session (20260226-2023) -> wontfix**: Reviewed all proposed use cases and found none actionable: (1) Step-up auth is not meaningful when both OAuth2 and Passkey rely on password managers as trust anchors. (2) No concrete scenario where UI needs to differ by auth method. (3) Security audit trails already covered by login history records. (4) Passkey promotion works without session-level tracking.

**OAuth2 Token Storage (20260226-2022) -> deferred**: Outside library scope as an authentication library (not an OAuth2 API client). Token storage is only needed when the backend calls provider APIs on behalf of users, which is application-level concern.

### Key files

`.claude/issues/wontfix/20260226-2026-ui-improvements.md`, `.claude/issues/wontfix/20260226-2023-auth-method-tracking-in-session.md`, `.claude/issues/deferred/20260226-2022-oauth2-token-storage.md`

---

## 2026-02-27: Documentation cleanup, issue system migration, and tooling

**Issue**: N/A (housekeeping) | **Priority**: N/A | **Difficulty**: N/A

Housekeeping -- Documentation and project infrastructure

### Motivation

Multiple documentation debts accumulated before the v0.3.0 release: stale version numbers across docs, legacy `ToDo.md` with untracked tasks, inaccurate appendices, no automated version checking for releases, and no guidance for LazyLock environment variable patterns. This was a focused cleanup sprint (2/24-2/27) addressing these across 5 PRs (#239-#244).

### User-facing impact

- **Before**: Documentation referenced version 0.2/0.4 inconsistently. Appendices on type-safe validation and storage patterns contained inaccurate claims. No tooling to prevent version skew in releases. Developer guidance on LazyLock env var handling was missing.
- **After**: All docs consistently reference v0.3.0. Two appendices rewritten for accuracy and motivation-first structure. `utils/update_doc_versions.sh` automates bulk version updates with auto-detection from `Cargo.toml`. `utils/release.sh` includes `check_doc_versions()` for pre-release validation. LazyLock force-evaluation guideline documented.

**Issue system migration**: 11 tasks from legacy `ToDo.md` migrated to structured issue files with priority, difficulty, decision logs, and implementation tasks. `ToDo.md` moved to `docs/src/archived/`. Also created tracking issues for DBSC (Device Bound Session Credentials) and env var silent fallback audit.

**Appendix rewrites**:
- Type-safe validation: Replaced inaccurate claims about session validation with factual descriptions. Added newtype pattern code examples and enum definitions with rationale.
- Storage pattern: Reorganized around motivation (why singleton over Axum State). Replaced verbose comparison tables with concise prose.

**Other changes**: Removed mdbook chapter number prefixes from 11 files. Added demo GIF animations to README. Fixed GitHub URL (anthropics/ -> ktaka-ccmp/).

### Design decisions

**Issue system over ToDo.md**: Structured issue files with decision logs provide better traceability than a flat task list. Each issue captures priority, difficulty, approach, and decision history, enabling better triage and context transfer across sessions.

**Version tooling approach**: `update_doc_versions.sh` auto-detects current version from `Cargo.toml` (removes `-dev` suffix) and performs bulk `sed` replacement across all doc files. `check_doc_versions()` in `release.sh` validates before publishing, catching version skew before it reaches crates.io.

### Key files

`utils/update_doc_versions.sh`, `utils/release.sh`, `docs/src/appendix/type-safe.md`, `docs/src/appendix/storage-pattern.md`, `docs/src/maintainer/development.md`, `.claude/issues/README.md`, `Readme.md`

---

## 2026-02-23: Core crate functional-layer tests for _core() functions

**Issue**: `20260223-0027` | **Priority**: low | **Difficulty**: large

Enhancement (test coverage) -- Core library

### Motivation

After moving all HTTP integration tests to the Axum crate (issue `20260213-0145`), the core crate had zero integration-level tests for its `_core()` coordination functions. These functions are the public API contract between the core library and the Axum integration layer. Changes to core logic could only be detected by the Axum crate's HTTP-level tests, not by the core crate's own test suite.

The core crate had extensive unit tests (40+ files) covering individual components (storage, type conversions, session management, crypto), but no tests that exercised the coordination-layer `_core()` functions with real (in-memory) storage backends.

### User-facing impact

- **Before**: The core crate had 509 tests, all unit-level. No test directly called `_core()` coordination functions. Core logic regressions were only detectable through the Axum crate's HTTP integration tests.
- **After**: 23 new functional-layer tests added. The core crate now has 531 tests. All 11 critical `_core()` functions are tested directly with real in-memory storage (SQLite + memory cache) and zero HTTP/Axum dependency.

### Design decisions

**Passkey tests (15 tests)**: A fixed ECDSA P-256 key pair was used to construct binary-level `auth_data`, CBOR attestation responses ("none" format), and ECDSA-signed assertion responses. Negative security tests verify that a tampered signature (flipped byte in the r-value) and challenge mismatch are correctly rejected.

**OAuth2 tests (6 tests)**: A minimal mock OAuth2 server (~250 lines) was implemented directly in the test file, running on port 19876 (distinct from the Axum crate's mock on port 9876). The mock server provides 4 endpoints (auth, token, JWKS, userinfo), uses HS256 JWT signing, and validates PKCE S256 challenges with nonce correlation. Environment variable overrides use `dotenvy::from_filename_override` to avoid the `unsafe` constraint on `std::env::set_var` in Rust 2024 edition.

**idtoken tests (2 tests)**: Existing `idtoken/tests.rs` had 23 tests covering format and Base64 errors for `verify_signature`, but lacked tests for cryptographic validation. Two tests were added: one verifying a valid HS256 signature is accepted, and one verifying that the wrong key is rejected.

**Code reviews**: Two formal code reviews were conducted:

- Review 1: 9 findings. 6 addressed (MockUserGuard RAII for panic safety, parameterized `drive_oauth2_flow` with `extra_request_headers`, deleted redundant test, strengthened start-* test assertions with challenge/rpId/user_handle checks, fixed `rp_id` from `"localhost"` to `"127.0.0.1"`, added doc comment for placeholder public key). 3 accepted as-is (env var override impractical to restore, helper duplication unavoidable across sibling modules, fixture duplication deliberate for architecture boundary).
- Review 2: 3 findings. 1 partially addressed (passkey negative security tests added; OAuth2 JWT negative tests deferred to `idtoken.rs` unit-test level). 2 accepted as-is (mock server graceful shutdown unnecessary for test infrastructure, TCP polling sufficient for readiness detection).

### Key files

`oauth2_passkey/src/coordination/oauth2/tests.rs`, `oauth2_passkey/src/coordination/passkey/tests.rs`, `oauth2_passkey/src/oauth2/main/idtoken/tests.rs`

---

## 2026-02-23: Security test crate placement correction

**Issue**: `20260213-0145` | **Priority**: low | **Difficulty**: medium

Refactoring (architecture) -- Workspace restructuring

### Motivation

Triggered on Feb 13 when changing OAuth2 callback error handling from `400 Bad Request` to `303 See Other` (popup UX improvement). The change was purely in `oauth2_passkey_axum/src/oauth2.rs` (HTTP handler layer), yet it broke 14 test assertions in `oauth2_passkey/tests-security/` (core crate). This exposed an architectural boundary violation: core crate tests were testing HTTP-level behavior.

Investigation revealed that every test in `oauth2_passkey/tests/` and `oauth2_passkey/tests-security/` used `TestServer` (Axum HTTP server) + `MockBrowser` (reqwest HTTP client). Not a single test called core library `_core()` functions directly. The core crate had `oauth2-passkey-axum` as a dev-dependency, creating a reverse dependency.

### User-facing impact

- **Before**: The core crate (`oauth2_passkey`) had a dev-dependency on the Axum crate (`oauth2-passkey-axum`), creating a reverse dependency. HTTP-layer changes in the Axum crate broke tests in the core crate.
- **After**: All HTTP integration tests reside in the Axum crate where they belong. The core crate's dev-dependencies were reduced from 9 to 2 (`serial_test`, `proptest`). The reverse dependency is eliminated. HTTP-layer changes only affect tests in the HTTP-layer crate.

### Design decisions

All 27 test files (10 common utilities, 6 integration tests, 11 security tests) were moved from `oauth2_passkey/` to `oauth2_passkey_axum/`. The directory structure was preserved so `#[path]` references continued to work without modification. No code changes to test files were required.

The core crate retains 40+ unit test files in `src/` that have zero dependency on Axum -- these remained in place.

Verification: 629 tests passed (509 unit + 10 integration + 21 security + 56 lib + 33 doc), zero clippy warnings.

### Key files

`oauth2_passkey/Cargo.toml`, `oauth2_passkey_axum/Cargo.toml`, `oauth2_passkey_axum/tests/`, `oauth2_passkey_axum/tests-security/`

---

## 2026-02-22: Early evaluation of OAUTH2_RESPONSE_MODE at startup

**Issue**: `20260222-2201` | **Priority**: low | **Difficulty**: easy

Enhancement (developer experience) -- Core library

### Motivation

`OAUTH2_RESPONSE_MODE` is a `LazyLock<String>` that panics on invalid values (anything other than `form_post` or `query`). Because it is lazily evaluated, a typo such as `OAUTH2_RESPONSE_MODE=frm_post` is not detected until the first OAuth2 login attempt at runtime, resulting in a confusing panic far from application startup.

This was discovered during a comprehensive audit of all `LazyLock` variables with `panic!`/`expect!` during issue `20260222-1315`. Every other panic-capable config variable was already evaluated during `init()`, but `OAUTH2_RESPONSE_MODE` was missed.

### User-facing impact

- **Before**: `OAUTH2_RESPONSE_MODE=frm_post` (typo) -- Application starts normally. First OAuth2 login attempt causes a runtime panic: `Invalid OAUTH2_RESPONSE_MODE 'frm_post'. Must be 'form_post' or 'query'.`
- **After**: Same typo -- Application panics immediately at startup with the same clear error message, before serving any requests.

### Design decisions

Added `let _ = *config::OAUTH2_RESPONSE_MODE;` to `oauth2::init()` in the core crate, consistent with how all other environment variables are force-evaluated at startup. One-line change.

### Key files

`oauth2_passkey/src/oauth2/mod.rs`, `oauth2_passkey/src/oauth2/config.rs`

---

## 2026-02-22: user-ui feature flag granularity improvement

**Issue**: `20260222-1316` | **Priority**: low | **Difficulty**: medium

Enhancement (breaking change) -- Axum integration crate

### Motivation

The `user-ui` feature flag controlled four routes as a single unit. `demo-live` has its own custom login page at `/login` but needed `user-ui` enabled for account management (`/account`) and admin pages. This forced the built-in login page (`/o2p/user/login`) to also be enabled and accessible, even though it was unused and unwanted.

### User-facing impact

- **Before**: Enabling `user-ui` enabled both the built-in login page and account management pages. Disabling it removed both. There was no way to selectively enable only account management.
- **After**: Three independent feature flags (`login-ui`, `user-ui`, `admin-ui`) allow granular control. Applications with custom login pages can disable only the built-in login page.

```toml
# Before: No way to disable just the login page
[dependencies]
oauth2-passkey-axum = { version = "0.3" }  # user-ui enables /login + /account

# After: login-ui excluded, account + admin retained
[dependencies]
oauth2-passkey-axum = { version = "0.3", default-features = false, features = ["user-ui", "admin-ui"] }
# /account and /admin are enabled, built-in /login is disabled
```

### Design decisions

The module `user/optional.rs` (4 routes in one file) was split into two modules:

- `user/login.rs` (gated by `login-ui`): `/login` route only
- `user/account.rs` (gated by `user-ui`): `/account`, `/account.js`, `/o2p-base.css`

The meaning of `user-ui` changed from "all user UI" to "account management UI only." No backward compatibility shims were added since the library is pre-1.0.

CI was extended with all feature combination tests (`--all-features`, `--no-default-features`, each flag individually) to ensure all combinations compile and pass.

### Key files

`oauth2_passkey_axum/Cargo.toml`, `oauth2_passkey_axum/src/user/mod.rs`, `oauth2_passkey_axum/src/user/login.rs`, `oauth2_passkey_axum/src/user/account.rs`, `demo-live/Cargo.toml`

---

## 2026-02-22: Make O2P_LOGIN_URL functional in middleware

**Issue**: `20260222-1315` | **Priority**: medium | **Difficulty**: medium

Enhancement (breaking change) -- Axum integration crate

### Motivation

`O2P_LOGIN_URL` existed as a convenience constant but was not used by middleware or the `AuthUser` extractor. Unauthenticated users were redirected to `O2P_DEFAULT_REDIRECT` (default: `/`), forcing a 2-hop redirect chain: `protected route -> middleware -> "/" -> app's "/" handler -> login page`. This made application code unnecessarily complex and contradicted the documented behavior.

### User-facing impact

- **Before**: Applications had to implement manual redirect logic in their `/` handler to forward unauthenticated users to the login page. The `index()` handler required `Option<AuthUser>` with a `None` branch implementing the redirect (~13 lines).
- **After**: Middleware directly redirects unauthenticated users to `O2P_LOGIN_URL`. Applications can use `AuthUser` (non-optional) in their `index()` handler (~3 lines), as unauthenticated requests never reach the handler.

```rust
// Before: Application implements manual redirect (~13 lines)
async fn index(user: Option<AuthUser>) -> impl IntoResponse {
    match user {
        Some(user) => { /* render page */ }
        None => Ok(Redirect::to(O2P_LOGIN_URL.as_str()).into_response())
    }
}

// After: Middleware handles redirect, handler is simplified (~3 lines)
async fn index(user: AuthUser) -> impl IntoResponse {
    /* render page -- unauthenticated users never reach here */
}
```

After this change, the two environment variables have clearly distinct roles:

| Variable | Role | Default |
|----------|------|---------|
| `O2P_LOGIN_URL` | Where to send **unauthenticated** users | `/o2p/user/login` |
| `O2P_DEFAULT_REDIRECT` | Where to send **authenticated** users (away from login page, after logout) | `/` |

**Breaking change**: Applications that relied on `O2P_DEFAULT_REDIRECT` to control where unauthenticated users go need to set `O2P_LOGIN_URL` instead.

### Design decisions

A redirect loop issue was discovered during implementation: when `login-ui` is disabled and `O2P_LOGIN_URL` is not set, the default `/o2p/user/login` route does not exist, causing the middleware to redirect to a non-existent page, which falls back to `/`, which triggers the middleware again -- an infinite loop (`ERR_TOO_MANY_REDIRECTS`). The solution was to add a `panic!()` in the `LazyLock` initializer when `login-ui` is disabled and the environment variable is not set, with an `init()` wrapper for early evaluation at startup. This converts a confusing runtime redirect loop into a clear startup error message.

### Key files

`oauth2_passkey_axum/src/middleware.rs`, `oauth2_passkey_axum/src/session.rs`, `oauth2_passkey_axum/src/config.rs`, `demo-both/src/main.rs`, `demo-live/src/main.rs`

---

## 2026-02-22: O2P_LOGIN_URL role clarification and user-ui feature investigation

**Issue**: `20260216-1500` | **Priority**: medium | **Difficulty**: medium

Investigation/Analysis -- Axum integration crate

### Motivation

While reviewing `dot.env.example` comments and feature flags, two problems were discovered:

1. `O2P_LOGIN_URL` was defined in `config.rs` and publicly exported, but never used internally by the library. Documentation stated it was "required for custom login pages to work," which was misleading. Middleware and the `AuthUser` extractor redirected unauthenticated users to `O2P_DEFAULT_REDIRECT` (default: `/`), not `O2P_LOGIN_URL`.

2. The `user-ui` feature flag controlled four routes (`/login`, `/account`, `/account.js`, `/o2p-base.css`) as a single unit. There was no way to disable only the built-in login page while keeping account management pages.

### User-facing impact

- **Before**: Two latent issues existed but were worked around by application developers implementing manual redirect chains.
- **After**: The problems were formally documented and split into two independent issues for resolution: `20260222-1315` (runtime environment variable) and `20260222-1316` (compile-time feature flag).

### Design decisions

Git history investigation traced `O2P_LOGIN_URL` back to the original `O2P_REDIRECT_ANON`, which was actively used by middleware. Commit `402cf8b` (2025-04-04, "refactor: unify demo implementations") split it into `O2P_LOGIN_URL` (login page URL, removed from middleware) and a new `O2P_REDIRECT_ANON` (redirect target, default `/`). This split disconnected `O2P_LOGIN_URL` from functional use.

The two problems were split into separate issues because they affect different layers: runtime environment variables vs. compile-time feature flags. Fixing the environment variable problem (making `O2P_LOGIN_URL` functional) largely eliminated the urgency of the feature flag problem.

### Key files

`oauth2_passkey_axum/src/config.rs`, `oauth2_passkey_axum/src/middleware.rs`, `oauth2_passkey_axum/src/session.rs`

---

## 2026-02-21: Full masking for email and name in demo mode

**Issue**: `20260220-2357` | **Priority**: medium | **Difficulty**: small

Enhancement -- Axum integration crate

### Motivation

The partial masking implemented on Feb 14 (e.g., `u***@***`, `J*** S***`) exposed the first character of email and name fields. On a public demo site where strangers share the same instance, even a single character can help narrow down identities. This contradicted the login page's "masked for privacy" promise.

### User-facing impact

- **Before**: Other users' emails displayed as `u***@***`, names as `J*** S***`, and OAuth2 profile pictures were shown.
- **After**: Other users' emails display as `***`, names as `***`, and profile pictures are hidden.

Self-view remains fully unmasked.

| Field | Before | After |
|-------|--------|-------|
| Email (Account) | `u***@***` | `***` |
| Name (Label) | `J*** S***` | `***` |
| Profile picture | Visible | Hidden |

### Design decisions

`mask_email()` and `mask_name()` were simplified to return `"***"` unconditionally. For profile pictures, a new `Masker::redact()` method returns an empty string. Since templates already guard with `{% if picture != "" %}`, an empty string suppresses the image tag entirely without requiring template modifications.

### Key files

`oauth2_passkey_axum/src/admin/masking.rs`, `oauth2_passkey_axum/src/admin/optional.rs`

---

## 2026-02-20: Demo login page informational notice

**Issue**: `20260220-2252` | **Priority**: medium | **Difficulty**: small

Enhancement -- Demo application (template only)

### Motivation

The demo site login page had no explanation of the demo environment. Users logging in with their Google account had no visibility into what happens after registration -- admin privileges, data masking, storage ephemerality, or self-deletion options.

### User-facing impact

- **Before**: Login page showed only authentication buttons with no context about the demo environment.
- **After**: An "About this demo" section appears below the authentication buttons, explaining: admin privileges for all users, data masking for privacy, memory-based storage (data resets on restart), and account self-deletion from the My Account page.

### Design decisions

The notice is placed below the primary login buttons so it does not interfere with the main authentication flow. Subdued styling (`text-secondary`, smaller font) keeps it unobtrusive. Four bullet points provide scannability. The change is template-only with zero modifications to the core library.

### Key files

`demo-live/templates/login.j2`

---

## 2026-02-16: Release v0.3.0

**Issue**: `20260216-1730` | **Priority**: high | **Difficulty**: medium

Release -- Core library and Axum integration crate

### Motivation

Changes accumulated since v0.2.0 were substantial, including 4 breaking changes. Under semver 0.x conventions, breaking changes require a minor version bump, making a patch release (0.2.1) inappropriate.

### User-facing impact

- **Before**: v0.2.0 published on crates.io.
- **After**: v0.3.0 published on crates.io for both `oauth2-passkey` and `oauth2-passkey-axum`.

Major new features: login history (IP/UA recording, admin panel display), passkey promotion (OAuth2 login prompts passkey registration), demo mode (`O2P_DEMO_MODE`), admin force logout, CSS theme support, feature flags (`user-ui`, `admin-ui`).

Four breaking changes requiring migration:

| Category | v0.2.0 | v0.3.0 |
|----------|--------|--------|
| Environment variable | `O2P_REDIRECT_ANON` | `O2P_DEFAULT_REDIRECT` |
| Environment variable | `O2P_SESSION_CONFLICT_POLICY` | `SESSION_CONFLICT_POLICY` |
| Admin route | `/admin/list_users` | `/admin/index` |
| user_handle default | `PASSKEY_USER_HANDLE_UNIQUE` = `true` | `PASSKEY_USER_HANDLE_UNIQUE` = `false` |

Bug fixes included the JWKS cache expiry deadlock (`tokio::sync::Mutex` reentrant locking) and SQLite in-memory pool connection eviction (connections cycling caused in-memory database destruction).

### Design decisions

Release procedure followed the documented workflow: finalize `CHANGELOG.md`, merge `dev` to `master` via PR, dry-run `release.sh`, execute release (publishes `oauth2-passkey` first, waits for crates.io availability, then publishes `oauth2-passkey-axum` with updated dependency), create tag `v0.3.0`, set dev version to `0.3.1-dev`.

### Key files

`Cargo.toml`, `CHANGELOG.md`, `utils/release.sh`

---

## 2026-02-14: Demo site UI/UX customization with O2P_DEMO_MODE

**Issue**: `20260210-1935` | **Priority**: medium | **Difficulty**: medium

New feature -- Core library and demo application

### Motivation

The public demo site (passkey-demo.ccmp.jp) needed UI/UX adaptations for an environment where strangers share the same instance. Requirements included: (1) all users should experience admin functionality, (2) other users' personal information must be protected, (3) the first user should be created via OAuth2 to ensure a linked Google account.

### User-facing impact

- **Before**: No demo mode concept. All user data was visible in the admin panel. New users were created with `is_admin: false`. Making all users admin required custom code.
- **After**: Setting `O2P_DEMO_MODE=true` enables: (a) all new users are automatically promoted to admin so they can explore full functionality, (b) other users' sensitive data (email, IP, user agent, credential IDs) is masked in admin views via server-side processing, (c) the user's own data remains unmasked.

### Design decisions

**Single `O2P_DEMO_MODE` environment variable**: Initially, separate variables for admin defaults and masking were considered (`O2P_NEW_USER_DEFAULT_ADMIN` + a masking toggle). However, enabling admin defaults without masking would expose all user data to everyone. A single toggle ensures both behaviors are always paired, preventing misconfiguration.

**Backend masking over client-side masking**: CSS/JS masking was considered but rejected because DevTools can trivially bypass it. Masking is performed in Axum handlers before response generation, so unmasked data never reaches the client.

**`Masker` struct**: A dedicated struct consolidates all masking logic, reducing `O2P_DEMO_MODE` references from 4 locations across 3 files to 2 locations in 1 file.

**OAuth2-only first user via UI design, not API gating**: Rather than adding an API-level enforcement in the core library, the custom login page (`demo-live/templates/login.j2`) only shows "Sign in with Google" and "Create account with Google" buttons. This avoids core library pollution while effectively achieving OAuth2-first registration.

### Key files

`oauth2_passkey/src/config.rs`, `oauth2_passkey_axum/src/admin/masking.rs`, `demo-live/src/main.rs`, `demo-live/templates/login.j2`

---

## 2026-02-13: OAuth2 popup error handling UX improvement

**Issue**: `2026-02-09-02` | **Priority**: medium | **Difficulty**: medium

Enhancement -- Axum integration crate

### Motivation

When an OAuth2 operation failed in the popup window (e.g., user tries to log in but is not registered, or tries to create an account that already exists), the error handling was poor: raw HTTP error text was shown in the popup, the popup did not close (no `postMessage('auth_complete')` was sent), the parent page was stuck, and `Conflict` errors returned 500 (Internal Server Error) instead of 409.

### User-facing impact

- **Before**: OAuth2 errors in popup showed raw HTTP error text (e.g., "Conflict: This OAuth2 account is not registered"). The popup remained open indefinitely. The parent page never refreshed. `Conflict` errors returned HTTP 500.
- **After**: OAuth2 errors redirect to `popup_close` with a styled error page using `login-card` styling. Error messages are user-friendly (e.g., "This account is not registered. Please create an account first."). On success, `postMessage('auth_complete')` is sent and the popup auto-closes. On error, a red-styled message with a Close button is shown, and `postMessage` is skipped to avoid unnecessary parent reload. `Conflict` errors correctly return HTTP 409.

### Design decisions

- **Redirect to popup_close on error**: Instead of returning `Err(...)` from the handler (which renders a raw error page), errors are caught and redirect to `popup_close` with a URL-encoded error message. This ensures the popup always shows a styled page.
- **Skip postMessage on error**: Error popup was sending `postMessage('auth_complete')` to parent, causing unnecessary page reload even when authentication failed. Since no session is created on error, parent reload is pointless.
- **Infallible handlers**: `get_authorized`/`post_authorized` were refactored from `Result<...>` to infallible handlers using `match`, with a `friendly_error_message()` helper for user-facing messages.
- **Security test updates**: 14 test assertions were updated from `ExpectedSecurityError::BadRequest` to `RedirectWithError` to match the new redirect-based error flow.

### Key files

`oauth2_passkey_axum/src/oauth2.rs`, `oauth2_passkey_axum/src/error.rs`, `oauth2_passkey_axum/templates/popup_close.j2`

---

## 2026-02-13: GitHub Actions auto-deploy for Cloud Run

**Issue**: `20260212-1200` | **Priority**: low | **Difficulty**: small

Enhancement (CI/CD) -- Demo infrastructure

### Motivation

Demo site deployment (passkey-demo.ccmp.jp) was entirely manual, requiring `gcloud builds submit` and `gcloud run deploy` commands for each update. Automating this reduces deployment friction and ensures the demo always reflects the latest code.

### User-facing impact

- **Before**: Deploying the demo site required manual execution of two `gcloud` commands after each code change.
- **After**: Pushing to the `dev` branch triggers automatic Cloud Build and Cloud Run deployment via GitHub Actions. Relevant path filters prevent unnecessary builds on documentation-only changes.

### Design decisions

A `github-actions-deploy` service account was created with five IAM roles: `run.admin`, `iam.serviceAccountUser`, `cloudbuild.builds.editor`, `artifactregistry.writer`, and `storage.admin`. A JSON key was stored in GitHub repository secrets.

A significant issue arose with Cloud Build log streaming: `gcloud builds submit` failed on GitHub Actions with "This tool can only stream logs if you are Viewer/Owner of the project." Three approaches were attempted:

1. `roles/logging.viewer` -- Insufficient because the default logs bucket is Cloud Storage, not Cloud Logging.
2. `--suppress-logs` flag -- Did not prevent the log streaming attempt.
3. `roles/viewer` -- Rejected as overly broad (read access to all project resources).

The final solution was adding `defaultLogsBucketBehavior: REGIONAL_USER_OWNED_BUCKET` to `cloudbuild.yaml`. This directs logs to a user-owned regional bucket instead of the Google-managed default, allowing the existing `roles/storage.admin` to cover read/write access without the broad `roles/viewer`.

### Key files

`.github/workflows/deploy-demo.yml`, `demo-live/cloudbuild.yaml`, `demo-live/DEPLOY.md`

---

## 2026-02-13: Admin deletion safeguard -- prevent deleting the last admin

**Issue**: `20260210-1930` | **Priority**: high | **Difficulty**: medium

Enhancement (security/data integrity) -- Core library

### Motivation

Discovered during demo site deployment planning: if all admin users are deleted, the system becomes permanently locked out of admin functionality. New users are created with `is_admin: false`, and auto-promotion to admin only applies to `sequence_number = 1` (the first user ever created). Once that user is deleted, the sequence number is never reused, so there is no mechanism to recover admin access.

### User-facing impact

- **Before**: Deleting or demoting the last admin succeeded silently, permanently locking out all administrative functionality. The self-deletion path (`delete_user_account` on the user account page) had no safeguard at all, allowing any admin to bypass admin-page protections entirely.
- **After**: Attempting to delete or demote the last admin returns `409 Conflict` across all three modification paths. The invariant "at least one admin must always exist" is enforced consistently.

### Design decisions

Two approaches were evaluated:

1. **Protect the first user (seq=1) from deletion** -- Creates a permanently undeletable user, which is undesirable.
2. **Guard the invariant "at least one admin exists"** -- Any admin can be deleted or demoted as long as another admin remains. More flexible.

Approach 2 was adopted. However, the first user's demotion is still unconditionally blocked because `has_admin_privileges()` checks `is_admin || sequence_number == 1` -- demoting seq=1 would create an inconsistency between the UI display (non-admin) and actual privileges (still admin).

The admin count uses `WHERE is_admin = true OR sequence_number = 1` to match `has_admin_privileges()` semantics. The count query is skipped for operations on non-admin users, so there is no performance impact on regular user operations.

During implementation, a previously unknown security gap was discovered: the user self-deletion path (`delete_user_account`) had no admin guard at all, allowing an admin to bypass admin-page restrictions by self-deleting from the user account page.

Eight tests cover all scenarios. A test infrastructure issue with parallel test FK constraint conflicts was resolved by adding a `delete_user_atomically()` helper that holds the `GENERIC_DATA_STORE` lock for the entire deletion sequence.

### Key files

`oauth2_passkey/src/coordination/admin.rs`, `oauth2_passkey/src/coordination/user.rs`, `oauth2_passkey/src/userdb/storage/store_type.rs`

---

## 2026-02-12: Separate demo-live from demo-both

**Issue**: `20260212-1804` | **Priority**: medium | **Difficulty**: medium

Enhancement -- separating the live demo site (`passkey-demo.ccmp.jp`) from the library usage example (`demo-both`).

### Motivation

The deployment work (issue `2026-01-30-08`) had added Docker, Cloud Build, and Cloud Run files directly to `demo-both`. Upcoming UI/UX customizations for the live demo site would further diverge `demo-both` from a simple library usage example. Users looking at `demo-both` for how to integrate the library would encounter deployment-specific code, `bundled-tls` features, `PORT` environment variable handling, and eventually custom UI that does not represent typical library usage.

### User-facing impact

- **Before**: `demo-both/` contained a mix of library usage example code and deployment files (Dockerfile, docker-compose.yml, cloudbuild.yaml, DEPLOY.md, env.cloud-run.yaml). The development and live site versions shared the same code, with `bundled-tls` feature and `PORT` env var support added for Cloud Run.
- **After**: Two distinct directories with clear purposes:

| Aspect | `demo-both` | `demo-live` |
|--------|-------------|-------------|
| Purpose | Library usage example | `passkey-demo.ccmp.jp` live site |
| `bundled-tls` | Not present | Enabled |
| Port | Hardcoded 3001 | `PORT` env var (Cloud Run) |
| Dockerfile | None | Present |
| cloudbuild.yaml | None | Present |

### Design decisions

- **Restore demo-both from master**: The `master` branch had a clean version of `demo-both` without any deployment files or feature flags. Using `git checkout master -- demo-both/` provided a pristine library usage example.
- **Rename-then-restore strategy**: `git mv demo-both demo-live` preserved Git history for the deployment files, then `git checkout master -- demo-both/` restored the clean example.
- **External references left unchanged**: 40 files reference `demo-both`. Since `demo-both` continues to exist as the library example, references were intentionally left unchanged.

### Key files

`demo-both/`, `demo-live/`, `demo-live/Cargo.toml`, `demo-live/Dockerfile`, `demo-live/cloudbuild.yaml`, `Cargo.toml`

---

## 2026-02-12: Demo site deployment to Cloud Run

**Issue**: `2026-01-30-08` | **Priority**: low | **Difficulty**: medium

New feature -- first public deployment of the demo application. Previously, the only way to try the library was running `cargo run` locally. The demo is now publicly accessible at `https://passkey-demo.ccmp.jp`.

### Motivation

There was no way to demonstrate the library's functionality without cloning the repository and running locally. A public demo site makes the library accessible for evaluation without any setup, and provides a reference implementation for potential users.

### User-facing impact

- **Before**: No public demo existed. Users needed to clone the repository, set up Google OAuth2 credentials, configure environment variables, and run `cargo run` to try the library. No Docker image was available.
- **After**: A live demo is accessible at `https://passkey-demo.ccmp.jp` supporting OAuth2 login and passkey registration/authentication. A Docker image is available (27.7MB, `scratch`-based) for self-hosting.

### Design decisions

- **Platform selection**: Initially planned for Fly.io, but Fly.io had eliminated its free tier (only a 2-hour/7-day trial remained). After evaluating 11 platforms, Google Cloud Run was selected for its generous free tier (180k vCPU-sec, 2M requests/month), automatic HTTPS, and no code changes required.

- **Docker image optimization**: The image evolved from `debian:bookworm-slim` (111MB) to `scratch` (27.7MB) through several steps:
  - Builder: `rust:1.88-alpine` with musl target for static linking
  - Runtime: `scratch` (no OS, no shell, just the binary)
  - TLS: `webpki-roots` for compile-time certificate bundling, eliminating the need for `ca-certificates` package

- **`bundled-tls` feature flag**: `webpki-roots` and `rustls` are made optional via a `bundled-tls` feature flag. Normal deployments using OS certificate stores do not need these dependencies.

- **Shared HTTP client (`get_client()`)**: The `scratch` container has no OS certificate store, so all `reqwest::get()` calls (3 locations: `aaguid.rs`, `idtoken.rs` x2) were replaced with `get_client().get().send()` using the centralized TLS configuration. `get_client()` was moved from `oauth2/main/utils.rs` to crate-level `utils.rs` since the HTTP client is a shared utility.

- **Ephemeral storage**: SQLite (ephemeral) + memory cache is used for the demo, accepting that data is lost on container restart.

### Key files

`demo-live/Dockerfile`, `demo-live/DEPLOY.md`, `demo-live/cloudbuild.yaml`, `demo-live/docker-compose.yml`, `oauth2_passkey/src/utils.rs`, `.dockerignore`

---

## 2026-02-11: OAuth2 callback deadlock fix (JWKS cache expiry)

**Issue**: `20260211-1742` | **Priority**: high | **Difficulty**: medium

Bug fix -- a `tokio::sync::Mutex` deadlock in `fetch_jwks_cache()` that caused the OAuth2 login flow to hang permanently exactly 10 minutes after the first successful login, but only when using the in-memory cache backend (Docker containers).

### Motivation

During Docker container testing with in-memory cache (`GENERIC_CACHE_STORE_TYPE=memory`), the OAuth2 login flow deadlocked exactly 600 seconds (the JWKS cache TTL) after the first successful login. The server became completely unresponsive for all authentication operations. The 30-second HTTP timeout never fired because the code was stuck on Mutex acquisition, not an HTTP request. The bug was never caught during development because `cargo run` typically uses Redis, which auto-expires entries and never reaches the deadlock code path.

### User-facing impact

- **Before**: In Docker/Cloud Run deployments using in-memory cache, the first OAuth2 login worked, subsequent logins within 10 minutes worked, but the first login attempt after 10 minutes hung permanently. The server became completely unresponsive -- all users were blocked from authentication. Additionally, in-memory SQLite tables disappeared after ~30 minutes of low traffic due to connection pool eviction.
- **After**: OAuth2 login works reliably regardless of elapsed time. In-memory cache correctly expires entries via lazy TTL (matching Redis semantics). In-memory SQLite databases persist indefinitely with `min_connections(1)` and disabled connection cycling.

### Design decisions

Three fixes were applied:

1. **Deadlock elimination (primary fix)**: The root cause was in `idtoken.rs`, where an `if let` pattern held a `MutexGuard` temporary through the entire block body while attempting to re-acquire the same non-reentrant `tokio::sync::Mutex` for a `remove()` operation on expired entries:

```rust
// DEADLOCK: MutexGuard from if-let scrutinee lives through the body
if let Some(cached) = GENERIC_CACHE_STORE.lock().await.get(...).await {
    // MutexGuard still alive here
    GENERIC_CACHE_STORE.lock().await.remove(...)  // Waits forever
}
```

The fix refactored `fetch_jwks_cache()` to use the `cache_operations` module functions (`get_data`, `remove_data`, `store_cache_keyed`), each of which acquires and releases the Mutex independently. This makes double-locking structurally impossible.

2. **In-memory cache TTL (defense in depth)**: `InMemoryCacheStore::put_with_ttl()` had been ignoring the `_ttl` parameter entirely -- entries persisted forever. A `CacheEntry` wrapper with `expires_at: Option<Instant>` was added, and `get()` now returns `None` for expired entries (lazy expiration), matching Redis semantics.

3. **SQLite pool stability**: In-memory SQLite pools defaulted to `min_connections=0`. After idle timeout (~10 min) or max lifetime (~30 min), all pool connections were evicted, destroying the shared in-memory database. Fixed by setting `min_connections(1)`, `idle_timeout(None)`, and `max_lifetime(None)`.

### Key files

`oauth2_passkey/src/oauth2/main/idtoken.rs`, `oauth2_passkey/src/storage/cache_operations.rs`, `oauth2_passkey/src/storage/cache_store/memory.rs`, `oauth2_passkey/src/storage/cache_store/types.rs`, `oauth2_passkey/src/storage/cache_store/memory/tests.rs`, `oauth2_passkey/src/storage/data_store/config.rs`

---

## 2026-02-10: Login history auth-method-specific detail enhancement

**Issue**: `20260210-0547` | **Priority**: medium | **Difficulty**: medium

Enhancement to the login history feature (`2026-01-30-03`) -- adding authenticator identification via AAGUID recording and enriching OAuth2 login records with email information.

### Motivation

Login history entries contained minimal auth-method-specific data. For passkey logins, only `credential_id` was recorded; if the credential was later deleted, authenticator identification information was permanently lost. For OAuth2 logins, no email information was recorded. The display showed only text-based auth method indicators with no visual differentiation.

### User-facing impact

- **Before**: Login history showed generic auth method text ("Passkey", "OAuth2"). Passkey entries linked to a credential ID, but deleting the credential lost all authenticator context. OAuth2 entries showed provider name but not the email used. No icons or visual indicators.
- **After**: Passkey login entries display authenticator-specific icons and names (e.g., iCloud Keychain icon, Google Password Manager icon) via AAGUID lookup. This information is self-contained in each history entry and survives credential deletion. OAuth2 login entries show the email address used for authentication. All 4 login history templates display authenticator icons and names.

```rust
// Before: AuthMethodDetails as unit variants
enum AuthMethodDetails {
    Passkey,
    OAuth2,
}

// After: data-carrying variants with self-contained information
enum AuthMethodDetails {
    Passkey { credential_id: String, aaguid: Option<String> },
    OAuth2 { provider: String, provider_user_id: String, email: Option<String> },
}
```

```rust
// Before: finish_authentication() returned a tuple
let (user_handle, credential_id) = finish_authentication(...).await?;

// After: returns a structured result with AAGUID
let result: AuthenticationResult = finish_authentication(...).await?;
// result.user_handle, result.credential_id, result.aaguid
```

### Design decisions

- **AAGUID as nullable column**: Added `aaguid TEXT` as a nullable column to `o2p_login_history`. Existing rows naturally have `NULL`, requiring no migration script.
- **Self-contained history entries**: By recording AAGUID directly in login history rather than joining against the credentials table, each history entry is self-sufficient. Credential deletion does not affect historical records.
- **`EnrichedLoginHistoryEntry` with `#[serde(flatten)]`**: Rather than a separate wrapper response, authenticator name and icon are embedded directly into each entry.
- **Batch AAGUID lookup**: When rendering login history, AAGUIDs are collected from all entries and looked up in batch against the AAGUID database, avoiding N+1 queries.

### Key files

`oauth2_passkey/src/audit/types.rs`, `oauth2_passkey/src/audit/storage/sqlite.rs`, `oauth2_passkey/src/audit/storage/postgres.rs`, `oauth2_passkey/src/coordination/login_history.rs`, `oauth2_passkey_axum/templates/user_login_history.j2`, `oauth2_passkey_axum/templates/admin_audit.j2`

---

## 2026-02-10: Passkey registration promotion feature

**Issue**: `2026-01-30-07` | **Priority**: medium | **Difficulty**: large

New feature -- a passkey registration promotion system that encourages OAuth2 users to register a passkey for faster future logins. Controlled by the `O2P_PASSKEY_PROMOTION` environment variable (disabled by default).

### Motivation

Users who authenticate via OAuth2 may not be aware they can also register a passkey for faster, passwordless login on their current device. There was no mechanism to prompt them about this option. The core challenge is that the server cannot determine whether a user's existing passkeys are accessible on their current device/authenticator -- passkeys are per-authenticator (per device/platform), so a server-side `has_passkey` flag is insufficient.

### User-facing impact

- **Before**: After OAuth2 login, users were redirected directly to the destination page. They had no awareness of passkey registration unless they independently navigated to account settings. No promotion mechanism existed in the library.
- **After**: When `O2P_PASSKEY_PROMOTION` is enabled (`ask` or `force` mode), users are prompted to register a passkey inside the OAuth2 popup window after successful login. In `ask` mode, a modal dialog appears. In `force` mode, the WebAuthn registration dialog is presented directly. Devices that already have a registered passkey automatically skip the prompt via WebAuthn's `InvalidStateError` from `excludeCredentials`. A UA + AAGUID heuristic further reduces unnecessary prompts by detecting platform-specific authenticators.

```bash
# Environment variable configuration:
O2P_PASSKEY_PROMOTION=ask    # Show confirmation modal
O2P_PASSKEY_PROMOTION=force  # Skip modal, direct WebAuthn registration
# unset or "false"           # Disabled (default)
```

### Design decisions

- **Three design iterations**: The implementation went through three approaches before arriving at the final design:
  1. **sessionStorage approach** (commit `e4014c0`): Required consumer apps to include `passkey_promotion.js` on their destination pages, violating the "zero app-side changes" goal.
  2. **Intermediate redirect page** (commit `cdd6960`): Eliminated app-side changes but introduced race conditions with `oauth2.js` and visible redirect flashes.
  3. **Popup-based approach** (commit `1bf42b7`, final): Runs the entire promotion flow inside the OAuth2 popup window before sending `postMessage('auth_complete')`. Zero consumer app changes, no race conditions.

- **`excludeCredentials` for duplicate prevention**: Uses WebAuthn's `excludeCredentials` parameter so the authenticator itself rejects registration with `InvalidStateError` when it already has a matching credential.

- **Separate endpoint from existing registration**: Creating a new `/passkey/promotion/register/start` endpoint rather than modifying the existing `/passkey/register/start` preserves backward compatibility. Adding `excludeCredentials` to the existing endpoint would have broken the "Add New Passkey" flow on the account page.

- **Axum router double-nest bug discovered**: Adding promotion routes with `.nest("/passkey", promotion_router)` alongside `.nest("/passkey", base_router)` caused route shadowing in Axum 0.8. Fixed by merging sub-routers before nesting.

```rust
// Bug: double-nest at same prefix causes route shadowing
Router::new()
    .nest("/passkey", base_router)
    .nest("/passkey", promotion_router)  // shadows base_router

// Fix: merge first, then nest once
let passkey = base_router.merge(promotion_router);
Router::new().nest("/passkey", passkey)
```

### Key files

`oauth2_passkey_axum/src/passkey/promotion.rs`, `oauth2_passkey_axum/src/passkey/promotion/tests.rs`, `oauth2_passkey_axum/templates/promotion_popup.j2`, `oauth2_passkey_axum/src/config.rs`, `oauth2_passkey_axum/src/oauth2.rs`

---

## 2026-02-09: CHANGELOG update (post v0.2.0)

**Issue**: `2026-02-09-01` | **Priority**: medium | **Difficulty**: medium

Documentation maintenance -- updating the `[Unreleased]` section of CHANGELOG.md to reflect all changes since the v0.2.0 release.

### Motivation

Extensive development since v0.2.0 had introduced numerous features, fixes, and refactoring across 195 non-merge commits, but the CHANGELOG's `[Unreleased]` section had not been kept in sync. A systematic review was needed to ensure completeness before the next release.

### User-facing impact

- **Before**: The `[Unreleased]` section was incomplete, omitting many significant changes. Users reviewing the CHANGELOG for upgrade decisions would miss important features and fixes.
- **After**: All post-v0.2.0 changes are documented. 12 new entries added to Added, 7 to Fixed. The Changed section was reorganized and a Removed section was added.

### Design decisions

- **Systematic commit review**: All 195 non-merge commits were reviewed individually (`git log --oneline v0.2.0..HEAD --no-merges`) and categorized into Added/Changed/Fixed/Security/Removed sections following Keep a Changelog conventions.
- **Single commit**: The CHANGELOG update was committed as a single commit rather than incremental updates, since it was a documentation-only change affecting one file.

### Key files

`CHANGELOG.md`

---

## 2026-02-08: Audit page enhancement -- date filtering and security event logging

**Issue**: `2026-02-08-01` | **Priority**: medium | **Difficulty**: large

Enhancement to the login history feature (`2026-01-30-03`) -- the base login history functionality was implemented immediately prior (Feb 7-8), and this enhancement followed directly.

### Motivation

The initial login history implementation displayed all entries inline on the user detail page with no filtering, pagination, or dedicated view. For administrators, there was no way to query across users or filter by success/failure status. Additionally, OAuth2 CSRF attack attempts (state validation failures) were not logged, leaving a gap in security monitoring.

### User-facing impact

- **Before**: Login history was displayed as an unbounded list on the user detail page. No filtering, no pagination, no dedicated page. Administrators had no cross-user audit view. OAuth2 CSRF attack attempts went unrecorded.
- **After**: User detail page shows only the latest 5 entries with a "View All" link. A dedicated user history page (`/o2p/user/login_history_page`) provides date range filtering and pagination. A dedicated admin audit page (`/o2p/admin/audit_page`) offers date range filtering, user filtering, success/failure filtering, and pagination. OAuth2 state validation failures are recorded as anonymous security events with IP address and User-Agent for CSRF attack pattern detection.

### Design decisions

- **Anonymous security events via existing table**: Rather than creating a new table for security events, OAuth2 CSRF failures are recorded in the existing `o2p_login_history` table with an empty `user_id`. This reuses the existing schema and query infrastructure.
- **Layered implementation**: Changes span all three architectural layers (Storage -> Coordination -> Axum), maintaining the library's separation of concerns.
- **Passkey failure logging**: In addition to OAuth2 CSRF events, passkey authentication failures are now logged with `credential_id` for tracking repeated failed attempts against specific credentials.

### Key files

`oauth2_passkey/src/audit/storage/sqlite.rs`, `oauth2_passkey/src/audit/storage/postgres.rs`, `oauth2_passkey/src/coordination/login_history.rs`, `oauth2_passkey_axum/src/login_history.rs`, `oauth2_passkey_axum/templates/user_login_history.j2`, `oauth2_passkey_axum/templates/admin_audit.j2`

---

## 2026-02-07: README and documentation update for current API

**Issue**: `2026-02-07-01` | **Priority**: medium | **Difficulty**: medium

Documentation maintenance -- updating README files and docs to reflect the current API (`oauth2_passkey_full_router`) and the expanded demo structure.

### Motivation

The library's public API had evolved from `oauth2_passkey_router()` with `.nest()` to `oauth2_passkey_full_router()` with `.merge()`, but documentation across 12 files still referenced the old API. Additionally, the demo count had grown from 3 to 7 without the documentation reflecting this. HTTPS references (`https://localhost:3443`) were also outdated since WebAuthn's secure context requirement is satisfied by `localhost` even over plain HTTP.

### User-facing impact

- **Before**: Documentation recommended an outdated API pattern. New users following the quick-start guide would use deprecated `oauth2_passkey_router()` with `.nest()`. The demo table listed only 3 demos. URLs pointed to `https://localhost:3443`.
- **After**: Documentation consistently uses the current API pattern. All 7 demos are listed. URLs point to `http://localhost:3001`.

```rust
// Before (documented usage):
use oauth2_passkey_axum::{oauth2_passkey_router, O2P_ROUTE_PREFIX};

let app = Router::new()
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

// After (updated documentation):
use oauth2_passkey_axum::oauth2_passkey_full_router;

let app = Router::new()
    .merge(oauth2_passkey_full_router());
```

### Design decisions

- **HTTP-only for localhost documentation**: `localhost` is explicitly listed as a secure context in the W3C specification, so HTTPS is unnecessary for local development.
- **Scope limited to documentation**: No code changes were made. The old API still exists for backward compatibility, but documentation now points exclusively to the new pattern.

### Key files

`Readme.md`, `oauth2_passkey_axum/README.md`, `docs/src/getting-started/quick-start.md`, `docs/src/integration/server-setup.md`, `dot.env.simple`

---

## 2026-01-31: Remove HTTPS support from demo applications

**Issue**: `2026-01-31-02` | **Priority**: low | **Difficulty**: medium

Enhancement (feature reduction) -- Removes unnecessary complexity from all 6 demo applications. This is an intentional simplification, not a regression.

### Motivation

All 6 demo applications included built-in HTTPS support using self-signed certificates with `axum-server` and `rustls`. This added complexity without practical benefit: `localhost` satisfies WebAuthn's secure context requirement even over HTTP, and production deployments universally use nginx or Caddy for TLS termination rather than embedding TLS in the application.

### User-facing impact

- **Before**: Each demo started on two ports -- HTTP (e.g., 3001) and HTTPS (e.g., 3443). Access URL was `https://localhost:3443`. Dependencies included `axum-server` and `rustls`. Self-signed certificates were stored in `self_signed_certs/` directories.
- **After**: Each demo starts on HTTP only (e.g., port 3001). Access URL is `http://localhost:3001`. TLS dependencies removed entirely. Two testing methods documented: (1) localhost for development (HTTP, no setup), (2) HTTPS proxy for production testing (nginx/Caddy terminates TLS).

**Change scale**: 43 files changed, +115 lines, -868 lines.

### Design decisions

- **Consistent with `demo-cross-origin`**: The cross-origin demo had already been simplified to HTTP-only. This change applies the same rationale to the remaining 6 demos.
- **All 6 demos updated uniformly**: `demo-both`, `demo-oauth2`, `demo-passkey`, `demo-custom-login`, `demo-todo`, and `demo-profile` all received identical treatment.

### Key files

`demo-both/src/server.rs`, `demo-passkey/src/server.rs`, `demo-oauth2/src/server.rs`, `demo-custom-login/src/server.rs`, `demo-todo/src/server.rs`, `demo-profile/src/server.rs`

---

## 2026-01-30: README links update

**Issue**: `2026-01-30-04` | **Priority**: medium | **Difficulty**: small

Enhancement -- Improves discoverability of documentation and resources.

### Motivation

Users who discovered the library on crates.io had no pathway to the User Guide or demo site. The READMEs only linked to the API reference on docs.rs, leaving the comprehensive User Guide and other resources undiscoverable from the crate pages.

### User-facing impact

- **Before**: README files contained no external links section. Users on crates.io could only access the auto-generated API reference.
- **After**: Both `oauth2_passkey/README.md` and `oauth2_passkey_axum/README.md` include a "Documentation" section with links to the User Guide, API Reference (docs.rs), Crates.io, and GitHub repository.

### Design decisions

- **Both crate READMEs updated**: Since `oauth2-passkey` and `oauth2-passkey-axum` are published as separate crates, both need independent documentation links for discoverability from their respective crates.io pages.

### Key files

`oauth2_passkey/README.md`, `oauth2_passkey_axum/README.md`

---

## 2026-01-30: Move /info and /csrf_token endpoints to default router

**Issue**: `2026-01-30-01` | **Priority**: medium | **Difficulty**: small

Enhancement -- Improves feature flag ergonomics for custom UI developers.

### Motivation

The `/info` (user information retrieval) and `/csrf_token` (CSRF token retrieval) endpoints were placed in `optional.rs`, which is gated behind the `user-ui` feature flag. These are pure JSON APIs with no UI dependency, yet disabling `user-ui` (to avoid the library's built-in login pages when implementing a custom UI) also removed these essential API endpoints.

### User-facing impact

- **Before**: Using `/info` and `/csrf_token` required enabling the `user-ui` feature flag, which also activated the built-in login pages.
- **After**: Both endpoints are always available regardless of feature flags. Custom UI developers can disable `user-ui` without losing access to these APIs.

```toml
# Before: /info and /csrf_token require user-ui
[dependencies]
oauth2-passkey-axum = { version = "...", features = ["user-ui"] }
# Built-in login pages are also enabled -- unwanted for custom UI

# After: /info and /csrf_token are always available
[dependencies]
oauth2-passkey-axum = { version = "...", default-features = false }
# Only custom UI, no built-in pages, but /info and /csrf_token still work
```

### Design decisions

- **Moved to `default.rs`**: These endpoints join `/logout`, `/update`, and `/delete` which were already in the always-available router. This is consistent -- all pure JSON API endpoints are in `default.rs`, while HTML-rendering UI pages remain in `optional.rs` behind `user-ui`.

### Key files

`oauth2_passkey_axum/src/user/default.rs`, `oauth2_passkey_axum/src/user/optional.rs`, `oauth2_passkey_axum/src/user/mod.rs`

---

## 2026-01-30: Bearer token authentication demo (not merged / deferred)

**Issue**: `2026-01-30` (demo) / `2026-01-23-01` (parent) | **Priority**: medium | **Difficulty**: large | **Status**: NOT MERGED -- parent issue deferred

The Bearer token authentication core implementation (6 phases) was completed on branch `dev-2026-01-23-01`, and the `demo-api` was built on the same branch. However, open design questions about `both` mode token acquisition and native app OAuth2 support caused the parent issue (`2026-01-23-01`) to be deferred. The demo remains on the branch and has NOT been merged to master.

### Motivation

All existing demo applications used browser-based cookie authentication exclusively. There was no reference implementation showing how API clients (cURL, Postman, mobile applications) could authenticate using Bearer tokens with the library.

### User-facing impact

- **Before**: No API-only demo existed. Developers building non-browser clients had no reference implementation.
- **After (on branch `dev-2026-01-23-01` only)**: `demo-api` demonstrates Bearer token authentication with Passkey. It uses the `oauth2-passkey` core library directly (not `oauth2-passkey-axum`), providing a pure API server without browser UI.

### Design decisions

- **Core library only**: `demo-api` deliberately avoids `oauth2-passkey-axum` to demonstrate that the core library can be used independently for API-only servers.
- **Passkey only**: OAuth2 authentication was excluded because it requires browser redirects, which are incompatible with a pure API flow.

### Open design questions (reason for deferral)

1. **`SESSION_AUTH_MODE=both` token acquisition**: In `both` mode, only a cookie is returned during session creation. There is no mechanism to obtain a Bearer token.
2. **Native app + OAuth2**: OAuth2 callback is an HTTP redirect (302), which in-app browsers cannot intercept to extract tokens.
3. **SPA security**: Storing tokens in localStorage creates XSS vulnerabilities. The recommended pattern for cross-origin SPAs is `both` mode with a Backend-for-Frontend (BFF) proxy.

### Key files (on branch `dev-2026-01-23-01`)

`demo-api/src/main.rs`, `demo-api/.env.example`, `demo-api/README.md`, `oauth2_passkey/src/session/config.rs`, `oauth2_passkey/src/session/main/session.rs`

---

## 2026-01-30: Cross-origin same-site demo (Pattern 2)

**Issue**: `2026-01-30-09` | **Priority**: medium | **Difficulty**: medium

New feature -- Both the library-level cookie domain/CORS support and the demo application are entirely new.

### Motivation

In microservice architectures, an authentication server (`auth.example.com`) and a resource API (`api.example.com`) commonly reside on different subdomains. This pattern requires sharing cookies across subdomains via the `Domain` attribute and configuring CORS for cross-origin requests. The library lacked both the cookie `Domain` attribute support and a CORS configuration module.

### User-facing impact

- **Before**: Cookies were always scoped to the exact origin. There was no way to share session cookies across subdomains. No built-in CORS support existed.
- **After**: The new `SESSION_COOKIE_DOMAIN` environment variable enables cross-subdomain cookie sharing. A new `cors` feature flag in `oauth2-passkey-axum` provides configurable CORS middleware. The `demo-cross-origin` application demonstrates the complete pattern.

```bash
# Auth server
ORIGIN='https://auth.example.local:3000'
SESSION_COOKIE_DOMAIN='.example.local'
SESSION_COOKIE_NAME='SessionId'  # Cannot use __Host- prefix with Domain attribute

# Resource API (CORS)
CORS_ALLOWED_ORIGINS='https://auth.example.local:3000'
CORS_ALLOW_CREDENTIALS=true
```

### Design decisions

- **Auth + Resource API architecture**: The auth server hosts both the frontend and oauth2_passkey, while the resource API only validates the shared cookie and handles CORS. CORS is only needed on the resource API since the frontend is same-origin with the auth server.
- **`SESSION_COOKIE_DOMAIN` as opt-in**: The domain attribute is only set when this environment variable is configured, preserving the default single-origin cookie behavior.
- **`__Host-` prefix incompatibility**: Documented that the `__Host-` cookie name prefix cannot be used with the `Domain` attribute per the cookie specification.
- **Feature flag for CORS**: CORS support is gated behind a `cors` feature flag to avoid pulling in `tower-http` as a dependency for applications that do not need cross-origin support.

### Key files

`oauth2_passkey/src/session/config.rs`, `oauth2_passkey/src/utils.rs`, `oauth2_passkey_axum/src/cors.rs`, `oauth2_passkey_axum/Cargo.toml`, `demo-cross-origin/`, `dot.env.example`

---

## 2026-01-30: getClientCapabilities feature detection

**Issue**: `2026-01-30-05` | **Priority**: medium | **Difficulty**: small

Enhancement (refactoring) -- Improves code quality of the existing Signal API implementation (`2026-01-28-01`).

### Motivation

The Signal API implementation scattered inline `typeof PublicKeyCredential.signalXxx !== 'undefined'` checks across multiple JavaScript files. Each Signal API call site duplicated the same browser support detection pattern.

### User-facing impact

- **Before**: Browser capability detection was done inline at each Signal API call site with verbose `typeof` checks. No centralized logging of browser capabilities.
- **After**: A unified `hasSignalCapability()` helper function checks cached capabilities. Browser WebAuthn capabilities are logged once on page load for easier debugging.

```javascript
// Before: inline typeof checks scattered across files
if (typeof window.PublicKeyCredential.signalAllAcceptedCredentials !== "function") {
    console.log("signalAllAcceptedCredentials API not supported");
    return;
}

// After: unified capability detection helper
if (!hasSignalCapability('signalAllAcceptedCredentials')) {
    console.log("signalAllAcceptedCredentials not available");
    return;
}
```

### Design decisions

- **`initPasskeyCapabilities()`**: Called on page load, queries `PublicKeyCredential.getClientCapabilities()` (Chrome 131+), caches results in `_passkeyCapabilities`. For browsers that do not support the API, the variable is set to `undefined` and `hasSignalCapability()` falls back to `typeof` checks.
- **Single source of truth**: All Signal API support checks were converted from inline `typeof` to `hasSignalCapability()` calls.

### Key files

`oauth2_passkey_axum/static/passkey.js`, `oauth2_passkey_axum/static/conditional_ui.js`, `oauth2_passkey_axum/static/account.js`

---

## 2026-01-30: Login history view (admin + user)

**Issue**: `2026-01-30-03` | **Priority**: medium | **Difficulty**: large

New feature -- No login history recording or display capability existed prior to this implementation.

### Motivation

Users had no way to check whether their account had experienced unauthorized logins. Administrators lacked the ability to review a specific user's login history during security audits or incident investigations.

### User-facing impact

- **Before**: No login history was recorded. Neither users nor administrators could see past login activity.
- **After**: Every login attempt (both Passkey and OAuth2) is recorded with IP address, User-Agent, authentication method, credential ID, provider information, and failure reason. Users see their recent login history on their account page with IP addresses partially masked (last octet hidden) for privacy. Administrators see the full unmasked history on the user detail page.

New API endpoints:

```
GET /o2p/user/login_history          -- User's own history (IP masked, default limit: 10)
GET /o2p/admin/user/{id}/login_history -- Admin view of any user's history (full IP, default limit: 50)
```

### Design decisions

- **4-phase implementation**: (1) Storage layer with `o2p_login_history` table supporting both SQLite and PostgreSQL with auto-initialization at startup; (2) Coordination layer with separate masked (user) and unmasked (admin) history retrieval functions; (3) Axum handlers extracting IP address and User-Agent from request headers at login time; (4) UI components embedded in the user account page and admin user detail page.
- **Privacy by design**: IP masking is applied at the coordination layer rather than the UI layer, ensuring that user-facing APIs never leak full IP addresses regardless of how they are consumed.
- **Dual authentication method support**: Login history recording is integrated into both the Passkey authentication flow and the OAuth2 callback flow.

### Key files

`oauth2_passkey/src/login_history/`, `oauth2_passkey/src/coordination/login_history.rs`, `oauth2_passkey_axum/src/login_history.rs`, `oauth2_passkey_axum/templates/user_account.j2`, `oauth2_passkey_axum/templates/admin_user_page.j2`

---

## 2026-01-30: Admin force logout feature

**Issue**: `2026-01-30-02` | **Priority**: medium | **Difficulty**: medium

New feature -- Leverages the user-to-session-ID mapping introduced by the Session Conflict Policy feature (`2026-01-28-02`).

### Motivation

When a security incident occurs (account compromise, suspicious activity), administrators had no way to immediately invalidate a specific user's sessions. The only options were waiting for the user to log out voluntarily or for the session to expire naturally.

### User-facing impact

- **Before**: The admin user list showed no session information. There was no mechanism to invalidate a suspicious user's sessions.
- **After**: The admin user list displays an "Active" column with green dot indicators (filled circle for active, hollow circle for inactive). Clicking an active indicator triggers a confirmation dialog and immediately force-logs out the user. The admin user detail page shows "Active Sessions: N" with a dedicated "Force Logout" button. Session status refreshes every 5 seconds via polling.

### Design decisions

- **Core API**: Two new coordination-layer functions -- `get_all_active_sessions(session_id)` retrieves session counts for all users in a single bulk call, and `force_logout_user(session_id, target_user_id)` terminates all sessions for a target user.
- **Clickable indicators**: Active session indicators in the user list are directly clickable for quick force logout, eliminating the need to navigate to the user detail page.
- **Defense in depth**: Admin privilege verification occurs at both the Axum handler layer and the coordination layer. POST requests require CSRF token validation.
- **Self-logout prevention**: The admin template receives the `current_user_id` to disable the force logout action on the admin's own row.

### Key files

`oauth2_passkey/src/coordination/admin.rs`, `oauth2_passkey/src/coordination/admin/tests.rs`, `oauth2_passkey/src/session/main/user_sessions.rs`, `oauth2_passkey_axum/src/admin/optional.rs`, `oauth2_passkey_axum/templates/admin_index.j2`, `oauth2_passkey_axum/templates/admin_user_page.j2`

---

## 2026-01-29: Terminology glossary document

**Issue**: `2026-01-29-03` | **Priority**: low | **Difficulty**: small

New documentation -- no code changes.

### Motivation

WebAuthn and the oauth2-passkey library use multiple identifiers with similar names but different meanings. In particular, `user_id` (the library's internal database user identifier) and `user_handle` (the WebAuthn user identifier) are easily confused.

### User-facing impact

- **Before**: No centralized reference for identifier terminology. Users had to piece together meanings from scattered documentation and source code.
- **After**: `docs/src/appendix/terminology.md` provides a comprehensive glossary with user identifiers, credential identifiers, session identifiers, OAuth2 identifiers, type-safe wrappers reference, common confusion points, and ASCII diagram showing database relationships.

Key clarification:

| Term | Context | Description |
|------|---------|-------------|
| `user_id` | Library (DB) | Application's internal user identifier |
| `user_handle` | Library (DB) | WebAuthn user identifier stored with credentials |
| `user.id` | WebAuthn registration | User identifier in `PublicKeyCredentialUserEntity` |
| `userHandle` | WebAuthn authentication | Returned in `AuthenticatorAssertionResponse` |
| `userId` | Signal API | Parameter name for user identifier |

Note: `user_handle`, `user.id`, `userHandle`, and `userId` all refer to the same value. `user_id` is different.

### Design decisions

- **Placed in appendix**: The glossary is reference material, not a tutorial.
- **ASCII diagrams over images**: Ensures the documentation renders correctly in all environments without external dependencies.

### Key files

`docs/src/appendix/terminology.md`, `docs/src/SUMMARY.md`

---

## 2026-01-29: SESSION_CONFLICT_POLICY default review

**Issue**: `2026-01-29-04` | **Priority**: low | **Difficulty**: small

Design review -- no code changes.

### Motivation

Following the session conflict policy implementation on 2026-01-28, a review was conducted to determine whether the default should be changed from `allow` (multiple sessions permitted) to `replace` (old sessions invalidated) for stronger out-of-the-box security.

### User-facing impact

- **Before**: `allow` as default.
- **After**: `allow` remains as default. No change.

### Design decisions

The decision to keep `allow` as the default was made based on the following reasoning:

1. **Business decision, not technical correctness**: Unlike `PASSKEY_USER_HANDLE_UNIQUE` (which was changed because the old default deviated from the WebAuthn spec and broke Signal API), session conflict policy is a purely business/UX decision that varies by application.
2. **Multi-device login is the common case**: With `replace`, logging in from a phone would automatically log out the desktop session.
3. **Documented security guidance**: The documentation already explains the security implications.
4. **Easy opt-in for stricter policy**: Applications can set `SESSION_CONFLICT_POLICY=replace` with a single environment variable.

### Key files

`oauth2_passkey/src/env_var.rs`, `docs/src/security/sessions.md`

---

## 2026-01-29: Filter remaining_credential_ids by user_handle

**Issue**: `2026-01-29-02` | **Priority**: low | **Difficulty**: small

Enhancement -- correctness fix for Signal API credential synchronization data.

### Motivation

After credential deletion, the server returned `remaining_credential_ids` for the `signalAllAcceptedCredentials` call. However, this list was built by querying all credentials for the `user_id`, which could include credentials with different `user_handle` values (when `PASSKEY_USER_HANDLE_UNIQUE=true`).

### User-facing impact

- **Before**: `remaining_credential_ids` included all credentials for the user regardless of `user_handle`. When `PASSKEY_USER_HANDLE_UNIQUE=true`, credentials with different user handles were incorrectly reported as "remaining."
- **After**: `remaining_credential_ids` only includes credentials sharing the same `user_handle` as the deleted credential.

```rust
// Before: user_id-based query returns all credentials
let remaining = list_credentials_core(user_id).await?;
let remaining_credential_ids = remaining.iter()
    .map(|c| c.credential_id.clone()).collect();

// After: filtered to same user_handle only
let remaining_credential_ids = remaining.iter()
    .filter(|c| c.user.user_handle == user_handle)
    .map(|c| c.credential_id.clone()).collect();
```

No breaking changes. This is a semantic correctness improvement.

### Design decisions

- **Part of Signal API implementation**: This fix was shipped as part of the broader Signal API work (commit `d145ecc`) rather than as a standalone change.

### Key files

`oauth2_passkey/src/coordination/passkey.rs`, `docs/src/webauthn/user-handle-and-signal-api.md`

---

## 2026-01-29: Change PASSKEY_USER_HANDLE_UNIQUE default to false

**Issue**: `2026-01-29-01` | **Priority**: medium | **Difficulty**: small

**BREAKING CHANGE** -- default behavior change for `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL`.

### Motivation

`PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` defaulted to `true`, meaning a unique `user_handle` was generated for every credential even when they belonged to the same user. This undermined the Signal API's `signalAllAcceptedCredentials` -- since each credential had a different `user_handle`, authenticators could not determine which credentials belonged to the same user. The WebAuthn specification states that `user_handle` should be unique per user, not per credential.

### User-facing impact

- **Before**: Default `true`. Each credential got a unique `user_handle`. `signalAllAcceptedCredentials` could not correlate credentials belonging to the same user. Non-standard behavior relative to the WebAuthn spec.
- **After**: Default `false`. All credentials for the same user share a single `user_handle`. Signal API credential synchronization works correctly. Aligns with WebAuthn specification expectations.

| Aspect | `true` (old default) | `false` (new default) |
|--------|---------------------|----------------------|
| Credentials per authenticator | Unlimited | One (same user_handle causes replacement) |
| Signal API effectiveness | Limited | Full |
| WebAuthn spec alignment | Non-standard | Aligned |

Existing credentials are not affected; only newly registered credentials use the new default. Developers who need the old behavior can explicitly set `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true`.

### Design decisions

- **Breaking change justified by spec alignment**: Unlike a purely preferential change, this corrects a deviation from the WebAuthn specification that had functional consequences (broken Signal API).

### Key files

`oauth2_passkey/src/passkey/config.rs`, `docs/src/webauthn/user-handle-and-signal-api.md`, `docs/src/integration/configuration.md`, `docs/src/integration/passkey.md`, `dot.env.example`, `CHANGELOG.md`

---

## 2026-01-28: Windows Hello TPM attestation fix (RS1 algorithm)

**Issue**: `2026-01-28-03` | **Priority**: high | **Difficulty**: medium

Bug fix -- Windows Hello passkey registration was completely broken.

### Motivation

Windows Hello (TPM-based authentication) passkey registration failed on the server side. Windows Hello uses the TPM attestation format and signs with COSE algorithm RS1 (`-65535`, RSA PKCS#1 v1.5 with SHA-1). The server did not recognize this algorithm identifier.

### User-facing impact

- **Before**: Windows Hello users could not register passkeys. Registration failed with an unrecognized algorithm error.
- **After**: Windows Hello users can successfully register passkeys using TPM attestation with the RS1 algorithm.

### Design decisions

Two separate bugs were identified and fixed:

1. **`integer_to_i64()` used a hardcoded value list**: The function compared CBOR integers against an explicit list of known values, and `-65535` was not in that list. Replaced with a generic conversion using `i128::from(*i)` + `i64::try_from()`.

2. **`verify_tpm_attestation()` only supported RS256 and ES256**: Added RS1 (`-65535`) handling using `ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY`. While SHA-1 is considered legacy for general use, it is acceptable for TPM attestation verification where the signing key is bound to hardware.

- **No new dependencies**: Both `ring` and `x509-parser` were already in `Cargo.toml`.

### Key files

`oauth2_passkey/src/passkey/main/attestation/utils.rs`, `oauth2_passkey/src/passkey/main/attestation/tpm.rs`, `oauth2_passkey/src/passkey/main/attestation/utils/tests.rs`

---

## 2026-01-28: WebAuthn Signal API improvements

**Issue**: `2026-01-28-01` | **Priority**: medium | **Difficulty**: medium

Enhancement -- a basic Signal API implementation existed since 2025-03 (calling `signalUnknownCredential` on credential deletion only), but lacked structured responses and comprehensive call-site coverage.

### Motivation

The existing Signal API integration was minimal: only `signalUnknownCredential` was called on credential deletion, implemented as inline JavaScript in templates. Login success/failure events did not trigger any Signal API calls. Server responses used `StatusCode::NO_CONTENT`, which did not provide the data (`remaining_credential_ids`, `user_handle`) that Signal API methods require.

### User-facing impact

- **Before**: Signal API called only on credential deletion (`signalUnknownCredential`). Server returned `204 No Content` with no credential metadata. No synchronization on login success or failure. No configuration for Signal API behavior.
- **After**: Signal API called on three events -- credential deletion, login success (`signalAllAcceptedCredentials`), and login failure (`signalUnknownCredential`). Server returns structured JSON with `remaining_credential_ids`, `user_handle`, and `signal_api_mode`. Three configurable modes via `PASSKEY_SIGNAL_API_MODE`:

| Mode | Behavior |
|------|----------|
| `direct` (default) | Signal API called on direct user actions (deletion) |
| `sync` | Signal API called on login events for sync |
| `direct+sync` | Both direct and sync calls |

### Design decisions

- **Server-controlled client behavior**: The server response includes a `signal_api_mode` field, allowing the server to dictate which Signal API calls the client makes.
- **Fire-and-forget Signal API calls**: Signal API invocations do not block the main authentication/deletion flow. Failures are logged but do not affect the user experience.
- **`signalCurrentUserDetails` excluded**: Testing revealed no practical benefit during login flows.

### Key files

`oauth2_passkey/src/coordination/passkey.rs`, `oauth2_passkey/src/env_var.rs`, `oauth2_passkey_axum/src/passkey.rs`, `oauth2_passkey_axum/static/passkey.js`, `oauth2_passkey_axum/static/account.js`, `oauth2_passkey_axum/static/conditional_ui.js`, `docs/src/webauthn/user-handle-and-signal-api.md`

---

## 2026-01-28: Session conflict policy implementation

**Issue**: `2026-01-28-02` | **Priority**: medium | **Difficulty**: medium

New feature -- no session conflict control existed prior to this change; multiple concurrent sessions were implicitly allowed.

### Motivation

When a user who already had an active session logged in again, the behavior was undefined. By default, unlimited concurrent sessions were silently permitted. Depending on security requirements, applications may need to "invalidate old sessions and replace with the new one" or "reject the login entirely." App developers had no way to implement this themselves because session management was handled entirely within the library internals.

### User-facing impact

- **Before**: No session conflict control. Multiple concurrent sessions were always allowed. No mechanism for apps to restrict concurrent logins.
- **After**: `SESSION_CONFLICT_POLICY` environment variable provides three configurable policies:

| Policy | Behavior |
|--------|----------|
| `allow` (default) | Multiple concurrent sessions permitted |
| `replace` | Old sessions automatically invalidated on new login |
| `reject` | Login denied if an active session already exists |

```bash
# Example: enable session replacement
SESSION_CONFLICT_POLICY=replace
```

### Design decisions

- **JSON array for user-to-session mapping**: The mapping from user to session IDs is stored in the existing CacheStore as a JSON array with a 30-day TTL and lazy cleanup of stale sessions.
- **Always-maintained mapping**: The user-to-session mapping is updated regardless of the policy value. This means changing the policy at any time takes immediate effect without a migration step.
- **Environment variable rename during implementation**: Originally `O2P_SESSION_CONFLICT_POLICY`, renamed to `SESSION_CONFLICT_POLICY` for naming consistency with other session-related environment variables.
- **`allow` as default**: Multi-device login is a common use case and the library should not impose a strict default.

### Key files

`oauth2_passkey/src/session/main/user_sessions.rs`, `oauth2_passkey/src/session/config.rs`, `oauth2_passkey/src/session/errors.rs`, `oauth2_passkey/src/session/main/session.rs`, `dot.env.example`

---

## 2026-01-27: Demo application cleanup and unification

**Issue**: `2026-01-27-03` | **Priority**: medium | **Difficulty**: medium

Enhancement -- Consistency and safety improvements across all demo applications.

### Motivation

Across the six demo applications, naming conventions, configuration methods, and router API usage were inconsistent. A particularly dangerous inconsistency was that some demos silently fell back to a hardcoded database URL when the environment variable was not set.

### User-facing impact

- **Before**: Template names varied between demos. Database configuration silently fell back to hardcoded defaults:
  ```rust
  // Silent fallback -- production deployment with missing config goes unnoticed
  .unwrap_or_else(|_| "postgres://demo:demo@localhost:5432/demo".to_string());
  ```
  Router setup used the manual nest pattern.

- **After**: All template names are consistent across demos. Database configuration fails fast with a clear error message:
  ```rust
  // Fail-fast -- missing config is caught at startup, not in production
  .expect("APP_DATABASE_URL environment variable must be set (see .env.example)");
  ```
  All demos use the unified router API:
  ```rust
  .merge(oauth2_passkey_full_router());
  ```

### Design decisions

- **Fail-fast over silent fallback**: The `expect()` with a descriptive message that references `.env.example` is intentional. In a demo context, failing early with guidance is far better than silently connecting to the wrong database.
- **Inline CSS exception**: demo-custom-login intentionally retains inline CSS rather than using the library's stylesheet. This is a deliberate design choice to demonstrate fully independent UI styling.
- **Unified router API**: All demos were migrated to `oauth2_passkey_full_router()` to provide a consistent reference implementation.

### Key files

`demo-custom-login/`, `demo-profile/src/db.rs`, `demo-todo/src/db.rs`, `demo-oauth2/src/main.rs`

---

## 2026-01-27: Unified router API design

**Issue**: `2026-01-27-02` | **Priority**: medium | **Difficulty**: medium

New feature -- API simplification

### Motivation

The library's router construction required users to perform multiple manual steps: obtain the router from `oauth2_passkey_router()`, nest it under `O2P_ROUTE_PREFIX` themselves, and -- for multi-origin WebAuthn configurations -- separately add `passkey_well_known_router()` for the `/.well-known/webauthn` endpoint. This boilerplate was duplicated across every demo application and was error-prone for new users. Additionally, the `/.well-known/webauthn` path was incorrectly implemented as `/webauthn` (missing the `/.well-known` prefix).

### User-facing impact

- **Before**: Users had to manually nest the router under the correct prefix and separately merge the well-known route:
  ```rust
  // 3 things to get right: prefix, router, well-known
  let app = Router::new()
      .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
      .merge(passkey_well_known_router());  // easy to forget
  ```

- **After**: A single `merge` call handles everything:
  ```rust
  // One line, nothing to forget
  let app = Router::new()
      .merge(oauth2_passkey_full_router());
  ```

The new function automatically nests auth endpoints under `O2P_ROUTE_PREFIX`, checks `WEBAUTHN_ADDITIONAL_ORIGINS` and conditionally adds `/.well-known/webauthn`, and fixes the path from `/webauthn` to `/.well-known/webauthn` (bug fix).

### Design decisions

- Made the new `oauth2_passkey_full_router()` the recommended API while keeping the lower-level functions available. This follows the "easy things should be easy, hard things should be possible" principle.
- The well-known route is conditionally included (not always present) to avoid exposing unnecessary endpoints in single-origin deployments.

### Key files

`oauth2_passkey_axum/src/lib.rs`, `oauth2_passkey_axum/src/passkey.rs`, `docs/src/integration/multi-origin.md`, `demo-both/src/main.rs`

---

## 2026-01-27: Admin route refactoring

**Issue**: `2026-01-27-01` | **Priority**: medium | **Difficulty**: medium

Enhancement (BREAKING CHANGE) -- Route naming and mobile responsiveness

### Motivation

The admin page routes and handler names were unintuitive. The admin user list URL was `/o2p/admin/list_users`, which violated common API design conventions where collection resources are accessed at the root of their namespace. Handler function names like `list_users()` were generic. Additionally, the admin user list page had no mobile-responsive layout.

### User-facing impact

- **Before**: Admin user list was at `/o2p/admin/list_users`. The page used a plain HTML table that was unusable on mobile devices.
- **After**:
  - Route: `/o2p/admin/list_users` -> `/o2p/admin/index`
  - Handlers: `list_users()` -> `admin_index()`, `user_summary()` -> `admin_user_page()`
  - Template: `UserListTemplate` -> `AdminIndexTemplate`
  - Page title: "User List" -> "User Management"
  - Default config: `O2P_ADMIN_URL` default changed
  - Feature flag: handler moved from `default.rs` to `optional.rs`, now controlled by `admin-ui`
  - Mobile responsive layout: table view on desktop, card view on mobile

**BREAKING CHANGE**: The admin URL changed from `/admin/list_users` to `/admin/index`.

### Design decisions

- Chose `/admin/index` over `/admin/` (bare path) to be explicit about the endpoint.
- Moved the admin list handler behind the `admin-ui` feature flag because it is an optional UI component.
- Used CSS-based responsive design (card layout on mobile) rather than a JavaScript-based approach.

### Key files

`oauth2_passkey_axum/src/admin/optional.rs`, `oauth2_passkey_axum/src/config.rs`, `oauth2_passkey_axum/templates/admin_user_list.j2`

---

## 2026-01-26: Documentation structure and demo configuration cleanup

**Issue**: `2026-01-26-02` | **Priority**: low | **Difficulty**: low

Enhancement -- Documentation organization and configuration consistency

### Motivation

The documentation structure had organizational issues: CSS customization and template customization were mixed into a single page (`custom-pages.md`). Demo applications used inconsistent environment variable names for database configuration.

### User-facing impact

- **Before**: A user looking for "how to customize CSS" had to open `custom-pages.md` and search through template customization content. Demo apps used different environment variable names for database URLs.
- **After**:
  - `custom-pages.md` renamed to `customizing-templates.md` (focused solely on template customization)
  - New `customizing-css.md` created (focused solely on CSS customization)
  - All demo apps use `APP_DATABASE_URL` consistently

### Design decisions

- Created a parallel naming convention for customization docs: `customizing-templates.md` and `customizing-css.md`.
- Unified on `APP_DATABASE_URL` to avoid collision with common framework conventions while keeping the `APP_` prefix to clearly indicate application-level configuration.

### Key files

`docs/src/integration/customizing-css.md`, `docs/src/integration/customizing-templates.md`, `demo-profile/src/db.rs`, `demo-todo/src/db.rs`

---

## 2026-01-26: Demo app database configuration and documentation

**Issue**: `2026-01-26-01` | **Priority**: medium | **Difficulty**: medium

Enhancement -- Configuration and documentation

### Motivation

The demo-profile application had its database URL hardcoded, making it unclear how users could switch between SQLite and PostgreSQL. Documentation was missing for user data integration and custom admin pages.

### User-facing impact

- **Before**: demo-profile's database connection was hardcoded. No documentation for user data integration or custom admin pages.
- **After**:
  - **demo-profile**: Database URL unified under `APP_DATABASE_URL` environment variable
  - **demo-todo**: Full CRUD operations implemented (previously incomplete)
  - **demo-custom-login**: Admin page implementation added
  - **New documentation**: `docs/src/integration/user-data.md` explains how to link application-specific tables to the library's `o2p_users` table
  - **UI modernization**: Library's default templates received a modern UI redesign
  - **CSS customization docs**: New documentation for CSS customization

### Design decisions

- Presented both same-database and separate-database configurations as equally valid options in demo-profile.
- Added necessary re-exports from the library to support custom admin page implementations.

### Key files

`demo-profile/`, `demo-todo/`, `demo-custom-login/`, `docs/src/integration/user-data.md`, `docs/src/integration/custom-pages.md`

---

## 2026-01-24: Demo applications for user data integration (demo-profile, demo-todo)

**Issue**: `2026-01-24-02` | **Priority**: medium | **Difficulty**: medium

New feature -- Demo applications

### Motivation

The existing demo applications were focused exclusively on demonstrating authentication flows. They did not show the most critical real-world pattern: how to manage application-specific user data after authentication.

### User-facing impact

- **Before**: After studying the existing demos, a developer understood how to authenticate users but had no reference for "what comes next" -- linking app-specific data to authenticated users.
- **After**: Two new demo applications provide concrete integration patterns:
  - **demo-profile**: Demonstrates a 1:1 relationship extension pattern. An application-specific `user_profiles` table is linked to the library's `o2p_users` table via a foreign key on `user_id`.
  - **demo-todo**: Demonstrates a 1:N relationship pattern. Each authenticated user has their own ToDo list with full CRUD operations.

```sql
CREATE TABLE user_profiles (
    user_id TEXT PRIMARY KEY,
    display_name TEXT,
    bio TEXT,
    avatar_url TEXT,
    theme TEXT DEFAULT 'light',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Design decisions

- Kept demo-profile and demo-todo as separate applications rather than combining them, because they illustrate distinct data patterns (1:1 extension vs. 1:N ownership).
- Added documentation in `docs/src/getting-started/architecture.md` explaining the data integration patterns.

### Key files

`demo-profile/`, `demo-todo/`, `docs/src/getting-started/architecture.md`

---

## 2026-01-23: CSRF documentation reorganization and session snapshot system

**Issue**: `2025-01-23-02` | **Priority**: medium | **Difficulty**: medium

Enhancement -- Documentation and developer tooling

### Motivation

Two separate problems were addressed:

1. **CSRF documentation gap**: The existing CSRF documentation only covered AJAX (fetch API) token submission via the `X-CSRF-Token` header. Users implementing traditional HTML form submissions had no guidance.
2. **Development context loss**: When switching machines or resuming work across Claude Code sessions, all working context was lost.

### User-facing impact

- **Before**: `csrf-handling.md` described only AJAX-based CSRF token flow. Two documentation files had overlapping content. No way to transfer work context between machines.
- **After**: `csrf-handling.md` rewritten to cover both AJAX and HTML form submission patterns. Document roles clearly delineated. Key technical note documented: always use `ct_eq` (constant-time comparison) for CSRF token verification, never `==`, to prevent timing attacks. Session snapshot system (`.claude/sessions/`) provides context transfer mechanism.

### Design decisions

- Separated the CSRF documentation by audience: security reviewers read `security/csrf.md`, implementors follow `integration/csrf-handling.md`.
- The session snapshot system uses simple markdown files for maximum portability and readability.

### Key files

`docs/src/integration/csrf-handling.md`, `.claude/sessions/`, `.claude/commands/snapshot.md`, `CLAUDE.md`

---

## 2026-01-23: CI/CD pipeline documentation

**Issue**: `2025-01-23-01` | **Priority**: low | **Difficulty**: low

Enhancement -- Documentation

### Motivation

The CI/CD pipeline configuration (GitHub Actions) existed only as institutional knowledge. Contributors had no way to understand the intent, structure, or trigger conditions of each workflow.

### User-facing impact

- **Before**: No documentation for CI/CD workflows. Contributors had to reverse-engineer `.github/workflows/*.yml` files.
- **After**: `docs/src/maintainer/ci-cd.md` provides a clear reference covering all three workflows -- their roles, trigger conditions, and job structure:
  - **CI** (`ci.yml`): Testing across Rust versions, linting, security audit, MSRV check
  - **Coverage** (`coverage.yml`): Code coverage via cargo-llvm-cov, upload to Codecov
  - **Documentation** (`docs.yml`): mdBook build and GitHub Pages deployment

### Design decisions

- Documented all three workflows in a single page rather than one page per workflow, since they are tightly related and benefit from being viewed together.
- Also explained the GitHub Pages URL naming convention to help forks set up their own docs sites.

### Key files

`docs/src/maintainer/ci-cd.md`, `docs/src/SUMMARY.md`
