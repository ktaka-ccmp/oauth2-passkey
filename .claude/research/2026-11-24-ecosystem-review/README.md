# oauth2-passkey: Ecosystem Position and Architecture Review (2026-11-24)

Investigation carried out on 2026-11-24/25 after the v0.6.2 release. It
asks why the crate has little adoption, how it compares with other Rust
options, and whether building on `webauthn-rs` / `openidconnect` or
decoupling the internals is worthwhile.

Sources: crates.io and GitHub APIs (numbers as of 2026-11-24), crate
sources (`webauthn-rs` 0.6.2, `openidconnect` 4.1.0, `torii` 0.5.3,
`axum-login` main), the rust-lang Zulip, and this repository at
origin/dev 13fde6c. Three parts were delegated to sub-agents; their
reports are attached (`webauthn-rs.md`, `openidconnect.md`,
`effort-comparison.md`) and their main claims were re-checked against
source. Anything not checked is marked "unverified".

## 1. Summary

- Adoption is very low (87 downloads in 90 days, no third-party
  dependents). RustSec declined the advisory for the 0.6.2 fix on
  notability grounds.
- For the target use case (Google OIDC + passkey sign-in on Axum), this
  crate needs far less application code than the alternatives: about
  20-60 lines of Rust and no JS/SQL, versus about 1,000-1,300 lines of
  Rust plus JS and SQL with `axum-login` + `tower-sessions` +
  `openidconnect` + `webauthn-rs`.
- Torii, the closest "all-in-one" competitor, does not yet implement
  OIDC or WebAuthn in its released code.
- Weaknesses are mostly structural: env-var-only configuration and
  global state, a fixed user schema, protocol code coupled to users and
  sessions, a hand-written WebAuthn implementation, and sessions that
  persist only with Redis.
- Building on `webauthn-rs` / `openidconnect` is only partly feasible
  today (see sections 5 and 6). A large internal rework was judged not
  worth it for now; specific defects found during the study were filed
  as issues instead.

## 2. Adoption data

crates.io, 2026-11-24 ("recent" = last 90 days):

| Crate | Total downloads | Recent |
|---|---|---|
| oauth2-passkey | 2,537 | 87 |
| oauth2-passkey-axum | 2,120 | 31 |
| webauthn-rs | ~9.9M | ~3.8M |
| axum-login | ~1.7M | ~750k |
| tower-sessions | ~5.0M | ~1.6M |
| openidconnect | ~18.6M | ~6.3M |
| torii | 33,853 | 1,081 |

- Per version: 0.1.x (June-July 2025) 461-769 each; 0.2.0-0.6.1 (2026)
  27-132 each, close to the level produced by mirrors and bots.
- Monthly downloads, Aug-Nov 2026: 2, 16, 30, 42.
- GitHub: 19 stars, 1 fork. Reverse dependencies: only
  `oauth2-passkey-axum`.
- crates.io search rank: "passkey" 11th of 366; "webauthn" not in the
  top 50; "passkey axum" 3rd; "oauth2 axum" 34th.
- Announcements: one post on users.rust-lang.org (2025-07-11, no
  replies); no Hacker News mentions; four posts on the author's blog.
  Reddit and This Week in Rust were not checked.

### RustSec notability

The RustSec advisory for GHSA-f7r7-vc8j-f293
(rustsec/advisory-db#3642) was closed on 2026-11-24 as not meeting the
minimum notability criteria. As stated by the maintainer in several PRs
and in the Zulip topic "Minimum notability criteria?" (#wg-secure-code),
a crate needs at least one of:

- 1,000 recent downloads,
- 100,000 all-time downloads,
- one reverse dependency from a different maintainer.

oauth2-passkey meets none of them. The advisory remains available
through GitHub (GHSA / Dependabot).

## 3. The usual way to build auth with Axum

There is no official standard; Axum has no auth built in. Common
patterns:

1. Components: `axum-login` + `tower-sessions` (+ a SQL store) +
   `argon2` / `password-auth` + `oauth2` / `openidconnect` +
   `webauthn-rs`. The application owns its user schema and UI.
2. External IdP (Keycloak, Zitadel, Ory, Auth0, ...) over OIDC, with a
   thin client in the app.
3. Token-based APIs: `jsonwebtoken` plus extractors.

Other ecosystems have a default batteries-included option (Rails +
Devise, Django auth / allauth, Auth.js, Laravel Breeze). Rust does not;
the official examples of the components stop short of a working login
(section 7). This gap is what oauth2-passkey targets.

## 4. Weaknesses compared with alternatives

Ordered by expected impact on adoption.

1. Configuration only through environment variables (53 names) and
   global `LazyLock` state (49 statics), with a single `init()`. No
   programmatic/builder configuration.
2. Fixed user model and tables; no public trait to plug in an
   application's own users (`axum-login` lets the app supply them).
3. Only OIDC and passkeys (no password, magic link). Deliberate, but it
   narrows the audience.
4. Hand-written WebAuthn verification, without third-party review
   (formats: none, packed, tpm, u2f; no android-key, apple, MDS).
5. All-in-one: own sessions, cache, templates and admin UI; cannot be
   combined with `tower-sessions` / `axum-login`. 382 crates in the
   dependency tree with all features.
6. API still changing (0.2 -> 0.6 in ten months).
7. Single maintainer.
8. Production features still open: rate limiting, login history spam
   (`20260226-2024`, `2026-02-08-02`).
9. Discoverability (search, announcements).

Strengths: working demo site, mdBook guide, many OIDC providers
(Google + 8 presets + 8 generic slots), FedCM, four database backends,
CI with coverage.

## 5. Coupling analysis

The intended layering holds at the module level: only `coordination`
imports `oauth2` and `passkey`. The coupling is elsewhere:

1. Global state. `GENERIC_DATA_STORE` and `GENERIC_CACHE_STORE` are
   global `LazyLock<Mutex<Box<dyn ...>>>`
   (`storage/data_store/config.rs:17`, `storage/cache_store/config.rs:14`),
   used directly by each module; configuration is read by `LazyLock`
   statics in each module. Dependencies are invisible in signatures and
   cannot be injected.
2. Protocol modules know about users and sessions. `passkey` and
   `oauth2` use `crate::session::UserId` and
   `crate::userdb::DB_TABLE_USERS`; `passkey` also uses `UserStore`.
3. HTTP concepts in the core: `HeaderMap` etc. in `session`, `oauth2`,
   `coordination`, `audit`; `session` is imported by `oauth2`,
   `passkey`, `userdb`, `storage`.

Symptoms already filed: `20261117-0727` (filtered test runs need
`ORIGIN`), `20261120-0851` (PostgreSQL test hang), `20261124-1130`
(tests affected by leftover rows). The sqlx 0.9 upgrade touched 120
call sites in 14 files.

Possible incremental path (not scheduled): make passkey/OIDC
verification pure functions (input -> verified result) with
`coordination` wiring storage, users and sessions; then pass stores and
configuration explicitly, keeping `init()` + env vars as a convenience
layer; then decouple credential tables from the users table.

## 6. Building on webauthn-rs

Full report: `webauthn-rs.md`. Conclusion: partly feasible.

- `webauthn-rs` 0.6.2 can replace all verification (client data,
  origin, rpIdHash, flags, signature, counter, attestation including
  apple and android-key). Stored keys are all P-256, so existing
  passkeys could be converted without re-registration.
- The safe high-level API fixes user verification `Required`, resident
  key not required and attestation `None`
  (`webauthn-rs` `src/lib.rs` around 567-575, checked). Our defaults are
  the opposite: UV `discouraged`, resident key `required`, attestation
  `direct` (`passkey/config.rs`).
- Keeping current behavior requires `webauthn-rs-core`, whose
  constructor `new_unsafe_experts_only` is documented as "MAY change
  WITHOUT NOTICE and WITHIN MINOR VERSIONS ... Use `webauthn-rs`
  instead" (`core.rs` 184-199, checked).
- Other differences: JSON shape (camelCase, nested `publicKey`), backup
  flags must be tracked, counter value 0 after a non-zero value is
  rejected (`core.rs` 1186-1205, checked), `crossOrigin: true`
  rejected.
- Effort: about 10-15 files, removal of about 1,850 lines of attestation
  code and 3,190 lines of tests, schema change on three backends, JS
  changes; several weeks including tests with real authenticators.

## 7. Building on openidconnect

Full report: `openidconnect.md`. Conclusion: partly feasible.

- Blocker: `openidconnect` 4.1.0 depends on `rsa` 0.9.2 (checked),
  affected by RUSTSEC-2023-0071, which CI's `cargo audit` would flag.
- It could take over ID token verification (signature, iss, aud, exp,
  nonce), authorization URL and code exchange. `azp` is intentionally
  not verified (checked), `nbf` is not handled, issuer match is exact
  (Auth0 trailing slash), no discovery/JWKS caching, reqwest 0.12
  integration (we use 0.13).
- Public API would not change (`oauth2` module is private).
- Lowest-risk option if ever pursued: keep discovery and caching, use
  the crate only for ID token verification.

## 8. Effort comparison for the same app

Full report: `effort-comparison.md`. Target app: Google OIDC sign-in,
passkey registration and usernameless passkey sign-in, session and
logout, protected route, SQLite persistence, CSRF, minimal UI.

| | Components | Torii 0.5.3 | oauth2-passkey-axum |
|---|---|---|---|
| App Rust | ~1,000-1,300 (estimate) | ~800-1,100 (estimate) | ~20-60 (counted) |
| JS | ~110-150 | ~110-150 | 0 |
| SQL | ~25-40 | 0-10 | 0 |
| Security work left to the app | state/nonce/PKCE, ID token verification, challenge storage, counter, CSRF, ... | as components, plus email auto-link check | env config, CSRF header on own routes |

Findings checked against source:

- Torii: `torii-axum/src/lib.rs` lists OAuth and Passkey as "Coming
  soon"; no Torii crate depends on a WebAuthn or OIDC library;
  `PasskeyService::authenticate_credential` returns the user for a
  credential ID without verifying any signature or challenge
  (`torii-core/src/services/passkey.rs:56-78`). Its README marks both
  as supported.
- `openidconnect` `examples/google.rs` prints the returned state but
  does not compare it with the expected one (lines 196-201) and uses no
  PKCE. The `webauthn-rs` Axum tutorial is username-based and keeps
  data in memory.
- oauth2-passkey stores sessions in the cache store, which supports only
  `memory` or `redis` (`storage/cache_store/config.rs:24-26`); without
  Redis, sessions are lost on restart.

## 9. Defects and follow-ups filed

| ID | Title |
|---|---|
| `20261124-1130` | Login History Retention Tests Fail on a Reused Database |
| `20261124-2345` | signalAllAcceptedCredentials Sends a userId That Does Not Match the Registered User ID |
| `20261124-2346` | is_discoverable() Uses the Backup Eligibility Flag |
| `20261125-0003` | Registration Offers RS256 but Only ES256 Credential Keys Can Be Stored and Verified |
| `20261125-0018` | Database-Backed Cache Store (Persistent Sessions Without Redis) |

Related existing issues: `20261124-2136` (no credential IDs from
unauthenticated auth/start), `20261124-2137` (typed authData parsing),
`20260226-2019` (finalize public API for 1.0).

## 10. Decision (2026-11-25)

- No migration to `webauthn-rs` / `openidconnect` and no large internal
  rework for now. The benefit relative to the size of the change was
  not considered sufficient; the defects found are fixed individually
  through the issues above.
- Points that would change this assessment: the cost of keeping up with
  WebAuthn spec changes as a single maintainer, a `webauthn-rs`
  high-level API that allows the current defaults, an `openidconnect`
  release on `rsa` 0.10, or a goal of wider adoption.
- Ideas considered and not pursued now: splitting into an auth API
  server or OIDC provider (crowded space: SuperTokens, Ory Kratos,
  Hanko, Kanidm, Rauthy), and a builder-based configuration API.
