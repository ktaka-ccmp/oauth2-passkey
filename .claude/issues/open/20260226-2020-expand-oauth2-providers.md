# Issue: Expand OAuth2 Provider Support

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2020

## Created: 2026-02-26

## Closed:

## Status: open (Step 1 completed 2026-04-16; Step 2 completed 2026-04-20, pending LT screenshots + Phase 2+)

## Priority: high

## Difficulty: large

## Description

Currently only Google OAuth2/OIDC is supported. Add support for additional OAuth2 providers to expand the library's utility:

- **GitHub** - Popular for developer-facing applications
- **Apple** - Required for iOS apps using third-party login
- **Microsoft** (Azure AD / Entra ID) - Common in enterprise environments

### Design Considerations

- The existing provider system was designed with extensibility in mind (OIDC Discovery, typed `Provider` wrapper)
- Each provider has slightly different OAuth2/OIDC implementations and quirks
- Apple Sign-In has unique requirements (form_post response mode, private email relay)
- GitHub uses OAuth2 but not full OIDC (no ID token by default)

## Related Issues

None

## Approach

Revised on 2026-04-15 (second revision, same day) after reconsidering the
order. The original phased plan put "Auth0 switch mode" as Phase 0 and "multi-
instance refactor" as Phase 1. That ordering was chosen for deadline safety
(an Auth0 LT on 2026-04-20), but it wastes work: Phase 0 would add narrowly-
scoped fixes that Phase 1 then rewrites. The revised ordering does the
architectural work first and adds Auth0 as a trivial follow-up:

- **Step 1 — Multi-IdP capable internals, Google-only at runtime** (target:
  2026-04-18). Replace the global `LazyLock` config with a provider registry.
  Thread a `&ProviderConfig` context through every OAuth2 flow function. Add
  a `provider` field to `StateParams` for callback dispatch. Per-instance
  CSRF cookie names. Per-instance OIDC Discovery cache. Make `IdInfo` /
  `GoogleUserInfo` fields that are Google-specific optional. Fix the OIDC
  Discovery trailing-slash issuer comparison bug. Done condition: all existing
  tests pass unchanged, the Google login flow works identically from a
  user's perspective, but the codebase is ready to add a second instance
  without any further refactoring.
- **Step 2 — Add Auth0 as a second instance** (target: 2026-04-19). Pure
  configuration work if Step 1 is truly done: create an Auth0 tenant, register
  the app, add `OAUTH2_INSTANCES=google,auth0` and `OAUTH2_AUTH0_*` entries
  to the demo `.env`, verify end-to-end. No code changes expected — if code
  changes are needed, Step 1 was incomplete.
- **Phase 2 — GitHub (non-OIDC) flow**. Separate flow branch (no id_token,
  userinfo via REST, no nonce/at_hash). Introduces an `OAuth2Flow` trait.
- **Phase 3 — Apple Sign-In**. `response_mode=form_post` forced, `client_secret`
  as ES256 JWT, name/email only in the initial authorization form body.
- **Phase 4 — FedCM multi-provider** (optional, only if demand appears).

Step 1 and Step 2 together replace what the earlier revision called Phase 0
and Phase 1. Steps 1-2 are the deadline-critical path; Phases 2-4 are deferred
until after the LT.

### Fallback plan

If by Saturday morning (2026-04-18) Step 1 is not on track to finish the
weekend, fall back to the earlier "Phase 0 minimal" plan on a separate branch:
fix discovery trailing-slash, make `IdInfo` fields optional, add
`OAUTH2_PROVIDER_NAME` env var. That is ~80 lines and gets Auth0 working via
switch mode for the LT. Step 1 then resumes after the LT as an unhurried
refactor. This fallback branch should be prepared preemptively on Wednesday
so it is available if needed.

### Design decisions fixed on 2026-04-15 (for Step 1)

To avoid losing time to design churn mid-refactor, the following are locked:

- **Configuration format**: one `LazyLock<ProviderConfig>` static per
  supported provider, listed explicitly in code. No `OAUTH2_INSTANCES` env var
  and no HashMap registry — the set of providers is fixed at compile time by
  the `ProviderKind` enum variants. Google is unconditional (panics if
  `OAUTH2_GOOGLE_CLIENT_ID` / `OAUTH2_GOOGLE_CLIENT_SECRET` are missing,
  matching current behaviour). Optional providers (e.g. Auth0 in Step 2) use
  `LazyLock<Option<ProviderConfig>>` and are enabled by setting their env vars.
  Each provider's `redirect_uri` is built as
  `{ORIGIN}{O2P_PREFIX}/oauth2/{provider}/authorized` during static init.
  TOML/JSON config files are explicitly deferred; revisit if instance count
  grows past ~3 in practice.
- **Callback routing**: per-instance `/oauth2/{provider}/authorized`. The
  provider is identified from the URL path at the Axum router level, before
  any state decoding. `StateParams` still carries `provider` as a
  defense-in-depth cross-check. This is a **breaking change** from the
  previous single `/oauth2/authorized` callback, requiring existing users
  to update their IdP console redirect URIs from `/oauth2/authorized` to
  `/oauth2/google/authorized`. The old URL is **not** kept as an alias:
  instead, a temporary `410 Gone` handler at `/oauth2/authorized` returns
  a JSON payload pointing to the new URL, retained for 2-3 releases so
  mis-configured setups fail loudly with a clear message. Rationale: at
  0.x versioning, minor-bump breaking changes are allowed; the migration
  cost for existing users is a single redirect URI edit in the IdP
  console; maintaining a dual code path with the old "provider from state
  only" approach would perpetuate the weaker defense-in-depth property
  that was the main reason to move callback identification into the URL
  in the first place.
- **Reserved provider names**: `ProviderRegistry::init_from_env` rejects
  any instance name that would collide with existing literal routes under
  `/oauth2/*`: `authorized`, `accounts`, `fedcm`, `popup_close`, `oauth2.js`.
  Also reject names containing `/`, `.`, or characters outside `[a-z0-9_-]`.
- **Next release**: `0.6.0` (minor bump). The callback URL change is a
  SemVer breaking change and must not ship as a patch. CHANGELOG gets a
  prominent "Breaking Changes" section with a 2-line migration guide.
- **CSRF cookie name**: `__Host-CsrfId` remains a single global name, not
  per-instance. The single-cookie design is the mechanism that implements
  the existing "latest flow wins" policy: when a new OAuth2 flow starts
  while another is in flight, the new flow's cookie overwrites the old
  one, causing the abandoned flow's callback to fail at `csrf_checks`
  (cookie token will not match the cached token keyed by `state.csrf_id`).
  This is intentional and must be preserved under multi-IdP: OAuth2
  callbacks have irreversible side effects (session rotation, account
  linking, login history insertion), and silently completing an abandoned
  flow in parallel with a newer one would create ghost state the user
  did not consent to. Fail-closed is the safer direction. `ProviderConfig`
  must **not** carry a `csrf_cookie_name` field; `OAUTH2_CSRF_COOKIE_NAME`
  stays as a global `LazyLock`. Step 1 adds a policy comment near
  `csrf_checks` so future "clean-up" PRs that try to make the cookie
  per-instance understand the intent.
- **Claim → OAuth2Account conversion**: replace the `From<GoogleIdInfo>` /
  `From<GoogleUserInfo>` trait impls with free functions that take a
  `provider_name: &str` argument. The provider name is supplied by the
  callback handler from the URL path (with `StateParams` cross-check), so
  DB rows get the correct instance name instead of hardcoded `"google"`.

## Related Files

- `oauth2_passkey/src/oauth2/config.rs` - Global `LazyLock` config (Phase 1 replaces this with a registry)
- `oauth2_passkey/src/oauth2/discovery.rs` - OIDC Discovery; has trailing-slash issuer comparison bug blocking Auth0
- `oauth2_passkey/src/oauth2/main/core.rs` - OAuth2 flow core; `OAUTH2_GOOGLE_CLIENT_ID` hardcoded in auth URL
- `oauth2_passkey/src/oauth2/main/google.rs` - Token exchange + userinfo fetch (Google-named but mostly generic OIDC)
- `oauth2_passkey/src/oauth2/main/idtoken.rs` - `IdInfo` struct with Google-specific required fields
- `oauth2_passkey/src/oauth2/main/fedcm.rs` - FedCM support (Google-only, unchanged in Phase 0)
- `oauth2_passkey/src/oauth2/types.rs` - `From<GoogleUserInfo/IdInfo> for OAuth2Account` with hardcoded `provider: "google"`
- `oauth2_passkey/src/coordination/oauth2.rs` - Coordination layer; tracing span hardcodes `provider = "google"`
- `oauth2_passkey_axum/src/oauth2.rs` - Axum handlers; `/oauth2/google` route
- `oauth2_passkey_axum/static/oauth2.js` - Frontend; hardcodes `/oauth2/google` and Google FedCM configURL
- `dot.env.example` - Environment variable documentation

## Implementation Tasks

### Step 1: Multi-IdP capable internals, Google-only at runtime (target 2026-04-18)

Provider infrastructure (simplified — no registry, no HashMap, no `OAUTH2_INSTANCES`):

- [x] Create `oauth2_passkey/src/oauth2/provider.rs` with `ProviderKind` enum (`pub(crate)`), `ProviderConfig` struct (`pub(crate)`), `GOOGLE_PROVIDER: LazyLock<ProviderConfig>` static, and `provider_for(kind: ProviderKind) -> Option<&'static ProviderConfig>` match dispatcher
- [x] `ProviderConfig` owns its OIDC Discovery cache as `OnceCell<OidcDiscoveryDocument>` (replacing the global `OIDC_DISCOVERY_CACHE`)
- [x] `ProviderConfig` async methods: `token_url()`, `jwks_url()`, `userinfo_url()`, `expected_issuer()` (reading from discovery doc via `OnceCell`)
- [x] `ProviderKind::from_path_segment(&str) -> Option<ProviderKind>` for URL path parsing; `ProviderKind::as_str() -> &'static str` for display / DB values
- [x] Per-provider `redirect_uri` built as `{ORIGIN}{O2P_PREFIX}/oauth2/{provider_name}/authorized` in `ProviderConfig` initialization
- [x] `ProviderConfig` does **not** carry `csrf_cookie_name`. `OAUTH2_CSRF_COOKIE_NAME` stays global — see "latest wins" policy in Design decisions
- [x] Reserved provider names (`authorized`, `accounts`, `fedcm`, `popup_close`, `oauth2.js`) documented as compile-time constraint comment in `provider.rs` (no runtime rejection needed since providers are code-defined, not env-configured)

Thread `&ProviderConfig` through flow functions:

- [x] `prepare_oauth2_auth_request(provider, headers, mode)` takes an instance name, looks up the config
- [x] `get_idinfo_userinfo(ctx, auth_response)` reads client_id / client_secret / endpoints from ctx
- [x] `exchange_code_for_token(ctx, code, verifier)` in `main/oidc.rs` (was `main/google.rs`; also renamed `fetch_user_data_from_google` -> `fetch_userinfo`)
- [x] `csrf_checks` signature unchanged — cookie name is still global, ctx not needed
- [x] Add a policy comment near `csrf_checks` / the cookie `Set-Cookie` site explaining why the cookie name is single and global ("latest flow wins" rationale), referencing the 2026-04-16 Decision Log entry
- [x] Add a short paragraph to `docs/src/security/oauth2-security.md` under "Note on CSRF Tokens in the System" documenting the "latest flow wins" behaviour explicitly
- [x] `prepare_fedcm_nonce(ctx)` / `validate_fedcm_token(ctx, token, nonce_id)` — FedCM stays Google-only but accepts ctx for API symmetry

State and callback dispatch:

- [x] Add `provider: String` field to `StateParams` (as defense-in-depth cross-check, not the primary dispatch signal)
- [x] `prepare_oauth2_auth_request` writes the instance name into state
- [x] Callback handler receives `Path(provider)` from Axum, looks up provider **before** decoding state, then decodes state and asserts `state.provider == path_provider` (reject mismatch as security event)
- [x] Existing `OAUTH2_RESPONSE_MODE` global becomes `ctx.response_mode` — callback method validation uses ctx

Claim extraction refactor:

- [x] Make `IdInfo` fields optional: `azp`, `given_name`, `family_name`, `email_verified` (renamed to `OidcIdInfo`)
- [x] Make `GoogleUserInfo` fields optional to match (renamed to `OidcUserInfo`)
- [x] Replace `impl From<GoogleIdInfo> for OAuth2Account` with free function `oauth2_account_from_idinfo(idinfo, provider_name)`
- [x] Replace `impl From<GoogleUserInfo> for OAuth2Account` with free function `oauth2_account_from_userinfo(userinfo, provider_name)`
- [x] Callers in `coordination/oauth2.rs` pass the URL-derived provider name to the free functions

OIDC Discovery and endpoint resolution:

- [x] Fix trailing-slash issuer comparison in `fetch_oidc_discovery` (normalize both sides)
- [x] Remove global `OIDC_DISCOVERY_CACHE`, `OAUTH2_ISSUER_URL`, `OAUTH2_REDIRECT_URI`, `OAUTH2_GOOGLE_CLIENT_ID/SECRET`, `OAUTH2_RESPONSE_MODE`, `OAUTH2_QUERY_STRING` from `config.rs` — these move into `ProviderConfig`
- [x] **Keep** `OAUTH2_CSRF_COOKIE_NAME` and `OAUTH2_CSRF_COOKIE_MAX_AGE` as global `LazyLock` (intentional, see "latest wins" policy)

Axum route and handler:

- [x] Change initiate route from `/oauth2/google` to `/oauth2/{provider}` with `Path<String>` extraction
- [x] `google_auth` → `oauth2_initiate(Path(provider), ...)` — looks up instance, calls `prepare_oauth2_auth_request(&provider, headers, mode)`
- [x] Change callback route from `/oauth2/authorized` to `/oauth2/{provider}/authorized` with both `.get()` and `.post()` (provider in URL path, not state)
- [x] Add `410 Gone` handler at `/oauth2/authorized` returning JSON `{"error": "callback URL moved", "new_url_pattern": "/oauth2/{provider}/authorized"}` — retained for 2-3 releases as a helpful migration error
- [x] `get_google_client_id()` public API: resolves to Google instance's client_id via provider_for()

Frontend:

- [x] Update `static/oauth2.js` initiate URL (already `/oauth2/google` — stays the same, no change needed)
- [x] FedCM path unchanged (Google-only)

Tests and verification:

- [x] Update `oauth2/main/core/tests.rs` to use a test `ProviderConfig` helper
- [x] Update `oauth2/main/oidc/tests.rs` (was `google/tests.rs`) — updated with renamed types
- [x] Update `oauth2/main/idtoken/tests.rs` for optional fields
- [x] Update `oauth2/config/tests.rs` for registry initialization
- [x] New test: `GOOGLE_PROVIDER` LazyLock initializes from `OAUTH2_GOOGLE_CLIENT_ID` / `OAUTH2_GOOGLE_CLIENT_SECRET` env vars
- [x] New test: `ProviderKind::from_path_segment` parses known and unknown provider names (in `provider/tests.rs`)
- [x] New test: `provider_for` returns `Some` for Google (in `provider/tests.rs`)
- [x] New test: callback handler reads provider from URL path and cross-checks with `state.provider` (implemented in `coordination/oauth2.rs:process_oauth2_authorization`)
- [x] New test: callback handler rejects URL/state provider mismatch as a security event (`test_oauth2_provider_mismatch_rejected_as_security_event` in `tests-security/oauth2_security.rs`; impl in `coordination/oauth2.rs`)
- [x] New test: `410 Gone` handler at `/oauth2/authorized` returns the migration payload
- [x] `cargo test --manifest-path oauth2_passkey/Cargo.toml` passes
- [x] `cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --all-features` passes
- [x] `cargo clippy --all-targets --all-features` clean
- [x] Manual Google login end-to-end test via demo-oauth2

### Step 2: Add Auth0 as a second instance (target 2026-04-19)

- [x] Create Auth0 tenant and register a regular web application
- [x] Configure allowed callback URL `{ORIGIN}/o2p/oauth2/auth0/authorized`
- [x] Update existing Google Cloud Console redirect URI to `{ORIGIN}/o2p/oauth2/google/authorized` (for demo environment)
- [x] Add Auth0 example block to `dot.env.example`
- [x] Configure `demo-live/env.cloud-run.yaml` with `OAUTH2_AUTH0_*` settings (ISSUER_URL / RESPONSE_MODE / SCOPE), plus GSM secrets for CLIENT_ID / CLIENT_SECRET and `--set-secrets` wiring in `.github/workflows/deploy-demo.yml`
- [x] Run demo, log in via Auth0 button, verify DB row has `provider="auth0"` and correct `sub`
- [x] Verify Google login still works concurrently
- [ ] Capture screenshots for LT
- [x] If any code change is needed here, mark Step 1 as incomplete and address (no code changes required)


### Phase 2: GitHub (non-OIDC)

- [ ] Introduce `OAuth2Flow` trait with OIDC and non-OIDC implementations
- [ ] GitHub flow: code exchange + `GET /user` + `GET /user/emails`, no id_token, no nonce
- [ ] GitHub-specific claim mapping
- [ ] Integration test with mocked GitHub API

### Phase 3: Apple Sign-In

- [ ] Force `response_mode=form_post` per instance
- [ ] Generate `client_secret` as ES256 JWT from Apple private key
- [ ] Extract name/email from initial form body (first authorization only)
- [ ] Handle Apple private email relay
- [ ] Integration test

### Phase 4: FedCM multi-provider (optional)

- [ ] Per-instance FedCM configURL
- [ ] Frontend FedCM `providers: [...]` array support

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as medium-priority, large-difficulty issue
- Reason: Multiple providers, each with unique requirements; important for adoption but not blocking current users

### 2026-04-15: Codebase investigation + phased plan

#### Current architecture (what's Google-specific)

The OAuth2 module is written as if there is exactly one provider. Concretely:

- `oauth2/config.rs` uses `LazyLock` globals for every setting
  (`OAUTH2_ISSUER_URL`, `OAUTH2_GOOGLE_CLIENT_ID/SECRET`, `OAUTH2_SCOPE`,
  `OAUTH2_RESPONSE_MODE`, `OAUTH2_REDIRECT_URI`, ...). All `get_*_url()`
  helpers return a single global value.
- `OIDC_DISCOVERY_CACHE: OnceLock<OidcDiscoveryDocument>` — first-write-wins,
  can only cache one provider's discovery document.
- `oauth2/main/core.rs:141-151` builds the auth URL with a hardcoded reference
  to `OAUTH2_GOOGLE_CLIENT_ID`.
- `oauth2/main/idtoken.rs` defines `IdInfo` with Google-specific required
  fields (`azp`, `given_name`, `family_name`, `email_verified: bool`, plus
  optional `hd` and `at_hash`).
- `oauth2/types.rs:76-120` hardcodes `provider: "google"` and
  `provider_user_id: format!("google_{}", sub)` in the `From` impls.
- `oauth2_passkey_axum/src/oauth2.rs` exposes `/oauth2/google` as a fixed route.
- `static/oauth2.js` hardcodes `/oauth2/google` and the Google FedCM configURL.
- The DB schema stores `provider` and has `UNIQUE(provider, provider_user_id)`,
  so the storage layer is already multi-provider-ready — this is the only
  layer that does not need changes.

#### Why "just point at a different issuer" does not work

A first instinct was that since `OAUTH2_ISSUER_URL` is already an env var,
switching to e.g. Auth0 should work by just changing it. Investigation found
three concrete blockers:

1. **Issuer trailing-slash comparison**. `fetch_oidc_discovery` trims trailing
   slashes from the request URL, then string-compares the discovery document's
   `issuer` against the trimmed URL. Auth0 returns its issuer with a trailing
   slash (e.g. `https://tenant.auth0.com/`), so the comparison always fails.
2. **`IdInfo` required fields**. Auth0 database-connection logins can return
   id_tokens without `given_name`/`family_name`. Serde fails to deserialize.
3. **Hardcoded `provider: "google"`**. Even if the flow worked, DB rows would
   claim `provider="google"` for Auth0 users, breaking identification.

These three are narrow and fixable without any abstraction work, which is
what makes Phase 0 feasible in days.

#### Why multi-IdP simultaneous support is a separate phase

An earlier design sketch assumed a "generic OIDC provider" abstraction could
be added in one shot, so that Auth0/Keycloak/Okta/Microsoft/Entra/Zitadel
would all work for free. That framing holds only for *one provider at a time*.
As soon as multiple IdPs are enabled simultaneously, the following break:

- **Single global state**: every `LazyLock` becomes a `HashMap<InstanceName, _>`.
- **Kind vs. instance**: two Keycloak realms are two instances of one kind,
  and the DB `(provider, provider_user_id)` uniqueness must be keyed on the
  *instance name*, not the kind, to avoid collisions.
- **Callback dispatch**: the single `/oauth2/authorized` callback has no way
  to know which provider issued the code. `StateParams` must carry provider
  info. Alternatively, per-instance callback URLs.
- **Parallel flow cookie clobbering**: a single `__Host-CsrfId` cookie name
  means two in-flight flows (user clicks two buttons) overwrite each other.
- **Per-provider response mode**: Apple requires `form_post`, GitHub requires
  `query`. The current global `OAUTH2_RESPONSE_MODE` cannot hold both.
- **Non-OIDC flows**: GitHub has no id_token, no nonce, no `at_hash`. Apple
  has no userinfo endpoint. The current `get_idinfo_userinfo()` assumes
  both are always available.
- **Frontend**: the single `/oauth2/google` route and single login button
  must become a list of buttons rendered from the enabled-instances set.
- **Configuration surface**: N providers × M settings becomes ugly as flat
  env vars. At some N, a config file becomes necessary.

This is the reason for the phased plan above: Phase 0 unblocks the LT demo,
Phase 1 does the real architectural work, and Phases 2-4 layer on the
provider-specific quirks.

#### Phase 0 plan (Auth0 switch mode)

Minimum changes to make Auth0 usable via environment-variable switching:

1. Fix `fetch_oidc_discovery` to normalise both sides before comparing
   (trim trailing slash from `document.issuer` as well, or store and compare
   the original URL).
2. Make `IdInfo` fields optional: `azp`, `given_name`, `family_name`,
   `email_verified`. Adjust `From<IdInfo> for OAuth2Account` accordingly.
3. Make `GoogleUserInfo` fields optional to match.
4. Add `OAUTH2_PROVIDER_NAME` env var (default `"google"`). Read it in the
   `From` impls to set `provider` and `provider_user_id` prefix.
5. Add an Auth0 example block to `dot.env.example`.
6. Manually verify end-to-end against a real Auth0 tenant.

Not in Phase 0: renaming `OAUTH2_GOOGLE_CLIENT_ID` (backwards-compat risk,
defer to Phase 1), renaming `GoogleUserInfo` structs (churn without value),
FedCM changes (Auth0 does not use FedCM anyway — doc note is enough),
removing hardcoded tracing span `provider = "google"` (cosmetic, defer).

Estimated: 50-80 lines of core changes plus test adjustments. Target completion
before 2026-04-20.

#### Open design questions for Phase 1

Deferred until Phase 0 ships:

- Should the provider registry be built from env vars (namespaced like
  `OAUTH2_<INSTANCE>_CLIENT_ID`) or a config file (TOML/JSON)? Env becomes
  ugly past ~3 instances; config file adds a dependency.
- Single callback URL with provider in state, vs. per-instance callback URLs?
  Single is simpler but requires all IdPs to register the same redirect URI.
- How much of the existing public API (`get_google_client_id`, etc.) can be
  renamed without breaking downstream users of the library at 0.x?
- FedCM: keep it Google-only forever, or eventually support per-instance
  configURLs?

### 2026-04-15 (second revision, same day): Reorder — refactor first, Auth0 second

#### Why the reorder

The first 2026-04-15 plan put "Auth0 switch mode" as Phase 0 and "multi-
instance refactor" as Phase 1. On reflection, that ordering creates waste:
Phase 0 adds narrowly-scoped fixes (`OAUTH2_PROVIDER_NAME` env var, small
optional-field changes on Google-specific types) that Phase 1 then rewrites
with the registry-based approach. The refactor-first ordering reuses
everything.

The refactor-first ordering is also safer from a correctness standpoint:
the completion test for Step 1 is "all existing tests pass and Google login
still works identically". This is a much stronger regression signal than
"new code path works for Auth0". If Step 1 breaks anything, the existing
test suite catches it before the LT demo.

The risk of the refactor-first ordering is timeline: Step 1 is ~900-1100
lines of diff vs Phase 0's ~80 lines. To mitigate, the fallback branch
(Phase 0 minimal) is prepared preemptively on 2026-04-15 so it can be
activated on Saturday morning if Step 1 is not converging.

#### Design decisions locked on 2026-04-15

See the "Design decisions fixed on 2026-04-15 (for Step 1)" subsection under
the Approach section. Summary:

1. Env-namespaced config format with backward compat (not TOML file).
2. Single `/oauth2/authorized` callback with provider in state (not per-
   instance callback URLs).
3. CSRF cookie named `__Host-CsrfId-{instance}` (per-instance).
4. `From<IdInfo>` / `From<GoogleUserInfo>` trait impls replaced with free
   functions taking `provider_name: &str`.

These are locked because design churn mid-refactor would eat the deadline.
If one turns out to be wrong during implementation, the decision is to
ship Step 1 with the locked choice and revisit in a follow-up, not to
rework mid-flight.

#### Day-by-day schedule

| Date | Work |
|------|------|
| Wed 2026-04-15 | Lock design, scaffold `provider/` module, make `IdInfo` optional, prepare fallback branch |
| Thu 2026-04-16 | Refactor `config.rs`, per-instance Discovery, thread ctx through `main/core.rs`, `main/google.rs`, `main/fedcm.rs` |
| Fri 2026-04-17 | `StateParams.provider`, callback dispatch, cookie name change, Axum route `/oauth2/{instance}`, coordination layer adjustments |
| Sat 2026-04-18 | Fix broken tests, new registry/dispatch tests, clippy clean, manual Google E2E. Decision point: if not on track by morning, switch to fallback branch. |
| Sun 2026-04-19 | Step 2: Auth0 tenant setup, `.env` config, Auth0 E2E, LT slide prep |
| Mon 2026-04-20 | LT |

#### Risks

1. **Test suite tightly coupled to global config state**. `test_utils` may
   set env vars before `LazyLock` init and expect them to stick. If the
   registry replaces those globals, test setup has to change. Investigate
   on Wednesday; if the coupling is deep, expose a registry-replacement
   hook for tests.
2. **Hidden call sites reading `OAUTH2_GOOGLE_CLIENT_ID` or similar
   globals from outside the `oauth2/` module**. FedCM exposes
   `get_google_client_id()` to the axum crate; other unexpected callers
   may exist. Grep broadly on Wednesday.
3. **Demo apps breaking on new route**. demo-oauth2 / demo-both expect
   `/oauth2/google`. Route must change to `/oauth2/google` under the new
   `/oauth2/{instance}` handler, which means the hardcoded frontend URL
   still works. Verify this holds.
4. **Two consecutive same-day revisions** to this plan means the third
   revision is also possible. Commit to the refactor-first direction on
   Wednesday and resist further re-planning; if a genuine blocker appears,
   jump to the fallback branch rather than redesigning.

### 2026-04-15 (third revision, same day): Per-instance callback URL

#### Why the callback routing was reconsidered

The second revision locked "single `/oauth2/authorized` + provider in state"
for the callback routing, with the rationale "per-instance callbacks would
require every IdP to be reconfigured with a different redirect URI". On
reflection that rationale is weak: the "reconfiguration" is a one-line edit
in the IdP console that every operator has to do anyway when adopting a new
library version. Weighing it against the ongoing benefits of URL-based
dispatch, per-instance callbacks are the better design.

The benefits of putting the provider in the URL path:

1. **Provider identification happens before state decoding**. `Path(provider)`
   is extracted by Axum at the router level. Tracing spans, metrics, and
   error logs can tag every callback — including ones where state is
   malformed, expired, or missing — with the correct provider. With the
   state-only approach, state-decode failures produce anonymous errors.
2. **Defense in depth against cross-IdP confusion**. The URL path is a
   browser-controlled channel tied to the redirect URI each IdP has on
   file. A code issued by IdP A can't physically reach the callback for
   IdP B unless A's redirect URI is misconfigured. State is just
   base64-encoded JSON with no HMAC — if a future bug weakens CSRF checks,
   the URL path remains as a second independent signal. `StateParams`
   still carries `provider` as a cross-check so that URL/state mismatch
   is a detectable security event.
3. **IdP console URL structure matches OAuth2 client reality**. One OAuth2
   client per IdP, one redirect URI per client, one URL per callback.
   "All providers share the same callback URL" conflates the URL structure
   with the identity of the OAuth2 client, which is misleading.
4. **Future per-provider sub-resources fit naturally**. `/oauth2/{provider}/`
   becomes a subtree where per-provider FedCM (`/oauth2/{provider}/fedcm/*`),
   token refresh, or other operations can live in Phase 4 without
   reshuffling the URL space.

#### Callback URL shape: `/oauth2/{provider}/authorized` vs `/oauth2/authorized/{provider}`

Both work and dispatch equivalently. `/oauth2/{provider}/authorized` was
chosen because:

- Per-provider subtree is more extensible (future FedCM, refresh, etc. fit
  under `/oauth2/{provider}/...`).
- Reads more naturally for IdP console operators ("this is the google
  callback under the oauth2 prefix" vs "this is the authorized-google callback").
- Matches the initiate URL structure `/oauth2/{provider}` — the provider
  segment appears in the same position for both flows.

Downside of `/oauth2/{provider}/authorized`: `/oauth2/{provider}` as initiate
pattern collides with existing literal routes (`/oauth2/accounts`,
`/oauth2/fedcm/*`, `/oauth2/popup_close`, `/oauth2/oauth2.js`). Resolved by
reserving those names at registry-init time. Axum routes literals before
captures so runtime dispatch is not a problem.

#### No backward-compat alias

The second revision also suggested keeping `/oauth2/authorized` as a
deprecated alias for one release. Reconsidered: keeping it is not worth
the cost.

- **Migration cost is trivial**: a single redirect URI edit in the IdP
  console. Release notes with 2-line migration instructions are sufficient.
- **Maintenance cost of the alias is real**: a second handler reading
  provider from state, tests for both paths, deprecation tracing, a
  follow-up PR to remove it later.
- **The alias perpetuates the weaker defense-in-depth property** that
  per-instance callbacks were adopted to fix. Leaving the weak path in
  place during the deprecation window means the same attack surface
  remains usable by anyone who has not yet migrated.
- **0.x versioning makes breaking changes acceptable** in minor bumps,
  provided they are documented.
- **Small user base**: release notes reach everyone.

Instead of an alias, a **`410 Gone` handler** is mounted at `/oauth2/authorized`
for 2-3 releases. It returns a JSON error with the new URL pattern, so
mis-configured setups fail loudly and clearly instead of with a generic
404 or a silent success path.

#### Decisions locked

- **Callback route**: `/oauth2/{provider}/authorized` (per-instance, GET + POST).
- **Migration**: `/oauth2/authorized` returns `410 Gone` with JSON payload for 2-3 releases, then removed.
- **Reserved instance names**: `authorized`, `accounts`, `fedcm`, `popup_close`, `oauth2.js`, plus invalid-character rejection (`ProviderRegistry::init_from_env`).
- **Cross-check**: `StateParams.provider` retained as a secondary signal; URL path is primary dispatch, state is cross-check only.
- **Next release**: `0.6.0` (minor bump). CHANGELOG must include a prominent "Breaking Changes" section with the one-line migration instruction.

### 2026-04-16: Preserve the "latest flow wins" CSRF cookie policy

#### What the existing design does

The single global CSRF cookie name `__Host-CsrfId` is not an accident. It
is the mechanism that implements an intentional "latest OAuth2 flow wins"
policy:

1. Every new OAuth2 flow generates a fresh `csrf_token`, stores it in the
   cache keyed by a random `csrf_id`, embeds the `csrf_id` in state, and
   sets `__Host-CsrfId` to the `csrf_token`.
2. If a second flow starts before the first completes, the second flow
   overwrites the cookie with its own `csrf_token`. The first flow's
   `csrf_id` still points to its own (different) cached token.
3. When the first flow's callback arrives, `csrf_checks` reads the cookie
   (= second flow's token) and compares it to the cache lookup by
   `state.csrf_id` (= first flow's token). Mismatch → error → flow fails.
4. Net effect: the user's most recent flow succeeds, earlier in-flight
   flows are silently killed at callback time.

This was a deliberate design choice, not cookie-name laziness.

#### Why it is the right design

OAuth2 callback completion is not idempotent data retrieval. It triggers
irreversible side effects:

- `new_session_header` performs full session rotation (old session deleted,
  new session created with fresh CSRF token and page session token).
- `upsert_oauth2_account` writes to the `oauth2_accounts` table.
- `record_login_success` / `record_login_failure` inserts a row into
  `login_history`.
- `add_to_user` mode links an OAuth2 account to the currently-logged-in user.
- `create_user` mode creates a brand new user row.

If two concurrent flows both complete, both sets of side effects fire, in
an order that depends on network timing. A user who starts flow A
(`add_to_user` for user X), changes their mind and starts flow B (`login`
with a different Google account), and lets both complete, ends up with:

- User X silently linked to a Google account they no longer wanted linked
- A session rotated to the new Google account mid-interaction
- Two `login_history` rows, one of which the user did not intend

The fail-closed "latest wins" design prevents this: flow A's callback
fails, its side effects never fire, and only the user's most recent
intention is reflected in the database.

Additional supporting arguments:

- **Matches the documented double-submit pattern** (`docs/src/security/oauth2-security.md:100-106`).
  Double-submit assumes one browser-owned secret; single cookie name is
  the natural implementation of that assumption. Per-flow cookie naming
  would require rewriting the security model as "per-flow state-cookie
  binding" and re-doing the security review.
- **OAuth2 has no explicit cancel**. Starting a second flow is the user's
  implicit cancel of the first. Enforcing this mechanically is better
  than leaving the abandoned flow completable in the background.
- **Fail-closed is the right direction**. "Callback for abandoned flow
  silently errors" is far less bad than "callback for abandoned flow
  creates state the user did not intend".
- **Concurrent flows are rare in practice**. Users do not typically
  start a second OAuth2 flow within the ~15 seconds it takes to complete
  one. Multi-IdP does not increase the rate — a user linking Google
  and then Auth0 does so sequentially, not in parallel.

#### Why multi-IdP does not change this

The argument for per-instance cookie naming (`__Host-CsrfId-{instance}`)
was that two different-provider flows could both succeed without
clobbering each other. This is weak:

- Same-provider concurrent flows still clobber (two Google tabs). The
  fix would be partial, creating an inconsistent UX where the "can I
  run two flows?" answer depends on the provider pair.
- Even cross-provider concurrent flows carry the same irreversible side
  effects. Letting both complete is not a feature, it is a foot-gun
  waiting for the user to trigger.
- The single-cookie "latest wins" design works identically under
  multi-IdP without modification.

#### Decisions locked

- **Keep `OAUTH2_CSRF_COOKIE_NAME` and `OAUTH2_CSRF_COOKIE_MAX_AGE` as global `LazyLock`**. Do not move them into `ProviderConfig`.
- **`ProviderConfig` must not carry `csrf_cookie_name`**. If a future PR proposes making this per-instance, that PR must first justify changing the policy (not just "clean-up").
- **Step 1 adds a policy comment in `oauth2/main/core.rs`** near `csrf_checks` and near the `Set-Cookie` site, explaining the "latest wins" rationale in code so the intent survives future refactors. Reference this Decision Log entry from the comment.
- **`docs/src/security/oauth2-security.md` gets a short new paragraph** under the "Note on CSRF Tokens in the System" section describing the "latest flow wins" behaviour explicitly. Currently the behaviour is undocumented, which is the main reason it got questioned in this design round.

### 2026-04-16: Simplified provider design — no registry, per-provider statics

#### What changed from the 2026-04-15 locked decisions

The 2026-04-15 second revision locked a `ProviderRegistry` with a HashMap,
`OAUTH2_INSTANCES` env var, and `ProviderRegistry::init_from_env()`. On
further discussion (2026-04-16), this was recognised as overengineering:
the supported providers are an explicit, code-defined list, not a user-
configurable registry. There is no reason to build a HashMap at startup
when a `match` expression serves the same purpose with zero runtime cost.

#### The simplified design

- `ProviderKind` enum (`pub(crate)`): one variant per supported provider.
  Adding a provider = adding a variant + one static + one match arm, all
  in `provider.rs`. The compiler's exhaustiveness check catches missed arms.
- One `LazyLock<ProviderConfig>` static per provider (e.g. `GOOGLE_PROVIDER`).
  Optional providers use `LazyLock<Option<ProviderConfig>>`.
- `provider_for(kind: ProviderKind) -> Option<&'static ProviderConfig>`:
  a `match` dispatcher. No HashMap lookup, no string-keyed registry.
- No `OAUTH2_INSTANCES` env var. The set of providers is determined by code,
  not configuration. A provider is "enabled" if its env vars are set.

#### Why this is better

- **Simpler**: adding a provider touches four places in one file (enum variant,
  static, `provider_for` arm, `from_path_segment` arm), all in lock-step.
- **No validation code needed**: reserved-name checks and character validation
  were only necessary because the registry accepted arbitrary user-supplied
  names. With code-defined providers, the names are `"google"`, `"auth0"`,
  etc. — they can never be `"authorized"` or contain `/`.
- **No runtime registry init**: `LazyLock` initialization happens on first
  access, exactly as today. No new init lifecycle, no startup failure mode.

#### Decisions locked

- **No `ProviderRegistry` struct**. No HashMap.
- **No `OAUTH2_INSTANCES` env var**. Providers listed in code.
- **`ProviderKind` enum `pub(crate)`**: axum boundary still takes `&str`.

### 2026-04-16: B1 (ctx threading) chosen over B2 (kind threading)

#### The B1 vs B2 question

With the simplified provider design in place, the remaining question was how
to pass provider configuration through the OAuth2 flow functions:

- **B2**: every flow function takes `kind: ProviderKind`, calls
  `provider_for(kind)` inside to resolve `&ProviderConfig`. Each function
  independently does the lookup.
- **B1**: public entry points parse `&str` → `ProviderKind` → `&ProviderConfig`
  once at the boundary. Internal `pub(crate)` helpers receive `ctx: &ProviderConfig`
  directly. The `ProviderConfig` reference is threaded down the call chain.

#### Why B1

The deciding factor was **test parallelism**. With B2, every unit test of a
private flow helper must set env vars to drive the `LazyLock<ProviderConfig>`
initialization, so tests must be serialized with `#[serial]`. With B1, a test
of a private helper constructs a `ProviderConfig` inline and passes it
directly — no env vars, no `LazyLock` state, tests run in parallel.

Additional reasons B1 wins:

- **Error handling in one place**: `provider_for` returns `Option`; with B1
  the `None` path is handled once at the public boundary. With B2, every
  function that calls `provider_for` has a redundant "not enabled" branch even
  though the boundary already validated this.
- **Phase 2 prep**: when an `OAuth2Flow` trait is introduced for non-OIDC
  providers (GitHub, Apple), B1 requires changing one argument type per
  function. B2 requires introducing a parallel `flow_for` dispatcher and
  changing every call site.
- **Explicit dependencies**: `ctx: &ProviderConfig` in a signature declares
  the dependency; `kind: ProviderKind` with an implicit global lookup hides it.

#### Coupling is not increased

`ProviderConfig` is `pub(crate)`, so axum does not see it. The public
functions in `oauth2_passkey` take `provider: &str` at their boundary — the
axum crate's API surface is identical to what B2 would produce. The coupling
question was resolved in favour of B1.

### 2026-04-20: Step 2 repo-side complete — demo-live deployment config

Step 2 was originally described around demo-oauth2 local `.env` configuration, but the actual implementation targeted the demo-live Cloud Run production deployment instead. The step goal ("Auth0 as a second instance") is equivalent; only the deployment target changed.

Key decisions:

- `OAUTH2_INSTANCES` env var (locked on 2026-04-15, second revision) was superseded by the 2026-04-16 simplified design. The original Step 2 task `:242` referenced it; rewritten to reflect the actual implementation.
- `OAUTH2_AUTH0_RESPONSE_MODE: form_post` (library default) was chosen instead of `query` for demo-live, matching Auth0 form_post behavior on production HTTPS. The plan had suggested `query` for consistency with Google, but the user's choice is functionally correct.
- No Rust code changes were required, confirming Step 1 was complete.
- Three files modified: `demo-live/env.cloud-run.yaml`, `.github/workflows/deploy-demo.yml`, `demo-live/DEPLOY.md` (commits `cbc36e5`, `a9cd8f3`).
- Remaining: Google Cloud Console redirect URI update (user-side, external), post-deploy end-to-end verification.

## Resolution
