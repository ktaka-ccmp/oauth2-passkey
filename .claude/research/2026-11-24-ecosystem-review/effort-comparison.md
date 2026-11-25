# Effort Comparison: Components vs Torii vs oauth2-passkey

Sub-agent report, 2026-11-24. Summary and verification notes: [README.md](README.md).

**Main findings:**
- **Torii 0.5.3 does not run OIDC or WebAuthn itself.** None of its crates depend on a WebAuthn or OIDC library. `torii-axum` says OAuth and Passkey support is "Coming soon". Its passkey `authenticate(credential_id)` looks up the credential and returns the user without checking any signature or challenge. The docs call `get_oauth_authorization_url` and `exchange_oauth_code`, but neither exists in the code.
- **oauth2-passkey keeps sessions in its cache store, which is memory or Redis only.** With SQLite alone, sessions and pending passkey challenges are lost on restart.
- **The official examples for approach A leave security steps out.** openidconnect's `google.rs` prints the returned state but never compares it, and uses no PKCE. The webauthn-rs axum tutorial uses username-based, non-discoverable sign-in and keeps everything in memory.

---

# Effort comparison: Google OIDC + discoverable passkey + session app on Axum

Date: 2026-11-24. Read-only study; nothing was built or run. "Counted" = raw `wc -l` (includes blank lines, comments and imports). "Estimate" = a judgement based on counted material; treat as order of magnitude.

Versions (crates.io API, `max_stable_version`): axum-login 0.19.0, tower-sessions 0.15.0, tower-sessions-sqlx-store 0.16.0, openidconnect 4.1.0, webauthn-rs 0.6.2, torii 0.5.3, torii-axum 0.5.2, oauth2-passkey-axum 0.6.2.

## 1. Summary table

| | A. Components | B. Torii | C. oauth2-passkey-axum |
|---|---|---|---|
| Crates | axum-login, tower-sessions, tower-sessions-sqlx-store, openidconnect, webauthn-rs (features `danger-allow-state-serialisation`, `conditional-ui`), sqlx, reqwest | torii (`sqlite`, `oauth`, `passkey`), torii-axum, **plus openidconnect and webauthn-rs** | oauth2-passkey-axum |
| Rust | ~1,000–1,300 (estimate; starting material counted: 471 + 470) | ~800–1,100 (estimate) | ~20–60 (counted: README snippet 20 lines; demo-passkey `main.rs` 61) |
| JS | ~110–150 (estimate; tutorial `auth.js` = 100 counted, plus js-base64 from a CDN) | ~110–150 (estimate) | 0 (library serves `passkey.js` and the pages) |
| HTML | ~50–90 (estimate) | ~50–90 (estimate) | 0 (built-in login and account pages); ~30–60 for your own pages |
| SQL | ~25–40 (estimate; users, oidc_accounts, passkeys) | 0–10 | 0 |
| Config | ~20–25 Cargo.toml lines, ~4–6 .env lines, builder code (Webauthn, OIDC client, session layer) | ~10–15 Cargo.toml lines, ~4–6 .env lines, builder code, `CookieConfig` | 1 crate line, 5–6 .env lines |
| Security work left to the developer | state/nonce/PKCE storage and checks, ID-token verification call, account linking, single-use challenge storage, credential persistence and counter update, user-handle mapping, CSRF, cookie flags | all of A's list except users, sessions and the extractor; **plus** setting the session cookie by hand and checking `email_verified` (Torii links accounts by email automatically) | env values; sending the CSRF header on the app's own state-changing routes |
| Gaps | No single example covers this app; example version drift | OAuth/passkey routes "Coming soon"; no protocol verification; no way to update a stored credential; no challenge API | Sessions only in memory or Redis; fixed user schema; configured through env vars only |

## 2. A: Components

**Roles.**
- **axum-login:** the `AuthUser`/`AuthnBackend` traits, `AuthSession`, `login`/`logout`, and the `Require` layer. It contains no credential protocol.
- **tower-sessions (+ sqlx-store):** server-side sessions. The examples use `MemoryStore`.
- **openidconnect:** discovery, state/nonce, code exchange, ID-token verification.
- **webauthn-rs 0.6.2:** the WebAuthn ceremonies.
  - Discoverable sign-in requires the `conditional-ui` feature (`src/lib.rs:1313`).
  - Keeping ceremony state in a serialised session requires `danger-allow-state-serialisation` (`src/interface.rs:21`, `src/lib.rs:102`).
  - `Passkey` itself can be serialised (`interface.rs:54–56`).

**What the developer writes:**
1. **Schema:** three tables. The axum-login oauth2 migration has one table (7 lines).
2. **User model:** the `AuthUser` and `AuthnBackend` implementations, using a `Credentials { Oidc, Passkey }` enum like the one in `multi-auth/src/users.rs:55`.
3. **OIDC flow:**
   - Start handler that stores state, nonce and the PKCE verifier in the session.
   - Callback that compares state, exchanges the code with PKCE, and verifies the ID token with the nonce.
   - Linking the Google `sub` to a user, then calling `login`.
   - Gaps in the official examples:
     - `google.rs` (251 lines) is a CLI. It prints the returned and expected state but does not compare them (~lines 195–201), and it has no PKCE. PKCE and access-token-hash checks appear only in the crate docs (`lib.rs:188, 201, 229`).
     - axum-login `examples/oauth2` uses plain oauth2 against GitHub: no OIDC, no nonce, no PKCE, and an in-memory DB and session store.
4. **WebAuthn:**
   - The `Webauthn` builder and four JSON handlers.
   - Challenge state kept in the session and removed after use.
   - Credentials persisted, with counter updates saved through `update_credential`.
   - The tutorial does not cover this: it is username-based and non-discoverable (`auth.rs:220`) and keeps data in `HashMap`s behind a `Mutex` (`startup.rs`).
5. **JS:** base64url conversion and the `navigator.credentials` calls (`auth.js`, 100 lines, plus the js-base64 CDN script).
6. **Session store:** `SqliteStore` plus `migrate()`, and SameSite=Lax so the OIDC redirect works (comment in axum-login `app.rs`).
7. **Logout and route protection.**
8. **CSRF:** none of the examples include CSRF tokens; SameSite=Lax is the only mitigation shown.
9. **Error types:** the tutorial's `error.rs` is 33 lines.
10. **Templates.**

**Counted starting material:**
- axum-login oauth2 Rust: main 23 + users 163 + web 6 + app 80 + auth 81 + oauth 80 + protected 38 = **471**. Templates 28, SQL 7, Cargo.toml 23.
- axum-login multi-auth Rust: 569.
- webauthn tutorial Rust: auth 289 + startup 55 + error 33 + main 93 = **470**. `auth.js` 100, `index.html` 28, Cargo.toml 36.

**How the estimate was built:**

| Step | Lines |
|---|---|
| Counted starting material (471 + 470) | 941 |
| Duplicate setup between the two examples | about −100 |
| Swap GitHub OAuth for OIDC (discovery, nonce, PKCE, ID-token check) | +60–100 |
| SQLite passkey storage and counter updates | +80–120 |
| Discoverable sign-in and user-handle mapping | +20–40 |
| Linking the Google `sub` to a user | +40–60 |
| Persistent session store | +10 |
| **Total (estimate)** | **~1,000–1,300** |

**Difficulties:**
- The tutorial pins axum 0.7 and tower-sessions 0.13; axum-login main uses axum 0.8, tower-sessions 0.15 and sqlx 0.9.
- Whether sqlx-store 0.16 works with sqlx 0.9 is unverified.

**Config:**
- Google console: a Web OAuth client, the redirect URI and the consent screen.
- App: client id and secret, issuer, redirect URL, rp_id and origin (must match the browser origin), cookie flags, DB URL.

**Security pieces left to the developer:**
- The state check, nonce and PKCE storage, and actually verifying the ID token.
- Deciding whether to trust `email_verified`.
- Single-use challenges and counter persistence.
- Mapping the user handle without leaking whether accounts exist.
- CSRF on JSON POSTs and cookie flags.
- Turning off redirect-following in the HTTP client: both examples do this and comment that it prevents SSRF.

## 3. B: Torii

**What Torii provides** (checked in source at tag torii-v0.5.3):
- **Storage:** `SqliteRepositoryProvider` (`torii/src/lib.rs:139`), with sessions saved in SQLite.
- **OAuth helpers:**
  - `oauth().authenticate(provider, subject, email, name, ua, ip)` returns `(User, Session)`.
  - `store_pkce_verifier` and `get_pkce_verifier`, keyed by the CSRF state.
  - Tables `oauth_accounts` and `oauth_state(csrf_state, pkce_verifier, expires_at)`. There is no nonce storage.
- **Passkey helpers:** `register_credential(user_id, credential_id, public_key, name)` and `authenticate(credential_id, …)`.
- **torii-axum:** the `AuthUser`/`OptionalAuthUser` extractors (`extractors.rs:36, 52`), `auth_middleware`, logout and session routes, and `CookieConfig` (default cookie name `session_id`).

**What Torii does not do:**
- **No protocol code.** No Torii Cargo.toml lists webauthn, openidconnect or oauth2.
- **No OAuth/passkey routes yet.** The `torii-axum/src/lib.rs` header says "OAuth: Coming soon" and "Passkey: Coming soon". `routes.rs` only has password and magic-link routes.
- **Docs refer to methods that don't exist.** `docs/src/code/getting-started/oauth-start.rs` and `oauth-callback.rs` call `get_oauth_authorization_url` and `exchange_oauth_code`; neither appears anywhere in the non-doc source.
- **No passkey verification.** `PasskeyService::authenticate_credential` (`services/passkey.rs:56–79`) only looks up the credential and returns the user.
- **Stored credentials can't be updated.** The repository has no method to change stored credential data, so counter and backup-state updates can't be saved through the API. A `passkey_challenges` table exists in the migrations, but nothing in the API uses it.
- **Email auto-linking.** `get_or_create_user` (`services/oauth.rs:27–63`) links a new OAuth subject to an existing user by email alone, with no `email_verified` check.
- **Email is mandatory.** The users table has `email NOT NULL UNIQUE`.
- **README overstates support.** The feature table marks "OAuth2/OIDC ✅" and "Passkey/WebAuthn ✅" (`README.md:22–37`).

**What the developer writes:**
- All of A's OIDC, WebAuthn, JS and template work.
- State and nonce storage.
- Bridging webauthn-rs `Passkey` into Torii's `public_key` field.
- Counter persistence outside the API.
- A user-handle → user mapping for discoverable sign-in (the intended mechanism is unverified).
- Setting the session cookie by hand, as `examples/todos/src/routes.rs:208–215` does.
- CSRF protection (a grep of torii-axum for "csrf" found nothing).

What Torii saves compared with A: the user model and backend, the users/oauth/sessions schema, session store wiring, the extractor and logout.

**LOC:**
- Counted: todos Rust 439 (main 72 + routes 333 + templates.rs 34), templates 126, Cargo.toml 33. These examples use password sign-in only.
- Estimate: A's figure minus ~200–300, plus ~30–60 for cookie handling and data bridging, giving ~800–1,100 Rust.

**Config:** the same Google, OIDC and WebAuthn setup as A, plus `Torii::new`, a `HasTorii` implementation and `CookieConfig`.

**Security pieces left to the developer:** everything in A's list, plus:
- Call `authenticate(credential_id)` only after webauthn-rs has verified the assertion; on its own it signs a user in from a credential ID alone.
- Check `email_verified` because of the email auto-linking.
- Cookie flags on the hand-set cookie.

## 4. C: oauth2-passkey-axum

**Provides:**
- OIDC for Google and up to eight custom providers, using PKCE S256 (`oauth2/main/core.rs:145–153`).
- Passkey registration and sign-in, verified by the library's own code (not webauthn-rs).
- Sessions and CSRF tokens.
- The `AuthUser` extractor and middlewares.
- A built-in login page (`login-ui`), an account page where signed-in users add passkeys (`user-ui`), an admin UI (`admin-ui`), and `passkey.js`.

**What the developer writes:**
- `init()` plus `merge(oauth2_passkey_full_router())`: the README snippet is 20 lines; demo-passkey `main.rs` is 61 and demo-both `main.rs` is 62 (working-tree copy, which has uncommitted local changes).
- A handler that takes `AuthUser`.
- Optional own templates (demo-passkey's two templates are 31 + 30 lines).
- No schema, JS or linking code.
- demo-both `protected.rs` (308) and templates p1–p6 (481) only demonstrate patterns and aren't needed for this app.

**Gaps:**
- **Sessions are not persistent with SQLite alone.** `GENERIC_CACHE_STORE_TYPE` accepts only `memory` or `redis` (`cache_store/config.rs:25–26`), and sessions are kept in that cache store. With memory, sessions and pending challenges are lost on restart and can't be shared across processes; durable sessions need Redis.
- **Fixed user model.** Fields are `id`, `account`, `label`, `is_admin`, `sequence_number` and so on (`oauth2_passkey_axum/src/session.rs:77–85`). Extra user data goes in your own tables.
- **Env-var configuration only.** `init()` reads environment variables (`oauth2_passkey/src/lib.rs:155`, `oauth2_passkey_axum/src/lib.rs:113`); no builder API was found. `init()` panics if `login-ui` is off and `O2P_LOGIN_URL` is unset.
- **Table names are configurable, the schema is not.**
- **Passkey defaults not confirmed.** `dot.env.example:321` shows `PASSKEY_USER_VERIFICATION='discouraged'` commented out; the actual default is unverified.

**Config:**
- Required: `ORIGIN`, `OAUTH2_GOOGLE_CLIENT_ID`, `OAUTH2_GOOGLE_CLIENT_SECRET`, `GENERIC_DATA_STORE_TYPE` and `_URL`, `GENERIC_CACHE_STORE_TYPE`.
- Recommended: `AUTH_SERVER_SECRET`.
- `dot.env.example` (422 lines) lists about 60 more optional variables.
- Google console: redirect URI `ORIGIN/o2p/oauth2/google/authorized`. The response mode is `form_post` by default.

**Security pieces left to the developer:**
- A correct `ORIGIN` and handling of secrets.
- `AUTH_SERVER_SECRET` when running several processes.
- The `X-CSRF-Token` header on the app's own state-changing routes.
- Using Redis if sessions must survive restarts.
- The protocol pieces are inside the library, so their correctness depends on the library.

## 5. Method and caveats

- **Sources:**
  - Downloaded to a temporary local directory (not kept):
    - `t1/torii-rs-torii-v0.5.3` (the release tag).
    - `t2/axum-login-main`: main branch, whose Cargo.toml says 0.19.0; there is no v0.19.0 tag.
    - `t3/webauthn-rs-master`: master branch; the latest tag is v0.5.2. The 0.6.2 crate source is in `a/`.
    - `openidconnect-4.1.0`: the crate itself.
  - oauth2-passkey was read from the local working tree (branch `chore-issues-post-0.6.2`).
- **LOC:** all counts are raw `wc -l`. Estimates assume an experienced Rust developer and minimal UI. A and B would grow with tests and passkey list/delete pages, which C already includes.
- **Unverified:**
  - Whether tower-sessions-sqlx-store 0.16 works with sqlx 0.9.
  - How Torii intends user handles to be mapped.
  - oauth2-passkey's actual passkey defaults.
  - Any runtime behaviour.
- **Context:** this study was run from inside the oauth2-passkey repository. Facts were taken from source, but weigh that context.
