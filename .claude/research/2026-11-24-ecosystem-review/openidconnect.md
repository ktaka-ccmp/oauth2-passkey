# Feasibility: Building on openidconnect

Sub-agent report, 2026-11-24. Summary and verification notes: [README.md](README.md).

Swapping our hand-written OIDC code for `openidconnect` is **partly feasible**. No repository files were changed.

`openidconnect` 4.1.0 (latest, 2026-10-31) can take over the core of ID token checking (signatures, `iss`, `aud`, `exp`, `nonce`), plus building the login URL, the code-for-token request, the userinfo request and parsing the discovery document. It is not a drop-in replacement, and adopting it today would fail our CI.

## Blocker
- `openidconnect` 4.1.0 requires `rsa` 0.9. That version has advisory RUSTSEC-2023-0071, fixed only in `rsa` 0.10 and later (`~/.cargo/advisory-db/crates/rsa/RUSTSEC-2023-0071.md`). CI runs `cargo audit` (`.github/workflows/ci.yml:88`), so it would flag this. Our current `jsonwebtoken` 12 already uses `rsa` 0.10.

## Where it fits and where we'd need extra code
- **ID token checks:**
  - **Algorithms:** it supports RS*, PS*, ES256/384, EdDSA and HS*. HS* always uses the client secret (`verification/mod.rs:420-441`).
  - **Allowed algorithms** default to RS256 only, or to the list in the discovery document. LINE advertises ES256 but signs with HS256, so its list would have to be set explicitly.
  - **`azp`:** not checked at all (the code is commented out, `:791-819`). Extra audiences are rejected by default, which is stricter than our rule.
  - **`nbf`:** not handled anywhere in the crate.
  - **`iat`:** not checked unless we add a check; no clock-skew allowance on `exp`.
  - **`at_hash`:** must be called manually.
  - **Nonce check:** it is synchronous, so our "look up and consume from cache" becomes two steps: load, then delete.
- **Discovery:**
  - The issuer must match exactly (`discovery/mod.rs:383`), so Auth0's trailing slash, which we tolerate today (`discovery.rs:626`), would fail.
  - It requires a `Content-Type` of `application/json`.
  - Nothing is cached. We keep our own discovery and JWKS caches; its metadata and key-set types can be serialized into our cache layer.
- **Token exchange:** it sends the client secret via HTTP Basic auth by default. Keeping today's behaviour (secret in the form body) needs `AuthType::RequestBody`.
- **HTTP client:** its built-in reqwest support is for reqwest 0.12; we use 0.13. With default features turned off, a closure adapter of about 30 lines connects it to our client.
- **FedCM:** feasible. Its verifier can check a token on its own, without a code flow.
- **form_post, prompt, custom scopes, `access_type`:** all expressible. A non-`code` value of `OAUTH2_RESPONSE_TYPE` is not.
- **Our own logic stays as is:** the 8 custom slots, presets and extra allowed origins, CSRF/state handling, and the claim merge/compare.
- **Entra multi-tenant:** unsupported both today and with this crate.
- **Test mock:** the axum mock identity provider signs HS256 with a key from the JWKS, not the client secret (`axum_mock_server.rs:461-513`), so it would have to change.

## Public API, dependencies and MSRV
- **Public API and axum handlers:** no change needed. The `oauth2` and `coordination` modules are private, and error types only carry strings.
- **MSRV:** `openidconnect` needs 1.88 and `oauth2` 1.65; our CI uses 1.94, so that is fine. Licences (MIT, and MIT OR Apache-2.0) are compatible.
- **Dependencies:**
  - **Removable:** `jsonwebtoken` could leave the production dependencies; tests still use it to sign tokens.
  - **Added:** `oauth2` 5, older duplicate copies of `hmac`, `sha2`, `thiserror`, `rand` and `rsa`, and new crates `serde_with`, `serde-value`, `itertools` and others. That conflicts with the project's minimal-dependencies principle.

## Effort and risks
- **Scope:** about 9–10 production files (mainly `idtoken.rs`, `oidc.rs`, `core.rs`, `provider.rs`, `discovery.rs`, `types.rs`, `utils.rs`) and 6 test files, including up to about 80 tests and the axum mock. Roughly 600 lines removed and 300–450 lines of glue added; this is an estimate, not prototyped.
- **Silent behaviour changes:** `aud`/`azp` semantics, `nbf` dropped unless re-added, exact issuer match, HS keys taken only from the client secret, Basic auth by default, LINE's algorithm list.
- **Generics:** the client type is heavily generic, which makes storing one per provider in our static configs awkward. Not checked by compiling.

## Open questions
- **Partial adoption:** we could keep our own discovery and caching and use the crate only for ID token and key checks. I think that is the lowest-risk option.
- **`rsa` advisory:** should we ignore RUSTSEC-2023-0071, or wait for a release on `rsa` 0.10?
- **Multi-audience policy:** adopt its stricter default, or keep our `azp` rule?
- **Apple details:** whether its discovery omits a userinfo endpoint, and whether `email_verified` arrives as a string. Not checked; Apple support is itself marked unverified in our docs.

Nothing was built or run, so the exact `Cargo.lock` changes and transitive MSRVs are not confirmed. The crate sources were downloaded to a temporary local directory (not kept).
