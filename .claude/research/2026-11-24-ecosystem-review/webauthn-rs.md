# Feasibility: Building on webauthn-rs

Sub-agent report, 2026-11-24. Summary and verification notes: [README.md](README.md).

Replacing the hand-written WebAuthn code with `webauthn-rs` is only **partly feasible**. I didn't compile `webauthn-rs` against our workspace or test it with real authenticators; everything here comes from reading the code.

I examined `webauthn-rs`, `webauthn-rs-core` and `webauthn-rs-proto` 0.6.2, the latest stable release (2026-10-31, MPL-2.0). The sources were downloaded to a temporary local directory (not kept). Our working tree has no diff from `origin/dev` in the two crates.

## Conclusion
- **What `webauthn-rs` can replace:** all the verification work. That covers clientData, origin, rpIdHash, the user-present and user-verified checks, signatures, the counter, and attestation formats none/packed/tpm/fido-u2f (plus apple and android-key, which we don't support).
- **Existing users keep their passkeys:** every stored key is P-256, so rows can be converted without anyone re-registering.
- **The problem:** the safe high-level API (`webauthn_rs::Webauthn`) can't keep our current behaviour. For passkeys it hard-codes:
  - user verification `required`, residentKey `discouraged`, attestation `none`, no attachment (`a/src/lib.rs:567-575`, `:683`);
  - usernameless login only behind the `conditional-ui` feature, which forces `mediation: "conditional"` (`a/src/lib.rs:1344`) and expects a 16-byte UUID user handle (`:1355-1364`). Ours is 32 random bytes, base64url-encoded.

  Our defaults are the opposite: user verification `discouraged`, residentKey `required`, attestation `direct` (`passkey/config.rs`).
- **Keeping today's config means using `webauthn-rs-core` directly.** Its constructor is `new_unsafe_experts_only`, and its docs say signatures "MAY change … WITHIN MINOR VERSIONS" (`b/src/core.rs:184-199`). That undercuts the "widely used component" goal.

So there are two paths:
- **(A) `webauthn-rs-core`:** keeps all current settings, but rests on an unstable API.
- **(B) high-level `webauthn-rs`:** stable API, but accepts breaking behaviour changes.

## How our code maps onto it
- **Registration start** (`register.rs:112-226`): high-level `start_passkey_registration`, or the core challenge builder (`b/src/core.rs:92-158,236,276`). The core builder exposes every setting we use.
- **Challenge storage:** the cache would hold `RegistrationState` / `AuthenticationState` instead of `StoredOptions`.
  - Same cache keys (`user_handle`, `auth_id`) and TTL.
  - The high-level API only allows storing state with the `danger-allow-state-serialisation` feature. Our server-side cache is the case its docs call safe (`a/src/lib.rs:94-96`).
- **Verification:**
  - `verify_client_data`, `ParsedClientData::verify`, `AuthenticatorData::verify`, `verify_signature` and the `attestation/*` modules all move into core.
  - We must still check `userHandle` ourselves (`auth.rs:199`); core doesn't.
  - We must still check for duplicate credential IDs in the database (`register.rs:333`).
  - Usernameless login works through core: start with an empty credential list (`b/src/core.rs:942`), then call `authenticate_single_credential` after looking the credential up by ID (`:1115`).
- **AAGUID:** core only provides it for packed and tpm attestation (`b/src/core.rs:697`), so we keep our own `extract_aaguid`.

## Stored data and migration
- **Converting existing rows:**
  - `public_key` is `0x04‖x‖y` (`register.rs:553`), which maps directly to `COSEKey` ES256. Credential ID and counter carry over.
  - Turning a raw `Credential` into a high-level `Passkey` needs the `danger-credential-internals` feature (`a/src/interface.rs:112-125`).
- **Fields we never stored and would have to guess:** the user-verified flag, the registration policy, the backup-eligible / backed-up flags, and transports.
- **Risk with that guess:** core rejects a login if the backup-eligible flag has changed since registration, except false→true with `allow_backup_eligible_upgrade` (`b/src/core.rs:878-888`). Migrated rows therefore need backup-eligible = false plus that override; the high-level usernameless flow sets the override to false (`a/src/lib.rs:1329`).
- **Schema work:** all three backends need a new column (serialized credential or the missing flags). There's no migration framework (`storage/schema_validation.rs:173`).
- **User handles:** core accepts any byte string as user ID (`b/src/core.rs:236`), so existing handles keep working. The high-level API takes a `Uuid` (`a/src/lib.rs:539`), so new registrations would switch format.

## Settings (`passkey/config.rs`, `dot.env.example`)
| Setting | Can webauthn-rs express it? |
|---|---|
| RP ID / origin, `PASSKEY_RP_NAME`, `PASSKEY_TIMEOUT` | Yes (builder, `a/src/lib.rs:286,364,373`). Origins without a domain name, such as a bare IP, are rejected. |
| `PASSKEY_CHALLENGE_TIMEOUT` | Stays our cache TTL; the library's state has no expiry. |
| `WEBAUTHN_ADDITIONAL_ORIGINS` | Yes (`append_allowed_origin`). Today these origins only appear in `/.well-known/webauthn`; verification accepts only `ORIGIN` (`main/types.rs:250`, `register.rs:732`). Adopting this would newly accept them. |
| `PASSKEY_ATTESTATION` | High-level: `none` only (`direct` needs a CA list). Core: none/indirect/direct; there is no `enterprise` value (`c/src/options.rs:113-126`). |
| `PASSKEY_AUTHENTICATOR_ATTACHMENT` | High-level: no. Core: yes. |
| `PASSKEY_RESIDENT_KEY` / `PASSKEY_REQUIRE_RESIDENT_KEY` | High-level: always discouraged. Core: a bool meaning required or discouraged (`b/src/core.rs:298-302`); `preferred` needs a manual edit of the public field afterwards. |
| `PASSKEY_USER_VERIFICATION` | High-level: always required. Core: yes (discouraged is named `Discouraged_DO_NOT_USE`). |
| `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` | Yes; we choose the handle per call (UUID-only on the high-level API). |
| excludeCredentials | Yes. The library also rejects an excluded credential when registration finishes (`b/src/core.rs:740`). |

## What changes in behaviour
**What we have that it lacks or changes:**
- The configurable options above, on the high-level API.
- A modal usernameless login with non-UUID user handles (high-level API).
- A counter value of 0 after a non-zero stored value: we accept it (`auth.rs:277`); core rejects it (`b/src/core.rs:1186-1205`).
- Core also rejects `crossOrigin: true`, which affects use inside iframes.

**What it adds:**
- apple and android-key attestation.
- ES384 and RS256 that actually work. We request -257 but can only store and verify P-256 (`register.rs:207-216,627-662`, `auth.rs:322`).
- Optional trust checks against attestation certificate lists.
- Tracking of the backup flags, the credProtect / credProps / uvm extensions, and the user-verified state recorded at registration.

**Two existing issues I noticed along the way:**
- `is_discoverable` reads the backup-eligible flag as "discoverable" (`main/types.rs:345`).
- The Signal API calls build the user ID with `TextEncoder` (`passkey.js:222`, `account.js:194`), while registration base64url-decodes it (`passkey.js:355`). The two produce different bytes.

## Public API and browser JS
- **Re-exported types change:** `lib.rs:98-100` exposes `AuthenticationOptions`, `AuthenticatorResponse`, `RegisterCredential`, `RegistrationOptions` and `PasskeyCredential` (which has a `pub public_key: String`). These would become wrappers or change shape.
- **JSON differs both ways:**
  - Options: webauthn-rs uses `{publicKey:{…, user:{id}}}`. Ours is flat, with `rpId`, `authId` and `user.user_handle`.
  - Responses: webauthn-rs expects camelCase (`rawId`, `clientDataJSON`, …); our JS sends snake_case (`passkey.js:108-120,374-384`, `conditional_ui.js:135-143`).
  - Either the JS changes or the server converts; all the library's fields are public, so a converter is possible.
- **Axum handlers** only pass these types through (`coordination/passkey.rs:81-280`), so they change little.

## Dependencies and minimum Rust version
- **Minimum Rust:** 1.89, which is within our 1.94. Note that none of our Cargo.toml files declares a `rust-version`.
- **No OpenSSL.** It uses `crypto-glue` (RustCrypto), which pulls in p256/p384/p521, a pre-release `rsa ^0.10.0-rc.18`, x509-cert, and also argon2/aes-gcm/pbkdf2 as required dependencies.
- **Overlap with what we already use:** `base64 0.21` (we use 0.23), `serde_cbor_2` alongside our `ciborium`, plus `x509-parser 0.18`, `der-parser 10`, `nom 7`, `rand 0.10`.

## Effort and risks
- **Effort (path A, a rough guess):**
  - Rewrite `register.rs` (751 lines), `auth.rs` (360) and part of `types.rs` (415).
  - Delete `attestation/*` (about 1,850 lines of code and about 3,190 lines of tests).
  - Rewrite the register/auth/types tests (about 4,000 lines).
  - Add the schema change in three backends.
  - Update the two JS files, `coordination/passkey.rs`, and `oauth2_passkey_axum/tests/common/fixtures.rs`.

  That's about 10–15 files: several weeks including end-to-end checks with real authenticators.
- **Risks:**
  1. Core's API can change in minor versions.
  2. Behaviour changes for migrated passkeys (backup-flag checks, counter of 0, guessed user-verification policy).
  3. Path B breaks current defaults: required user verification shuts out security keys without a PIN, and discouraged resident keys hurt usernameless login.
  4. `enterprise` attestation and residentKey `preferred` have no native equivalent.
  5. A larger dependency tree that includes a pre-release `rsa`.

## Decisions for you
1. Is `webauthn-rs-core` (path A) good enough for "building on a widely used component", or only the safe high-level API with its behaviour changes (path B)?
2. Are the current defaults (user verification `discouraged`, residentKey `required`, attestation `direct`) firm requirements?
3. Should `WEBAUTHN_ADDITIONAL_ORIGINS` become origins we actually accept during verification?
4. For migrated passkeys, is setting backup-eligible = false plus the upgrade override acceptable, or should the backup flags be recorded during a transition period first?
