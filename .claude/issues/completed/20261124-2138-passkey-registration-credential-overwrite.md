# Issue: Passkey Registration Could Overwrite Another User's Credential

## Metadata

- ID: 20261124-2138
- Created: 2026-11-24-21-38
- Closed: 2026-11-24-21-38
- Status: completed
- Priority: high
- Difficulty: medium
- Related Issues:
  - `20261124-2136` Stop Returning Credential IDs from Unauthenticated auth/start (follow-up)
  - `20261124-2137` Parse Registration authData into a Typed Structure (follow-up)
  - `20261120-0852` MySQL/MariaDB Compare Identifiers Case-Insensitively

## Problem

Privately reported security issue, published as
[GHSA-f7r7-vc8j-f293](https://github.com/ktaka-ccmp/oauth2-passkey/security/advisories/GHSA-f7r7-vc8j-f293)
(CVSS 3.1 6.5, Medium; CWE-345, CWE-284). Reported by Rathnadeepan
(HotWater, GitHub @HotWater-015).

In 0.6.1 and earlier, `register/finish`:

1. took the credential ID from the client-supplied `rawId`, without
   comparing it to the credential ID in the attested credential data;
   and
2. stored the credential with an upsert keyed on `credential_id`
   (`INSERT OR REPLACE` on SQLite, `ON CONFLICT ... DO UPDATE` on
   PostgreSQL, select-then-update on MySQL/MariaDB).

A user who knew another user's credential ID (obtainable from the
unauthenticated `passkey/auth/start` with a username) could register
with their own authenticator, submit that ID as `rawId`, and replace
the victim's credential. The victim lost that passkey; the requester
did not gain access to the victim's account. All versions from v0.1.0
were affected.

## Timeline

### 2026-11-16 — Report confirmed, fix prepared privately

Branch `fix-passkey-registration-validation`, not pushed until the
advisory draft existed. Wording of commits and PR kept neutral.

### 2026-11-24T09:22 — Rebased onto dev

Rebased onto `dev` after PR #356 (sqlx 0.9). Conflicts in the MySQL and
PostgreSQL storage files were resolved by keeping the plain `INSERT`
and wrapping the SQL in `sqlx::AssertSqlSafe`.

### 2026-11-24 — Release and disclosure

- Draft advisory GHSA-f7r7-vc8j-f293 created.
- Fix merged to `dev` as #358; CHANGELOG as #359; `dev` -> `master` #360.
- `oauth2-passkey` and `oauth2-passkey-axum` 0.6.2 published to
  crates.io; tag `v0.6.2` and GitHub Release created.
- Advisory published (12:05 UTC) with both crates listed
  (`<= 0.6.1`, patched `0.6.2`). CVE requested from GitHub.
- RustSec advisory submitted: rustsec/advisory-db#3642.

## Latest Plan

Done. Remaining follow-ups:

- Add the CVE ID to the RustSec advisory `aliases` (and optionally the
  CHANGELOG) once GitHub assigns it.
- Tell the reporter the CVE ID.
- `20261124-2136` and `20261124-2137` (hardening, not part of 0.6.2).

### Files

- `oauth2_passkey/src/passkey/main/register.rs`
- `oauth2_passkey/src/passkey/main/register/tests.rs`
- `oauth2_passkey/src/passkey/storage/{sqlite,postgres,mysql}.rs`
- `oauth2_passkey/src/coordination/passkey/tests.rs`
- `oauth2_passkey_axum/tests/common/fixtures.rs`

### Verification

- New tests: rejection of an already-registered credential ID, of a
  `rawId` mismatch and of an `id` mismatch.
- `cargo test` (SQLite) and axum tests with all feature sets; storage
  and registration tests on PostgreSQL, MySQL 8.0 and MariaDB 11.

## Resolution

Fixed in 0.6.2 (#358, commits `20ec255` and `3924714`):

- Registration rejects a credential ID that is already registered for
  any user, before any user or credential is created.
- The credential ID is taken from the attested credential data; the
  client-supplied `id` and `rawId` must both match it.
- Credential storage uses a plain `INSERT` on all backends, so the
  `UNIQUE` constraint on `credential_id` also rejects duplicates.
