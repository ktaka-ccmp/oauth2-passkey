# Issue: Unify Credential ID Format in Test Data

## Metadata

- ID: 20261117-0726
- Created: 2026-11-17-07-26
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:

## Problem

Real credential IDs are base64url-encoded bytes, and browsers send
`id` equal to `rawId`. Test data uses several different formats.

Based on examination of the code on 2026-11-16:

- Registration and authentication fixtures in
  `coordination/passkey/tests.rs` (around lines 160 and 233) use a
  plain text `id` with `raw_id` set to the base64url of that text, so
  `id != raw_id`.
- `oauth2_passkey_axum/tests/common/fixtures.rs` builds its own IDs
  for registration and authentication.
- Seeded credential: `"first-user-test-passkey-credential"`
  (`oauth2_passkey/src/test_utils.rs:246`,
  `oauth2_passkey_axum/tests/common/secure_auth.rs`).

Mixed formats make it easy to write tests that pass with IDs a browser
would never produce.

## Timeline

## Latest Plan

Use base64url credential IDs (with `id == raw_id`) throughout test
data, keeping each test's intent unchanged.

### Files

- `oauth2_passkey/src/test_utils.rs`
- `oauth2_passkey/src/coordination/passkey/tests.rs`
- `oauth2_passkey_axum/tests/common/{fixtures,secure_auth}.rs`

### Implementation Tasks

- [ ] Inventory credential ID literals in tests
- [ ] Convert authentication fixtures
- [ ] Convert seeded credential

### Verification

- Full test suite including axum `--all-features`.

## Resolution
