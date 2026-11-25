# Issue: Filtered Test Runs Fail with "ORIGIN must be set"

## Metadata

- ID: 20261117-0727
- Created: 2026-11-17-07-27
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:

## Problem

Running a subset of the core crate's tests can fail, while the full run
passes.

Observed on 2026-11-16:

- `cargo test -p oauth2-passkey --lib passkey::main::register`
  -> 25 passed, 18 failed.
- First failure: `ORIGIN must be set: NotPresent` at
  `oauth2_passkey/src/passkey/config.rs:4`
  (in `test_extract_credential_public_key_malformed_attestation_object`).
- The other failures: `LazyLock instance has previously been poisoned`.
- `cargo test -p oauth2-passkey --lib` (no filter) -> all pass.

Presumed mechanism (not verified): `ORIGIN` is a `LazyLock` reading the
environment. Synchronous tests that do not call
`init_test_environment()` (for example
`test_extract_credential_public_key_invalid_attestation_object`,
`..._malformed_attestation_object`, `..._invalid_client_data`) can be
the first to dereference it. In the full run another test has usually
loaded `.env_test` first. Once the `LazyLock` panics, it is poisoned
for the rest of the process.

Whether this also occurs on origin/dev was not checked.

## Timeline

## Latest Plan

1. Confirm the mechanism (which test first dereferences `ORIGIN`).
2. Make those tests initialize the environment (or avoid the
   dependency), so any filtered run behaves like the full run.

### Files

- `oauth2_passkey/src/passkey/main/register/tests.rs`
- possibly other `tests.rs` with the same pattern

### Implementation Tasks

- [ ] Reproduce on origin/dev
- [ ] Identify tests that touch `ORIGIN` without initialization
- [ ] Fix and check several filtered runs

### Verification

- `cargo test -p oauth2-passkey --lib passkey::main::register` passes.
- Full run still passes.

## Resolution
