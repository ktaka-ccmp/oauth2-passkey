# Issue: Correct the Rationale in the Storage Pattern Appendix

## Metadata

- ID: 20261125-0133
- Created: 2026-11-25-01-33
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20261125-0121` Global Store Mutex Serializes All Database and Cache Access
  - `20260226-2019` Finalize Public API for 1.0 Release

## Problem

`docs/src/appendix/storage-pattern.md` ("Why Singleton Instead of Axum
State") explains the global-store design with reasons that do not hold,
and describes code that no longer exists. The design itself is kept;
the explanation needs to be accurate.

Based on a review on 2026-11-25 of the document, the code at origin/dev
13fde6c, the git history and the 2025-02-11 daily journal entry
("Evolution of axum-liboauth2: From State Pattern to Singleton
Pattern"):

1. "Users must initialize and manage library state" / must merge it
   with their own state type. Not required by Axum: a library router
   can carry its own state (`Router::with_state` returns a router for
   any outer state type). This library did exactly that before
   2025-02-11 (`router(state)` with `.with_state(state)`, removed in
   `0456239`).
2. "State prevents environment-variable-only configuration." The state
   used before 2025-02-11 was itself built from environment variables
   (`4a00b72`). Where configuration comes from is independent of how
   stores are reached.
3. "Lock-holding deletion: `delete_user_atomically()` holds the
   `GENERIC_DATA_STORE` mutex ..." (line 69). The function no longer
   exists; deletion relies on `ON DELETE CASCADE`
   (`coordination/user.rs:133-147`).
4. The code sample shows `store.get_user(&user_id)` on the data store;
   the `DataStore` trait only exposes pools
   (`storage/data_store/types.rs:20-24`).
5. The env var names in the sample comments (`DB_TYPE`, `CACHE_TYPE`)
   are not the real names (`GENERIC_DATA_STORE_TYPE`,
   `GENERIC_CACHE_STORE_TYPE`).
6. "forgetting to call `init()` causes a runtime panic on first
   access": the stores are `LazyLock`s initialized on first use; `init()`
   forces evaluation and validation at startup (`lib.rs:155-171`).

Reasons that do hold (2026-11-25 review):

- The public API is built on process-global state: about 40 free
  functions without a handle argument (`get_user_from_session`,
  `*_core`, admin functions), public statics such as
  `O2P_ROUTE_PREFIX`, middleware functions and the `AuthUser`
  extractor. A state-passing design would be a different public API,
  and users would also need to add a layer.
- No state threading through internal layers (38 data store and 49
  cache store access sites).
- An authentication system is one-per-process, like a logging
  subscriber or the rustls crypto provider.
- Integration is `init()` plus `merge`.

Costs to state accurately: one configuration per process; tests share
stores and configuration (`20261117-0727`); no programmatic
configuration (in edition 2024 `std::env::set_var` is `unsafe`, so env
vars are the only safe input); the store mutex (`20261125-0121`).

`docs/src/getting-started/architecture.md:149-165` summarizes the same
rationale and links to the appendix.

## Timeline

## Latest Plan

Rewrite the appendix keeping its conclusion (global stores) and
replacing the rationale and limitations with the points above. Fix the
code samples. Adjust the summary in `architecture.md` if needed.
Mention the history briefly (State until 2025-02; multi-crate state
composition was the original pain).

### Files

- `docs/src/appendix/storage-pattern.md`
- `docs/src/getting-started/architecture.md`

### Implementation Tasks

- [ ] Rewrite rationale and limitations
- [ ] Fix code samples and env var names
- [ ] Remove the `delete_user_atomically()` description
- [ ] Update after `20261125-0121` if the mutex is removed first

### Verification

- Every statement in the appendix can be traced to current code.
- `mdbook build` succeeds.

## Resolution
