# Issue: Reduce E2E pollution in demos (lib-side /test/reset + SQLite for demo-todo/profile)

## Metadata

- ID: 20260513-1356
- Created: 2026-05-13-13-56
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20260226-2025` E2E Tests (Phase 3 records the trade-off this issue resolves)

## Problem

Phase 3 of the E2E suite (commit landed alongside this issue) added one
spec per demo (`demo-custom-login`, `demo-cross-origin`, `demo-todo`,
`demo-profile`). For each spec to be order-independent, the demo it
targets must expose a `POST /test/reset` route that wipes library
state. The current implementation puts that route — and its supporting
wiring — directly in every demo's `main.rs`:

```rust
async fn test_reset(State(state): State<AppState>) -> Result<...> {
    reset_storage_for_test().await...;
    sqlx::query("TRUNCATE todos RESTART IDENTITY").execute(&state.pool).await...;
    Ok(StatusCode::NO_CONTENT)
}

// ...

if std::env::var("DEMO_TODO_TEST_RESET").is_ok() {
    app_routes = app_routes.route("/test/reset", post(test_reset));
}
```

Plus the env-var gate, the conditional `mut` on the router builder, the
`reset_storage_for_test` import, and the `routing::{get, post}` import
swap.

Measured pollution per demo:

| Demo                  | Original main.rs | After Phase 3 | Test-only LoC |
|-----------------------|------------------|---------------|---------------|
| `demo-both`           | 67               | 79            | +12           |
| `demo-custom-login`   | 370              | 390           | +20           |
| `demo-cross-origin`   | 260              | 275           | +15           |
| `demo-todo`           | 96               | 121           | +25           |
| `demo-profile`        | 95               | 119           | +24           |

`demo-todo` / `demo-profile` carry the heaviest load because they have
to wipe an app-specific table inside the same handler.

In parallel, `demo-todo` and `demo-profile` hard-code `sqlx::PgPool`,
which forces the E2E suite (and any local integrator running the demo)
to provision a Postgres instance. The pedagogical value of "use
Postgres alongside the library" is real but is already covered by
`demo-live`; for the standalone demos, SQLite would let `cargo run`
work zero-setup.

The two demos read as more complex than they need to be, which dilutes
the educational signal an integrator gets when scanning the source.

## Latest Plan

Two independent changes that together return every demo's `main.rs` to
its pre-Phase-3 line count.

### Change A: move `/test/reset` into `oauth2-passkey-axum`

Mount the route inside the library's router when the existing
`test-reset` Cargo feature is enabled. Sketch:

```rust,ignore
// oauth2_passkey_axum/src/router.rs (or wherever oauth2_passkey_router lives)
pub fn oauth2_passkey_router() -> Router {
    let router = Router::new()
        .nest("/oauth2", super::oauth2::router())
        .nest("/passkey", super::passkey::router())
        // ... existing nests
        ;

    #[cfg(feature = "test-reset")]
    let router = router.route(
        "/test/reset",
        axum::routing::post(|| async {
            oauth2_passkey::reset_storage_for_test()
                .await
                .map(|_| axum::http::StatusCode::NO_CONTENT)
                .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }),
    );

    router
}
```

Each demo's `Cargo.toml` keeps the passthrough:

```toml
[features]
# Enables POST /o2p/test/reset via the library; only used by the
# Playwright E2E suite. Never enable in production.
test-reset = ["oauth2-passkey-axum/test-reset"]
```

Playwright config switches each demo's `cargo run` line to
`cargo run -p <demo> --features test-reset`. The `helpers/db.ts`
target changes from `/test/reset` to `/o2p/test/reset`.

### Change B: switch demo-todo and demo-profile from Postgres to SQLite

`PgPool` → `SqlitePool`, `SERIAL PRIMARY KEY` → `INTEGER PRIMARY KEY
AUTOINCREMENT`, `TIMESTAMPTZ DEFAULT NOW()` → `TEXT DEFAULT
(datetime('now'))`, `$1, $2` → `?, ?`, `TRUNCATE ... RESTART IDENTITY`
(if still needed; otherwise `DELETE FROM`).

`APP_DATABASE_URL` default becomes `sqlite:demo-todo.db` (or
`sqlite::memory:` for tests). `chrono::DateTime<Utc>` keeps working —
sqlx-sqlite stores it as an RFC3339 string. `bool` is stored as
INTEGER 0/1; sqlx maps transparently.

Pedagogical note in each demo's README: "In production switch the pool
type — see `demo-live` for an HTTPS+Postgres example."

### Trade-offs

- After Change A, app-specific tables (`todos`, `user_profiles`) are
  no longer wiped by `/test/reset`. This is fine in practice because
  rows are keyed by random UUID `user_id`s; tests querying their own
  user see only their own rows. Worst case is unbounded growth in long
  local sessions, mitigated by the existing `reuseExistingServer:
  !process.env.CI` (CI runs fresh; locals can `docker rm e2e-pg` to
  reset).
- After Change B, the demos no longer demonstrate Postgres usage
  directly. `demo-live` continues to demonstrate the production
  Postgres+HTTPS topology, so the lesson isn't lost from the project.

### Files

- `oauth2_passkey_axum/src/router.rs` — add gated route
- `demo-both/Cargo.toml` + `src/main.rs` — drop test-only code, add
  passthrough feature
- `demo-custom-login/Cargo.toml` + `src/main.rs` — same
- `demo-cross-origin/Cargo.toml` + `src/main.rs` — same
- `demo-todo/Cargo.toml` + `src/main.rs` + `src/db.rs` — drop test
  code, passthrough feature, switch to SqlitePool + SQLite SQL
- `demo-profile/Cargo.toml` + `src/main.rs` + `src/db.rs` — same
- `tests-e2e/playwright.config.ts` — `cargo run -p <demo> --features
  test-reset`, drop `DEMO_*_TEST_RESET` env vars, drop globalSetup
  block, drop APP_DATABASE_URL for todo/profile (point at sqlite
  in-memory instead)
- `tests-e2e/helpers/db.ts` — path `/test/reset` → `/o2p/test/reset`
- `tests-e2e/global-setup.ts` / `global-teardown.ts` — delete
- `tests-e2e/README.md` — drop "Postgres dependency" section
- `.github/workflows/e2e.yml` — drop `services: postgres`
- `demo-todo/README.md` + `demo-profile/README.md` — note the SQLite
  default and the production-Postgres pointer

### Implementation Tasks

- [ ] Add gated `/test/reset` route in `oauth2_passkey_axum::router`
- [ ] Revert `demo-both/src/main.rs` test code; add passthrough feature
- [ ] Revert `demo-custom-login/src/main.rs`; add passthrough feature
- [ ] Revert `demo-cross-origin/src/main.rs`; add passthrough feature
- [ ] Migrate `demo-todo/src/db.rs` + `main.rs` to `SqlitePool`; add
      passthrough feature
- [ ] Migrate `demo-profile/src/db.rs` + `main.rs` to `SqlitePool`; add
      passthrough feature
- [ ] Update Playwright config + helpers + tests-e2e README
- [ ] Drop global-setup / global-teardown
- [ ] Drop `services: postgres` from `.github/workflows/e2e.yml`
- [ ] Re-run full Playwright suite; expect 38 tests still passing
- [ ] Confirm each demo's `main.rs` returns to its pre-Phase-3 size

### Verification

- Demo size: `wc -l demo-*/src/main.rs` should match the
  pre-Phase-3 numbers (67, 95, 96, 260, 370).
- `cargo run -p demo-todo` works with **no external setup** (no
  Postgres, no docker, no env file).
- Playwright E2E: `cd tests-e2e && npx playwright test` runs **38
  tests, all green, without any docker container started**.
- CI: `.github/workflows/e2e.yml` runs the same suite without
  `services: postgres`.

## Resolution

<!-- written when status moves to completed -->
