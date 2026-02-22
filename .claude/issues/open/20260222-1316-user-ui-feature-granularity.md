# Issue: user-ui Feature Flag Granularity

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260222-1316

## Created: 2026-02-22-13-16

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

The `user-ui` feature flag controls all 4 optional user routes as a single unit:
- `/user/login` (login page)
- `/user/account` (account management page)
- `/user/account.js` (account management JS)
- `/user/o2p-base.css` (base CSS)

It is not possible to disable just the built-in login page while keeping the account management pages.

Concrete problem: `demo-live` has its own custom login page at `/login`, but the library's built-in login page at `/o2p/user/login` is also registered and accessible because `user-ui` is enabled (needed for the built-in account management and admin pages). There is no way to remove the unused built-in login route without losing all other UI.

## Related Issues

- `20260216-1500` Original combined issue (superseded)
- `20260222-1315` Make O2P_LOGIN_URL functional (independent, different layer: runtime vs compile-time)

## Approach

Restructure into 3 flat, independent feature flags (breaking change, acceptable for pre-1.0).

Concrete beneficiary: `demo-live` has its own custom login page at `/login`, but the library's built-in login page at `/o2p/user/login` is also accessible because `user-ui` is enabled (needed for account management). After this change, `demo-live` can use `features = ["user-ui", "admin-ui"]` to disable only the built-in login page.

### Feature flags (`oauth2_passkey_axum/Cargo.toml`)

```toml
[features]
default = ["login-ui", "user-ui", "admin-ui"]
login-ui = []    # login page (/login)
user-ui = []     # account management (/account, /account.js, /o2p-base.css)
admin-ui = []    # admin pages (unchanged)
```

The meaning of `user-ui` changes from "all user UI" to "account management UI only". The login page is extracted into `login-ui`.

### Module split

Split `user/optional.rs` into two modules:

**Current structure:**
```
user/
  mod.rs
  default.rs          # always: /info, /csrf_token, /logout, /update, /delete
  optional.rs          # user-ui: /login, /account, /account.js, /o2p-base.css
  optional/tests.rs
```

**New structure:**
```
user/
  mod.rs
  default.rs          # unchanged
  login.rs             # login-ui: /login
  account.rs           # user-ui: /account, /account.js, /o2p-base.css
  account/tests.rs     # tests from optional/tests.rs
```

**`user/login.rs`** (gated by `login-ui`):
- `LoginTemplate` struct (from optional.rs lines 31-37)
- `login()` handler (from optional.rs lines 39-56)
- `pub(super) fn router()` -> `Router::new().route("/login", get(login))`

**`user/account.rs`** (gated by `user-ui`):
- `TemplateCredential`, `TemplateAccount`, `TemplateAuthUser` structs
- `UserAccountTemplate` struct + `impl`
- `user_account()` handler
- `serve_account_js()`, `serve_base_css()` handlers
- `format_date_tz()` helper + `TIMEZONE_MAP`
- `pub(super) fn router()` -> routes for `/account`, `/account.js`, `/o2p-base.css`
- `#[cfg(test)] mod tests;`

**`user/mod.rs`** update:
```rust
mod default;
#[cfg(feature = "login-ui")]
mod login;
#[cfg(feature = "user-ui")]
mod account;

pub(super) fn router() -> Router {
    let mut base = default::router().merge(login_history::user_router());
    #[cfg(feature = "login-ui")]
    { base = base.merge(login::router()); }
    #[cfg(feature = "user-ui")]
    { base = base.merge(account::router()); }
    base
}
```

### demo-live update

```toml
# Before: default features (includes login-ui -> built-in login page)
oauth2-passkey-axum = { path = "../oauth2_passkey_axum" }

# After: disable built-in login page, keep account + admin UI
oauth2-passkey-axum = { path = "../oauth2_passkey_axum", default-features = false, features = ["user-ui", "admin-ui"] }
```

### CI test matrix

Add feature combination tests to `.github/workflows/ci.yml` (stable only):
```yaml
- name: Test axum integration (login-ui only)
  run: cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --no-default-features --features login-ui

- name: Test axum integration (user-ui only)
  run: cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --no-default-features --features user-ui
```

### Documentation updates

- `oauth2_passkey_axum/README.md` - update feature flag table
- `docs/src/api/axum.md` - update feature flag section

### Out of scope

- `admin-ui` split (admin routes are cohesive, no need to split)
- `demo-custom-login` changes (intentionally builds all UI from scratch with `default-features = false`)

### Verification

```bash
cargo build --manifest-path oauth2_passkey_axum/Cargo.toml --all-features
cargo build --manifest-path oauth2_passkey_axum/Cargo.toml --no-default-features
cargo build --manifest-path oauth2_passkey_axum/Cargo.toml --no-default-features --features login-ui
cargo build --manifest-path oauth2_passkey_axum/Cargo.toml --no-default-features --features user-ui
cargo build --manifest-path oauth2_passkey_axum/Cargo.toml --no-default-features --features login-ui,user-ui
cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --all-features
cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --no-default-features
cargo fmt --all
cargo clippy --all-targets --all-features
cargo clippy --all-targets --no-default-features
```

## Related Files

- `oauth2_passkey_axum/Cargo.toml` - feature flag definition
- `oauth2_passkey_axum/src/user/mod.rs` - user-ui conditional compilation
- `oauth2_passkey_axum/src/user/optional.rs` - routes to be split into login.rs + account.rs
- `oauth2_passkey_axum/src/admin/mod.rs` - admin-ui (unchanged)
- `demo-live/Cargo.toml` - concrete beneficiary of the split
- `.github/workflows/ci.yml` - feature combination tests

## Implementation Tasks

- [ ] Update feature flags in Cargo.toml (login-ui, user-ui, admin-ui)
- [ ] Create user/login.rs with login handler (gated by login-ui)
- [ ] Create user/account.rs with account management code (gated by user-ui)
- [ ] Move tests from optional/tests.rs to account/tests.rs
- [ ] Update user/mod.rs to use new modules
- [ ] Delete optional.rs and optional/tests.rs
- [ ] Update demo-live/Cargo.toml to use features = ["user-ui", "admin-ui"]
- [ ] Add feature combination tests to CI
- [ ] Update documentation (README.md, docs/src/api/axum.md)
- [ ] Verify all feature combinations compile and pass tests

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-22: Issue created from split of 20260216-1500, deferred

- Context: Investigation showed that fixing O2P_LOGIN_URL (20260222-1315) largely eliminates the practical need for finer feature flag granularity
- Decision: Defer this issue until a concrete need arises
- Reason: The feature flag problem is at the compile-time layer and is lower priority than the runtime redirect behavior fix

### 2026-02-22: Decided on 3 flat feature flags, no backward compatibility

- Context: Discussed splitting approach. Considered Option C (feature split with umbrella) vs Option D (runtime env var). Also evaluated whether admin-ui needs splitting.
- Decision: 3 flat features: `login-ui`, `user-ui` (repurposed for account management), `admin-ui` (unchanged). No umbrella features, no backward compatibility shims. Feature flag approach chosen over runtime env var.
- Reason: Feature flags are the natural Rust mechanism for compile-time component selection. Runtime env var adds complexity for a problem that is inherently compile-time. admin-ui routes are cohesive and don't need splitting. Backward compatibility is not needed for this pre-1.0 library. `demo-live` is the concrete beneficiary: it has its own login page but cannot currently disable the built-in one without losing account/admin UI.

## Resolution
