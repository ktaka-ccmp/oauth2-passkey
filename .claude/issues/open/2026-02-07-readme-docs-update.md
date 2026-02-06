# Issue: Update README and Docs for Current API and Demo Structure

## ID: 2026-02-07-01

## Status: open

## Priority: medium

## Difficulty: medium

## Description

Update README files and documentation to reflect the current API (`oauth2_passkey_full_router`) and demo structure. Multiple files still reference the old `oauth2_passkey_router` API and outdated demo lists.

## Background

1. **API Change**: `oauth2_passkey_router()` with `.nest()` has been superseded by `oauth2_passkey_full_router()` with `.merge()`
2. **Demo Structure**: Repository now has 8 demos, but READMEs only list 3
3. **HTTPS References**: Many docs reference `localhost:3443` which may change after issue 2026-01-31-02

## Tasks

### 1. Top-level Readme.md

- [ ] Update code snippet: `oauth2_passkey_router` -> `oauth2_passkey_full_router`
- [ ] Update `.nest()` -> `.merge()` pattern
- [ ] Update demo list to include all 8 demos:
  - demo-api (API/Bearer token demo)
  - demo-both (OAuth2 + Passkey)
  - demo-cross-origin (Cross-origin setup)
  - demo-custom-login (Custom login page)
  - demo-oauth2 (OAuth2 only)
  - demo-passkey (Passkey only)
  - demo-profile (User profile example)
  - demo-todo (Todo app example)
- [ ] Update Repository Structure section

### 2. oauth2_passkey_axum/README.md

- [ ] Line 83, 94: Update `oauth2_passkey_router` -> `oauth2_passkey_full_router`
- [ ] Line 150: Update description text

### 3. docs/ Files with Old API References

| File | Lines | Notes |
|------|-------|-------|
| `docs/src/api/axum.md` | 64, 69, 72, 86, 89, 92, 305 | API reference - needs careful review |
| `docs/src/getting-started/architecture.md` | 161 | |
| `docs/src/integration/server-setup.md` | 157, 251, 286 | |
| `docs/src/integration/passkey.md` | 574, 578, 641, 754, 770 | |
| `docs/src/integration/user-data.md` | 135 | |
| `docs/src/integration/customizing-templates.md` | 118, 205, 307 | |
| `docs/src/integration/multi-origin.md` | 71, 76, 82, 139 | |
| `docs/src/appendix/storage-pattern.md` | 58, 94, 108 | |

### 4. HTTPS Port References (Dependent on Issue 2026-01-31-02)

After HTTPS removal from demos is complete, update `localhost:3443` references in:

- `Readme.md`
- `demo-both/README.md`
- `demo-oauth2/README.md`
- `demo-passkey/README.md`
- `demo-custom-login/README.md`
- `demo-todo/README.md`
- `demo-profile/README.md`
- `docs/src/getting-started/quick-start.md`
- `docs/src/integration/customizing-templates.md`
- `docs/src/appendix/troubleshooting.md`

### 5. demo-cross-origin/README.md Improvements

- [ ] Add `/etc/hosts` setup example before nginx/Caddy configuration:

```bash
# Add to /etc/hosts (for local testing without DNS)
127.0.0.1  auth.foobar.com
127.0.0.1  api.foobar.com
```

## Related Files

- `Readme.md`
- `oauth2_passkey_axum/README.md`
- `docs/src/**/*.md`
- `demo-*/README.md`
- `demo-cross-origin/README.md` (specifically for /etc/hosts example)

## Notes

### Current vs New API Pattern

**Old (deprecated)**:
```rust
use oauth2_passkey_axum::{oauth2_passkey_router, O2P_ROUTE_PREFIX};

let app = Router::new()
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());
```

**New (current)**:
```rust
use oauth2_passkey_axum::oauth2_passkey_full_router;

let app = Router::new()
    .merge(oauth2_passkey_full_router());
```

### Dependency

- Task 4 (HTTPS port references) depends on completion of Issue `2026-01-31-02` (Remove HTTPS from demos)

## Resolution

