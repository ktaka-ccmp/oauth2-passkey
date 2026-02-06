# Issue: Update README and Docs for Current API and Demo Structure

## ID: 2026-02-07-01

## Status: completed

## Priority: medium

## Difficulty: medium

## Description

Update README files and documentation to reflect the current API (`oauth2_passkey_full_router`) and demo structure. Multiple files still reference the old `oauth2_passkey_router` API and outdated demo lists.

## Background

1. **API Change**: `oauth2_passkey_router()` with `.nest()` has been superseded by `oauth2_passkey_full_router()` with `.merge()`
2. **Demo Structure**: Repository now has 7 demos, but READMEs only list 3
3. **HTTPS References**: Many docs reference `localhost:3443` which may change after issue 2026-01-31-02

## Tasks

### 1. Top-level Readme.md

- [x] Update code snippet: `oauth2_passkey_router` -> `oauth2_passkey_full_router`
- [x] Update `.nest()` -> `.merge()` pattern
- [x] Update demo list to include all 7 demos
- [x] Update Repository Structure section

### 2. oauth2_passkey_axum/README.md

- [x] Update `oauth2_passkey_router` -> `oauth2_passkey_full_router`
- [x] Update description text

### 3. docs/ Files with Old API References

- [x] `docs/src/api/axum.md` - Already uses new API
- [x] `docs/src/getting-started/architecture.md`
- [x] `docs/src/integration/server-setup.md` - Rewrote for HTTP-only approach
- [x] `docs/src/integration/passkey.md`
- [x] `docs/src/integration/user-data.md`
- [x] `docs/src/integration/customizing-templates.md`
- [x] `docs/src/integration/multi-origin.md` - Alternative code kept intentionally
- [x] `docs/src/appendix/storage-pattern.md`

### 4. HTTPS Port References

- [x] `Readme.md` - Updated to http://localhost:3001
- [x] `dot.env.simple` - Updated ORIGIN
- [x] `docs/src/getting-started/quick-start.md`
- [x] `docs/src/integration/customizing-templates.md`
- [x] `docs/src/appendix/troubleshooting.md`
- [x] `docs/src/integration/server-setup.md` - Rewrote entirely

Note: demo-*/README.md files were already updated in issue 2026-01-31-02.

### 5. demo-cross-origin/README.md Improvements

- [x] Add `/etc/hosts` setup example before nginx/Caddy configuration

## Related Files

- `Readme.md`
- `oauth2_passkey_axum/README.md`
- `docs/src/**/*.md`
- `demo-*/README.md`
- `demo-cross-origin/README.md`
- `dot.env.simple`

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

## Resolution

Completed on 2026-02-07.

Updated 12 files:
- `Readme.md` - New API, demo table with 7 demos, http://localhost:3001
- `oauth2_passkey_axum/README.md` - New API pattern
- `docs/src/getting-started/architecture.md` - New API
- `docs/src/getting-started/quick-start.md` - HTTP-only, secure context explanation
- `docs/src/integration/server-setup.md` - Rewrote entirely for HTTP-only approach
- `docs/src/integration/passkey.md` - New API
- `docs/src/integration/user-data.md` - New API
- `docs/src/integration/customizing-templates.md` - New API, http://localhost:3001
- `docs/src/appendix/storage-pattern.md` - New API
- `docs/src/appendix/troubleshooting.md` - HTTP/secure context updates
- `demo-cross-origin/README.md` - Added /etc/hosts example
- `dot.env.simple` - Updated ORIGIN to http://localhost:3001