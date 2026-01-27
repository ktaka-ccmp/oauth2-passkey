# Session Snapshot: Unified Router API Design

**Date**: 2026-01-27
**Topic**: Router API simplification and documentation improvements

## Current Task

Designing a unified router API (`oauth2_passkey_full_router()`) that:
- Nests auth endpoints under `O2P_ROUTE_PREFIX`
- Conditionally includes `/.well-known/webauthn` when `WEBAUTHN_ADDITIONAL_ORIGINS` is set

**Plan file**: `/home/ktaka/.claude/plans/transient-wibbling-turtle.md`

## Files Modified This Session

### Code Changes
| File | Change |
|------|--------|
| `oauth2_passkey_axum/src/passkey.rs` | Fixed path: `/webauthn` → `/.well-known/webauthn` |

### Documentation Changes
| File | Change |
|------|--------|
| `docs/src/integration/multi-origin.md` | **NEW** - Multi-Origin Passkey Setup guide |
| `docs/src/SUMMARY.md` | Added multi-origin.md to TOC |
| `docs/src/api/axum.md` | Added endpoint reference, linked to multi-origin docs |
| `docs/src/integration/framework.md` | Simplified endpoint list, linked to reference |

### Pending Changes (Not Committed)
```
modified:   demo-both/src/main.rs
modified:   docs/src/SUMMARY.md
modified:   docs/src/api/axum.md
modified:   docs/src/integration/framework.md
modified:   oauth2_passkey_axum/src/passkey.rs
new file:   docs/src/integration/multi-origin.md
```

## Key Decisions

1. **`/.well-known/webauthn` path fix**: Changed from `/webauthn` to `/.well-known/webauthn` so `.merge()` creates correct endpoint
2. **Multi-origin docs location**: Part 2: Basic Integration (not Internals) - it's user-facing configuration
3. **Unified router design**: Create `oauth2_passkey_full_router()` that:
   - Uses `has_additional_origins()` to check if multi-origin is configured
   - Conditionally merges well-known router
   - Maintains backward compatibility with existing APIs

## Next Steps

### Immediate (Plan approved)
1. Add `has_additional_origins()` to `oauth2_passkey/src/passkey/main/related_origin.rs`
2. Re-export through module hierarchy
3. Create `oauth2_passkey_full_router()` in `oauth2_passkey_axum/src/router.rs`
4. Update demos to use new API
5. Update documentation

### Files to Modify (from plan)
- `oauth2_passkey/src/passkey/main/related_origin.rs` - Add `has_additional_origins()`
- `oauth2_passkey/src/passkey/mod.rs` - Re-export
- `oauth2_passkey/src/lib.rs` - Re-export
- `oauth2_passkey_axum/src/lib.rs` - Re-export + export new router
- `oauth2_passkey_axum/src/router.rs` - Add `oauth2_passkey_full_router()`
- `demo-both/src/main.rs` - Use new router
- `demo-passkey/src/main.rs` - Use new router

## Context

### Related Origins Explanation
- `/.well-known/webauthn` is for WebAuthn Related Origins feature
- Allows passkeys to work across multiple subdomains (same RP ID)
- NOT for sharing passkeys between different RPs (security design)
- Only needed when `WEBAUTHN_ADDITIONAL_ORIGINS` env var is set

### Current API (Problem)
```rust
// Users must remember two things
.nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
.merge(passkey_well_known_router())  // Easy to forget
```

### Target API (Solution)
```rust
// Single call handles everything
.merge(oauth2_passkey_full_router())
```

## Previous Session Work

From earlier in this session:
- Renamed `/user/summary` → `/user/account` (committed as 7dbb0b3)
- Added comprehensive endpoint reference to api/axum.md
