# Issue: Move /info and /csrf_token endpoints to default.rs

## Status: open

## Priority: medium

## Description

The `/info` and `/csrf_token` endpoints are currently in `optional.rs` which requires the `user-ui` feature flag. These should be moved to `default.rs` (always available) because:

1. They are pure JSON APIs, not UI pages
2. Custom page developers need them even without `user-ui` feature
3. Consistency with `/logout`, `/update`, `/delete` which are already in default.rs

## Related Files

- `oauth2_passkey_axum/src/user/optional.rs` - Current location (lines 27-29)
- `oauth2_passkey_axum/src/user/default.rs` - Target location
- `oauth2_passkey_axum/src/user/mod.rs` - Router merging logic

## Notes

From session 2026-01-30:
- User asked whether these routes should be moved
- Analysis confirmed they are JSON APIs that should be always available
- Moving them allows custom page implementations to access user info without enabling full UI

Implementation steps:
1. Move `/info` handler from optional.rs to default.rs
2. Move `/csrf_token` handler from optional.rs to default.rs
3. Update imports in both files
4. Test with `user-ui` feature disabled

## Resolution

