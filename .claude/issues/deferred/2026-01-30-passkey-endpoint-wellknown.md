# Issue: Add Passkey Endpoint (.well-known) Support

## ID: 2026-01-30-06

## Status: deferred

## Priority: low

## Description

Implement `.well-known/passkey-endpoints` to advertise passkey support to password managers, enabling automatic upgrade prompts.

## Related Files

- `oauth2_passkey_axum/src/routes/` - Route handlers
- New: `.well-known/passkey-endpoints` endpoint

## Notes

**What is Passkey Endpoint?**

A `.well-known` file that tells password managers "this site supports passkeys". When detected, password managers can prompt users to upgrade from passwords to passkeys.

**Specification**:
```
GET /.well-known/passkey-endpoints
```

Returns JSON:
```json
{
  "enroll": "https://example.com/account/passkeys",
  "manage": "https://example.com/account/passkeys"
}
```

**Fields**:
- `enroll`: URL where users can create a new passkey
- `manage`: URL where users can manage existing passkeys

**Benefits**:
- Password managers (1Password, Dashlane, etc.) can detect passkey support
- Users receive prompts to upgrade from passwords to passkeys
- Better discoverability of passkey feature

**Implementation**:

1. Add new route handler:
```rust
async fn passkey_endpoints() -> Json<Value> {
    Json(json!({
        "enroll": format!("{}/account", origin()),
        "manage": format!("{}/account", origin())
    }))
}
```

2. Register route at `/.well-known/passkey-endpoints`

3. Make URLs configurable via environment variables:
```
PASSKEY_ENROLL_URL=/account
PASSKEY_MANAGE_URL=/account
```

**Considerations**:
- Should this be opt-in or opt-out?
- URLs depend on the app's route structure
- May need to be configurable per deployment

**Reference**:
- https://blog.agektmr.com/ja/2025/12/passkey-keywords.html
- https://github.com/nicholasleexyz/passkey-endpoints

## Resolution

**Deferred** - This specification is still in proposal stage and not widely adopted. This library uses OAuth2 + Passkey (no password authentication), so the benefit of "upgrade from password to passkey" prompts is limited. Will revisit when the specification gains broader adoption.
