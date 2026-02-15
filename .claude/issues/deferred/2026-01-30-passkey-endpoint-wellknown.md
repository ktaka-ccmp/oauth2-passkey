# Issue: Add Passkey Endpoint (.well-known) Support

## Table of Contents

- [Description](#description)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 2026-01-30-06

## Status: deferred

## Priority: low

## Difficulty: small

## Description

Implement `.well-known/passkey-endpoints` to advertise passkey support to password managers,
enabling automatic upgrade prompts.

### What is Passkey Endpoint?

A `.well-known` file that tells password managers "this site supports passkeys". When detected,
password managers can prompt users to upgrade from passwords to passkeys.

**Specification:**
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

**Fields:**
- `enroll`: URL where users can create a new passkey
- `manage`: URL where users can manage existing passkeys

**Benefits:**
- Password managers (1Password, Dashlane, etc.) can detect passkey support
- Users receive prompts to upgrade from passwords to passkeys
- Better discoverability of passkey feature

## Approach

### Implementation

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

### Considerations

- Should this be opt-in or opt-out?
- URLs depend on the app's route structure
- May need to be configurable per deployment

### References

- https://blog.agektmr.com/ja/2025/12/passkey-keywords.html
- https://github.com/nicholasleexyz/passkey-endpoints

## Related Files

- `oauth2_passkey_axum/src/routes/` - Route handlers
- New: `.well-known/passkey-endpoints` endpoint

## Implementation Tasks

- [ ] Add route handler for `.well-known/passkey-endpoints`
- [ ] Add configurable env vars for enroll/manage URLs
- [ ] Add documentation

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-01-30: Deferred

- Context: Evaluated `.well-known/passkey-endpoints` specification for inclusion
- Decision: Defer implementation
- Reason: Specification is still in proposal stage and not widely adopted. This library
  uses OAuth2 + Passkey (no password authentication), so the benefit of "upgrade from
  password to passkey" prompts is limited. Will revisit when the specification gains
  broader adoption.

## Resolution

Deferred -- specification not yet widely adopted; limited benefit for OAuth2 + Passkey
(no password) library.
