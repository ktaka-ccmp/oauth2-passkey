# Issue: Enhance Login History with Auth-Method-Specific Details

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260210-0547

## Created: 2026-02-10-05-47

## Closed:

## Status: open

## Priority: medium

## Difficulty: medium

## Description

The login history currently records minimal auth-method-specific data: `credential_id`
for passkey logins and `provider`/`provider_user_id` for OAuth2 logins. The display
shows only text-based auth method indicators.

### Enhancement Goals

1. **Record AAGUID in login history** for passkey logins, enabling authenticator
   identification (name, icon) without joining the passkey credentials table
2. **Display authenticator icons** in login history views using AAGUID-based
   AuthenticatorInfo lookup (icon_light/icon_dark URLs from passkey-authenticator-aaguids)
3. **Enrich display** of auth-method-specific details in both user and admin views

### Current State

| Field | Passkey | OAuth2 |
|-------|---------|--------|
| credential_id | Recorded | Not applicable |
| aaguid | **Not recorded** | Not applicable |
| provider | Not applicable | Recorded |
| provider_user_id | Not applicable | Recorded |

### Why AAGUID in Login History

- AAGUID is stored in the passkey credentials table but NOT in login history
- If a credential is later deleted, the AAGUID information is lost for historical records
- Recording AAGUID directly enables AuthenticatorInfo lookup (name + icon) without joins
- Icons make it immediately clear which authenticator was used (iCloud Keychain, Google PM, etc.)

## Related Issues

- `2026-01-30-03` Admin Login History View (completed, built the base feature)
- `2026-02-08-01` Audit Page Enhancement (completed, added date filtering + admin audit)
- `2026-01-30-07` Passkey Registration Promotion After Login (related, uses AAGUID heuristic)

## Approach

### Phase 1: Record AAGUID in login history

- Add `aaguid` column (TEXT NULLABLE) to `o2p_login_history` table
- Update `LoginHistoryEntry` struct to include `aaguid: Option<String>`
- Update `record_login_success()` to pass AAGUID when auth_method is passkey
- Update storage layer (SQLite + PostgreSQL) INSERT and SELECT queries

### Phase 2: Display authenticator info in login history

- Fetch `AuthenticatorInfo` for AAGUIDs in login history entries (batch lookup)
- User login history page: show authenticator icon + name alongside credential info
- Admin audit page: show authenticator icon + name in passkey login entries

### Database Migration

Add nullable column (no migration script needed for existing rows):

```sql
ALTER TABLE o2p_login_history ADD COLUMN aaguid TEXT;
```

Existing rows will have `aaguid = NULL`, which is handled gracefully.

## Related Files

- `oauth2_passkey/src/audit/types.rs` -- `LoginHistoryEntry` struct
- `oauth2_passkey/src/audit/storage/sqlite.rs` -- SQLite login history queries
- `oauth2_passkey/src/audit/storage/postgres.rs` -- PostgreSQL login history queries
- `oauth2_passkey/src/coordination/login_history.rs` -- `record_login_success()`, `record_login_failure()`
- `oauth2_passkey_axum/templates/user_login_history.j2` -- User login history display
- `oauth2_passkey_axum/templates/admin_audit.j2` -- Admin audit display
- `oauth2_passkey/src/passkey/types.rs` -- `PasskeyCredential` (has `aaguid` field)

## Implementation Tasks

- [ ] Add `aaguid` column to login history schema (SQLite + PostgreSQL)
- [ ] Update `LoginHistoryEntry` struct with `aaguid: Option<String>`
- [ ] Update storage INSERT queries to include `aaguid`
- [ ] Update storage SELECT queries to return `aaguid`
- [ ] Update `record_login_success()` to pass AAGUID for passkey logins
- [ ] Look up AAGUID in passkey auth flow and pass to recording function
- [ ] Batch fetch `AuthenticatorInfo` for AAGUIDs in history entries
- [ ] Update user login history template to show authenticator icon + name
- [ ] Update admin audit template to show authenticator icon + name
- [ ] Add unit tests for AAGUID recording
- [ ] Manual testing: verify AAGUID appears in login history after passkey login

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-10: Initial design

- Context: Login history records credential_id for passkey logins but not AAGUID.
  Without AAGUID, displaying authenticator icons requires joining with the credentials
  table, which fails for deleted credentials.
- Decision: Add AAGUID as a nullable column in login_history, record it alongside
  credential_id during passkey login
- Reason: Self-contained historical records; icons improve UX; nullable column is
  backward-compatible with no migration needed for existing data

## Resolution
