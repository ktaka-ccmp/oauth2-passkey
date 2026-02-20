# Issue: Full Masking for Email and Name in Demo Mode

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260220-2357

## Created: 2026-02-20-23-57

## Closed: 2026-02-21-00-16

## Status: completed

## Priority: medium

## Difficulty: small

## Description

In demo mode (`O2P_DEMO_MODE`), the Account (email) and Label (name) fields of
other users are currently partially masked (e.g., `u***@***`, `J*** S***`),
exposing the first character. On a public demo site where strangers share the
same instance, even a single character can narrow down identities.

Change to full masking (`***`) for both fields to better protect user privacy.
Self-view remains unmasked.

### Current vs Proposed

| Field | Current | Proposed |
|-------|---------|----------|
| Email (Account) | `u***@***` | `***` |
| Name (Label) | `J*** S***` | `***` |

## Related Issues

- `20260210-1935` Demo Site UI/UX Customizations (parent: original masking implementation)
- `20260220-2252` Add Informational Notice to Demo-Live Login Page (related: login page says "masked for privacy")

## Approach

Modify `mask_email()` and `mask_name()` in `masking.rs` to return `"***"` instead
of preserving the first character. Also redact OAuth2 profile pictures via new
`Masker::redact()` method (returns empty string to suppress template rendering).
Update corresponding unit tests.

## Related Files

- `oauth2_passkey_axum/src/admin/masking.rs` (masking functions + Masker::redact)
- `oauth2_passkey_axum/src/admin/masking/tests.rs` (unit tests)
- `oauth2_passkey_axum/src/admin/optional.rs` (TemplateAccount::masked - picture redaction)

## Implementation Tasks

- [x] Change `mask_email()` to return `"***"`
- [x] Change `mask_name()` to return `"***"`
- [x] Add `Masker::redact()` and redact OAuth2 profile picture
- [x] Update unit tests for new expected values
- [x] Verify locally with `cargo run`

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-20: Full masking over partial masking for public demo

- Context: Partial masking exposes first character of email/name to other users
- Decision: Use full masking (`***`) for Account and Label fields
- Reason: On a public demo with strangers, even one character can help identify
  users. Full masking better delivers on the "masked for privacy" promise.
  Self-view remains unmasked, so users can still see their own data.

### 2026-02-21: Include OAuth2 profile picture in masking scope

- Context: Profile picture from Google OAuth2 is displayed on admin user detail page
- Decision: Redact picture field (empty string) via new `Masker::redact()` method
- Reason: Full masking of email/name is meaningless if profile picture identifies
  the user. Template already guards with `{% if picture != "" %}`, so empty string
  suppresses rendering without template changes.

## Resolution

Implemented full masking for email, name, and OAuth2 profile picture in demo mode:
- `mask_email()` and `mask_name()` return `"***"` (no first-character exposure)
- New `Masker::redact()` method returns empty string for fields guarded by template
  conditionals (profile picture)
- `TemplateAccount::masked()` now redacts the `picture` field
- All unit tests updated. Clippy and tests pass.
