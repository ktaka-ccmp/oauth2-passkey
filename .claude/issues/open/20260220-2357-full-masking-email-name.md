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

## Closed:

## Status: open

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
of preserving the first character. Update corresponding unit tests.

## Related Files

- `oauth2_passkey_axum/src/admin/masking.rs` (masking functions)
- `oauth2_passkey_axum/src/admin/masking/tests.rs` (unit tests)

## Implementation Tasks

- [ ] Change `mask_email()` to return `"***"`
- [ ] Change `mask_name()` to return `"***"`
- [ ] Update unit tests for new expected values
- [ ] Verify locally with `cargo run`

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-20: Full masking over partial masking for public demo

- Context: Partial masking exposes first character of email/name to other users
- Decision: Use full masking (`***`) for Account and Label fields
- Reason: On a public demo with strangers, even one character can help identify
  users. Full masking better delivers on the "masked for privacy" promise.
  Self-view remains unmasked, so users can still see their own data.

## Resolution
