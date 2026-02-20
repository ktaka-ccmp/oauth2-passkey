# Issue: Add Informational Notice to Demo-Live Login Page

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260220-2252

## Created: 2026-02-20-22-52

## Closed: 2026-02-20-23-50

## Status: completed

## Priority: medium

## Difficulty: small

## Description

The demo-live login page should display informational notes so users understand
the demo environment before logging in with their Google account. Currently the
login page has no explanation of what happens after registration.

Users should be informed of:

1. **Admin access**: All users are granted admin privileges to explore full functionality
2. **Data masking**: Other users' information is masked for privacy protection
3. **Memory-based storage**: Data is stored in memory and reset on app restart
4. **Account deletion**: Users can delete their own account from the admin page if concerned

This improves transparency and lowers the barrier to trying the demo, as users
know their data is ephemeral and privacy is protected.

## Related Issues

- `20260210-1935` Demo Site UI/UX Customizations (parent: this extends the demo site UX work)

## Approach

Add a compact "About this demo" notice section below the authentication buttons
on the demo-live login page (`demo-live/templates/login.j2`).

Design considerations:
- Place below buttons so it does not interfere with the primary login flow
- Use subdued styling (`text-secondary` color, smaller font) to keep it unobtrusive
- Bullet-point format for scannability (4 items)
- No changes to core library code; template-only change in demo-live

## Related Files

- `demo-live/templates/login.j2` (login page template)

## Implementation Tasks

- [x] Add "About this demo" notice section to login.j2
- [x] Style the notice to be compact and unobtrusive
- [ ] Verify on passkey-demo.ccmp.jp after deployment

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-20: New issue rather than reopening 20260210-1935

- Context: Considering whether to reopen the completed demo UI customizations issue
- Decision: Create a new issue
- Reason: The original issue has a clear resolution and scope. This is a discrete
  new enhancement (informational notice) that was not part of the original requirements.

## Resolution

Added "About this demo" notice section to `demo-live/templates/login.j2`, displayed
below the authentication buttons with subdued styling. Four bullet points cover:
admin access, data masking, memory-based storage, and account deletion from My Account
page. Deployment verification pending.
