# Issue: FedCM Auto Re-Authentication Rate Limit Error

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260314-0222

## Created: 2026-03-14-02-22

## Closed: 2026-03-14-02-37

## Status: completed

## Priority: high

## Difficulty: small

## Description

When using FedCM login, the browser sometimes shows an error in the Dev Console:

```
Auto re-authn was previously triggered less than 10 minutes ago.
Only one auto re-authn request can be made every 10 minutes.
```

When this error occurs, the browser window becomes dimmed (grayed out) and the page becomes unresponsive. The FedCM UI does not appear, and **the fallback to popup flow does not happen** - the user is stuck.

**Root Cause**: The browser attempts automatic re-authentication (silent sign-in) even though our code uses `mode: 'active'`. Without explicitly setting `mediation: 'required'`, the browser defaults to `mediation: 'optional'` which allows auto re-authn attempts. When the rate limit is hit, the FedCM API appears to hang rather than rejecting cleanly.

**Impact**:
- Page becomes completely unresponsive (dimmed overlay, no interaction possible)
- FedCM UI does not appear
- Fallback to popup flow does NOT trigger
- Users see error in console but no recovery path
- Requires page reload to recover

## Related Issues

- `20260311-1039` FedCM (Federated Credential Management) Integration (parent feature)

## Approach

Add `mediation: 'required'` to FedCM login call:
- Forces user interaction for every login attempt
- Prevents auto re-authn behavior
- Aligns with our button-triggered login flow
- Single parameter provides complete control over the behavior

Changes are in `oauth2_passkey_axum/static/oauth2.js`.

## Related Files

- `oauth2_passkey_axum/static/oauth2.js` - FedCM login implementation

## Implementation Tasks

- [x] Add `mediation: 'required'` to `navigator.credentials.get()` call in `fedcmLogin()`
- [x] Update FedCM documentation
- [x] Test that FedCM UI appears consistently on repeated logins
- [x] Remove `preventSilentAccess()` implementation (decided unnecessary - mediation parameter is sufficient)

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-14: Use both mediation: 'required' and preventSilentAccess()

- Context: FedCM auto re-authn rate limit error occurring intermittently
- Decision: Implement both `mediation: 'required'` (login) and `preventSilentAccess()` (logout)
- Reason: They complement each other - mediation controls login behavior, preventSilentAccess ensures clean logout state. No conflicts, both are best practices.

### 2026-03-14: Remove preventSilentAccess(), use mediation parameter only

- Context: Implemented `preventSilentAccess()` in logout helper, but realized it adds complexity without clear benefit
- Decision: Remove `preventSilentAccess()` implementation entirely, rely solely on `mediation: 'required'`
- Reason:
  - `mediation: 'required'` already prevents auto re-authn completely
  - `preventSilentAccess()` has no observable effect when mediation is set
  - If behavior should be controlled by mediation parameter, preventSilentAccess interferes with that control
  - Simpler solution: single parameter (`mediation`) controls all behavior
  - Avoids ad-hoc template modifications that don't work for custom templates

## Resolution

Fixed by adding `mediation: 'required'` parameter to `oauth2_passkey_axum/static/oauth2.js`.

**Implementation**: Added `mediation: 'required'` to the `navigator.credentials.get()` call in the FedCM login flow. This explicitly forces user interaction for every login attempt, preventing the browser from attempting automatic re-authentication that triggers the 10-minute rate limit.

**Why this solution**: The `mediation` parameter provides complete control over FedCM auto re-authentication behavior. Setting it to `'required'` ensures the browser always prompts for user interaction, preventing the rate limit error entirely. This is simpler and more maintainable than implementing additional logout hooks with `preventSilentAccess()`.

The fix prevents the issue where the browser window becomes dimmed and unresponsive when the auto re-authn rate limit is hit. Users will now always see the FedCM account chooser UI on login attempts.

Commit: `62f999f` - fix: prevent FedCM auto re-authn rate limit error (20260314-0222)
