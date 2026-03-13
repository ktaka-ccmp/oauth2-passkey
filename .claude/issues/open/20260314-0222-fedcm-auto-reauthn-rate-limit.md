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

## Closed:

## Status: open

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

Implement two complementary fixes:

1. **Add `mediation: 'required'` to FedCM login call**
   - Forces user interaction for every login attempt
   - Prevents auto re-authn behavior
   - Aligns with our button-triggered login flow

2. **Add `preventSilentAccess()` call on logout**
   - Clears auto re-authn state when user explicitly logs out
   - Best practice for clean logout behavior
   - Ensures logged-out state is respected by FedCM

Both changes are in `oauth2_passkey_axum/static/oauth2.js`.

## Related Files

- `oauth2_passkey_axum/static/oauth2.js` - FedCM login implementation and logout helper

## Implementation Tasks

- [ ] Add `mediation: 'required'` to `navigator.credentials.get()` call in `fedcmLogin()`
- [ ] Add logout helper function that calls `navigator.credentials.preventSilentAccess()` before redirecting
- [ ] Test that FedCM UI appears consistently on repeated logins
- [ ] Test that logout clears FedCM state
- [ ] Update FedCM documentation if needed

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-14: Use both mediation: 'required' and preventSilentAccess()

- Context: FedCM auto re-authn rate limit error occurring intermittently
- Decision: Implement both `mediation: 'required'` (login) and `preventSilentAccess()` (logout)
- Reason: They complement each other - mediation controls login behavior, preventSilentAccess ensures clean logout state. No conflicts, both are best practices.

## Resolution

<To be filled when issue is resolved>
