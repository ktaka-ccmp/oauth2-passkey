# Issue: FedCM Promise Hangs Indefinitely in Stale Tab

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260316-1630

## Created: 2026-03-16-16-30

## Closed:

## Status: deferred

## Priority: high

## Difficulty: small

## Description

When using FedCM login, `navigator.credentials.get()` can hang indefinitely in certain tabs, causing the page to become dimmed and unresponsive with no way to recover except opening a new tab.

### Symptoms

- Page becomes dimmed (browser-level FedCM overlay)
- FedCM account chooser UI does NOT appear
- No errors in DevTools console
- Promise never resolves or rejects (confirmed via AbortController test)
- Page reload does NOT fix the issue (same behavior after reload)
- Opening a new tab works normally
- The problematic tab may have been open since the code used passive mode (before `mode: 'active'` was added)

### Diagnostic Results

| Check | Result |
|-------|--------|
| AbortController timeout test (5s) | Promise hangs, only resolves via abort |
| Network requests (nonce, fedcm.json, accounts) | All 200 OK |
| DevTools console errors | None |
| `chrome://settings/content/federatedIdentityApi` | Site NOT in blocked list |
| `FedCm.resetCooldown` via CDP | CDP FedCm domain not supported in this Chrome version |
| New tab behavior | FedCM works normally |
| Reload behavior | Problem persists |

### AbortController Test (Reproduction)

Run in the problematic tab's DevTools Console:

```javascript
const controller = new AbortController();
setTimeout(() => { controller.abort(); console.log('TIMEOUT: FedCM hung for 5s'); }, 5000);

navigator.credentials.get({
    identity: {
        providers: [{
            configURL: 'https://accounts.google.com/gsi/fedcm.json',
            clientId: OAUTH2_CLIENT_ID,
        }],
        mode: 'active',
    },
    mediation: 'required',
    signal: controller.signal,
}).then(c => console.log('RESOLVED:', c))
  .catch(e => console.log('REJECTED:', e.name, e.message));
```

Expected output after 5 seconds:
```
TIMEOUT: FedCM hung for 5s
REJECTED: AbortError signal is aborted without reason
```

### Root Cause Analysis

**Suspected cause**: Stale browsing context state from passive mode era. The tab was likely open when FedCM code did not use `mode: 'active'` (passive mode). A FedCM dismissal during that period may have left internal browser state that persists across page reloads within the same browsing context (tab).

**Chrome documentation vs actual behavior**:

- Chrome docs state: "Active mode is not affected by cooldown restrictions since it requires explicit user gesture" ([source](https://developer.chrome.com/docs/identity/fedcm/customization))
- Chrome's cooldown mechanism exponentially expands: 2 hours -> 1 day -> 1 week -> 4 weeks on consecutive dismissals ([source](https://developer.chrome.com/docs/identity/fedcm/customization))
- Chromium code should reject with `kDisabledInSettings` error during cooldown ([source](https://chromium.googlesource.com/chromium/src/+/982292f469687016dc4578b1829e8a7322a829d4%5E!/))
- **Actual behavior**: No error, no rejection, Promise hangs silently

**Bug or spec?**:
- The cooldown mechanism itself is by design (anti-abuse for passive mode)
- However, two aspects are problematic:
  1. Promise hanging without resolve/reject violates the expected Promise contract. The browser should reject with an error.
  2. Active mode (user-initiated, button-triggered) should not be subject to cooldown per Chrome's own documentation.

### Impact

Without a fix, users who encounter this state are stuck with no recovery path:
- The page dims and becomes unresponsive
- No fallback to popup flow triggers (because the catch handler never fires)
- Reloading does not help
- Only workaround is to open a new tab

### Difference from Previous Issue (20260314-0222)

| Aspect | 20260314-0222 | This issue |
|--------|---------------|------------|
| Console error | "Auto re-authn was previously triggered less than 10 minutes ago" | None |
| Cause | Missing `mediation: 'required'` | Browser internal state (stale tab) |
| Recovery | Page reload | Only new tab |
| Fix | Add `mediation: 'required'` | AbortController timeout + fallback |

## Related Issues

- `20260314-0222` FedCM Auto Re-Authentication Rate Limit Error (related, similar symptoms)
- `20260311-1039` FedCM (Federated Credential Management) Integration (parent feature)

## Approach

Add `AbortController` with a timeout to the `navigator.credentials.get()` call. When the timeout fires, abort the request and fall back to the popup OAuth2 flow.

```javascript
async function fedcmLogin(mode) {
    // ... fetch nonce ...

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
        const credential = await navigator.credentials.get({
            identity: { /* ... */ },
            mediation: 'required',
            signal: controller.signal,
        });
        clearTimeout(timeoutId);
        // ... process credential ...
    } catch (err) {
        clearTimeout(timeoutId);
        throw err; // caught by outer catch -> falls back to popup
    }
}
```

The outer catch in `openPopup()` already handles fallback:
```javascript
fedcmLogin(mode).catch(function(err) {
    console.log('FedCM failed, falling back to popup:', err.message);
    openPopupLegacy(mode, page_context);
});
```

### Design Decisions

- **Timeout duration**: 5 seconds. FedCM UI normally appears within 1-2 seconds. 5 seconds provides margin while keeping the user experience responsive.
- **Fallback behavior**: Use existing popup flow (`openPopupLegacy`), which is already the fallback for browsers without FedCM support.
- **No retry**: If FedCM hangs once in a tab, it will likely hang again. Falling back to popup is the correct behavior.

## Related Files

- `oauth2_passkey_axum/static/oauth2.js` - FedCM login implementation (lines 13-93)

## Implementation Tasks

- [ ] Add `AbortController` with 5-second timeout to `navigator.credentials.get()` in `fedcmLogin()`
- [ ] Ensure `clearTimeout` is called on both success and failure paths
- [ ] Test: FedCM works normally when not in stale state
- [ ] Test: Fallback to popup triggers after timeout in stale tab

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-16: Use AbortController timeout for FedCM hang detection

- Context: `navigator.credentials.get()` hangs indefinitely in stale tabs (likely passive mode era browsing context). No console error, no Promise rejection. Catch handler never fires, so popup fallback never triggers. Chrome's FedCm CDP domain not available in user's browser version, preventing deeper diagnosis.
- Decision: Add `AbortController` with 5-second timeout to detect hanging FedCM calls and fall back to popup OAuth2 flow.
- Reason:
  - Proven to work via manual Console test (AbortController successfully aborted the hanging call)
  - Minimal code change (add controller + timeout around existing `navigator.credentials.get()` call)
  - Does not affect normal FedCM operation (timeout only fires if FedCM hangs)
  - Root cause is in Chrome's internal state, not fixable from application side
  - Existing popup fallback infrastructure already handles the error path

### 2026-03-17: Deferred - no good solution yet

- Context: The AbortController timeout approach (5s) has a fundamental flaw: it cannot distinguish between "FedCM UI hung" and "user is taking time to choose an account." Auto-timeout would interrupt normal users. Manual fallback link is poor UX.
- Decision: Defer this issue pending:
  - Error reproduction (to study the problem further)
  - Chrome improvements (Promise should reject, not hang - this is arguably a browser bug)
  - A better detection approach emerging
  - FedCM is still experimental support in this project, so the risk is acceptable
- Rejected approaches:
  - **AbortController with auto-timeout (5s)**: Cannot distinguish "FedCM UI hung" from "user is taking time to choose an account." Would interrupt normal users mid-interaction.
  - **Manual fallback link**: Show a "try popup login" link after a delay. Poor UX - clutters the interface, requires user to understand what happened, and the timing of when to show it is still arbitrary.

## Resolution
