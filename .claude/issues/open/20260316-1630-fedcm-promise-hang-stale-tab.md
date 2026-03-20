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

## Status: open

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

**2026-03-20 update: Cooldown hypothesis is insufficient**:

The hang reproduces on tabs that have been open for a long time **regardless of whether FedCM was previously cancelled in that tab**. This means cooldown from prior dismissals is NOT the sole cause. Other possible causes:

- Chrome's internal IdP login status becoming stale (Google session cookie rotation / expiry while the tab is open, causing Chrome's internal state to diverge from actual login state)
- Chrome's FedCM accounts endpoint cache becoming stale per browsing context
- Chrome's internal network state degrading at the tab level over time

The common factor is **time since the tab was opened**, not prior FedCM interaction history.

**2026-03-20 update: Chromium issue tracker investigation**:

Searched the Chromium issue tracker for related reports. No exact match for "Promise hangs indefinitely" was found, but two issues are likely related to the root cause:

- [Chromium #40070360](https://issues.chromium.org/issues/40070360): "FedCM IdP Signin Status mismatch UI not displaying as expected" -- When login status is mismatched (e.g., Chrome thinks user is logged-out but they're actually logged-in, or vice versa), the mismatch UI fails to display. This could directly cause our symptom: Chrome activates the FedCM overlay (page dims), but no dialog appears, so the Promise has no way to settle.
- [Chromium #370796104](https://issues.chromium.org/issues/370796104): "[FedCM] Implement error UI on active mode" -- Error UI for active mode is still being implemented. If active mode encounters an error state (login status mismatch, cooldown, etc.) but has no error UI to display, the flow may silently stall instead of rejecting the Promise.

These two issues together suggest the following chain:

1. Tab open for a long time -> Chrome's IdP login status becomes stale/mismatched
2. `credentials.get({mode: 'active'})` is called
3. Chrome detects login status mismatch and should show mismatch UI, but it doesn't display correctly (#40070360)
4. Active mode has no error UI to fall back to (#370796104)
5. Result: FedCM overlay active (page dimmed), no dialog shown, Promise never settles

Other potentially related Chromium issues:
- [#40268652](https://issues.chromium.org/issues/40268652): Reset 10 min quiet period after explicit sign in (cooldown behavior)
- [#40929258](https://issues.chromium.org/issues/40929258): Account endpoints fail with ERR_FAILED (endpoint communication failure)

Additional W3C/GitHub issues:
- [w3c-fedid/FedCM #604](https://github.com/w3c-fedid/FedCM/issues/604): Infinite `login_url` loop when hints are not met (active mode mismatch handling)
- [w3c-fedid/FedCM #419](https://github.com/w3c-fedid/FedCM/issues/419): Decide how to handle signin dialog closure for the IdP signin status API
- [w3c-fedid/FedCM #488](https://github.com/w3c-fedid/FedCM/issues/488): Users confused after showing intent to sign in but sign-in failed
- [w3c-fedid/active-mode](https://github.com/w3c-fedid/active-mode): Active mode proposal (handle logged-out users gracefully)

**2026-03-20 update: Active mode mismatch behavior documented by Chrome**:

Chrome's official documentation describes the expected behavior when login status is mismatched in active mode ([source](https://privacysandbox.google.com/blog/fedcm-chrome-132-updates)):

> "If the login status saved in the browser for an IdP was logged-in, but no accounts for this IdP were returned by the fetch request (for example, if the user session expired, but the login status hasn't yet been updated by the browser), the mismatch UI is shown."

> "For the active mode, the login dialog window is directly opened."

This means the expected behavior is: session expired -> login status mismatch -> active mode opens a login popup window. In our case, this popup window either fails to open or opens but is not visible, causing the FedCM overlay to remain active with no way for the user to interact.

The active mode proposal ([w3c-fedid/active-mode](https://github.com/w3c-fedid/active-mode)) explicitly states that active mode must handle logged-out users gracefully, meaning a user must be able to successfully sign in even when logged out. The hang behavior we observe violates this requirement.

**2026-03-20 update: Tab count hypothesis**:

After adding a 15-second AbortController timeout and testing, a critical observation was made:

- The hang was occurring while many browser tabs were open
- After closing/organizing the excess tabs, the hang state was resolved
- FedCM started working normally again in previously-hanging tabs

This suggests the root cause may be **Chrome resource constraints with many open tabs**, not login status mismatch or cooldown. Possible mechanisms:

- Chrome limits concurrent FedCM operations or UI rendering across tabs
- The FedCM dialog or login popup is being rendered but lost/hidden among many tabs/windows ([Chromium #338233148](https://issues.chromium.org/issues/338233148): FedCM prompt bubble renders outside of opening window)
- Chrome's per-tab resource management (memory, network connections) degrades with many tabs, causing FedCM endpoints to fail silently

This would explain all previous observations:
- "New tab works" -> may have been coincidence of focusing on fewer tabs, not the tab being new
- "Tabs open for a long time" -> long sessions correlate with accumulating more tabs
- "Reload doesn't fix" -> tab count doesn't change on reload
- "Closing tabs fixes it" -> directly addresses the root cause

Further testing needed to determine exact threshold and whether the issue is about total tab count, Chrome resource pressure, or the FedCM dialog being hidden among many windows.

### Impact

Without a fix, users who encounter this state are stuck with no recovery path:
- The page dims and becomes unresponsive
- No fallback to popup flow triggers (because the catch handler never fires)
- Reloading does not help
- Workarounds: open a new tab, or close excess tabs

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

Align our `navigator.credentials.get()` call with Google's GIS library implementation.
GIS library analysis: `docs/src/archived/gis-fedcm-analysis.md`

### GIS vs Our Code: Differences Found

| Property | GIS | Our code | Action |
|----------|-----|----------|--------|
| `signal` | `new AbortController().signal` | Missing | Add |
| `federated` | Same object as `identity` | Missing | Add |
| `identity` | Present | Present | OK |
| `providers[0].url` | `"https://accounts.google.com/gsi/"` | Missing | Skip (see Decision Log) |
| `providers[0].fields` | `["name","email","picture"]` | Missing | Add |
| `.finally()` cleanup | Clears AbortController ref | Missing | Add |

### Improvement Plan

Match GIS behavior without exceeding it (no auto-timeout, no fallback link):

1. **Add `AbortController` and pass `signal`** -- GIS creates a fresh AbortController per call and passes `signal` to `credentials.get()`. This does not auto-abort; it provides a handle for future abort if needed (e.g., page navigation, flow restart).
2. **Add `federated` key alongside `identity`** -- GIS sets both `federated` and `identity` to the same object for backward compatibility with older Chrome versions (pre-131).
3. **Add `providers[0].fields`** -- GIS requests `["name", "email", "picture"]` via the `fields` property. This is part of the "unicorn" experiment that is enabled by default in current GIS.
4. **Add `.finally()` to clean up AbortController reference** -- GIS clears the AbortController reference in `.finally()` to avoid stale references.

### Code Sketch

```javascript
async function fedcmLogin(mode) {
    // ... fetch nonce ...

    const controller = new AbortController();

    const identityOptions = {
        providers: [{
            configURL: 'https://accounts.google.com/gsi/fedcm.json',
            clientId: OAUTH2_CLIENT_ID,
            fields: ['name', 'email', 'picture'],
            params: {
                nonce: nonceData.nonce,
                response_type: 'id_token',
                scope: 'email profile openid',
                ss_domain: window.location.origin,
            },
        }],
        mode: 'active',
        context: 'signin',
    };

    let credential;
    try {
        credential = await navigator.credentials.get({
            identity: identityOptions,
            federated: identityOptions,
            mediation: 'required',
            signal: controller.signal,
        });
    } finally {
        controller = undefined;
    }

    // ... process credential ...
}
```

## Related Files

- `oauth2_passkey_axum/static/oauth2.js` - FedCM login implementation (lines 13-93)

## Implementation Tasks

- [ ] Add `AbortController` and pass `signal` to `credentials.get()`
- [ ] Add `federated` key alongside `identity` (same object)
- [ ] Add `fields: ['name', 'email', 'picture']` to provider
- [ ] Add `.finally()` to clean up AbortController reference
- [ ] Test: FedCM works normally (no regression)
- [ ] Test: Verify behavior in previously-hanging stale tab scenario

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

### 2026-03-19: Reopen - align with GIS library implementation

- Context: The hang occurs frequently in practice. Analyzed Google's GIS library (`accounts.google.com/gsi/client`, 254KB) by beautifying the minified code and reverse-engineering the FedCM flow. Found that GIS also has no timeout/fallback for FedCM hangs, but our `credentials.get()` options differ from GIS in several ways.
- Decision: Reopen and align our implementation with GIS as closely as possible. Do not exceed what GIS does (no auto-timeout, no fallback link). Specific changes:
  1. Add `AbortController` + `signal`
  2. Add `federated` key (backward compat)
  3. Add `fields` property
  4. Add `.finally()` cleanup
- Reason: Matching GIS reduces the chance that our option differences contribute to the hang. The `signal` also provides a handle for future abort if a timeout strategy is later adopted.
- Skipped: `providers[0].url` (GIS sets `url: "https://accounts.google.com/gsi/"`) -- this is a non-standard property not in the FedCM spec. It appears to be Google-internal (possibly related to IdP login status). Adding an arbitrary URL could have unintended side effects. The standard `configURL` already points Chrome to the correct FedCM config.
- Reference: Full GIS analysis in `docs/src/archived/gis-fedcm-analysis.md`

## Resolution
