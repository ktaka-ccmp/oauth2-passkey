# Issue: FedCM Cancel Fallback Popup Gets Blocked by Browser

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260320-1410

## Created: 2026-03-20-14-10

## Closed:

## Status: open

## Priority: medium

## Difficulty: medium

## Description

When FedCM login is cancelled by the user, the fallback to OAuth2 popup flow fails because the browser's popup blocker prevents `window.open()` from opening.

### Symptoms

- User clicks login button -> FedCM dialog appears -> user cancels
- Fallback to popup OAuth2 flow is triggered via `.catch()`
- `window.open()` is blocked by the browser (no popup appears)
- No popup blocker notification icon in Chrome's address bar
- Second attempt (click login -> FedCM cancel -> fallback) succeeds

### Reproduction

1. Clear browser state or wait a long time since last test ("しばらくぶり")
2. Click login button (triggers FedCM)
3. Cancel the FedCM dialog
4. Observe: OAuth2 popup does not open (blocked)
5. Click login button again
6. Cancel FedCM dialog again
7. Observe: OAuth2 popup opens successfully

### Root Cause Analysis

The browser's User Activation (transient activation) policy controls `window.open()`.
Chrome allows `window.open()` only within ~5 seconds of a user gesture.

```
User clicks login button          (User Activation starts, ~5s window)
  -> openPopup()
    -> fedcmLogin(mode) [async]
      -> await fetch(nonce)         (network latency: cold=~1s, warm=~0.2s)
      -> await credentials.get()    (FedCM dialog shown by browser)
      -> user reads + cancels       (user interaction time)
    -> .catch() fires
      -> openPopupLegacy()
        -> window.open()            (if total elapsed > ~5s -> BLOCKED)
```

The total elapsed time from the original click to `window.open()` depends on:

1. **Network latency for nonce fetch**: Cold connection (DNS + TLS) = ~1s, warm = ~0.2s
2. **FedCM dialog display time**: Browser initialization
3. **User interaction time**: Time to read the dialog and click cancel

### Why First Attempt Fails but Second Succeeds

**Hypothesis: Timing difference between cold and warm attempts**

| Factor | 1st attempt ("しばらくぶり") | 2nd attempt (immediate) |
|--------|------------------------------|--------------------------|
| Nonce fetch | Cold connection (~1s) | Warm connection (~0.2s) |
| User reaction | Reads dialog, slower cancel | Already knows, instant cancel |
| Total elapsed | ~4-5s+ (exceeds 5s window) | ~2-3s (within 5s window) |

The first attempt after a long idle period has higher latency (cold connection) and
slower user reaction (reading the dialog for the first time), causing the total
elapsed time to exceed Chrome's ~5-second User Activation window.

The second attempt benefits from warm connections and the user already knowing to
cancel immediately.

### Open Questions

- Does `navigator.credentials.get({mode: 'active'})` consume User Activation, or
  only require it? If it consumes, then both attempts should fail. Since the second
  attempt succeeds, it likely does NOT consume the activation.
- Is the ~5-second window the exact threshold, or does Chrome have additional
  heuristics (site engagement score, recent popup block history)?
- Does Chrome show a popup blocker notification icon? (User reports: NO)
- Are there browser version differences in this behavior?

### Verification Plan

To confirm the timing hypothesis:

1. Add `console.log` timestamps at each step (click, nonce fetch complete,
   credentials.get start, catch, window.open)
2. Compare elapsed times between blocked and successful attempts
3. Test with pre-warmed nonce endpoint (fetch nonce on page load, not on click)
4. Test with deliberately fast cancel (cancel within 1-2s of dialog appearing)

## Related Issues

- `20260316-1630` FedCM Promise Hangs Indefinitely in Stale Tab (sibling issue, same flow)
- `20260311-1039` FedCM (Federated Credential Management) Integration (parent feature)

## Approach

TBD - Pending verification of root cause. Possible directions:

1. **Pre-open popup, then navigate**: Open blank popup on click, navigate on FedCM
   failure. Downside: blank popup flash on FedCM success.
2. **Retry button**: Show "click to continue with Google" on FedCM failure.
   Downside: extra click.
3. **Redirect fallback**: Use `window.location.href` instead of popup.
   Downside: loses page state, different UX.
4. **Pre-warm nonce**: Fetch nonce on page load to reduce latency.
   Downside: nonce might expire, only partially addresses timing.

None of these are ideal. Decision deferred until root cause is verified.

## Related Files

- `oauth2_passkey_axum/static/oauth2.js` - `openPopup()`, `fedcmLogin()`, `openPopupLegacy()`

## Implementation Tasks

- [ ] Add timing instrumentation to measure elapsed time at each step
- [ ] Reproduce and verify the timing hypothesis
- [ ] Determine whether `credentials.get()` consumes User Activation
- [ ] Choose and implement countermeasure

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-20: Created issue, timing hypothesis

- Context: During FedCM GIS alignment work (issue 20260316-1630), discovered that
  FedCM cancel -> popup fallback gets blocked on the first attempt after a long idle
  period, but succeeds on the second attempt. User reports no popup blocker
  notification icon in Chrome.
- Decision: Create separate issue to investigate. The timing hypothesis (cold vs warm
  connection + user reaction time determining whether 5s User Activation window is
  exceeded) explains the observed behavior but needs verification.
- Reason: This is independent from the FedCM hang/stale tab issue and needs its own
  investigation and solution.

## Resolution