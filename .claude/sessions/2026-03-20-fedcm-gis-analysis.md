# Session Snapshot: FedCM GIS Library Analysis & Stale Tab Investigation

## Date: 2026-03-20

## Branch: `fedcm-gis-alignment`

## Current State

Issue `20260316-1630` (FedCM Promise Hangs Indefinitely in Stale Tab) reopened.
Two commits on the branch:

1. `b58a037` docs: reopen FedCM hang issue with GIS library analysis
2. `fcdb91f` feat: align FedCM credentials.get() options with GIS library

## What Was Done

### GIS Library Reverse Engineering

Fetched and beautified Google's GIS library (`accounts.google.com/gsi/client`, 254KB -> 7520 lines).
Full analysis document: `.junk/gis-fedcm-analysis.md`

Key functions identified and documented:

| Function | Role |
|----------|------|
| `it()` | Builds `credentials.get()` options (AbortController, signal, federated+identity) |
| `jt()` | Executes `credentials.get()` with .then/.catch/.finally |
| `fu()` | FedCM eligibility check for One Tap |
| `ju()` | Launches FedCM One Tap flow |
| `bu()` | Aborts FedCM flow (user-initiated only) |
| `eu()` | Click-outside handler |
| `Gt()` | Sets GIS-level cooldown (cookie-based, separate from Chrome's) |

### GIS vs Our Code: Differences Found & Aligned

| Property | GIS | Our code (before) | Action |
|----------|-----|--------------------|--------|
| `signal` | `new AbortController().signal` | Missing | Added |
| `federated` | Same object as `identity` | Missing | Added |
| `providers[0].fields` | `["name","email","picture"]` | Missing | Added |
| `.finally()` cleanup | Clears AbortController ref | Missing | Added |
| `providers[0].url` | `"https://accounts.google.com/gsi/"` | Missing | Skipped (non-standard) |

### Key Finding: GIS Also Has No Timeout

- GIS has **no timeout** on `navigator.credentials.get()`
- No `AbortSignal.timeout()`, no `Promise.race()`, no `setTimeout` -> `abort()`
- The 90-second auto-dismiss timer only applies to the legacy iframe-based One Tap prompt
- AbortController is only triggered by user actions (click outside, flow restart)
- If FedCM hangs, GIS waits forever too

## Two New Problems Identified

### Problem A: Popup Blocked on FedCM Fallback

When FedCM is cancelled and falls back to OAuth2 popup, `window.open()` gets blocked.

**Root cause**: Browser User Activation policy.

```
User clicks button          (User Activation starts, ~5s window)
  -> openPopup()
    -> fedcmLogin() async
      -> await fetch(nonce)        (time passes)
      -> await credentials.get()   (FedCM dialog shown by browser)
      -> User cancels FedCM        (browser chrome UI, NOT page User Activation)
    -> .catch()
      -> openPopupLegacy()
        -> window.open()           (User Activation expired -> BLOCKED)
```

FedCM cancel is a browser-level UI interaction, not a page-level user gesture.
By the time `.catch()` fires, the original click's User Activation has expired.

**Possible countermeasures**:

1. **Pre-open popup, then navigate it**: Open a blank popup immediately on user click
   (while User Activation is valid), then navigate it to the OAuth2 URL if FedCM fails.
   Downside: user sees a blank popup flash if FedCM succeeds.

2. **Show a "retry" button instead of auto-opening**: On FedCM failure, show a button
   that the user clicks to open the OAuth2 popup. This creates a new User Activation.
   Downside: extra click required.

3. **Use redirect flow instead of popup for fallback**: Navigate the current page to
   the OAuth2 URL instead of opening a popup. No User Activation needed for
   `window.location.href` assignment.
   Downside: loses current page state, different UX from normal popup flow.

4. **Re-request user gesture**: Show a brief "FedCM unavailable, click to continue
   with Google" button that opens the popup on click.

### Problem B: Stale Tab Hang Reproduces Consistently

Opening a tab for a while and then trying FedCM consistently reproduces the hang.

**Root cause hypothesis**: Chrome's FedCM cooldown is per-browsing-context (tab).

- Any previous FedCM dismissal/cancel in that tab sets a cooldown
- Cooldown escalates: 2h -> 1d -> 1w -> 4w on consecutive dismissals
- `mode: 'active'` should be exempt per Chrome docs, but Chrome has a bug:
  active mode still hits cooldown state set by previous interactions
- Bug behavior: Promise hangs silently instead of rejecting with `kDisabledInSettings`
- New tab = new browsing context = no cooldown = works fine

**The true trigger is not "tab open for a while" but "tab has had a previous FedCM
cancel/dismiss"**. "A while" correlates because the cooldown durations are long.

## Files Modified

- `oauth2_passkey_axum/static/oauth2.js` - FedCM options aligned with GIS
- `.claude/issues/open/20260316-1630-fedcm-promise-hang-stale-tab.md` - Issue reopened
- `.claude/issues/README.md` - Issue table updated
- `.junk/gis-fedcm-analysis.md` - Full GIS reverse engineering document (not in repo)

## Next Steps

- [ ] Deploy and test FedCM login with aligned options (regression test)
- [ ] Test stale tab scenario with new code
- [ ] Decide on countermeasure for Problem A (popup blocked on fallback)
- [ ] Consider whether Problem B needs a separate issue
- [ ] Update issue `20260316-1630` with findings from testing