# Issue: deployment-patterns.md Example Sends an Ignored Field to auth/start

## Metadata

- ID: 20261117-0729
- Created: 2026-11-17-07-29
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:

## Problem

The cross-origin frontend example in
`docs/src/integration/deployment-patterns.md` (around line 99) calls
`/o2p/passkey/auth/start` with
`body: JSON.stringify({ account: 'user@example.com' })`.

Based on examination of the code on 2026-11-16, the handler reads only
an optional `username` field; `account` is ignored. The bundled JS
sends `{}` (`passkey.js`) or `null` (`conditional_ui.js`).

## Timeline

## Latest Plan

Change the example body to `{}` (matching the bundled JS).

### Files

- `docs/src/integration/deployment-patterns.md`

### Implementation Tasks

- [ ] Update the example body

### Verification

- Example matches the handler's accepted body.

## Resolution
