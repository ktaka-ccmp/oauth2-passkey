# Issue: Fix Google OAuth2 Setup Instructions (Callback URL, FedCM JavaScript Origins)

## Metadata

- ID: 20261117-0732
- Created: 2026-11-17-07-32
- Closed:
- Status: open
- Priority: medium
- Difficulty: small
- Related Issues:
  - `20261117-0731` Make It Clear How to Access Demos from Other Devices (related)

## Problem

Two problems in the Google OAuth2 setup instructions.

Based on examination of the code and docs on 2026-11-17:

### 1. Outdated callback URL

The OAuth2 callback route is `/o2p/oauth2/{provider}/authorized`
(e.g. `/o2p/oauth2/google/authorized`). The old `/o2p/oauth2/authorized`
returns 410 Gone (`oauth2_passkey_axum/src/oauth2.rs:96`).

These docs still give the old URL:

| File | Lines |
|------|-------|
| `docs/src/getting-started/quick-start.md` | 38-40 |
| `docs/src/guides/tunneling.md` | 29, 68 |
| `docs/src/appendix/troubleshooting.md` | 32-33, 134 |
| `demo-both/README.md` | 55 |
| `demo-oauth2/README.md` | 53 |
| `demo-cross-origin/README.md` | 93, 250 |

Following the root README / quick start as written, Google redirects to
the old URL and login fails with 410. The correct form is in
`dot.env.example:66` (`{ORIGIN}/o2p/oauth2/{NAME}/authorized`) and
`demo-live/DEPLOY.md`.

### 2. FedCM requires Authorized JavaScript origins, not documented everywhere

With `O2P_FEDCM=true`, the origin must also be added to "Authorized
JavaScript origins" in Google Cloud Console.

- Documented: `docs/src/integration/fedcm.md`,
  `docs/src/integration/configuration.md:543`, `dot.env.example:395`,
  `demo-both/README.md:56`, `demo-oauth2/README.md:54`.
- Missing: `demo-live/DEPLOY.md` (demo-live runs with
  `O2P_FEDCM: "true"` in `env.cloud-run.yaml`, but its Google setup
  lists only redirect URIs), `docs/src/getting-started/quick-start.md`,
  `docs/src/guides/tunneling.md` (a tunnel or proxy changes the origin,
  which must be registered too), `docs/src/appendix/troubleshooting.md`.

## Timeline

## Latest Plan

1. Replace every old callback URL with
   `{ORIGIN}/o2p/oauth2/google/authorized` (or the `{provider}` form
   where the text is generic).
2. Add the "Authorized JavaScript origins" step (when FedCM is used) to
   `demo-live/DEPLOY.md`, quick start and tunneling guide; add a
   troubleshooting entry for FedCM failing due to a missing origin.
3. Re-grep for `/oauth2/authorized` afterwards (excluding CHANGELOG and
   archived docs).

### Files

- `docs/src/getting-started/quick-start.md`
- `docs/src/guides/tunneling.md`
- `docs/src/appendix/troubleshooting.md`
- `demo-both/README.md`, `demo-oauth2/README.md`, `demo-cross-origin/README.md`
- `demo-live/DEPLOY.md`

### Implementation Tasks

- [ ] Fix callback URLs (6 files)
- [ ] Add FedCM JavaScript origins step where missing
- [ ] Troubleshooting entries (410 on old callback, FedCM origin)

### Verification

- `grep -rn "/oauth2/authorized"` finds no current-doc hits.
- Whitespace cleanup for Markdown files.

## Resolution
