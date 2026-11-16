# Issue: Make It Clear How to Access Demos from Other Devices

## Metadata

- ID: 20261117-0731
- Created: 2026-11-17-07-31
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20261117-0730` Allow Overriding the Listen Port in Demo Applications (related)

## Problem

The demos are meant to run on localhost. Passkeys need a secure
context, which plain HTTP provides only for `localhost`, so access
from another device needs an HTTPS proxy or a tunnel. This is
documented, but hard to find; even the maintainer could not recall it
quickly.

Based on examination of the docs on 2026-11-17:

- The root `Readme.md` "Try the Demos" section shows only
  `cp dot.env.simple demo-both/.env` and `cargo run`; nothing about
  localhost-only or HTTPS.
- The explanation is in the latter half of `demo-both`,
  `demo-oauth2` and `demo-passkey` READMEs under "HTTPS for
  Production", a heading that does not suggest "use from another
  device".
- Tunneling (Cloudflare Tunnel, ngrok) is in
  `docs/src/guides/tunneling.md`.
- The demo servers bind `0.0.0.0`, so another device can connect, but
  passkey operations then fail, which is confusing.

## Timeline

## Latest Plan

1. Add a short note to "Try the Demos" in the root `Readme.md`:
   - Plain HTTP works only on `localhost`.
   - From other devices: HTTPS reverse proxy (nginx/Caddy) or a tunnel,
     with links to the demo README section and `tunneling.md`.
   - `ORIGIN` is the URL the browser opens (e.g. the proxy's HTTPS
     URL), not the listen address.
2. Rename "HTTPS for Production" in the demo READMEs to a heading that
   states the purpose (e.g. "Accessing from Other Devices (HTTPS)").

A startup warning when `ORIGIN` is neither `https` nor `localhost` is
a library behavior change; consider it separately.

### Files

- `Readme.md`
- `demo-both/README.md`, `demo-oauth2/README.md`, `demo-passkey/README.md`
- possibly `docs/src/guides/tunneling.md` (cross-link)

### Implementation Tasks

- [ ] Root README note
- [ ] Rename and cross-link demo README sections

### Verification

- Starting from the root README, the HTTPS/tunnel instructions are
  reachable in one link.
- Whitespace cleanup for Markdown files.

## Resolution
