# Issue: Verify LINE Login as Custom OIDC Provider + Documentation

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-1456

## Created: 2026-04-20-14-56

## Closed:

## Status: open

## Priority: medium

## Difficulty: low

## Description

Verify that LINE Login v2.1 works as a Custom OIDC provider slot
(implemented in issue `20260420-1511`) and produce setup documentation.

Originally this issue planned LINE as a dedicated `ProviderKind::Line`
variant, but the generic OIDC provider slots (CUSTOM1..CUSTOM8) make a
dedicated variant unnecessary. LINE is OIDC-compliant and fits the
existing custom slot mechanism with zero code changes.

### LINE Login characteristics

- **OIDC compliant** (v2.1 and later)
- **Discovery URL**: `https://access.line.me/.well-known/openid-configuration`
- **Issuer**: `https://access.line.me`
- **Signing algorithm**: ES256 (already supported)
- **Scopes**: `openid`, `profile`, `email`

### Caveats

1. **`email` claim requires LINE approval**
   - LINE Developer Console -> "Email address permission" application required
   - Manual review process, typically approved within 1-2 business days
   - Before approval, `email` claim is not returned -> login fails with
     `OAuth2Error::Validation` (expected behavior, clean error)

2. **`name` is the LINE display name** — may contain emoji or spaces

3. **`picture`** — LINE profile image URL

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (relationship: part of)
- `20260420-1511` Add Generic OIDC Provider Slots (relationship: LINE uses this, completed)

## Approach

No code changes required. Deliverables:

1. **E2E verification**: Confirm LINE Login works via a CUSTOM slot
2. **Documentation**: Add LINE setup guide to `docs/src/guides/generic-oidc.md`
   (LINE section appended to existing provider guides)

### Environment variables for LINE

```bash
OAUTH2_CUSTOM<N>_CLIENT_ID="<LINE Channel ID>"
OAUTH2_CUSTOM<N>_CLIENT_SECRET="<LINE Channel Secret>"
OAUTH2_CUSTOM<N>_ISSUER_URL="https://access.line.me"
OAUTH2_CUSTOM<N>_DISPLAY_NAME="LINE"
OAUTH2_CUSTOM<N>_NAME="line"
OAUTH2_CUSTOM<N>_BUTTON_COLOR="#06C755"
OAUTH2_CUSTOM<N>_BUTTON_HOVER_COLOR="#05A647"
OAUTH2_CUSTOM<N>_SCOPE="openid+profile+email"
```

### LINE Developer Console setup outline

1. Create a LINE Login channel (channel type: LINE Login, app type: Web app)
2. Set callback URL to `https://<ORIGIN>/oauth2/line/authorized`
3. Apply for email address permission (requires screenshot of consent UI)
4. Wait for approval (~1-2 business days)
5. Copy Channel ID and Channel Secret to env vars

## Related Files

- `docs/src/guides/generic-oidc.md` — append LINE section
- `docs/src/SUMMARY.md` — already has generic-oidc entry (no change needed)
- `dot.env.example` — optionally add LINE example block

## Implementation Tasks

- [ ] Apply for LINE email permission in Developer Console
- [ ] Wait for email permission approval
- [ ] Configure LINE as CUSTOM slot in demo environment
- [ ] E2E: LINE login succeeds (email present after approval)
- [ ] E2E: Verify named providers still work (regression check)
- [ ] Append LINE section to `docs/src/guides/generic-oidc.md`
- [ ] Optionally add LINE example to `dot.env.example`

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-20: LINE as dedicated variant

- Context: Originally planned as `ProviderKind::Line` with 6 lock-step
  edits following the Entra pattern.
- Decision: Planned as a named variant.
- Reason: Issue was created before generic OIDC slots existed.

### 2026-05-04: Pivot to Custom OIDC slot verification

- Context: Generic OIDC provider slots (issue `20260420-1511`) landed with
  E2E verification against Zitadel, Ory Hydra, Authentik, and Okta. LINE
  is OIDC-compliant (v2.1, ES256, standard discovery) and fits the custom
  slot mechanism without code changes.
- Decision: Repurpose this issue as verification + documentation only.
  No `ProviderKind::Line` variant needed.
- Reason: Adding a dedicated variant for LINE would be unnecessary code
  when the generic slot handles it identically. The only LINE-specific
  concern (email permission) is a deployment/config issue, not a code issue.
  Document the setup process and verify E2E.

## Resolution
