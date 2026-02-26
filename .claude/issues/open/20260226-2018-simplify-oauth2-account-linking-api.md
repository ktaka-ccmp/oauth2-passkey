# Issue: Simplify OAuth2 Account Linking API

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2018

## Created: 2026-02-26

## Closed:

## Status: open

## Priority: high

## Difficulty: medium

## Description

The current OAuth2 account linking implementation creates a significant barrier to adoption due to its complexity. Users must understand and coordinate multiple concepts (CSRF tokens, page session tokens) and make multiple API calls (~50+ lines of code) to accomplish what should be a simple operation.

### Current Complexity

1. Call `/auth/user/csrf_token` to get CSRF token
2. Call `generate_page_session_token(&csrf_token)` for security token
3. Construct OAuth2 URL with `mode=add_to_user&context=${page_session_token}`
4. Handle popup window management and session verification

### Goal

Provide a simpler, more intuitive API that reduces the integration burden while maintaining security guarantees.

## Related Issues

None

## Approach

See detailed analysis and proposed solutions in `docs/src/archived/design-proposals/oauth2-account-linking-api-simplification.md`.

## Related Files

- `docs/src/archived/design-proposals/oauth2-account-linking-api-simplification.md`
- `oauth2_passkey/src/coordination/oauth2.rs`
- `oauth2_passkey_axum/src/oauth2.rs`

## Implementation Tasks

- [ ] Review existing design proposal
- [ ] Design simplified API surface
- [ ] Implement simplified account linking flow
- [ ] Update documentation and examples
- [ ] Add integration tests for new API

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as high-priority issue; design proposal already exists
- Reason: This is a key usability barrier for library adoption

## Resolution

