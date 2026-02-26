# Issue: Expand OAuth2 Provider Support

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2020

## Created: 2026-02-26

## Closed:

## Status: open

## Priority: medium

## Difficulty: large

## Description

Currently only Google OAuth2/OIDC is supported. Add support for additional OAuth2 providers to expand the library's utility:

- **GitHub** - Popular for developer-facing applications
- **Apple** - Required for iOS apps using third-party login
- **Microsoft** (Azure AD / Entra ID) - Common in enterprise environments

### Design Considerations

- The existing provider system was designed with extensibility in mind (OIDC Discovery, typed `Provider` wrapper)
- Each provider has slightly different OAuth2/OIDC implementations and quirks
- Apple Sign-In has unique requirements (form_post response mode, private email relay)
- GitHub uses OAuth2 but not full OIDC (no ID token by default)

## Related Issues

None

## Approach

1. Implement providers one at a time, starting with the most requested
2. Leverage existing OIDC Discovery infrastructure where possible
3. Handle provider-specific quirks in dedicated modules
4. Each provider should be independently enableable via environment variables

## Related Files

- `oauth2_passkey/src/oauth2/` - OAuth2 implementation
- `oauth2_passkey/src/coordination/oauth2.rs` - OAuth2 coordination
- `oauth2_passkey_axum/src/oauth2.rs` - OAuth2 handlers

## Implementation Tasks

- [ ] Design provider abstraction layer (if not already sufficient)
- [ ] Implement GitHub OAuth2 provider
- [ ] Implement Apple Sign-In provider
- [ ] Implement Microsoft/Azure AD provider
- [ ] Add provider-specific configuration documentation
- [ ] Add integration tests for each provider
- [ ] Update demo applications

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as medium-priority, large-difficulty issue
- Reason: Multiple providers, each with unique requirements; important for adoption but not blocking current users

## Resolution

