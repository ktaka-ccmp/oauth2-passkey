# Session Snapshot: Bearer Token Design Review

**Date**: 2026-01-30
**Branch**: `dev-2026-01-23-01`

## Current Task

Design review of Bearer Token authentication support. Clarifying use cases and determining what this library should provide.

## Files Modified

- `.claude/issues/open/2026-01-23-bearer-token-support.md` - Reopened with design review notes
- `.claude/issues/completed/2026-01-30-demo-api.md` - demo-api implementation completed
- `CLAUDE.md` - Added "Language: All issue documents must be written in English"
- `Cargo.toml` - Added demo-api to workspace
- `demo-api/` - New demo application for Bearer token authentication

## Key Decisions

### Use Case Matrix (Finalized)

| # | Client | Origin | Authentication | Session Maintenance | Status |
|---|--------|--------|----------------|---------------------|--------|
| 1 | Browser (traditional/SPA) | Same-Origin | Browser | Cookie | Supported |
| 2 | Browser (traditional/SPA) | Cross-Origin, Same-Site | Browser | Cookie + Domain + CORS | Supported (config) |
| 3 | Browser (traditional/SPA) | Cross-Site | - | - | Out of scope |
| 4 | Native App | - | Passkey (Native API) | Bearer | Supported |
| 5 | Native App | - | OAuth2 (In-App Browser) | Bearer | Not supported |

### Key Insights

1. **Same-Site subdomains (e.g., app.example.com, api.example.com)**:
   - Cookie-based authentication works with proper configuration
   - Required: `Domain=.example.com`, CORS headers, `credentials: 'include'`
   - Bearer Token NOT required for this case

2. **SESSION_AUTH_MODE purpose**:
   - Controls how session is maintained (not how authentication happens)
   - Authentication always requires browser/platform (OAuth2 redirects, Passkey native API)

3. **Bearer Token necessity**:
   - Required for: Native apps (Passkey)
   - Not required for: Browser/SPA (even cross-origin same-site)
   - Pending: Native apps with OAuth2 (needs Custom URL Scheme support)

4. **Session storage**:
   - Single server: Memory OK
   - Multiple servers (LB): Redis required
   - This applies to ALL use cases (#1-5)

## Next Steps

1. **Create documentation**: Use case guide for SPA/browser authentication
   - Same-origin setup
   - Cross-origin same-site setup (Cookie + Domain + CORS)
   - Infrastructure notes (session storage sharing)

2. **Update issue**: Finalize 2026-01-23-bearer-token-support with conclusions

3. **Decision needed**: Whether to support #5 (Native OAuth2 with Custom URL Scheme)

## Context

### Cross-Origin vs Cross-Site

- **Same-Site**: eTLD+1 is the same (e.g., app.example.com and api.example.com)
- **Cross-Site**: Different eTLD+1 (e.g., example.com and another.com)
- SameSite=Lax works for Same-Site requests regardless of Cross-Origin

### Native App OAuth2 Challenge

In-App Browser cannot read HTTP response body/headers. Token must be passed via:
- Custom URL Scheme redirect: `myapp://callback?token=xxx`
- Or JavaScript redirect to Custom URL Scheme

### Library Scope Summary

| Feature | Scope |
|---------|-------|
| OAuth2/Passkey authentication | Core |
| Cookie session | Core |
| Bearer session maintenance | Supported |
| Cross-origin CORS | User configuration |
| Custom URL Scheme (OAuth2) | Not yet implemented |
| JWT issuance | Out of scope |

## Commits This Session

- `d2036ca` - docs(issues): add demo-api issue for Bearer token demonstration
- `e7a837d` - feat(demo): add demo-api for Bearer token authentication
