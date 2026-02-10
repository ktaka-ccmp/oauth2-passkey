# Issue: Demo Site Deployment (Cloud Run)

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 2026-01-30-08

## Created: 2026-01-30

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

Deploy demo applications to a public hosting platform for demonstration and testing purposes.

## Related Issues

- None

## Approach

### Platform: Google Cloud Run

| Platform | Free Tier | Always-On | DB/Cache | Code Changes |
|----------|-----------|-----------|----------|-------------|
| **Cloud Run** (selected) | 180k vCPU-sec, 2M req/mo | Yes (min-instances=1) | SQLite (ephemeral) + memory cache | None |
| Oracle Cloud | ARM 4CPU/24GB (permanent) | Yes | Self-managed (persistent) | None |
| Fly.io | None | N/A | N/A | None |
| Render | 750 hrs/mo | No (sleeps 15min) | DB expires 30 days | None |
| Railway | $5 credit/mo | Yes | Usage-based | None |

### Docker Image

Multi-stage build with `scratch` base image (27.7MB total):

- **Builder**: `rust:1.88-alpine` (musl libc for static linking)
- **Runtime**: `scratch` (no OS, no shell, just the binary)
- **TLS certificates**: Bundled at compile time via `webpki-roots` (no `ca-certificates` needed)
- **PORT**: Configurable via environment variable (Cloud Run sets `PORT=8080`)

### Configuration

**Secrets** (via `gcloud run services update --set-secrets`):
```bash
gcloud secrets create OAUTH2_GOOGLE_CLIENT_ID --data-file=-
gcloud secrets create OAUTH2_GOOGLE_CLIENT_SECRET --data-file=-
```

**Environment variables** (in Cloud Run service config):
```
RUST_LOG=info
ORIGIN=https://<service-name>-<hash>.run.app
DB_TYPE=sqlite
CACHE_TYPE=memory
```

### Storage Strategy

- **SQLite** (ephemeral): Data is lost on container restart, acceptable for demo
- **Memory cache**: No Redis needed, simplifies deployment
- Users can re-register passkeys as needed

### Google OAuth2 Notes

- Authentication is free (no charges)
- Test mode: max 100 test users
- Public access requires Google review (review is free)
- Redirect URI: `https://<service-name>-<hash>.run.app/o2p/oauth2/callback`

### Auto-Deploy on dev Branch Update

GitHub Actions + Cloud Run:
```yaml
# .github/workflows/deploy-demo.yml
name: Deploy Demo
on:
  push:
    branches: [dev]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - uses: google-github-actions/deploy-cloudrun@v2
        with:
          service: oauth2-passkey-demo
          source: .
```

### References

- https://cloud.google.com/run/docs
- https://cloud.google.com/run/pricing

## Related Files

- `Dockerfile` - Multi-stage build (rust:1.88-alpine -> scratch)
- `.dockerignore` - Excludes db/, target/, .git/, etc.
- `demo-both/` - Combined OAuth2 + Passkey demo
- `demo-both/src/main.rs` - PORT env var support
- `oauth2_passkey/src/oauth2/main/utils.rs` - `get_client()` with webpki-roots TLS
- `oauth2_passkey/src/oauth2/discovery.rs` - Uses shared `get_client()`
- `.github/workflows/deploy-demo.yml` (to be created)

## Implementation Tasks

### Docker Image (done)
- [x] Create Dockerfile for demo-both
- [x] Add `.dockerignore`
- [x] Add PORT environment variable support to demo-both
- [x] Remove unnecessary `ring` feature from `rustls`
- [x] Add `webpki-roots` for bundled Mozilla root certificates
- [x] Centralize reqwest Client creation with `use_preconfigured_tls()`
- [x] Migrate Dockerfile to `rust:1.88-alpine` + `scratch` (111MB -> 27.7MB)
- [x] Pass `cargo check`, `cargo clippy`, `cargo test`

### Deployment (pending)
- [ ] Verify Docker image runs correctly with `docker run`
- [ ] Set up GCP project and enable Cloud Run
- [ ] Configure secrets in Google Secret Manager
- [ ] Configure Google OAuth2 redirect URIs for run.app domain
- [ ] Deploy manually and verify functionality
- [ ] Create GitHub Actions workflow for auto-deploy
- [ ] Document deployment process

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-01-30: Initial platform selection

- Context: Need public hosting for demo applications
- Decision: Use Fly.io
- Reason: Docker-based (no code changes), Tokyo region available, straightforward
  deployment. Shuttle.rs requires API changes, Cloud Run/Railway are viable
  alternatives but Fly.io is simpler for this use case.

### 2026-02-10: Switch from Fly.io to Cloud Run

- Context: Fly.io no longer offers a free tier (only a 2-hour/7-day trial).
  Investigated 11 platforms: Fly.io, Render, Railway, Shuttle.rs, Koyeb, Zeabur,
  Google Cloud Run, Oracle Cloud, AWS, Azure, Hetzner.
- Decision: Use Google Cloud Run with SQLite + memory cache (no PostgreSQL/Redis)
- Reason: Free tier (180k vCPU-sec, 2M requests/month) is sufficient for a demo.
  No code changes needed. HTTPS and FQDN provided automatically. Data volatility
  is acceptable for a demo site. Oracle Cloud (ARM, $0/month permanent) is a
  viable fallback if persistent storage becomes necessary.

### 2026-02-10: TLS dependency cleanup for scratch Docker image

- Context: Initial Docker image was 111MB (debian:bookworm-slim 75MB + ca-certificates 9MB + binary 27MB).
  Investigated scratch/alpine/distroless alternatives.
- Decision: Bundle Mozilla root certificates via `webpki-roots` + `use_preconfigured_tls()`,
  remove unused `ring` feature from `rustls`, use `rust:1.88-alpine` builder + `scratch` runtime
- Reason: Eliminates runtime `ca-certificates` dependency, enables musl static linking,
  reduces image from 111MB to 27.7MB. reqwest 0.13 removed `rustls-tls-webpki-roots` feature
  flag, so code-level `use_preconfigured_tls()` API is required.

## Resolution
