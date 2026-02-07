# Issue: Demo Site Deployment (Fly.io)

## ID: 2026-01-30-08

## Status: open

## Priority: low

## Description

Deploy demo applications to a public hosting platform for demonstration and testing purposes.

## Related Files

- `demo-both/` - Combined OAuth2 + Passkey demo
- `demo-oauth2/` - OAuth2-only demo
- `demo-passkey/` - Passkey-only demo
- `Dockerfile` (to be created)
- `fly.toml` (to be created)

## Notes

### Platform Comparison

| Platform | Features |
|----------|----------|
| **Fly.io** (recommended) | Docker-based, Tokyo region, no code changes needed |
| Shuttle.rs | Rust-specific, easy but requires code changes for their API |
| Cloud Run | Good if familiar with GCP, Terraform manageable |
| Railway | GitHub integration, auto-deploy |

### Environment Variables (Fly.io)

**Secrets** (via `fly secrets set`):
```bash
fly secrets set OAUTH2_GOOGLE_CLIENT_ID="xxx"
fly secrets set OAUTH2_GOOGLE_CLIENT_SECRET="yyy"
```

**Non-secrets** (in `fly.toml`):
```toml
[env]
RUST_LOG = "info"
APP_BASE_URL = "https://your-app.fly.dev"
```

### dotenvy Compatibility

```rust
dotenvy::dotenv().ok();  // Loads .env if exists, skips otherwise
let value = std::env::var("KEY")?;  // Works in both environments
```

| Environment | Behavior |
|-------------|----------|
| Local | dotenvy reads .env -> environment variables |
| Fly.io | fly.toml/secrets inject env vars, dotenvy does nothing |

**No code changes needed** - works in both environments.

### Google OAuth2 Notes

- **Authentication is free** (no charges)
- Test mode: max 100 test users
- Public access requires Google review (review is free)

### Auto-Deploy on dev Branch Update

**Goal**: dev ブランチへの push で自動的にデプロイされるようにする

**GitHub Actions + Fly.io**:
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
      - uses: superfly/flyctl-actions/setup-flyctl@master
      - run: flyctl deploy --remote-only
        env:
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
```

**Fly.io Token**:
1. `fly tokens create deploy` で deploy token を生成
2. GitHub リポジトリの Secrets に `FLY_API_TOKEN` として登録

### Implementation Tasks

- [ ] Create Dockerfile for demo apps
- [ ] Create fly.toml configuration
- [ ] Set up Fly.io account and app
- [ ] Configure Google OAuth2 redirect URIs for fly.dev domain
- [ ] Create GitHub Actions workflow for auto-deploy
- [ ] Add FLY_API_TOKEN to GitHub Secrets
- [ ] Deploy and verify functionality
- [ ] Document deployment process

### Reference

- https://fly.io/docs/rust/
- https://fly.io/docs/reference/secrets/
- https://fly.io/docs/app-guides/continuous-deployment-with-github-actions/

## Resolution

