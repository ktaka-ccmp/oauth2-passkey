# Demo-Live

Live demo application for [`oauth2-passkey-axum`](https://crates.io/crates/oauth2-passkey-axum), deployed at **https://passkey-demo.ccmp.jp**.

This directory contains the application code, custom templates, and all deployment configuration for the publicly hosted demo site on Google Cloud Run.

## What This Demo Provides

- Custom login page with Google OAuth2 and Passkey buttons
- Home page with navigation to My Account and Admin Panel
- Data masking in demo mode (`O2P_DEMO_MODE`) to protect user information
- Ephemeral storage (in-memory SQLite + in-memory cache) -- data resets on container restart

## Directory Structure

```text
demo-live/
├── src/
│   ├── main.rs              # App entry point, custom login/index handlers
│   └── server.rs            # HTTP server configuration
├── templates/               # Custom Askama templates
│   ├── index.j2            # Home page (welcome + navigation cards)
│   └── login.j2            # Login page (Google OAuth2 + Passkey buttons)
├── Cargo.toml              # Dependencies, bundled-tls feature for static linking
├── Dockerfile              # Multi-stage build: rust:1.88-alpine -> scratch
├── docker-compose.yml      # Local Docker testing (reads ../.env)
├── cloudbuild.yaml         # Google Cloud Build image config
├── env.cloud-run.yaml      # Cloud Run environment variables
├── DEPLOY.md               # Full deployment guide (GCP setup, secrets, domain)
├── DOCKER_NOTES.md         # Docker design decisions and troubleshooting
└── README.md               # This file
```

## CI/CD Pipeline

Pushing to the `dev` branch automatically deploys via GitHub Actions (`.github/workflows/deploy-demo.yml`):

1. **GitHub Actions** authenticates to GCP with a service account key
2. **Cloud Build** builds a Docker image per `cloudbuild.yaml` and pushes to **Artifact Registry**
3. **Cloud Run** deploys the image with environment variables from `env.cloud-run.yaml` and secrets from **Secret Manager**

Trigger paths: `oauth2_passkey/**`, `oauth2_passkey_axum/**`, `demo-live/**`, `.github/workflows/deploy-demo.yml`

## Build Details

The Docker build produces a fully static binary with no runtime dependencies:

- **Builder stage**: `rust:1.88-alpine` with musl libc for static linking
- **`bundled-tls` feature**: Compiles TLS certificates into the binary via `webpki-roots` (no `ca-certificates` package needed at runtime)
- **Runtime stage**: `FROM scratch` -- no OS, no shell, no libc (~28 MB total image)

See [DOCKER_NOTES.md](DOCKER_NOTES.md) for design decisions, image size breakdown, and known issues.

## Local Development

### Run with cargo

```bash
cp ../dot.env.simple .env
# Edit .env with your Google OAuth2 credentials
cargo run
# Access at http://localhost:3001
```

### Run with Docker

```bash
# From repository root (reads ../.env for OAuth2 credentials)
docker compose -f demo-live/docker-compose.yml up --build

# Access at http://localhost:3001

# Force full rebuild if cache is stale
docker compose -f demo-live/docker-compose.yml build --no-cache
```

## Demo-Specific Configuration

The following environment variables are set differently from a typical deployment. See `env.cloud-run.yaml` for the full list.

### Demo mode

| Variable | Value | Purpose |
|----------|-------|---------|
| `O2P_DEMO_MODE` | `true` | All new users get admin privileges, admin pages mask other users' sensitive data, and a placeholder user occupies seq=1 so no real user gets first-user treatment |
| `O2P_LOGIN_URL` | `/login` | Redirects unauthenticated users to the custom login page instead of the library default |

### Session

| Variable | Value | Purpose |
|----------|-------|---------|
| `SESSION_COOKIE_NAME` | `__Host-SessionId` | `__Host-` prefix enforces HTTPS-only, no Domain, Path=/ (browser security) |
| `SESSION_COOKIE_MAX_AGE` | `600` | 10-minute session lifetime (short for demo; default is longer) |
| `SESSION_CONFLICT_POLICY` | `allow` | Allows concurrent sessions from multiple devices |

### Passkey

| Variable | Value | Purpose |
|----------|-------|---------|
| `O2P_PASSKEY_PROMOTION` | `force` | Always prompts passkey registration after OAuth2 login |
| `PASSKEY_AUTHENTICATOR_ATTACHMENT` | `platform` | Only allows platform authenticators (fingerprint, Face ID, Windows Hello) |
| `PASSKEY_USER_VERIFICATION` | `discouraged` | Skips biometric prompt for faster UX |
| `PASSKEY_REQUIRE_RESIDENT_KEY` | `true` | Requires discoverable credentials (usernameless login) |

### Storage (ephemeral)

| Variable | Value | Purpose |
|----------|-------|---------|
| `GENERIC_DATA_STORE_TYPE` | `sqlite` | SQLite for simplicity (no external DB) |
| `GENERIC_DATA_STORE_URL` | `sqlite:file:memdb1?mode=memory&cache=shared` | In-memory database; all data lost on restart |
| `GENERIC_CACHE_STORE_TYPE` | `memory` | In-memory cache; no Redis dependency |

### Build feature

| Feature | Purpose |
|---------|---------|
| `bundled-tls` | Required for `scratch` container. Bundles Mozilla root certificates via `webpki-roots` so HTTPS calls (Google OAuth2, JWKS) work without system `ca-certificates`. |

## Related Documentation

- [DEPLOY.md](DEPLOY.md) -- Step-by-step GCP setup, secret management, custom domain, manual deployment
- [DOCKER_NOTES.md](DOCKER_NOTES.md) -- Base image selection, TLS architecture, in-memory backend stability
- [dot.env.example](../dot.env.example) -- All available configuration options
