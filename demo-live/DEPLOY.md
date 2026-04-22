# Demo Deployment Guide

This guide covers local Docker testing and Google Cloud Run deployment for the `demo-live` application (OAuth2 + Passkey authentication demo) at `https://passkey-demo.ccmp.jp`.

## Docker Image

Multi-stage build with `scratch` base image (27.7 MB total):

| Stage | Image | Purpose |
|-------|-------|---------|
| Builder | `rust:1.88-alpine` | Static linking with musl libc |
| Runtime | `scratch` | No OS, no shell, just the binary |

TLS certificates are bundled at compile time via `webpki-roots` (`bundled-tls` feature), so no `ca-certificates` package is needed at runtime.

For design decisions, trade-offs, and troubleshooting details, see [DOCKER_NOTES.md](DOCKER_NOTES.md).

## Local Testing

```bash
# Build and run (from repository root)
docker compose -f demo-live/docker-compose.yml up --build

# Access at http://localhost:3001
```

The `docker-compose.yml` reads `.env` from the repository root and overrides container-specific values (PORT, ORIGIN, storage config).

To force a full rebuild (if cache is stale):
```bash
docker compose -f demo-live/docker-compose.yml build --no-cache
docker compose -f demo-live/docker-compose.yml up
```

## Cloud Run Deployment

### Prerequisites

- Google Cloud CLI (`gcloud`) installed and authenticated
- A GCP project (or create one in Step 1)
- Google OAuth2 credentials (Client ID + Secret)
- Custom domain `passkey-demo.ccmp.jp` with DNS access

### Storage Strategy

- **SQLite** (in-memory, ephemeral): Data is lost on container restart, acceptable for demo
- **Memory cache**: No Redis needed, simplifies deployment
- Users can re-register passkeys as needed

### Step 1: Create GCP project and enable APIs

```bash
export PROJECT_ID="your-gcp-project-id"

# Create project (or use existing one)
gcloud projects create $PROJECT_ID --name="OAuth2 Passkey Demo"
gcloud config set project $PROJECT_ID

# Link a billing account (required before enabling APIs)
gcloud billing accounts list
export BILLING_ACCOUNT_ID="your-billing-account-id"
gcloud billing projects link $PROJECT_ID --billing-account=$BILLING_ACCOUNT_ID

# Enable required APIs
gcloud services enable run.googleapis.com
gcloud services enable artifactregistry.googleapis.com
gcloud services enable secretmanager.googleapis.com
# gcloud services enable cloudbuild.googleapis.com  # No longer needed (using GitHub Actions BuildKit)
```

### Step 2: Create Google OAuth2 credentials

1. Open Google Cloud Console > APIs & Services > Credentials
2. Click "Create Credentials" > "OAuth client ID"
3. Application type: "Web application"
4. Name: e.g. "oauth2-passkey-demo"
5. Authorized redirect URIs:
   - `http://localhost:3001/o2p/oauth2/google/authorized` (local development)
   - `https://passkey-demo.ccmp.jp/o2p/oauth2/google/authorized` (production)
6. Save the **Client ID** and **Client Secret**

```bash
export OAUTH2_GOOGLE_CLIENT_ID="your-client-id"
export OAUTH2_GOOGLE_CLIENT_SECRET="your-client-secret"
```

### Step 2a: Create Auth0 credentials (optional)

Auth0 runs as Custom slot 1 with `PRESET=auth0`. Skip this step if you only need Google login.

1. Log in to [Auth0 Dashboard](https://manage.auth0.com/)
2. Applications > Create Application
3. Application type: "Regular Web Application"
4. Allowed Callback URLs:
   - `http://localhost:3001/o2p/oauth2/auth0/authorized` (local development)
   - `https://passkey-demo.ccmp.jp/o2p/oauth2/auth0/authorized` (production)
5. Allowed Logout URLs: `https://passkey-demo.ccmp.jp/`
6. Save the **Domain**, **Client ID**, and **Client Secret**

```bash
export OAUTH2_CUSTOM1_CLIENT_ID="your-auth0-client-id"
export OAUTH2_CUSTOM1_CLIENT_SECRET="your-auth0-client-secret"
export OAUTH2_CUSTOM1_ISSUER_URL="https://your-tenant.auth0.com"  # no trailing slash
# PRESET=auth0 supplies DISPLAY_NAME / NAME / ICON_SLUG / colors; set in env.cloud-run.yaml.
```

For local development, see `dot.env.example` for the full Custom slot shape.

### Step 2b: Create Microsoft Entra ID credentials (optional)

Entra runs as Custom slot 2 with `PRESET=entra`. Skip this step if you don't need Microsoft login.
Full background (B2B vs B2C, consumers UUID, email claim handling) is in
[docs/src/guides/entra.md](../docs/src/guides/entra.md); the condensed deploy-time
steps are:

1. Open the [Azure Portal](https://portal.azure.com/) > Microsoft Entra ID > App registrations > New registration
2. Supported account types: choose "Single tenant" (B2B) or "Personal Microsoft accounts only" (B2C)
3. Authentication > Add a platform > Web > Redirect URIs:
   - `http://localhost:3001/o2p/oauth2/entra/authorized` (local development)
   - `https://passkey-demo.ccmp.jp/o2p/oauth2/entra/authorized` (production)
4. Certificates & secrets > New client secret — copy the **Value** immediately (not shown again)
5. (B2B only) Token configuration > Add optional claim > Token type: ID > check **email**
6. Save the **Application (client) ID**, **client secret Value**, and build the issuer URL:

```bash
export OAUTH2_CUSTOM2_CLIENT_ID="your-application-client-id"
export OAUTH2_CUSTOM2_CLIENT_SECRET="your-client-secret-value"
# Work/school (B2B): use your tenant ID
export OAUTH2_CUSTOM2_ISSUER_URL="https://login.microsoftonline.com/<tenant-id>/v2.0"
# Personal MS accounts (B2C): use Microsoft's fixed consumer tenant UUID
# export OAUTH2_CUSTOM2_ISSUER_URL="https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
# PRESET=entra supplies DISPLAY_NAME / NAME / ICON_SLUG / colors / login.live.com origin.
```

The `/v2.0` suffix is required — the v1 endpoint uses a different issuer format
(`sts.windows.net`) that will fail issuer validation. The `common` and
`organizations` aliases are also not supported.

### Step 3: Store secrets in Secret Manager

```bash
# Create secrets (first time only)
echo -n "$OAUTH2_GOOGLE_CLIENT_ID" | gcloud secrets create OAUTH2_GOOGLE_CLIENT_ID --data-file=-
echo -n "$OAUTH2_GOOGLE_CLIENT_SECRET" | gcloud secrets create OAUTH2_GOOGLE_CLIENT_SECRET --data-file=-
openssl rand -base64 32 | gcloud secrets create AUTH_SERVER_SECRET --data-file=-

# Auth0 secrets (first time only, if using Auth0 via CUSTOM1 slot)
echo -n "$OAUTH2_CUSTOM1_CLIENT_ID" | gcloud secrets create OAUTH2_CUSTOM1_CLIENT_ID --data-file=-
echo -n "$OAUTH2_CUSTOM1_CLIENT_SECRET" | gcloud secrets create OAUTH2_CUSTOM1_CLIENT_SECRET --data-file=-

# Entra secrets (first time only, if using Entra via CUSTOM2 slot)
echo -n "$OAUTH2_CUSTOM2_CLIENT_ID" | gcloud secrets create OAUTH2_CUSTOM2_CLIENT_ID --data-file=-
echo -n "$OAUTH2_CUSTOM2_CLIENT_SECRET" | gcloud secrets create OAUTH2_CUSTOM2_CLIENT_SECRET --data-file=-

# Update secrets (add a new version to existing secrets)
echo -n "$OAUTH2_GOOGLE_CLIENT_ID" | gcloud secrets versions add OAUTH2_GOOGLE_CLIENT_ID --data-file=-
echo -n "$OAUTH2_GOOGLE_CLIENT_SECRET" | gcloud secrets versions add OAUTH2_GOOGLE_CLIENT_SECRET --data-file=-
openssl rand -base64 32 | gcloud secrets versions add AUTH_SERVER_SECRET --data-file=-

# Auth0 secret rotation (CUSTOM1 slot)
echo -n "$OAUTH2_CUSTOM1_CLIENT_ID" | gcloud secrets versions add OAUTH2_CUSTOM1_CLIENT_ID --data-file=-
echo -n "$OAUTH2_CUSTOM1_CLIENT_SECRET" | gcloud secrets versions add OAUTH2_CUSTOM1_CLIENT_SECRET --data-file=-

# Entra secret rotation (CUSTOM2 slot; Azure client secrets expire; max 24 months)
echo -n "$OAUTH2_CUSTOM2_CLIENT_ID" | gcloud secrets versions add OAUTH2_CUSTOM2_CLIENT_ID --data-file=-
echo -n "$OAUTH2_CUSTOM2_CLIENT_SECRET" | gcloud secrets versions add OAUTH2_CUSTOM2_CLIENT_SECRET --data-file=-

# Grant Cloud Run's default service account access to secrets
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

`OAUTH2_CUSTOM1_ISSUER_URL` / `OAUTH2_CUSTOM2_ISSUER_URL` and the `_PRESET`
keys are not secrets — add them to `env.cloud-run.yaml` instead (see Step 5).

### Step 4: Build and push Docker image

```bash
# Create Artifact Registry repository (first time only)
gcloud artifacts repositories create demo \
  --repository-format=docker \
  --location=asia-northeast1

# Build and push manually (normally handled by GitHub Actions auto-deploy)
docker build -f demo-live/Dockerfile \
  -t asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo .
docker push asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo
```

The Dockerfile uses cargo-chef for dependency caching. See the Dockerfile for the multi-stage build structure.

### Step 5: Deploy to Cloud Run

```bash
gcloud run deploy oauth2-passkey-demo \
  --image asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo \
  --region asia-northeast1 \
  --port 8080 \
  --allow-unauthenticated \
  --min-instances 1 \
  --env-vars-file demo-live/env.cloud-run.yaml \
  --set-secrets "OAUTH2_GOOGLE_CLIENT_ID=OAUTH2_GOOGLE_CLIENT_ID:latest,OAUTH2_GOOGLE_CLIENT_SECRET=OAUTH2_GOOGLE_CLIENT_SECRET:latest,AUTH_SERVER_SECRET=AUTH_SERVER_SECRET:latest,OAUTH2_CUSTOM1_CLIENT_ID=OAUTH2_CUSTOM1_CLIENT_ID:latest,OAUTH2_CUSTOM1_CLIENT_SECRET=OAUTH2_CUSTOM1_CLIENT_SECRET:latest,OAUTH2_CUSTOM2_CLIENT_ID=OAUTH2_CUSTOM2_CLIENT_ID:latest,OAUTH2_CUSTOM2_CLIENT_SECRET=OAUTH2_CUSTOM2_CLIENT_SECRET:latest"
```

All environment variables including `ORIGIN` are managed in `env.cloud-run.yaml`.
For Auth0, `env.cloud-run.yaml` sets `OAUTH2_CUSTOM1_PRESET=auth0` and
`OAUTH2_CUSTOM1_ISSUER_URL` (and optionally `_RESPONSE_MODE`, `_SCOPE`). If
Auth0 is not used, omit the `OAUTH2_CUSTOM1_*` entries from `--set-secrets`
and remove the corresponding keys from `env.cloud-run.yaml`.

For Entra, `env.cloud-run.yaml` sets `OAUTH2_CUSTOM2_PRESET=entra` and
`OAUTH2_CUSTOM2_ISSUER_URL` (and optionally `_RESPONSE_MODE`, `_SCOPE`). If
Entra is not used, omit the `OAUTH2_CUSTOM2_*` entries from `--set-secrets`
and remove the corresponding keys from `env.cloud-run.yaml`.

### Step 6: Configure custom domain

Map the custom domain to the Cloud Run service (free, includes managed SSL):

```bash
# Create domain mapping (requires gcloud beta)
gcloud beta run domain-mappings create \
  --service oauth2-passkey-demo \
  --domain passkey-demo.ccmp.jp \
  --region asia-northeast1
```

Add a CNAME record in your DNS:
```
passkey-demo.ccmp.jp.  CNAME  ghs.googlehosted.com.
```

SSL certificate is provisioned automatically (10-20 min).

Note: `gcloud run domain-mappings create` (without `beta`) is for Cloud Run for Anthos only.

### Step 7: Verify functionality

1. Access `https://passkey-demo.ccmp.jp` in browser
2. Test OAuth2 login (Google)
3. Test Passkey registration and authentication
4. Wait 10+ minutes, test OAuth2 login again (JWKS cache refresh)

## Auto-Deploy (GitHub Actions)

Pushes to the trigger branch (currently `dev`) that change relevant files automatically build and deploy to Cloud Run. The trigger branch is configured in `.github/workflows/deploy-demo.yml`.

### Trigger paths

- `oauth2_passkey/**`, `oauth2_passkey_axum/**` - library changes
- `demo-live/**` - demo app changes
- `.github/workflows/deploy-demo.yml` - workflow changes

### GCP setup (one-time)

```bash
# 1. Create service account
gcloud iam service-accounts create github-actions-deploy \
  --display-name="GitHub Actions Deploy"

SA_EMAIL="github-actions-deploy@${PROJECT_ID}.iam.gserviceaccount.com"

# 2. Grant roles
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/run.admin"
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/iam.serviceAccountUser"
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/artifactregistry.writer"

# 3. Generate JSON key
gcloud iam service-accounts keys create sa-key.json \
  --iam-account=$SA_EMAIL
```

### GitHub repository secrets (one-time)

1. GitHub repository page > Settings > Secrets and variables > Actions
2. "New repository secret" for each:

| Name | Value |
|------|-------|
| `GCP_SA_KEY` | Contents of `sa-key.json` |
| `GCP_PROJECT_ID` | Your GCP project ID |

3. Delete the local key file:
```bash
rm sa-key.json
```

### Workflow

See `.github/workflows/deploy-demo.yml`. On each push to the trigger branch:
1. Authenticates to GCP with service account key
2. Builds and pushes Docker image via BuildKit with cargo-chef dependency caching (`type=gha` cache)
3. Full deploy to Cloud Run: image, env vars (`env.cloud-run.yaml`), and secrets

This ensures environment variable changes in `env.cloud-run.yaml` are automatically applied on every deploy.

## Manual Redeployment

To rebuild and redeploy manually (equivalent to what GitHub Actions does):

```bash
# Rebuild and push image
docker build -f demo-live/Dockerfile \
  -t asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo .
docker push asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo

# Full deploy (image + env vars + secrets)
gcloud run deploy oauth2-passkey-demo \
  --image asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo \
  --region asia-northeast1 \
  --port 8080 \
  --allow-unauthenticated \
  --min-instances 1 \
  --env-vars-file demo-live/env.cloud-run.yaml \
  --set-secrets "OAUTH2_GOOGLE_CLIENT_ID=OAUTH2_GOOGLE_CLIENT_ID:latest,OAUTH2_GOOGLE_CLIENT_SECRET=OAUTH2_GOOGLE_CLIENT_SECRET:latest,AUTH_SERVER_SECRET=AUTH_SERVER_SECRET:latest,OAUTH2_CUSTOM1_CLIENT_ID=OAUTH2_CUSTOM1_CLIENT_ID:latest,OAUTH2_CUSTOM1_CLIENT_SECRET=OAUTH2_CUSTOM1_CLIENT_SECRET:latest,OAUTH2_CUSTOM2_CLIENT_ID=OAUTH2_CUSTOM2_CLIENT_ID:latest,OAUTH2_CUSTOM2_CLIENT_SECRET=OAUTH2_CUSTOM2_CLIENT_SECRET:latest"
```

To update only environment variables (without rebuilding the image):

```bash
gcloud run services update oauth2-passkey-demo \
  --region asia-northeast1 \
  --env-vars-file demo-live/env.cloud-run.yaml
```

Note: `--env-vars-file` replaces all env vars. To update individual keys without affecting others, use `--update-env-vars "KEY=value"` instead.

## Google OAuth2 Notes

- Authentication is free (no charges)
- Test mode: max 100 test users (only added test users can log in)
- Public access requires Google verification review (review is free)
- Redirect URI: `https://passkey-demo.ccmp.jp/o2p/oauth2/google/authorized`

## Related Files

| File | Description |
|------|-------------|
| `Dockerfile` | Multi-stage build with cargo-chef (rust:1.88-alpine -> scratch) |
| `docker-compose.yml` | Local testing with env_file support |
| `env.cloud-run.yaml` | Cloud Run environment variables |
| `../.dockerignore` | Excludes db/, target/, .git/, etc. |
| `../.github/workflows/deploy-demo.yml` | GitHub Actions auto-deploy workflow |
