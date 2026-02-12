# Demo Deployment Guide

This guide covers local Docker testing and Google Cloud Run deployment for the `demo-both` application (OAuth2 + Passkey authentication demo).

## Docker Image

Multi-stage build with `scratch` base image (27.7 MB total):

| Stage | Image | Purpose |
|-------|-------|---------|
| Builder | `rust:1.88-alpine` | Static linking with musl libc |
| Runtime | `scratch` | No OS, no shell, just the binary |

TLS certificates are bundled at compile time via `webpki-roots` (`bundled-tls` feature), so no `ca-certificates` package is needed at runtime.

## Local Testing

```bash
# Build and run (from repository root)
docker compose -f demo-both/docker-compose.yml up --build

# Access at http://localhost:3001
```

The `docker-compose.yml` reads `.env` from the repository root and overrides container-specific values (PORT, ORIGIN, storage config).

To force a full rebuild (if cache is stale):
```bash
docker compose -f demo-both/docker-compose.yml build --no-cache
docker compose -f demo-both/docker-compose.yml up
```

## Cloud Run Deployment

### Prerequisites

- Google Cloud CLI (`gcloud`) installed and authenticated
- A GCP project (or create one in Step 1)
- Google OAuth2 credentials (Client ID + Secret)

### Storage Strategy

- **SQLite** (in-memory, ephemeral): Data is lost on container restart, acceptable for demo
- **Memory cache**: No Redis needed, simplifies deployment
- Users can re-register passkeys as needed

### Step 1: Create GCP project and enable APIs

```bash
# Create project (or use existing one)
gcloud projects create $PROJECT_ID --name="OAuth2 Passkey Demo"
gcloud config set project $PROJECT_ID

# Enable required APIs
gcloud services enable run.googleapis.com
gcloud services enable artifactregistry.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

### Step 2: Create Google OAuth2 credentials

1. Open Google Cloud Console > APIs & Services > Credentials
2. Click "Create Credentials" > "OAuth client ID"
3. Application type: "Web application"
4. Name: e.g. "oauth2-passkey-demo"
5. Authorized redirect URIs: `http://localhost:3001/o2p/oauth2/authorized` (placeholder)
6. Save the **Client ID** and **Client Secret**

Note: The Cloud Run redirect URI will be added in Step 6 after deployment.

### Step 3: Store secrets in Secret Manager

```bash
# Create secrets (first time only)
echo -n "$OAUTH2_GOOGLE_CLIENT_ID" | gcloud secrets create OAUTH2_GOOGLE_CLIENT_ID --data-file=-
echo -n "$OAUTH2_GOOGLE_CLIENT_SECRET" | gcloud secrets create OAUTH2_GOOGLE_CLIENT_SECRET --data-file=-
openssl rand -base64 32 | gcloud secrets create AUTH_SERVER_SECRET --data-file=-

# Update secrets (add a new version to existing secrets)
echo -n "$OAUTH2_GOOGLE_CLIENT_ID" | gcloud secrets versions add OAUTH2_GOOGLE_CLIENT_ID --data-file=-
echo -n "$OAUTH2_GOOGLE_CLIENT_SECRET" | gcloud secrets versions add OAUTH2_GOOGLE_CLIENT_SECRET --data-file=-
openssl rand -base64 32 | gcloud secrets versions add AUTH_SERVER_SECRET --data-file=-

# Grant Cloud Run's default service account access to secrets
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### Step 4: Build and push Docker image

```bash
# Create Artifact Registry repository (first time only)
gcloud artifacts repositories create demo \
  --repository-format=docker \
  --location=asia-northeast1

# Build and push using Cloud Build
gcloud builds submit --config=demo-both/cloudbuild.yaml
```

`demo-both/cloudbuild.yaml` specifies `demo-both/Dockerfile` and the image tag (using `$PROJECT_ID` built-in variable).

Alternatively, build locally and push:
```bash
docker build -f demo-both/Dockerfile \
  -t asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo .
docker push asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo
```

### Step 5: Deploy to Cloud Run

```bash
# Deploy with env vars from file + secrets
# (--env-vars-file and --update-env-vars are mutually exclusive)
gcloud run deploy oauth2-passkey-demo \
  --image asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo \
  --region asia-northeast1 \
  --port 8080 \
  --allow-unauthenticated \
  --min-instances 1 \
  --env-vars-file demo-both/env.cloud-run.yaml \
  --set-secrets "OAUTH2_GOOGLE_CLIENT_ID=OAUTH2_GOOGLE_CLIENT_ID:latest,OAUTH2_GOOGLE_CLIENT_SECRET=OAUTH2_GOOGLE_CLIENT_SECRET:latest,AUTH_SERVER_SECRET=AUTH_SERVER_SECRET:latest"

# Set ORIGIN separately (placeholder for first deploy; Step 6 updates to actual URL)
gcloud run services update oauth2-passkey-demo \
  --region asia-northeast1 \
  --update-env-vars "ORIGIN=https://placeholder.example.com"
```

Note: `--env-vars-file` and `--update-env-vars` cannot be combined in one command.
Environment variables are managed in `env.cloud-run.yaml`, and `ORIGIN` is set
separately because it is deployment-specific.

### Step 6: Configure ORIGIN and OAuth2 redirect URI

```bash
# Get the Cloud Run service URL
SERVICE_URL=$(gcloud run services describe oauth2-passkey-demo \
  --region asia-northeast1 --format='value(status.url)')
echo "Service URL: $SERVICE_URL"

# Update ORIGIN to the actual Cloud Run URL
gcloud run services update oauth2-passkey-demo \
  --region asia-northeast1 \
  --update-env-vars "ORIGIN=$SERVICE_URL"
```

Then add the redirect URI in Google Cloud Console:
1. APIs & Services > Credentials > edit the OAuth client
2. Add authorized redirect URI: `$SERVICE_URL/o2p/oauth2/authorized`

### Step 7: Verify functionality

1. Access `$SERVICE_URL` in browser
2. Test OAuth2 login (Google)
3. Test Passkey registration and authentication
4. Wait 10+ minutes, test OAuth2 login again (JWKS cache refresh)

## Custom Domain (Optional)

Map a custom domain to the Cloud Run service (free, includes managed SSL):

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

Then update ORIGIN and OAuth2 redirect URI:
```bash
gcloud run services update oauth2-passkey-demo \
  --region asia-northeast1 \
  --update-env-vars "ORIGIN=https://passkey-demo.ccmp.jp"
```

Add `https://passkey-demo.ccmp.jp/o2p/oauth2/authorized` as an authorized redirect URI
in Google Cloud Console. SSL certificate is provisioned automatically (10-20 min).

Note: `gcloud run domain-mappings create` (without `beta`) is for Cloud Run for Anthos only.

## Redeployment

After code changes, rebuild and redeploy:

```bash
# Rebuild image
gcloud builds submit --config=demo-both/cloudbuild.yaml

# Redeploy (env vars and secrets are preserved)
gcloud run deploy oauth2-passkey-demo \
  --image asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo \
  --region asia-northeast1

# If env vars changed, update them separately:
gcloud run services update oauth2-passkey-demo \
  --region asia-northeast1 \
  --env-vars-file demo-both/env.cloud-run.yaml
```

## Google OAuth2 Notes

- Authentication is free (no charges)
- Test mode: max 100 test users (only added test users can log in)
- Public access requires Google verification review (review is free)
- Redirect URI format: `https://<service-name>-<hash>.run.app/o2p/oauth2/authorized`

## Related Files

| File | Description |
|------|-------------|
| `Dockerfile` | Multi-stage build (rust:1.88-alpine -> scratch) |
| `docker-compose.yml` | Local testing with env_file support |
| `env.cloud-run.yaml` | Cloud Run environment variables |
| `cloudbuild.yaml` | Cloud Build config (image tag, Dockerfile path) |
| `../.dockerignore` | Excludes db/, target/, .git/, etc. |
| `../.gcloudignore` | Excludes files from Cloud Build upload |
