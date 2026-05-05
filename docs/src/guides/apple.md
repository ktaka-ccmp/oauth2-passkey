# Sign in with Apple Provider Setup

Sign in with Apple runs through a Custom OIDC slot with
`OAUTH2_CUSTOM{N}_PRESET=apple` — the preset supplies the display name,
URL segment (`apple`), icon, and brand colors.

Unlike other providers, Apple uses a **dynamic `client_secret`** — a
short-lived JWT signed with an ES256 private key (P8 file) from Apple
Developer. This library treats `CLIENT_SECRET` as a static string, so
**you must pre-generate the JWT externally** and pass it as an env var.
The JWT can be valid for up to 6 months; regenerate it periodically.

> **Status: unverified.** This configuration has not been E2E tested
> because verification requires an Apple Developer Program subscription
> ($99/year). The mechanism is straightforward (standard OIDC + a
> pre-generated JWT for `CLIENT_SECRET`), but if you verify it, please
> [open an issue or PR](https://github.com/ktaka-ccmp/oauth2-passkey/issues)
> with the result. Tracked in issue `20260420-1457`.

## Prerequisites

- Apple Developer Program membership ($99/year)
- A "Sign in with Apple" Service ID configured in the Apple Developer
  portal
- A private key (P8 file) downloaded from the **Keys** section
- A running oauth2-passkey application

## Step 1: Apple Developer Portal Setup

1. In the [Apple Developer Portal](https://developer.apple.com/account/),
   create or select an **App ID** with the **Sign in with Apple**
   capability enabled.
2. Create a **Service ID** under **Identifiers**:
   - Identifier (e.g. `com.example.app.web`) — this becomes your
     `CLIENT_ID`.
   - Enable **Sign in with Apple** and configure the **Return URLs**:
     `https://<ORIGIN>/o2p/oauth2/apple/authorized`
   - Apple requires HTTPS for production return URLs; localhost over
     HTTP is not accepted by Apple's consent flow.
3. Create a **Key** under **Keys**:
   - Enable **Sign in with Apple**
   - Download the P8 file once (Apple does not show it again)
   - Note the **Key ID** (10 chars) and your **Team ID** (top-right of
     the developer portal)

## Step 2: Generate the client_secret JWT

The JWT is valid for up to 6 months. Generate it with any JWT library;
this Python example uses `pyjwt`:

```python
import jwt, time

token = jwt.encode(
    {
        "iss": "<Team ID>",
        "sub": "<Service ID (client_id)>",
        "aud": "https://appleid.apple.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + 86400 * 180,  # 6 months
    },
    open("AuthKey_<Key ID>.p8").read(),
    algorithm="ES256",
    headers={"kid": "<Key ID>"},
)
print(token)
```

Regenerate before expiry (cron job or CI pipeline). For Cloud Run / k8s
deployments this can be automated at deploy time.

## Step 3: Configure Environment Variables

Add the following to your `.env` file. This example uses slot 1; any of
slots 1..8 works (each slot is independent).

```bash
OAUTH2_CUSTOM1_PRESET=apple
OAUTH2_CUSTOM1_CLIENT_ID='<Service ID>'
OAUTH2_CUSTOM1_CLIENT_SECRET='<pre-generated ES256 JWT>'
OAUTH2_CUSTOM1_ISSUER_URL='https://appleid.apple.com'
OAUTH2_CUSTOM1_SCOPE='openid+email+name'
```

The preset (`PRESET=apple`) fills in defaults for `DISPLAY_NAME`, `NAME`
(which becomes the `apple` URL segment), `ICON_SLUG`, and button colors.

## Step 4: Verify

Start your application and navigate to the login page. A **Sign in with
Apple** button should appear alongside Google.

After logging in via Apple, verify the database row:

```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"

# SQLite
sqlite3 db/sqlite/data/data.db "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"
```

## Notes

- **`name` only on first authorization** — Apple returns the user's name
  only the first time they authorize the app. If the user is deleted from
  the application but does not revoke access in Apple ID settings,
  re-registration will succeed (email is always in the ID token) but
  `name` will be empty. Workaround: user revokes the app in
  Settings → Apple ID → Sign in with Apple first.
- **Private email relay** — users who choose "Hide My Email" get a
  `@privaterelay.appleid.com` address. This works as-is for account
  identification. Sending emails to relay addresses requires registering
  outbound domains with SPF/DKIM in the Apple Developer Console, but
  oauth2-passkey itself does not send emails so this is only relevant to
  the consuming application.
- **Secret rotation** — the `client_secret` JWT must be regenerated before
  its `exp` (max 6 months). Plan a rotation cadence.
- **Status: unverified.** See note at the top of this page.
- See [Generic OIDC Provider Setup](./generic-oidc.md) for the full Custom
  slot reference, including how presets and env-var overrides compose.
