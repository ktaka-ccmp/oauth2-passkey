# LINE Login Provider Setup

LINE Login runs through a Custom OIDC slot with `OAUTH2_CUSTOM{N}_PRESET=line`
— the preset supplies the display name, URL segment (`line`), icon, and
brand colors. Setting the preset is equivalent to configuring a bespoke
"LINE" provider; no code change is required.

LINE Login v2.1 is OIDC-compliant and works as a Custom slot. Two things
are unusual compared to other providers:

1. **HS256 signing** — LINE web login signs ID tokens with HS256 using the
   channel secret, not ES256/RS256 with JWKS. The JWT has no `kid` header.
   This is supported automatically (the library detects the algorithm and
   falls back to `client_secret` verification).
2. **Email requires approval** — the `email` claim is only returned after
   you apply for and receive "Email address permission" in the LINE
   Developer Console. Without it, login fails with a validation error
   because neither `email` nor `preferred_username` is present.

## Prerequisites

- A LINE Developer account ([developers.line.biz](https://developers.line.biz/console/))
- A running oauth2-passkey application

## Step 1: Create a LINE Login Channel

1. Go to the [LINE Developers Console](https://developers.line.biz/console/).
2. Create a **Provider** (or select an existing one).
3. Create a new channel: **LINE Login** type, **Web app** application type.
4. Under **LINE Login settings**, add the callback URL:
   `https://<ORIGIN>/o2p/oauth2/line/authorized`
   (e.g. `https://passkey-demo.ccmp.jp/o2p/oauth2/line/authorized`)

## Step 2: Apply for Email Address Permission

1. In the channel's **Basic settings** tab, scroll to **OpenID Connect →
   Email address permission**.
2. Click **Apply**, agree to the LINE User Data Policy.
3. Upload a screenshot of your app that shows how the email address will
   be used (e.g. the login page with a note like "Your email address from
   the identity provider is used solely for account identification").
4. Submit. Approval typically takes 1–2 business days. There is no
   explicit notification — the feature silently activates.

## Step 3: Configure Environment Variables

Add the following to your `.env` file. This example uses slot 1; any of
slots 1..8 works (each slot is independent).

```bash
OAUTH2_CUSTOM1_PRESET=line
OAUTH2_CUSTOM1_CLIENT_ID='<Channel ID>'
OAUTH2_CUSTOM1_CLIENT_SECRET='<Channel Secret>'
OAUTH2_CUSTOM1_ISSUER_URL='https://access.line.me'
OAUTH2_CUSTOM1_SCOPE='openid+profile+email'
```

The preset (`PRESET=line`) fills in defaults for `DISPLAY_NAME`, `NAME`
(which becomes the `line` URL segment), `ICON_SLUG`, and button colors.

The channel is in **Developing** status by default. Only users with
**Admin** or **Tester** roles on the channel can log in. Switch to
**Published** when ready for production.

## Step 4: Verify

Start your application and navigate to the login page. A **LINE** button
should appear alongside Google.

After logging in via LINE, verify the database row:

```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"

# SQLite
sqlite3 db/sqlite/data/data.db "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"
```

Expected output:

```
 provider |              provider_user_id              |      email
----------+--------------------------------------------+------------------
 line     | line_U96a1377920729556fba3747bb71e001d     | user@example.com
```

## Debugging

- **"Missing both `email` and `preferred_username`"** — email permission
  has not been approved yet. Check the channel's Basic settings for the
  current status.
- **"Missing key component: kid"** — you are running a library version
  older than v0.5.1 that does not support HS256 without `kid`. Upgrade.
- **Scope shows `profile openid` but not `email`** — this is normal LINE
  behavior. Even when email permission is granted, LINE does not list
  `email` in the token response's `scope` field. The email is present in
  the ID token claims regardless.

## Notes

- The `provider_user_id` format is `line_{sub}` where `sub` is LINE's
  internal user identifier (begins with `U`).
- LINE's OIDC discovery advertises ES256, but web login always returns
  HS256 — oauth2-passkey handles both transparently.
- See [Generic OIDC Provider Setup](./generic-oidc.md) for the full Custom
  slot reference, including how presets and env-var overrides compose.
