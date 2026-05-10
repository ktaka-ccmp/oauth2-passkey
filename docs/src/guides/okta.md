# Okta Provider Setup

Okta runs through a Custom OIDC slot with `OAUTH2_CUSTOM{N}_PRESET=okta`
— the preset supplies the display name, URL segment (`okta`), icon, and
brand colors. Setting the preset is equivalent to configuring a bespoke
"Okta" provider; no code change is required.

Okta's Developer tenant is free and its OIDC defaults are
standards-compliant, but the setup is split across **two layers of
policies** that both need to be configured. Most first-time setups stall
on the second layer; walk through the steps in order.

## Prerequisites

- An Okta Developer Edition tenant (sign up at
  [developer.okta.com](https://developer.okta.com) — free)
- A running oauth2-passkey application

## Step 1: Tenant and Application

1. Sign up at [developer.okta.com](https://developer.okta.com). Your admin
   URL is `https://<tenant>-admin.okta.com`; the public OIDC host (used
   for discovery and redirects) is `https://<tenant>.okta.com`.
2. Admin console → **Applications → Create App Integration**.
   - **Sign-in method**: `OIDC - OpenID Connect`
   - **Application type**: `Web Application`
   - **Grant type**: `Authorization Code`
   - **Sign-in redirect URIs**: exactly
     `http://localhost:3001/o2p/oauth2/okta/authorized`
     (replace `http://localhost:3001` with your `ORIGIN`)
   - **Controlled access**: pick **Allow everyone in your organization**
     for fastest setup.

Copy **Client ID** and **Client Secret**.

## Step 2: Record the Issuer URL

```bash
curl -s https://<tenant>.okta.com/oauth2/default/.well-known/openid-configuration | jq .issuer
# -> "https://<tenant>.okta.com/oauth2/default"
```

Use the exact string it returns (including / excluding trailing slash) for
`OAUTH2_CUSTOM{N}_ISSUER_URL` — the library does strict issuer comparison
on the returned ID token.

Two authorization-server choices in Okta:

| Auth server                 | Issuer URL                                  |
|-----------------------------|---------------------------------------------|
| Custom Authorization Server | `https://<tenant>.okta.com/oauth2/default`  |
| Org Authorization Server    | `https://<tenant>.okta.com`                 |

Developer tenants default to the Custom Authorization Server (`default`).

## Step 3: Configure Environment Variables

Add the following to your `.env` file. This example uses slot 1; any of
slots 1..8 works (each slot is independent).

```bash
OAUTH2_CUSTOM1_PRESET=okta
OAUTH2_CUSTOM1_CLIENT_ID='<Client ID from Okta>'
OAUTH2_CUSTOM1_CLIENT_SECRET='<Client Secret from Okta>'
OAUTH2_CUSTOM1_ISSUER_URL='https://<tenant>.okta.com/oauth2/default'
```

The preset (`PRESET=okta`) fills in defaults for `DISPLAY_NAME`, `NAME`
(which becomes the `okta` URL segment), `ICON_SLUG`, and button colors.

## Step 4: Assign Users

Admin console → **Applications → [your app] → Assignments → Assign**:

- **Assign to Groups → Everyone** is simplest for a single-developer tenant.
- Or **Assign to People** to pick specific users.

Without this step the login returns **"You don't have access to this app.
Contact your administrator."** — note that *super admin accounts appear to
bypass this check* during normal navigation but **not** during OAuth2
token grant, which can produce confusing "works in browser, fails via
OAuth2" symptoms. Always assign explicitly.

## Step 5: Relax the Application Sign-On Policy

Admin console → **Applications → [your app] → Sign On** tab → the
**Authentication Policy** panel shows which policy is attached.

By default new apps get **"Any two factor types/IdPs"**, which requires
the user's *current session* to have completed two different factor types.
If only a password factor is on file, OAuth2 login fails immediately with
**"Policy evaluation failed"** even for admin accounts. Fixes, in order
of practicality:

- Edit the attached policy's catch-all rule: **Security → Authentication
  Policies** → open the policy → rule → **User must authenticate with**:
  `Password / IdP`.
- Enroll a second factor (Okta Verify is easiest) and sign into Okta with
  it at least once before starting the OAuth2 flow.
- Assign a different, looser policy to the app.

## Step 6: Add an Access Policy on the Authorization Server

The one that trips up most people. Okta Custom Authorization Servers
enforce their **own Access Policies** on top of the application's Sign-On
policy. Without a matching rule the token endpoint returns
`FAILURE: no_matching_policy` (visible in System Log) and the browser
sees `400 access_denied`.

**Security → API → Authorization Servers → default → Access Policies**
tab:

1. If there is no policy, **Add New Access Policy**:
   - Name: `Demo Access Policy`
   - **Assign to**: `The following clients` → select your app (or
     `All clients`).
2. Inside the policy, **Add Rule**:
   - **IF Grant type is**: check `Authorization Code`.
   - **AND User is**: `Any user assigned the app`.
   - **AND Scopes requested**: `Any scopes` (or list `openid`, `email`,
     `profile`).
3. Save.

## Step 7: Verify

Start your application and navigate to the login page. An **Okta** button
should appear alongside Google.

After logging in via Okta, verify the database row:

```bash
# PostgreSQL
psql $DATABASE_URL -c "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"

# SQLite
sqlite3 db/sqlite/data/data.db "SELECT provider, provider_user_id, email FROM o2p_oauth2_accounts ORDER BY created_at DESC LIMIT 3;"
```

Expected output:

```
 provider |          provider_user_id          |      email
----------+------------------------------------+------------------
 okta     | okta_<okta-sub>                    | user@example.com
```

## Debugging via System Log

**Reports → System Log** is the authoritative source when something
fails. Filter by the application name or look for the failing timestamp.
The rows matter in this order:

| Row                               | What's being checked                     |
|-----------------------------------|------------------------------------------|
| `User single sign on to app`      | App assignment + app-level access        |
| `Evaluation of sign-on policy`    | Application Authentication Policy        |
| `OAuth2 authorization request`    | Authorization Server Access Policy       |
| `OIDC access/id token is granted` | Final success signal                     |

`OAuth2 authorization request` → `FAILURE: no_matching_policy` maps to
Step 6. `Evaluation of sign-on policy` → `DENY` maps to Step 5. No entry
for your app at all = the request never reached Okta; check
`redirect_uri` and `client_id` in the browser's Network tab.

## Notes

- The `provider_user_id` format is `okta_{sub}` where `sub` is the Okta
  user identifier.
- See [Generic OIDC Provider Setup](./generic-oidc.md) for the full Custom
  slot reference, including how presets and env-var overrides compose.
