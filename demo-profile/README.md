# Demo Profile

A demonstration application showing how to extend user data with application-specific attributes using a separate table linked by `user_id`.

Defaults to SQLite (`sqlite:demo-profile.db?mode=rwc`) so the demo runs with `cargo run` and no external setup. For a production-style topology see `demo-live` (HTTPS + Postgres).

## Features

- **Profile Extension**: Add custom attributes (display name, bio, theme) to users
- **Avatar Support**: Automatically fetches Google profile picture for OAuth2 users
- **Theme Selection**: Light/dark theme preference stored per user
- **CSRF Protection**: Demonstrates form-based CSRF token handling

## Architecture

This demo shows the recommended pattern for extending user data:

```
oauth2-passkey library          Your Application
+------------------+           +------------------+
|     users        |           |  user_profiles   |
+------------------+           +------------------+
| user_id (PK)     |<--------->| user_id (PK/FK)  |
| account          |           | display_name     |
| label            |           | bio              |
| ...              |           | avatar_url       |
+------------------+           | theme            |
                               +------------------+
```

The library manages authentication; your app manages extended attributes in a separate table.

## Database Configuration

The library and the app each pick their own database via env vars. The
demo defaults both to SQLite for zero-setup development.

```env
# Library auth tables (users, oauth2_accounts, passkey_credentials, ...)
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:auth.db?mode=rwc'

# App tables (user_profiles)
APP_DATABASE_URL='sqlite:demo-profile.db?mode=rwc'
```

Swap either or both for Postgres in production — see `demo-live` for a
working HTTPS+Postgres deployment.

## Setup

1. Copy the example environment file:

```bash
cp .env.example .env
```

2. Configure your Google OAuth2 credentials in `.env`

3. Run the demo (SQLite files are created automatically):

```bash
cargo run
```

4. Open http://localhost:3001 in your browser

## How Avatar Works

When a user first visits their profile:

1. The app checks if a profile exists in `user_profiles`
2. If not, it queries the OAuth2 accounts via `list_accounts_core()`
3. If a Google account exists, the `picture` URL is extracted
4. A new profile is created with the Google avatar pre-populated

```rust
// Get Google avatar from OAuth2 accounts
let user_id = UserId::new(user_id_string)?;
let accounts = list_accounts_core(user_id).await?;
let google_avatar = accounts
    .iter()
    .find(|a| a.provider == "google")
    .and_then(|a| a.picture.clone());
```

## Database Schema

```sql
CREATE TABLE user_profiles (
    user_id TEXT PRIMARY KEY,        -- Links to oauth2-passkey user
    display_name TEXT,
    bio TEXT,
    avatar_url TEXT,                 -- Google picture or custom URL
    theme TEXT NOT NULL DEFAULT 'light',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

## Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Home page (shows avatar if logged in) |
| `/profile` | GET | Profile edit form |
| `/profile` | POST | Update profile |
| `/o2p/*` | * | OAuth2/Passkey authentication routes |

## Learn More

- [Basic Setup Guide](../docs/src/integration/framework.md)
- [CSRF Token Handling](../docs/src/integration/csrf-handling.md)
- [Route Protection](../docs/src/integration/route-protection.md)
