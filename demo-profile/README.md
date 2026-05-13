# Demo Profile

A demonstration application showing how to extend user data with application-specific attributes using a separate table linked by `user_id`.

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

The oauth2-passkey library and your application can use any combination of databases. Choose the setup that best fits your requirements.

### Same Database

Both library and app share a single SQLite database. This enables foreign key constraints and JOINs between `users` and `user_profiles` tables.

```env
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:demo.db?mode=rwc'
APP_DATABASE_URL='sqlite:demo.db?mode=rwc'
```

### Separate Databases

Library and app use independent databases. Useful for isolation or when using different database systems.

```env
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:auth.db?mode=rwc'
APP_DATABASE_URL='sqlite:demo-profile.db?mode=rwc'
```

> **Postgres on the app side**: point `APP_DATABASE_URL` at a
> `postgres://...` URL (start Postgres yourself) and switch
> `SqlitePool` → `PgPool` (plus the SQLite-specific SQL) in
> `src/db.rs`. See `demo-live` for a working HTTPS + Postgres
> deployment.

## Setup

1. Copy the example environment file:

```bash
cp .env.example .env
```

2. Configure your Google OAuth2 credentials in `.env`

3. Choose your database configuration in `.env`

4. Run the demo:

```bash
cargo run
```

5. Open http://localhost:3001 in your browser

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
