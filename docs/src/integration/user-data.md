# User Data Integration

This guide explains how to manage application-specific user data alongside the oauth2-passkey library.

## Overview

The oauth2-passkey library manages authentication data (users, credentials, OAuth2 accounts) in its own tables. Your application typically needs additional user data such as profiles, preferences, or application-specific records.

**Recommended approach**: Create separate tables in your database linked by `user_id`.

## Database Patterns

### Pattern 1: One-to-One (User Profile)

Each user has exactly one profile record.

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

See [demo-profile](https://github.com/anthropics/oauth2-passkey/tree/master/demo-profile) for a complete example.

### Pattern 2: One-to-Many (User Data)

Each user has multiple records (todos, posts, orders, etc.).

```
oauth2-passkey library          Your Application
+------------------+           +------------------+
|     users        |           |      todos       |
+------------------+           +------------------+
| user_id (PK)     |<----+     | id (PK)          |
| account          |     +---->| user_id (FK)     |
| label            |           | title            |
| ...              |           | completed        |
+------------------+           +------------------+
```

See [demo-todo](https://github.com/anthropics/oauth2-passkey/tree/master/demo-todo) for a complete example.

## Database Configuration

The library and your application can use any combination of databases.

### Same Database

Both library and app share a single PostgreSQL database.

```env
GENERIC_DATA_STORE_TYPE=postgresql
GENERIC_DATA_STORE_URL='postgres://demo:demo@localhost:5432/demo'
YOUR_APP_DATABASE_URL='postgres://demo:demo@localhost:5432/demo'
```

**Benefits:**
- Foreign key constraints between `users` and your tables
- Efficient JOINs across authentication and application data
- Single database to manage and backup

### Separate Databases

Library and app use independent databases.

```env
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:/tmp/auth.db'
YOUR_APP_DATABASE_URL='postgres://demo:demo@localhost:5432/myapp'
```

**Benefits:**
- Clear isolation between library and application data
- Independent scaling and management
- Flexibility to use different database systems

## Implementation Guide

### 1. Define Your Schema

```sql
-- One-to-one: User profiles
CREATE TABLE user_profiles (
    user_id TEXT PRIMARY KEY,
    display_name TEXT,
    bio TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- One-to-many: User todos
CREATE TABLE todos (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_todos_user_id ON todos(user_id);
```

### 2. Set Up Database Connection

Use standard Axum `State<T>` pattern for your application's database:

```rust,ignore
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize oauth2-passkey library (uses its own storage)
    oauth2_passkey_axum::init().await?;

    // Initialize your app's database
    let pool = PgPoolOptions::new()
        .connect(&std::env::var("YOUR_APP_DATABASE_URL")?)
        .await?;
    let state = AppState { pool };

    // Build routes
    let app = Router::new()
        .route("/", get(index))
        .with_state(state)
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

    // ...
}
```

### 3. Access User ID in Handlers

Use the `AuthUser` extractor to get the authenticated user's ID:

```rust,ignore
use oauth2_passkey_axum::AuthUser;

async fn get_profile(
    State(state): State<AppState>,
    user: AuthUser,  // Automatically extracts authenticated user
) -> Result<Response, StatusCode> {
    let profile = sqlx::query_as!(
        UserProfile,
        "SELECT * FROM user_profiles WHERE user_id = $1",
        user.id
    )
    .fetch_optional(&state.pool)
    .await?;

    // ...
}
```

### 4. Protect Routes

Use middleware to require authentication:

```rust,ignore
use oauth2_passkey_axum::is_authenticated_redirect;

pub fn protected_routes() -> Router<AppState> {
    Router::new()
        .route("/profile", get(show_profile).post(update_profile))
        .route_layer(from_fn(is_authenticated_redirect))
}
```

## Accessing OAuth2 Account Data

The library stores OAuth2 account information including profile pictures. You can access this data:

```rust,ignore
use oauth2_passkey_axum::{list_accounts_core, UserId};

async fn get_google_avatar(user_id: &str) -> Option<String> {
    let user_id = UserId::new(user_id.to_string()).ok()?;
    let accounts = list_accounts_core(user_id).await.ok()?;

    accounts
        .into_iter()
        .find(|a| a.provider == "google")
        .and_then(|a| a.picture)
}
```

## Example Applications

| Demo | Pattern | Description |
|------|---------|-------------|
| [demo-profile](https://github.com/anthropics/oauth2-passkey/tree/master/demo-profile) | 1:1 | User profile with avatar, bio, theme |
| [demo-todo](https://github.com/anthropics/oauth2-passkey/tree/master/demo-todo) | 1:N | Todo list with CRUD operations |

## Related Documentation

- [Storage Pattern](../appendix/storage-pattern.md) - Why the library uses singleton pattern
- [Route Protection](route-protection.md) - Authentication middleware options
- [CSRF Token Handling](csrf-handling.md) - Protecting form submissions
