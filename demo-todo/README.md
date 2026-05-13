# Demo Todo

A demonstration application showing how to manage user-specific data with a one-to-many relationship using a separate table linked by `user_id`.

## Features

- **CRUD Operations**: Create, read, toggle, and delete todo items
- **User Isolation**: Each user sees only their own todos
- **CSRF Protection**: Demonstrates form-based CSRF token handling

## Architecture

This demo shows the pattern for user-specific data with a 1:N relationship:

```
oauth2-passkey library          Your Application
+------------------+           +------------------+
|     users        |           |      todos       |
+------------------+           +------------------+
| user_id (PK)     |<----+     | id (PK)          |
| account          |     +---->| user_id (FK)     |
| label            |           | title            |
| ...              |           | completed        |
+------------------+           | created_at       |
                               +------------------+
```

The library manages authentication; your app manages user data in a separate table.

## Database Configuration

The oauth2-passkey library and your application can use any combination of databases. Choose the setup that best fits your requirements.

### Same Database

Both library and app share a single SQLite database. This enables foreign key constraints and JOINs between `users` and `todos` tables.

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
APP_DATABASE_URL='sqlite:demo-todo.db?mode=rwc'
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

## Database Schema

```sql
CREATE TABLE todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,        -- Links to oauth2-passkey user
    title TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_todos_user_id ON todos(user_id);
```

## Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Home page (shows todos if logged in) |
| `/todos` | POST | Create a new todo |
| `/todos/:id/toggle` | POST | Toggle todo completion |
| `/todos/:id/delete` | POST | Delete a todo |
| `/o2p/*` | * | OAuth2/Passkey authentication routes |

## CRUD Operations

### Create
```rust
db::create_todo(&pool, &user_id, "Buy groceries").await?;
```

### Read
```rust
let todos = db::list_todos(&pool, &user_id).await?;
```

### Update (Toggle)
```rust
db::toggle_todo(&pool, todo_id, &user_id).await?;
```

### Delete
```rust
db::delete_todo(&pool, todo_id, &user_id).await?;
```

## Learn More

- [Basic Setup Guide](../docs/src/integration/framework.md)
- [CSRF Token Handling](../docs/src/integration/csrf-handling.md)
- [Route Protection](../docs/src/integration/route-protection.md)
