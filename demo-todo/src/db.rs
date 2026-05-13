use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool, sqlite::SqlitePoolOptions};

/// A todo item belonging to a user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Todo {
    pub id: i64,
    pub user_id: String,
    pub title: String,
    pub completed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Initialize database connection pool and return it
pub async fn init_db() -> Result<SqlitePool, Box<dyn std::error::Error>> {
    let database_url = std::env::var("APP_DATABASE_URL").expect("APP_DATABASE_URL must be set");

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Create table if not exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await?;

    // Create index on user_id for faster queries
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_todos_user_id ON todos(user_id)
        "#,
    )
    .execute(&pool)
    .await?;

    tracing::info!("Todo database initialized");
    Ok(pool)
}

/// List all todos for a user
pub async fn list_todos(pool: &SqlitePool, user_id: &str) -> Result<Vec<Todo>, sqlx::Error> {
    sqlx::query_as::<_, Todo>(
        "SELECT id, user_id, title, completed, created_at, updated_at
         FROM todos WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Create a new todo
pub async fn create_todo(
    pool: &SqlitePool,
    user_id: &str,
    title: &str,
) -> Result<Todo, sqlx::Error> {
    sqlx::query_as::<_, Todo>(
        r#"
        INSERT INTO todos (user_id, title, completed, created_at, updated_at)
        VALUES (?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING id, user_id, title, completed, created_at, updated_at
        "#,
    )
    .bind(user_id)
    .bind(title)
    .fetch_one(pool)
    .await
}

/// Toggle todo completion status
pub async fn toggle_todo(
    pool: &SqlitePool,
    id: i64,
    user_id: &str,
) -> Result<Option<Todo>, sqlx::Error> {
    sqlx::query_as::<_, Todo>(
        r#"
        UPDATE todos
        SET completed = NOT completed, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
        RETURNING id, user_id, title, completed, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Delete a todo
pub async fn delete_todo(pool: &SqlitePool, id: i64, user_id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM todos WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
