use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, postgres::PgPoolOptions};

/// A todo item belonging to a user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Todo {
    pub id: i32,
    pub user_id: String,
    pub title: String,
    pub completed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Initialize database connection pool and return it
pub async fn init_db() -> Result<PgPool, Box<dyn std::error::Error>> {
    let database_url = std::env::var("TODO_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://demo:demo@localhost:5432/demo".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Create table if not exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS todos (
            id SERIAL PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            completed BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
pub async fn list_todos(pool: &PgPool, user_id: &str) -> Result<Vec<Todo>, sqlx::Error> {
    sqlx::query_as::<_, Todo>(
        "SELECT id, user_id, title, completed, created_at, updated_at
         FROM todos WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Create a new todo
pub async fn create_todo(pool: &PgPool, user_id: &str, title: &str) -> Result<Todo, sqlx::Error> {
    sqlx::query_as::<_, Todo>(
        r#"
        INSERT INTO todos (user_id, title, completed, created_at, updated_at)
        VALUES ($1, $2, FALSE, NOW(), NOW())
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
    pool: &PgPool,
    id: i32,
    user_id: &str,
) -> Result<Option<Todo>, sqlx::Error> {
    sqlx::query_as::<_, Todo>(
        r#"
        UPDATE todos
        SET completed = NOT completed, updated_at = NOW()
        WHERE id = $1 AND user_id = $2
        RETURNING id, user_id, title, completed, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Delete a todo
pub async fn delete_todo(pool: &PgPool, id: i32, user_id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM todos WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
