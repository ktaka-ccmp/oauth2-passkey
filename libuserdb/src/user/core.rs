use crate::{errors::UserError, types::User};
use libstorage::GENERIC_DATA_STORE;
use sqlx::{Pool, Postgres, Sqlite};
use uuid::Uuid;

pub struct UserStore;

impl UserStore {
    /// Initialize the user database tables
    pub async fn init() -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            create_tables_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            create_tables_postgres(pool).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Get a user by their ID
    pub async fn get_user(id: &str) -> Result<Option<User>, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_user_sqlite(pool, id).await
        } else if let Some(pool) = store.as_postgres() {
            get_user_postgres(pool, id).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Create or update a user
    pub async fn upsert_user(user: User) -> Result<User, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            upsert_user_sqlite(pool, user).await
        } else if let Some(pool) = store.as_postgres() {
            upsert_user_postgres(pool, user).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }
}

// SQLite implementations
async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), UserError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            picture TEXT,
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            metadata TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Create an index on provider_user_id for faster lookups
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_users_provider_user_id ON users(provider_user_id)
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}

async fn get_user_sqlite(pool: &Pool<Sqlite>, id: &str) -> Result<Option<User>, UserError> {
    sqlx::query_as::<_, User>(
        r#"
        SELECT * FROM users WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

async fn upsert_user_sqlite(pool: &Pool<Sqlite>, user: User) -> Result<User, UserError> {
    // First check if user exists by provider_user_id
    let existing_user = sqlx::query_as::<_, User>(
        r#"
        SELECT * FROM users WHERE provider_user_id = ? LIMIT 1
        "#,
    )
    .bind(&user.provider_user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    if let Some(existing_user) = existing_user {
        Ok(existing_user)
    } else {
        let uid = Uuid::new_v4().to_string();
        let user = User { id: uid, ..user };

        sqlx::query(
            r#"
            INSERT INTO users (id, name, email, picture, provider, provider_user_id, metadata, created_at, updated_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&user.id)
        .bind(&user.name)
        .bind(&user.email)
        .bind(&user.picture)
        .bind(&user.provider)
        .bind(&user.provider_user_id)
        .bind(&user.metadata)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(pool)
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

        Ok(user)
    }
}

// PostgreSQL implementations
async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), UserError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            picture TEXT,
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            metadata JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Create an index on provider_user_id for faster lookups
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_users_provider_user_id ON users(provider_user_id)
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}

async fn get_user_postgres(pool: &Pool<Postgres>, id: &str) -> Result<Option<User>, UserError> {
    sqlx::query_as::<_, User>(
        r#"
        SELECT * FROM users WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

async fn upsert_user_postgres(pool: &Pool<Postgres>, user: User) -> Result<User, UserError> {
    // First check if user exists by provider_user_id
    let existing_user = sqlx::query_as::<_, User>(
        r#"
        SELECT * FROM users WHERE provider_user_id = $1 LIMIT 1
        "#,
    )
    .bind(&user.provider_user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    if let Some(existing_user) = existing_user {
        Ok(existing_user)
    } else {
        let uid = Uuid::new_v4().to_string();
        let user = User { id: uid, ..user };

        sqlx::query(
            r#"
            INSERT INTO users (id, name, email, picture, provider, provider_user_id, metadata, created_at, updated_at) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#
        )
        .bind(&user.id)
        .bind(&user.name)
        .bind(&user.email)
        .bind(&user.picture)
        .bind(&user.provider)
        .bind(&user.provider_user_id)
        .bind(&user.metadata)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(pool)
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

        Ok(user)
    }
}
