//! PostgreSQL implementation for login history storage

use sqlx::{Pool, Postgres};

use super::super::{LoginHistoryEntry, LoginHistoryError};
use crate::storage::validate_postgres_table_schema;

use super::config::DB_TABLE_LOGIN_HISTORY;

/// Create login history table in PostgreSQL
pub(super) async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), LoginHistoryError> {
    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // Create login_history table
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {table_name} (
            id BIGSERIAL PRIMARY KEY,
            user_id TEXT NOT NULL,
            timestamp TIMESTAMPTZ NOT NULL,
            auth_method TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            success BOOLEAN NOT NULL,
            credential_id TEXT,
            provider TEXT,
            provider_user_id TEXT,
            failure_reason TEXT
        )
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    // Create index for user_id lookups
    sqlx::query(&format!(
        r#"
        CREATE INDEX IF NOT EXISTS idx_{table_name}_user_id ON {table_name}(user_id)
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    // Create index for timestamp-based queries
    sqlx::query(&format!(
        r#"
        CREATE INDEX IF NOT EXISTS idx_{table_name}_timestamp ON {table_name}(timestamp DESC)
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    Ok(())
}

/// Validates that the login history table schema matches what we expect
pub(super) async fn validate_login_history_tables_postgres(
    pool: &Pool<Postgres>,
) -> Result<(), LoginHistoryError> {
    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    let expected_columns = vec![
        ("id", "bigint"),
        ("user_id", "text"),
        ("timestamp", "timestamp with time zone"),
        ("auth_method", "text"),
        ("ip_address", "text"),
        ("user_agent", "text"),
        ("success", "boolean"),
        ("credential_id", "text"),
        ("provider", "text"),
        ("provider_user_id", "text"),
        ("failure_reason", "text"),
    ];

    validate_postgres_table_schema(
        pool,
        table_name,
        &expected_columns,
        LoginHistoryError::Storage,
    )
    .await
}

/// Insert a new login history entry
pub(super) async fn insert_login_history_postgres(
    pool: &Pool<Postgres>,
    entry: LoginHistoryEntry,
) -> Result<LoginHistoryEntry, LoginHistoryError> {
    create_tables_postgres(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    let result = sqlx::query_as::<_, LoginHistoryEntry>(&format!(
        r#"
        INSERT INTO {table_name} (
            user_id, timestamp, auth_method, ip_address, user_agent,
            success, credential_id, provider, provider_user_id, failure_reason
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *
        "#
    ))
    .bind(&entry.user_id)
    .bind(entry.timestamp)
    .bind(&entry.auth_method)
    .bind(&entry.ip_address)
    .bind(&entry.user_agent)
    .bind(entry.success)
    .bind(&entry.credential_id)
    .bind(&entry.provider)
    .bind(&entry.provider_user_id)
    .bind(&entry.failure_reason)
    .fetch_one(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    Ok(result)
}

/// Get login history for a user with pagination
pub(super) async fn get_login_history_by_user_postgres(
    pool: &Pool<Postgres>,
    user_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
    create_tables_postgres(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    sqlx::query_as::<_, LoginHistoryEntry>(&format!(
        r#"
        SELECT * FROM {table_name}
        WHERE user_id = $1
        ORDER BY timestamp DESC
        LIMIT $2 OFFSET $3
        "#
    ))
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))
}

/// Delete old login history entries (for retention policy)
#[allow(dead_code)]
pub(super) async fn delete_old_entries_postgres(
    pool: &Pool<Postgres>,
    days_to_keep: i64,
) -> Result<u64, LoginHistoryError> {
    create_tables_postgres(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    let result = sqlx::query(&format!(
        r#"
        DELETE FROM {table_name}
        WHERE timestamp < NOW() - INTERVAL '{days_to_keep} days'
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    Ok(result.rows_affected())
}
