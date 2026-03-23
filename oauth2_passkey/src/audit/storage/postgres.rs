//! PostgreSQL implementation for login history storage

use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};

use super::super::{LoginHistoryEntry, LoginHistoryError};
use crate::storage::validate_postgres_table_schema;

use super::config::DB_TABLE_LOGIN_HISTORY;

/// Create login history table in PostgreSQL
pub(super) async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), LoginHistoryError> {
    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // Create login_history table
    // Note: user_id intentionally has NO FK constraint to users table.
    // Login history is retained as an audit trail even after user deletion.
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
            failure_reason TEXT,
            aaguid TEXT,
            email TEXT
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
        ("aaguid", "text"),
        ("email", "text"),
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
            success, credential_id, provider, provider_user_id, failure_reason,
            aaguid, email
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
    .bind(&entry.aaguid)
    .bind(&entry.email)
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

/// Get login history for a user with date range filtering
pub(super) async fn get_login_history_by_user_with_date_range_postgres(
    pool: &Pool<Postgres>,
    user_id: &str,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    limit: i64,
    offset: i64,
) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
    create_tables_postgres(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // PostgreSQL uses $1, $2, etc. for parameters
    // We need to track the parameter index dynamically
    let mut param_idx = 1;
    let mut conditions = vec![format!("user_id = ${param_idx}")];
    param_idx += 1;

    if from.is_some() {
        conditions.push(format!("timestamp >= ${param_idx}"));
        param_idx += 1;
    }
    if to.is_some() {
        conditions.push(format!("timestamp <= ${param_idx}"));
        param_idx += 1;
    }

    let where_clause = conditions.join(" AND ");

    let query = format!(
        r#"
        SELECT * FROM {table_name}
        WHERE {where_clause}
        ORDER BY timestamp DESC
        LIMIT ${param_idx} OFFSET ${}
        "#,
        param_idx + 1
    );

    let mut query_builder = sqlx::query_as::<_, LoginHistoryEntry>(&query).bind(user_id);

    if let Some(f) = from {
        query_builder = query_builder.bind(f);
    }
    if let Some(t) = to {
        query_builder = query_builder.bind(t);
    }

    query_builder
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(|e| LoginHistoryError::Storage(e.to_string()))
}

/// Query login history for admin with filters (user, date range, success status)
pub(super) async fn query_login_history_admin_postgres(
    pool: &Pool<Postgres>,
    user_id: Option<&str>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    success: Option<bool>,
    limit: i64,
    offset: i64,
) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
    create_tables_postgres(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // Build WHERE clause with PostgreSQL parameter numbering
    let mut conditions = Vec::new();
    let mut param_idx = 1;

    if user_id.is_some() {
        conditions.push(format!("user_id = ${param_idx}"));
        param_idx += 1;
    }
    if from.is_some() {
        conditions.push(format!("timestamp >= ${param_idx}"));
        param_idx += 1;
    }
    if to.is_some() {
        conditions.push(format!("timestamp <= ${param_idx}"));
        param_idx += 1;
    }
    if success.is_some() {
        conditions.push(format!("success = ${param_idx}"));
        param_idx += 1;
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let query = format!(
        r#"
        SELECT * FROM {table_name}
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT ${param_idx} OFFSET ${}
        "#,
        param_idx + 1
    );

    let mut query_builder = sqlx::query_as::<_, LoginHistoryEntry>(&query);

    if let Some(uid) = user_id {
        query_builder = query_builder.bind(uid);
    }
    if let Some(f) = from {
        query_builder = query_builder.bind(f);
    }
    if let Some(t) = to {
        query_builder = query_builder.bind(t);
    }
    if let Some(s) = success {
        query_builder = query_builder.bind(s);
    }

    query_builder
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(|e| LoginHistoryError::Storage(e.to_string()))
}

/// Delete old login history entries (for retention policy)
pub(super) async fn delete_old_entries_postgres(
    pool: &Pool<Postgres>,
    cutoff: DateTime<Utc>,
) -> Result<u64, LoginHistoryError> {
    create_tables_postgres(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    let result = sqlx::query(&format!(
        r#"
        DELETE FROM {table_name}
        WHERE timestamp < $1
        "#
    ))
    .bind(cutoff)
    .execute(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    Ok(result.rows_affected())
}
