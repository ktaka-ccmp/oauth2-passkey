//! SQLite implementation for login history storage

use chrono::{DateTime, Utc};
use sqlx::{Pool, Sqlite};

use super::super::{LoginHistoryEntry, LoginHistoryError};
use crate::storage::validate_sqlite_table_schema;

use super::config::DB_TABLE_LOGIN_HISTORY;

/// Create login history table in SQLite
pub(super) async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), LoginHistoryError> {
    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // Create login_history table
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
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
pub(super) async fn validate_login_history_tables_sqlite(
    pool: &Pool<Sqlite>,
) -> Result<(), LoginHistoryError> {
    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    let expected_columns = vec![
        ("id", "INTEGER"),
        ("user_id", "TEXT"),
        ("timestamp", "TIMESTAMP"),
        ("auth_method", "TEXT"),
        ("ip_address", "TEXT"),
        ("user_agent", "TEXT"),
        ("success", "BOOLEAN"),
        ("credential_id", "TEXT"),
        ("provider", "TEXT"),
        ("provider_user_id", "TEXT"),
        ("failure_reason", "TEXT"),
        ("aaguid", "TEXT"),
        ("email", "TEXT"),
    ];

    validate_sqlite_table_schema(
        pool,
        table_name,
        &expected_columns,
        LoginHistoryError::Storage,
    )
    .await
}

/// Insert a new login history entry
pub(super) async fn insert_login_history_sqlite(
    pool: &Pool<Sqlite>,
    entry: LoginHistoryEntry,
) -> Result<LoginHistoryEntry, LoginHistoryError> {
    create_tables_sqlite(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // Use a transaction to ensure last_insert_rowid() returns the correct value.
    // last_insert_rowid() is connection-scoped; without a transaction, the INSERT
    // and SELECT could run on different pool connections under concurrent load.
    //
    // Transaction flow:
    //   BEGIN
    //   INSERT INTO login_history (...) VALUES (?, ?, ?, ...)
    //   SELECT * FROM login_history WHERE id = last_insert_rowid()
    //   COMMIT
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    sqlx::query(&format!(
        r#"
        INSERT INTO {table_name} (
            user_id, timestamp, auth_method, ip_address, user_agent,
            success, credential_id, provider, provider_user_id, failure_reason,
            aaguid, email
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    .execute(&mut *tx)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    // Fetch within the same transaction to guarantee last_insert_rowid() consistency
    let result = sqlx::query_as::<_, LoginHistoryEntry>(&format!(
        r#"
        SELECT * FROM {table_name} WHERE id = last_insert_rowid()
        "#
    ))
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    Ok(result)
}

/// Get login history for a user with pagination
pub(super) async fn get_login_history_by_user_sqlite(
    pool: &Pool<Sqlite>,
    user_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
    create_tables_sqlite(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    sqlx::query_as::<_, LoginHistoryEntry>(&format!(
        r#"
        SELECT * FROM {table_name}
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
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
pub(super) async fn get_login_history_by_user_with_date_range_sqlite(
    pool: &Pool<Sqlite>,
    user_id: &str,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    limit: i64,
    offset: i64,
) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
    create_tables_sqlite(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // Build query with optional date range filters
    let (query, has_from, has_to) = match (from.is_some(), to.is_some()) {
        (true, true) => (
            format!(
                r#"
                SELECT * FROM {table_name}
                WHERE user_id = ? AND timestamp >= ? AND timestamp <= ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                "#
            ),
            true,
            true,
        ),
        (true, false) => (
            format!(
                r#"
                SELECT * FROM {table_name}
                WHERE user_id = ? AND timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                "#
            ),
            true,
            false,
        ),
        (false, true) => (
            format!(
                r#"
                SELECT * FROM {table_name}
                WHERE user_id = ? AND timestamp <= ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                "#
            ),
            false,
            true,
        ),
        (false, false) => (
            format!(
                r#"
                SELECT * FROM {table_name}
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                "#
            ),
            false,
            false,
        ),
    };

    let mut query_builder = sqlx::query_as::<_, LoginHistoryEntry>(&query).bind(user_id);

    if has_from {
        query_builder = query_builder.bind(from.unwrap());
    }
    if has_to {
        query_builder = query_builder.bind(to.unwrap());
    }

    query_builder
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(|e| LoginHistoryError::Storage(e.to_string()))
}

/// Query login history for admin with filters (user, date range, success status)
pub(super) async fn query_login_history_admin_sqlite(
    pool: &Pool<Sqlite>,
    user_id: Option<&str>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    success: Option<bool>,
    limit: i64,
    offset: i64,
) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
    create_tables_sqlite(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // Build WHERE clause dynamically
    let mut conditions = Vec::new();
    if user_id.is_some() {
        conditions.push("user_id = ?");
    }
    if from.is_some() {
        conditions.push("timestamp >= ?");
    }
    if to.is_some() {
        conditions.push("timestamp <= ?");
    }
    if success.is_some() {
        conditions.push("success = ?");
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
        LIMIT ? OFFSET ?
        "#
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
pub(super) async fn delete_old_entries_sqlite(
    pool: &Pool<Sqlite>,
    days_to_keep: i64,
) -> Result<u64, LoginHistoryError> {
    create_tables_sqlite(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    let result = sqlx::query(&format!(
        r#"
        DELETE FROM {table_name}
        WHERE timestamp < datetime('now', '-{days_to_keep} days')
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    Ok(result.rows_affected())
}
