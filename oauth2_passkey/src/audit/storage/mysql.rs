//! MySQL implementation for login history storage

use chrono::{DateTime, Utc};
use sqlx::{MySql, Pool};

use super::super::{LoginHistoryEntry, LoginHistoryError};
use crate::storage::validate_mysql_table_schema;

use super::config::DB_TABLE_LOGIN_HISTORY;

/// Create login history table in MySQL
pub(super) async fn create_tables_mysql(pool: &Pool<MySql>) -> Result<(), LoginHistoryError> {
    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // Create login_history table
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {table_name} (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            user_id VARCHAR(255) NOT NULL,
            timestamp DATETIME(6) NOT NULL,
            auth_method VARCHAR(50) NOT NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            success BOOLEAN NOT NULL,
            credential_id VARCHAR(768),
            provider VARCHAR(255),
            provider_user_id VARCHAR(512),
            failure_reason TEXT,
            aaguid VARCHAR(255),
            email VARCHAR(255)
        )
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    // Create index for user_id lookups (ignore if exists)
    let _ = sqlx::query(&format!(
        r#"CREATE INDEX idx_{table_name}_user_id ON {table_name}(user_id)"#
    ))
    .execute(pool)
    .await;

    // Create index for timestamp-based queries (ignore if exists)
    let _ = sqlx::query(&format!(
        r#"CREATE INDEX idx_{table_name}_timestamp ON {table_name}(timestamp DESC)"#
    ))
    .execute(pool)
    .await;

    Ok(())
}

/// Validates that the login history table schema matches what we expect
pub(super) async fn validate_login_history_tables_mysql(
    pool: &Pool<MySql>,
) -> Result<(), LoginHistoryError> {
    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    let expected_columns = vec![
        ("id", "bigint"),
        ("user_id", "varchar"),
        ("timestamp", "datetime"),
        ("auth_method", "varchar"),
        ("ip_address", "varchar"),
        ("user_agent", "text"),
        ("success", "tinyint"),
        ("credential_id", "varchar"),
        ("provider", "varchar"),
        ("provider_user_id", "varchar"),
        ("failure_reason", "text"),
        ("aaguid", "varchar"),
        ("email", "varchar"),
    ];

    validate_mysql_table_schema(
        pool,
        table_name,
        &expected_columns,
        LoginHistoryError::Storage,
    )
    .await
}

/// Insert a new login history entry
pub(super) async fn insert_login_history_mysql(
    pool: &Pool<MySql>,
    entry: LoginHistoryEntry,
) -> Result<LoginHistoryEntry, LoginHistoryError> {
    create_tables_mysql(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

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
    .execute(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    // Get the inserted entry with its ID (MySQL has no RETURNING clause)
    let result = sqlx::query_as::<_, LoginHistoryEntry>(&format!(
        r#"
        SELECT * FROM {table_name} WHERE id = LAST_INSERT_ID()
        "#
    ))
    .fetch_one(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    Ok(result)
}

/// Get login history for a user with pagination
pub(super) async fn get_login_history_by_user_mysql(
    pool: &Pool<MySql>,
    user_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
    create_tables_mysql(pool).await?;

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
pub(super) async fn get_login_history_by_user_with_date_range_mysql(
    pool: &Pool<MySql>,
    user_id: &str,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    limit: i64,
    offset: i64,
) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
    create_tables_mysql(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // Build query with optional date range filters (MySQL uses ? placeholders like SQLite)
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
pub(super) async fn query_login_history_admin_mysql(
    pool: &Pool<MySql>,
    user_id: Option<&str>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    success: Option<bool>,
    limit: i64,
    offset: i64,
) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
    create_tables_mysql(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    // Build WHERE clause dynamically (MySQL uses ? placeholders like SQLite)
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
#[allow(dead_code)]
pub(super) async fn delete_old_entries_mysql(
    pool: &Pool<MySql>,
    days_to_keep: i64,
) -> Result<u64, LoginHistoryError> {
    create_tables_mysql(pool).await?;

    let table_name = DB_TABLE_LOGIN_HISTORY.as_str();

    let result = sqlx::query(&format!(
        r#"
        DELETE FROM {table_name}
        WHERE timestamp < DATE_SUB(NOW(), INTERVAL {days_to_keep} DAY)
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| LoginHistoryError::Storage(e.to_string()))?;

    Ok(result.rows_affected())
}
