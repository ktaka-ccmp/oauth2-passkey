use sqlx::{MySql, Pool};

use crate::session::UserId;
use crate::storage::validate_mysql_table_schema;
use crate::userdb::{
    errors::UserError,
    types::{User, UserSearchField},
};

use super::config::DB_TABLE_USERS;

// MySQL implementations
pub(super) async fn create_tables_mysql(pool: &Pool<MySql>) -> Result<(), UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    // Create users table
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {table_name} (
            sequence_number BIGINT PRIMARY KEY AUTO_INCREMENT,
            id VARCHAR(255) NOT NULL UNIQUE,
            account VARCHAR(255) NOT NULL,
            label VARCHAR(255) NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DATETIME(6) NOT NULL,
            updated_at DATETIME(6) NOT NULL
        )
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}

/// Validates that the User table schema matches what we expect
pub(super) async fn validate_user_tables_mysql(pool: &Pool<MySql>) -> Result<(), UserError> {
    let users_table = DB_TABLE_USERS.as_str();

    // Define expected schema (column name, data type)
    // MySQL INFORMATION_SCHEMA returns lowercase data type names
    let expected_columns = vec![
        ("sequence_number", "bigint"),
        ("id", "varchar"),
        ("account", "varchar"),
        ("label", "varchar"),
        ("is_admin", "tinyint"),
        ("created_at", "datetime"),
        ("updated_at", "datetime"),
    ];

    validate_mysql_table_schema(pool, users_table, &expected_columns, UserError::Storage).await
}

pub(super) async fn get_all_users_mysql(pool: &Pool<MySql>) -> Result<Vec<User>, UserError> {
    // Ensure tables exist before any operations
    create_tables_mysql(pool).await?;

    let table_name = DB_TABLE_USERS.as_str();

    sqlx::query_as::<_, User>(&format!(
        r#"
        SELECT * FROM {table_name} ORDER BY sequence_number ASC
        "#
    ))
    .fetch_all(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

pub(super) async fn get_user_by_field_mysql(
    pool: &Pool<MySql>,
    field: &UserSearchField,
) -> Result<Option<User>, UserError> {
    // Ensure tables exist before any operations
    create_tables_mysql(pool).await?;

    let table_name = DB_TABLE_USERS.as_str();

    match field {
        UserSearchField::Id(id) => sqlx::query_as::<_, User>(&format!(
            r#"
                SELECT * FROM {table_name} WHERE id = ?
                "#
        ))
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| UserError::Storage(e.to_string())),
        UserSearchField::SequenceNumber(sequence_number) => sqlx::query_as::<_, User>(&format!(
            r#"
                SELECT * FROM {table_name} WHERE sequence_number = ?
                "#
        ))
        .bind(sequence_number)
        .fetch_optional(pool)
        .await
        .map_err(|e| UserError::Storage(e.to_string())),
    }
}

pub(super) async fn upsert_user_mysql(pool: &Pool<MySql>, user: User) -> Result<User, UserError> {
    let table_name = DB_TABLE_USERS.as_str();
    let now = chrono::Utc::now();
    let mut updated_user = user;
    updated_user.updated_at = now;

    // Use SELECT+UPDATE/INSERT transaction pattern for MySQL/MariaDB compatibility.
    // The "AS new" syntax (MySQL 8.0.19+) is not supported by MariaDB,
    // and VALUES() is deprecated in MySQL 8.0.20+.
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    let existing = sqlx::query_as::<_, User>(&format!(
        r#"SELECT * FROM {table_name} WHERE id = ? FOR UPDATE"#
    ))
    .bind(&updated_user.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    if existing.is_some() {
        sqlx::query(&format!(
            r#"
            UPDATE {table_name} SET
                account = ?,
                label = ?,
                is_admin = ?,
                updated_at = ?
            WHERE id = ?
            "#
        ))
        .bind(&updated_user.account)
        .bind(&updated_user.label)
        .bind(updated_user.is_admin)
        .bind(now)
        .bind(&updated_user.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;
    } else {
        sqlx::query(&format!(
            r#"
            INSERT INTO {table_name} (id, account, label, is_admin, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#
        ))
        .bind(&updated_user.id)
        .bind(&updated_user.account)
        .bind(&updated_user.label)
        .bind(updated_user.is_admin)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;
    }

    // Fetch the user to get the sequence_number
    let result = sqlx::query_as::<_, User>(&format!(r#"SELECT * FROM {table_name} WHERE id = ?"#))
        .bind(&updated_user.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(result)
}

pub(super) async fn count_admin_users_mysql(pool: &Pool<MySql>) -> Result<i64, UserError> {
    // Ensure tables exist before any operations
    create_tables_mysql(pool).await?;

    let table_name = DB_TABLE_USERS.as_str();

    let row: (i64,) = sqlx::query_as(&format!(
        r#"
        SELECT COUNT(*) FROM {table_name} WHERE is_admin = true OR sequence_number = 1
        "#
    ))
    .fetch_one(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(row.0)
}

/// Insert a demo placeholder user with sequence_number=1
///
/// This occupies seq=1 so no real user gets first-user protections.
/// Idempotent: does nothing if the placeholder already exists.
/// Also resets AUTO_INCREMENT to avoid conflicts.
pub(super) async fn insert_demo_placeholder_mysql(pool: &Pool<MySql>) -> Result<(), UserError> {
    let table_name = DB_TABLE_USERS.as_str();
    let now = chrono::Utc::now();

    // Use a transaction to prevent race between INSERT, MAX() query, and ALTER TABLE
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    // MySQL: INSERT IGNORE skips if duplicate key (sequence_number=1 or id conflict)
    sqlx::query(&format!(
        r#"
        INSERT IGNORE INTO {table_name}
            (sequence_number, id, account, label, is_admin, created_at, updated_at)
        VALUES (1, ?, ?, ?, true, ?, ?)
        "#
    ))
    .bind(crate::config::DEMO_PLACEHOLDER_USER_ID)
    .bind("system@demo.local")
    .bind("[Demo Placeholder]")
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Reset AUTO_INCREMENT to avoid conflicts with the explicitly inserted value
    let max_seq: (i64,) = sqlx::query_as(&format!(
        r#"SELECT COALESCE(MAX(sequence_number), 0) FROM {table_name}"#
    ))
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    sqlx::query(&format!(
        r#"ALTER TABLE {table_name} AUTO_INCREMENT = {}"#,
        max_seq.0 + 1
    ))
    .execute(&mut *tx)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}

pub(super) async fn delete_user_mysql(pool: &Pool<MySql>, id: UserId) -> Result<(), UserError> {
    // Ensure tables exist before any operations
    create_tables_mysql(pool).await?;

    let table_name = DB_TABLE_USERS.as_str();

    sqlx::query(&format!(
        r#"
        DELETE FROM {table_name} WHERE id = ?
        "#
    ))
    .bind(id.as_str())
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}
