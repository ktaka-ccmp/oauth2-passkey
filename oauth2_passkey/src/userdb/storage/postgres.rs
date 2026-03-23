use sqlx::{Pool, Postgres};

use crate::session::UserId;
use crate::storage::validate_postgres_table_schema;
use crate::userdb::{
    errors::UserError,
    types::{User, UserSearchField},
};

use super::config::DB_TABLE_USERS;

// PostgreSQL implementations
pub(super) async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    // Create users table
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {table_name} (
            sequence_number BIGSERIAL PRIMARY KEY,
            id TEXT NOT NULL UNIQUE,
            account TEXT NOT NULL,
            label TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}

/// Validates that the User table schema matches what we expect
pub(super) async fn validate_user_tables_postgres(pool: &Pool<Postgres>) -> Result<(), UserError> {
    let users_table = DB_TABLE_USERS.as_str();

    // Define expected schema (column name, data type)
    let expected_columns = vec![
        ("sequence_number", "bigint"),
        ("id", "text"),
        ("account", "text"),
        ("label", "text"),
        ("is_admin", "boolean"),
        ("created_at", "timestamp with time zone"),
        ("updated_at", "timestamp with time zone"),
    ];

    validate_postgres_table_schema(pool, users_table, &expected_columns, UserError::Storage).await
}

pub(super) async fn get_all_users_postgres(pool: &Pool<Postgres>) -> Result<Vec<User>, UserError> {
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

pub(super) async fn get_user_by_field_postgres(
    pool: &Pool<Postgres>,
    field: &UserSearchField,
) -> Result<Option<User>, UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    match field {
        UserSearchField::Id(id) => sqlx::query_as::<_, User>(&format!(
            r#"
                SELECT * FROM {table_name} WHERE id = $1
                "#
        ))
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| UserError::Storage(e.to_string())),
        UserSearchField::SequenceNumber(sequence_number) => sqlx::query_as::<_, User>(&format!(
            r#"
                SELECT * FROM {table_name} WHERE sequence_number = $1
                "#
        ))
        .bind(sequence_number)
        .fetch_optional(pool)
        .await
        .map_err(|e| UserError::Storage(e.to_string())),
    }
}

pub(super) async fn upsert_user_postgres(
    pool: &Pool<Postgres>,
    user: User,
) -> Result<User, UserError> {
    let table_name = DB_TABLE_USERS.as_str();
    let now = chrono::Utc::now();
    let mut updated_user = user;
    updated_user.updated_at = now;

    // Upsert user with a single query and RETURNING to get the sequence_number
    let result = sqlx::query_as::<_, User>(&format!(
        r#"
        INSERT INTO {table_name} (id, account, label, is_admin, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (id) DO UPDATE SET
            account = EXCLUDED.account,
            label = EXCLUDED.label,
            is_admin = EXCLUDED.is_admin,
            updated_at = $7
        RETURNING *
        "#
    ))
    .bind(&updated_user.id)
    .bind(&updated_user.account)
    .bind(&updated_user.label)
    .bind(updated_user.is_admin)
    .bind(now) // created_at
    .bind(now) // updated_at
    .bind(now) // updated_at for the UPDATE part
    .fetch_one(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(result)
}

/// Insert a demo placeholder user with sequence_number=1
///
/// This occupies seq=1 so no real user gets first-user protections.
/// Idempotent: does nothing if seq=1 already exists.
/// Also advances the BIGSERIAL sequence past 1 to avoid conflicts.
pub(super) async fn insert_demo_placeholder_postgres(
    pool: &Pool<Postgres>,
) -> Result<(), UserError> {
    let table_name = DB_TABLE_USERS.as_str();
    let now = chrono::Utc::now();

    sqlx::query(&format!(
        r#"
        INSERT INTO {table_name}
            (sequence_number, id, account, label, is_admin, created_at, updated_at)
        VALUES (1, $1, $2, $3, true, $4, $5)
        ON CONFLICT (sequence_number) DO NOTHING
        "#
    ))
    .bind(crate::config::DEMO_PLACEHOLDER_USER_ID)
    .bind("system@demo.local")
    .bind("[Demo Placeholder]")
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Advance the BIGSERIAL sequence past any explicitly inserted values
    // Without this, the next auto-generated sequence_number could conflict with 1
    sqlx::query(&format!(
        r#"
        SELECT setval(
            pg_get_serial_sequence('{table_name}', 'sequence_number'),
            GREATEST(1, (SELECT COALESCE(MAX(sequence_number), 0) FROM {table_name}))
        )
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}

/// Atomically demote a user only if they are not the last admin.
/// Returns true if demoted, false if they were the last admin.
pub(super) async fn demote_user_if_not_last_admin_postgres(
    pool: &Pool<Postgres>,
    id: UserId,
) -> Result<bool, UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    let result = sqlx::query(&format!(
        r#"
        UPDATE {table_name} SET is_admin = false, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1 AND (SELECT COUNT(*) FROM {table_name} WHERE is_admin = true) > 1
        "#
    ))
    .bind(id.as_str())
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(result.rows_affected() > 0)
}

/// Atomically delete a user only if they are not the last admin.
/// Returns true if deleted, false if they were the last admin.
pub(super) async fn delete_user_if_not_last_admin_postgres(
    pool: &Pool<Postgres>,
    id: UserId,
) -> Result<bool, UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    let result = sqlx::query(&format!(
        r#"
        DELETE FROM {table_name}
        WHERE id = $1 AND (SELECT COUNT(*) FROM {table_name} WHERE is_admin = true) > 1
        "#
    ))
    .bind(id.as_str())
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(result.rows_affected() > 0)
}

pub(super) async fn delete_user_postgres(
    pool: &Pool<Postgres>,
    id: UserId,
) -> Result<(), UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    sqlx::query(&format!(
        r#"
        DELETE FROM {table_name} WHERE id = $1
        "#
    ))
    .bind(id.as_str())
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}
