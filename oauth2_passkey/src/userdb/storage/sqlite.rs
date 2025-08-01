use sqlx::{Pool, Sqlite};

use crate::storage::validate_sqlite_table_schema;
use crate::userdb::{
    errors::UserError,
    types::{User, UserSearchField},
};

use super::config::DB_TABLE_USERS;

// SQLite implementations
pub(super) async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    // Create users table
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {table_name} (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            account TEXT NOT NULL,
            label TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        )
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}

/// Validates that the User table schema matches what we expect
pub(super) async fn validate_user_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), UserError> {
    let users_table = DB_TABLE_USERS.as_str();

    // Define expected schema (column name, data type)
    let expected_columns = vec![
        ("sequence_number", "INTEGER"),
        ("id", "TEXT"),
        ("account", "TEXT"),
        ("label", "TEXT"),
        ("is_admin", "BOOLEAN"),
        ("created_at", "TIMESTAMP"),
        ("updated_at", "TIMESTAMP"),
    ];

    validate_sqlite_table_schema(pool, users_table, &expected_columns, UserError::Storage).await
}

pub(super) async fn get_all_users_sqlite(pool: &Pool<Sqlite>) -> Result<Vec<User>, UserError> {
    // Ensure tables exist before any operations - this is critical for in-memory databases
    create_tables_sqlite(pool).await?;

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

pub(super) async fn get_user_by_field_sqlite(
    pool: &Pool<Sqlite>,
    field: &UserSearchField,
) -> Result<Option<User>, UserError> {
    // Ensure tables exist before any operations - this is critical for in-memory databases
    create_tables_sqlite(pool).await?;

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

pub(super) async fn upsert_user_sqlite(pool: &Pool<Sqlite>, user: User) -> Result<User, UserError> {
    // Ensure tables exist before any operations - this is critical for in-memory databases
    create_tables_sqlite(pool).await?;

    let table_name = DB_TABLE_USERS.as_str();
    let now = chrono::Utc::now();
    let mut updated_user = user;
    updated_user.updated_at = now;

    // Upsert user with a single query
    sqlx::query(&format!(
        r#"
        INSERT INTO {table_name} (id, account, label, is_admin, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            account = excluded.account,
            label = excluded.label,
            is_admin = excluded.is_admin,
            updated_at = ?
        "#
    ))
    .bind(&updated_user.id)
    .bind(&updated_user.account)
    .bind(&updated_user.label)
    .bind(updated_user.is_admin)
    .bind(now) // created_at
    .bind(now) // updated_at
    .bind(now) // updated_at for the UPDATE part
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Fetch the user to get the sequence_number
    sqlx::query_as::<_, User>(&format!(
        r#"
        SELECT * FROM {table_name} WHERE id = ?
        "#
    ))
    .bind(&updated_user.id)
    .fetch_one(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

pub(super) async fn delete_user_sqlite(pool: &Pool<Sqlite>, id: &str) -> Result<(), UserError> {
    // Ensure tables exist before any operations - this is critical for in-memory databases
    create_tables_sqlite(pool).await?;

    let table_name = DB_TABLE_USERS.as_str();

    sqlx::query(&format!(
        r#"
        DELETE FROM {table_name} WHERE id = ?
        "#
    ))
    .bind(id)
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}
