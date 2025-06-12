use sqlx::{Pool, Sqlite};

use crate::storage::validate_sqlite_table_schema;
use crate::userdb::{errors::UserError, types::User};

use super::config::DB_TABLE_USERS;

// SQLite implementations
pub(super) async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    // Start a transaction
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return Err(UserError::Storage(format!(
                "Failed to begin transaction: {}",
                e
            )));
        }
    };

    // Create users table with IF NOT EXISTS to handle concurrent creation
    let create_table_result = sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            account TEXT NOT NULL,
            label TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        )
        "#,
        table_name
    ))
    .execute(&mut *tx)
    .await;

    // Handle table creation result
    match create_table_result {
        Ok(_) => {}
        Err(e) => {
            // Rollback on error
            if let Err(rollback_err) = tx.rollback().await {
                return Err(UserError::Storage(format!(
                    "Failed to rollback transaction: {}",
                    rollback_err
                )));
            }
            // Check if the error is because the table already exists (race condition)
            if !e.to_string().contains("already exists") {
                return Err(UserError::Storage(format!(
                    "Failed to create users table: {}",
                    e
                )));
            }
            // If the table already exists, we can continue with the transaction
            // Start a new transaction since we rolled back the previous one
            tx = match pool.begin().await {
                Ok(tx) => tx,
                Err(e) => {
                    return Err(UserError::Storage(format!(
                        "Failed to begin new transaction: {}",
                        e
                    )));
                }
            };
        }
    }

    // Create index for faster lookups by ID
    match sqlx::query(&format!(
        "CREATE INDEX IF NOT EXISTS idx_{}_id ON {}(id)",
        table_name, table_name
    ))
    .execute(&mut *tx)
    .await
    {
        Ok(_) => {}
        Err(e) => {
            if let Err(rollback_err) = tx.rollback().await {
                return Err(UserError::Storage(format!(
                    "Failed to rollback transaction: {}",
                    rollback_err
                )));
            }
            return Err(UserError::Storage(format!(
                "Failed to create index on users table: {}",
                e
            )));
        }
    }

    // Commit the transaction
    if let Err(e) = tx.commit().await {
        return Err(UserError::Storage(format!(
            "Failed to commit transaction: {}",
            e
        )));
    }

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
        SELECT * FROM {} ORDER BY sequence_number ASC
        "#,
        table_name
    ))
    .fetch_all(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

pub(super) async fn get_user_sqlite(
    pool: &Pool<Sqlite>,
    id: &str,
) -> Result<Option<User>, UserError> {
    // Ensure tables exist before any operations - this is critical for in-memory databases
    create_tables_sqlite(pool).await?;

    let table_name = DB_TABLE_USERS.as_str();

    sqlx::query_as::<_, User>(&format!(
        r#"
        SELECT * FROM {} WHERE id = ?
        "#,
        table_name
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
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
        INSERT INTO {} (id, account, label, is_admin, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            account = excluded.account,
            label = excluded.label,
            is_admin = excluded.is_admin,
            updated_at = ?
        "#,
        table_name
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
        SELECT * FROM {} WHERE id = ?
        "#,
        table_name
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
        DELETE FROM {} WHERE id = ?
        "#,
        table_name
    ))
    .bind(id)
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}
