use crate::storage::DB_TABLE_USERS;
use crate::userdb::{errors::UserError, types::User};
use sqlx::{Pool, Postgres, Row};

// PostgreSQL implementations
pub(super) async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    // Create users table
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id TEXT PRIMARY KEY NOT NULL,
            account TEXT NOT NULL,
            label TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
        table_name
    ))
    .execute(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    Ok(())
}

pub(super) async fn get_user_postgres(
    pool: &Pool<Postgres>,
    id: &str,
) -> Result<Option<User>, UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    sqlx::query_as::<_, User>(&format!(
        r#"
        SELECT * FROM {} WHERE id = $1
        "#,
        table_name
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))
}

pub(super) async fn upsert_user_postgres(
    pool: &Pool<Postgres>,
    user: User,
) -> Result<User, UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    // Upsert user with a single query
    sqlx::query(&format!(
        r#"
        INSERT INTO {} (id, account, label, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (id) DO UPDATE SET
            account = EXCLUDED.account,
            label = EXCLUDED.label,
            created_at = EXCLUDED.created_at,
            updated_at = EXCLUDED.updated_at
        RETURNING *
        "#,
        table_name
    ))
    .bind(&user.id)
    .bind(&user.account)
    .bind(&user.label)
    .bind(user.created_at)
    .bind(user.updated_at)
    .fetch_one(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    // Return updated user
    Ok(user)
}

pub(super) async fn delete_user_postgres(pool: &Pool<Postgres>, id: &str) -> Result<(), UserError> {
    let table_name = DB_TABLE_USERS.as_str();

    sqlx::query(&format!(
        r#"
        DELETE FROM {} WHERE id = $1
        "#,
        table_name
    ))
    .bind(id)
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
        ("id", "text"),
        ("account", "text"),
        ("label", "text"),
        ("created_at", "timestamp with time zone"),
        ("updated_at", "timestamp with time zone"),
    ];

    // Check if table exists
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)",
    )
    .bind(users_table)
    .fetch_one(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    if !table_exists {
        return Err(UserError::Storage(format!(
            "Schema validation failed: Table '{}' does not exist",
            users_table
        )));
    }

    // Query actual schema from database
    let rows = sqlx::query(
        "SELECT column_name, data_type FROM information_schema.columns 
         WHERE table_name = $1 ORDER BY column_name",
    )
    .bind(users_table)
    .fetch_all(pool)
    .await
    .map_err(|e| UserError::Storage(e.to_string()))?;

    let actual_columns: Vec<(String, String)> = rows
        .iter()
        .map(|row| {
            let name: String = row.get("column_name");
            let type_: String = row.get("data_type");
            (name, type_)
        })
        .collect();

    // Compare schemas
    for (expected_name, expected_type) in &expected_columns {
        let found = actual_columns
            .iter()
            .find(|(name, _)| name == expected_name);

        match found {
            Some((_, actual_type)) if actual_type == expected_type => {
                // Column exists with correct type, all good
            }
            Some((_, actual_type)) => {
                // Column exists but with wrong type
                return Err(UserError::Storage(format!(
                    "Schema validation failed: Column '{}' has type '{}' but expected '{}'",
                    expected_name, actual_type, expected_type
                )));
            }
            None => {
                // Column doesn't exist
                return Err(UserError::Storage(format!(
                    "Schema validation failed: Missing column '{}'",
                    expected_name
                )));
            }
        }
    }

    // Check for extra columns (just log a warning)
    for (actual_name, _) in &actual_columns {
        if !expected_columns.iter().any(|(name, _)| name == actual_name) {
            // Log a warning about extra column
            tracing::warn!(
                "Extra column '{}' found in table '{}'.",
                actual_name,
                users_table
            );
        }
    }

    Ok(())
}
