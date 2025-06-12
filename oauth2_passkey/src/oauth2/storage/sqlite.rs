use chrono::Utc;
use sqlx::{Pool, Sqlite};

use crate::oauth2::{
    errors::OAuth2Error,
    types::{AccountSearchField, OAuth2Account},
};
use crate::storage::validate_sqlite_table_schema;
use crate::userdb::DB_TABLE_USERS;

use super::config::DB_TABLE_OAUTH2_ACCOUNTS;

// SQLite implementations
pub(super) async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), OAuth2Error> {
    let oauth2_table = DB_TABLE_OAUTH2_ACCOUNTS.as_str();
    let users_table = DB_TABLE_USERS.as_str();

    // Create oauth2_accounts table
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES {}(id),
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            picture TEXT,
            metadata TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            UNIQUE(provider, provider_user_id)
        )
        "#,
        oauth2_table, users_table
    ))
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Create index on user_id for faster lookups
    sqlx::query(&format!(
        r#"
        CREATE INDEX IF NOT EXISTS idx_{}_user_id ON {}(user_id)
        "#,
        oauth2_table.replace(".", "_"),
        oauth2_table
    ))
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok(())
}

/// Validates that the OAuth2 account table schema matches what we expect
pub(super) async fn validate_oauth2_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), OAuth2Error> {
    let oauth2_table = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Define expected schema (column name, data type)
    let expected_columns = [
        ("id", "TEXT"),
        ("user_id", "TEXT"),
        ("provider", "TEXT"),
        ("provider_user_id", "TEXT"),
        ("name", "TEXT"),
        ("email", "TEXT"),
        ("picture", "TEXT"),
        ("metadata", "TEXT"),
        ("created_at", "TIMESTAMP"),
        ("updated_at", "TIMESTAMP"),
    ];

    validate_sqlite_table_schema(pool, oauth2_table, &expected_columns, OAuth2Error::Storage).await
}

pub(super) async fn get_oauth2_accounts_by_field_sqlite(
    pool: &Pool<Sqlite>,
    field: &AccountSearchField,
) -> Result<Vec<OAuth2Account>, OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Ensure tables exist before any operations
    create_tables_sqlite(pool).await?;

    let (query, value) = match field {
        AccountSearchField::Id(id) => (
            &format!("SELECT * FROM {} WHERE id = ?", table_name),
            id.as_str(),
        ),
        AccountSearchField::UserId(user_id) => (
            &format!("SELECT * FROM {} WHERE user_id = ?", table_name),
            user_id.as_str(),
        ),
        AccountSearchField::Provider(provider) => (
            &format!("SELECT * FROM {} WHERE provider = ?", table_name),
            provider.as_str(),
        ),
        AccountSearchField::ProviderUserId(provider_user_id) => (
            &format!("SELECT * FROM {} WHERE provider_user_id = ?", table_name),
            provider_user_id.as_str(),
        ),
        AccountSearchField::Name(name) => (
            &format!("SELECT * FROM {} WHERE name = ?", table_name),
            name.as_str(),
        ),
        AccountSearchField::Email(email) => (
            &format!("SELECT * FROM {} WHERE email = ?", table_name),
            email.as_str(),
        ),
    };

    sqlx::query_as::<_, OAuth2Account>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

pub(super) async fn get_oauth2_account_by_provider_sqlite(
    pool: &Pool<Sqlite>,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<OAuth2Account>, OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Ensure tables exist before any operations
    create_tables_sqlite(pool).await?;

    sqlx::query_as::<_, OAuth2Account>(&format!(
        r#"
        SELECT * FROM {}
        WHERE provider = ? AND provider_user_id = ?
        "#,
        table_name
    ))
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

pub(super) async fn upsert_oauth2_account_sqlite(
    pool: &Pool<Sqlite>,
    account: OAuth2Account,
) -> Result<OAuth2Account, OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Ensure tables exist before any operations - this is critical for in-memory databases
    // where different connections might get different database instances
    create_tables_sqlite(pool).await?;

    // Begin transaction
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Check if the account already exists
    let existing = sqlx::query_as::<_, OAuth2Account>(&format!(
        r#"
        SELECT * FROM {}
        WHERE provider = ? AND provider_user_id = ?
        "#,
        table_name
    ))
    .bind(&account.provider)
    .bind(&account.provider_user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    let account_id = if let Some(existing) = existing {
        // Update existing account
        sqlx::query(&format!(
            r#"
            UPDATE {} SET
                name = ?,
                email = ?,
                picture = ?,
                metadata = ?,
                updated_at = ?
            WHERE id = ?
            "#,
            table_name
        ))
        .bind(&account.name)
        .bind(&account.email)
        .bind(&account.picture)
        .bind(
            serde_json::to_string(&account.metadata)
                .map_err(|e| OAuth2Error::Storage(e.to_string()))?,
        )
        .bind(Utc::now())
        .bind(&existing.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

        existing.id
    } else {
        // Insert new account
        let id = account.id.clone();
        sqlx::query(
            &format!(
            r#"
            INSERT INTO {}
            (id, user_id, provider, provider_user_id, name, email, picture, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            table_name
            )
        )
        .bind(&id)
        .bind(&account.user_id)
        .bind(&account.provider)
        .bind(&account.provider_user_id)
        .bind(&account.name)
        .bind(&account.email)
        .bind(&account.picture)
        .bind(serde_json::to_string(&account.metadata).map_err(|e| OAuth2Error::Storage(e.to_string()))?)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&mut *tx)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

        id
    };

    // Commit transaction
    tx.commit()
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Return the updated account
    let updated_account = sqlx::query_as::<_, OAuth2Account>(&format!(
        r#"
        SELECT * FROM {} WHERE id = ?
        "#,
        table_name
    ))
    .bind(account_id)
    .fetch_one(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok(updated_account)
}

pub(super) async fn delete_oauth2_accounts_by_field_sqlite(
    pool: &Pool<Sqlite>,
    field: &AccountSearchField,
) -> Result<(), OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Ensure tables exist before any operations
    create_tables_sqlite(pool).await?;

    let (query, value) = match field {
        AccountSearchField::Id(id) => (
            &format!("DELETE FROM {} WHERE id = ?", table_name),
            id.as_str(),
        ),
        AccountSearchField::UserId(user_id) => (
            &format!("DELETE FROM {} WHERE user_id = ?", table_name),
            user_id.as_str(),
        ),
        AccountSearchField::Provider(provider) => (
            &format!("DELETE FROM {} WHERE provider = ?", table_name),
            provider.as_str(),
        ),
        AccountSearchField::ProviderUserId(provider_user_id) => (
            &format!("DELETE FROM {} WHERE provider_user_id = ?", table_name),
            provider_user_id.as_str(),
        ),
        AccountSearchField::Name(name) => (
            &format!("DELETE FROM {} WHERE name = ?", table_name),
            name.as_str(),
        ),
        AccountSearchField::Email(email) => (
            &format!("DELETE FROM {} WHERE email = ?", table_name),
            email.as_str(),
        ),
    };

    sqlx::query(query)
        .bind(value)
        .execute(pool)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok(())
}
