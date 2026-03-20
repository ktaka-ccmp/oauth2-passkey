use chrono::Utc;
use sqlx::{MySql, Pool};

use crate::oauth2::{
    errors::OAuth2Error,
    types::{AccountSearchField, OAuth2Account, Provider, ProviderUserId},
};
use crate::storage::validate_mysql_table_schema;
use crate::userdb::DB_TABLE_USERS;

use super::config::DB_TABLE_OAUTH2_ACCOUNTS;

// MySQL implementations
pub(super) async fn create_tables_mysql(pool: &Pool<MySql>) -> Result<(), OAuth2Error> {
    let oauth2_table = DB_TABLE_OAUTH2_ACCOUNTS.as_str();
    let users_table = DB_TABLE_USERS.as_str();

    // Create oauth2_accounts table
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {oauth2_table} (
            sequence_number BIGINT PRIMARY KEY AUTO_INCREMENT,
            id VARCHAR(255) NOT NULL UNIQUE,
            user_id VARCHAR(255) NOT NULL,
            provider VARCHAR(255) NOT NULL,
            provider_user_id VARCHAR(512) NOT NULL,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            picture TEXT,
            metadata JSON NOT NULL,
            created_at DATETIME(6) NOT NULL,
            updated_at DATETIME(6) NOT NULL,
            UNIQUE KEY uq_provider_user (provider, provider_user_id),
            FOREIGN KEY (user_id) REFERENCES {users_table}(id)
        )
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Create index on user_id for faster lookups
    // MySQL: use CREATE INDEX IF NOT EXISTS equivalent via ignoring errors
    let index_name = format!("idx_{}_user_id", oauth2_table.replace('.', "_"));
    let _ = sqlx::query(&format!(
        r#"CREATE INDEX {index_name} ON {oauth2_table}(user_id)"#,
    ))
    .execute(pool)
    .await;

    Ok(())
}

/// Validates that the OAuth2 account table schema matches what we expect
pub(super) async fn validate_oauth2_tables_mysql(pool: &Pool<MySql>) -> Result<(), OAuth2Error> {
    let oauth2_table = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Define expected schema (column name, data type)
    let expected_columns = [
        ("sequence_number", "bigint"),
        ("id", "varchar"),
        ("user_id", "varchar"),
        ("provider", "varchar"),
        ("provider_user_id", "varchar"),
        ("name", "varchar"),
        ("email", "varchar"),
        ("picture", "text"),
        ("metadata", "json"),
        ("created_at", "datetime"),
        ("updated_at", "datetime"),
    ];

    validate_mysql_table_schema(pool, oauth2_table, &expected_columns, OAuth2Error::Storage).await
}

pub(super) async fn get_oauth2_accounts_by_field_mysql(
    pool: &Pool<MySql>,
    field: &AccountSearchField,
) -> Result<Vec<OAuth2Account>, OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Ensure tables exist before any operations
    create_tables_mysql(pool).await?;

    let (query, value) = match field {
        AccountSearchField::Id(id) => (
            &format!("SELECT * FROM {table_name} WHERE id = ?"),
            id.as_str(),
        ),
        AccountSearchField::UserId(user_id) => (
            &format!("SELECT * FROM {table_name} WHERE user_id = ?"),
            user_id.as_str(),
        ),
        AccountSearchField::Provider(provider) => (
            &format!("SELECT * FROM {table_name} WHERE provider = ?"),
            provider.as_str(),
        ),
        AccountSearchField::ProviderUserId(provider_user_id) => (
            &format!("SELECT * FROM {table_name} WHERE provider_user_id = ?"),
            provider_user_id.as_str(),
        ),
        AccountSearchField::Name(name) => (
            &format!("SELECT * FROM {table_name} WHERE name = ?"),
            name.as_str(),
        ),
        AccountSearchField::Email(email) => (
            &format!("SELECT * FROM {table_name} WHERE email = ?"),
            email.as_str(),
        ),
    };

    sqlx::query_as::<_, OAuth2Account>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

pub(super) async fn get_oauth2_account_by_provider_mysql(
    pool: &Pool<MySql>,
    provider: Provider,
    provider_user_id: ProviderUserId,
) -> Result<Option<OAuth2Account>, OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Ensure tables exist before any operations
    create_tables_mysql(pool).await?;

    sqlx::query_as::<_, OAuth2Account>(&format!(
        r#"
        SELECT * FROM {table_name}
        WHERE provider = ? AND provider_user_id = ?
        "#
    ))
    .bind(provider.as_str())
    .bind(provider_user_id.as_str())
    .fetch_optional(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

pub(super) async fn upsert_oauth2_account_mysql(
    pool: &Pool<MySql>,
    account: OAuth2Account,
) -> Result<OAuth2Account, OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Ensure tables exist before any operations
    create_tables_mysql(pool).await?;

    // Begin transaction
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Check if the account already exists
    let existing = sqlx::query_as::<_, OAuth2Account>(&format!(
        r#"
        SELECT * FROM {table_name}
        WHERE provider = ? AND provider_user_id = ?
        "#
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
            UPDATE {table_name} SET
                name = ?,
                email = ?,
                picture = ?,
                metadata = ?,
                updated_at = ?
            WHERE id = ?
            "#
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
            INSERT INTO {table_name}
            (id, user_id, provider, provider_user_id, name, email, picture, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
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

    // Return the updated account (MySQL has no RETURNING clause)
    let updated_account = sqlx::query_as::<_, OAuth2Account>(&format!(
        r#"
        SELECT * FROM {table_name} WHERE id = ?
        "#
    ))
    .bind(account_id)
    .fetch_one(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok(updated_account)
}

pub(super) async fn delete_oauth2_accounts_by_field_mysql(
    pool: &Pool<MySql>,
    field: &AccountSearchField,
) -> Result<(), OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Ensure tables exist before any operations
    create_tables_mysql(pool).await?;

    let (query, value) = match field {
        AccountSearchField::Id(id) => (
            &format!("DELETE FROM {table_name} WHERE id = ?"),
            id.as_str(),
        ),
        AccountSearchField::UserId(user_id) => (
            &format!("DELETE FROM {table_name} WHERE user_id = ?"),
            user_id.as_str(),
        ),
        AccountSearchField::Provider(provider) => (
            &format!("DELETE FROM {table_name} WHERE provider = ?"),
            provider.as_str(),
        ),
        AccountSearchField::ProviderUserId(provider_user_id) => (
            &format!("DELETE FROM {table_name} WHERE provider_user_id = ?"),
            provider_user_id.as_str(),
        ),
        AccountSearchField::Name(name) => (
            &format!("DELETE FROM {table_name} WHERE name = ?"),
            name.as_str(),
        ),
        AccountSearchField::Email(email) => (
            &format!("DELETE FROM {table_name} WHERE email = ?"),
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
