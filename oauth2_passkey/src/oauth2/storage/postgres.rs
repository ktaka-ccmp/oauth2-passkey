use crate::storage::{DB_TABLE_OAUTH2_ACCOUNTS, DB_TABLE_USERS};
use chrono::Utc;
use sqlx::{Pool, Postgres};

use crate::oauth2::errors::OAuth2Error;
use crate::oauth2::types::{AccountSearchField, OAuth2Account};

// PostgreSQL implementations
pub(super) async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), OAuth2Error> {
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
            metadata JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
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

pub(super) async fn get_oauth2_accounts_by_field_postgres(
    pool: &Pool<Postgres>,
    field: &AccountSearchField,
) -> Result<Vec<OAuth2Account>, OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();
    let (query, value) = match field {
        AccountSearchField::Id(id) => (
            &format!("SELECT * FROM {} WHERE id = $1", table_name),
            id.as_str(),
        ),
        AccountSearchField::UserId(user_id) => (
            &format!("SELECT * FROM {} WHERE user_id = $1", table_name),
            user_id.as_str(),
        ),
        AccountSearchField::Provider(provider) => (
            &format!("SELECT * FROM {} WHERE provider = $1", table_name),
            provider.as_str(),
        ),
        AccountSearchField::ProviderUserId(provider_user_id) => (
            &format!("SELECT * FROM {} WHERE provider_user_id = $1", table_name),
            provider_user_id.as_str(),
        ),
        AccountSearchField::Name(name) => (
            &format!("SELECT * FROM {} WHERE name = $1", table_name),
            name.as_str(),
        ),
        AccountSearchField::Email(email) => (
            &format!("SELECT * FROM {} WHERE email = $1", table_name),
            email.as_str(),
        ),
    };

    sqlx::query_as::<_, OAuth2Account>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

pub(super) async fn get_oauth2_account_by_provider_postgres(
    pool: &Pool<Postgres>,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<OAuth2Account>, OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    sqlx::query_as::<_, OAuth2Account>(&format!(
        r#"
        SELECT * FROM {}
        WHERE provider = $1 AND provider_user_id = $2
        "#,
        table_name
    ))
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

pub(super) async fn upsert_oauth2_account_postgres(
    pool: &Pool<Postgres>,
    account: OAuth2Account,
) -> Result<OAuth2Account, OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Begin transaction
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Check if the account already exists
    let existing = sqlx::query_as::<_, OAuth2Account>(&format!(
        r#"
        SELECT * FROM {}
        WHERE provider = $1 AND provider_user_id = $2
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
                name = $1,
                email = $2,
                picture = $3,
                metadata = $4,
                updated_at = $5
            WHERE id = $6
            "#,
            table_name
        ))
        .bind(&account.name)
        .bind(&account.email)
        .bind(&account.picture)
        .bind(
            serde_json::to_value(&account.metadata)
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
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
        .bind(serde_json::to_value(&account.metadata).map_err(|e| OAuth2Error::Storage(e.to_string()))?)
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
        SELECT * FROM {} WHERE id = $1
        "#,
        table_name
    ))
    .bind(account_id)
    .fetch_one(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok(updated_account)
}

pub(super) async fn delete_oauth2_accounts_by_field_postgres(
    pool: &Pool<Postgres>,
    field: &AccountSearchField,
) -> Result<(), OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();
    let (query, value) = match field {
        AccountSearchField::Id(id) => (
            &format!("DELETE FROM {} WHERE id = $1", table_name),
            id.as_str(),
        ),
        AccountSearchField::UserId(user_id) => (
            &format!("DELETE FROM {} WHERE user_id = $1", table_name),
            user_id.as_str(),
        ),
        AccountSearchField::Provider(provider) => (
            &format!("DELETE FROM {} WHERE provider = $1", table_name),
            provider.as_str(),
        ),
        AccountSearchField::ProviderUserId(provider_user_id) => (
            &format!("DELETE FROM {} WHERE provider_user_id = $1", table_name),
            provider_user_id.as_str(),
        ),
        AccountSearchField::Name(name) => (
            &format!("DELETE FROM {} WHERE name = $1", table_name),
            name.as_str(),
        ),
        AccountSearchField::Email(email) => (
            &format!("DELETE FROM {} WHERE email = $1", table_name),
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
