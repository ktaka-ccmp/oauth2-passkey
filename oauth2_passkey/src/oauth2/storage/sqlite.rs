use chrono::Utc;
use sqlx::{Pool, Sqlite};

use crate::oauth2::{
    errors::OAuth2Error,
    types::{AccountSearchField, OAuth2Account, Provider, ProviderUserId},
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
        CREATE TABLE IF NOT EXISTS {oauth2_table} (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            user_id TEXT NOT NULL REFERENCES {users_table}(id) ON DELETE CASCADE,
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
        "#
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

/// Migrates the OAuth2 accounts table to add ON DELETE CASCADE to the FK constraint.
/// SQLite does not support ALTER TABLE for FK changes, so we recreate the table.
pub(super) async fn migrate_oauth2_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), OAuth2Error> {
    let oauth2_table = DB_TABLE_OAUTH2_ACCOUNTS.as_str();
    let users_table = DB_TABLE_USERS.as_str();

    // Check if FK already has CASCADE
    let has_cascade: bool = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) > 0 FROM pragma_foreign_key_list('{oauth2_table}') WHERE on_delete = 'CASCADE'"
    ))
    .fetch_one(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;
    if has_cascade {
        return Ok(());
    }

    // Recreate table with ON DELETE CASCADE
    let temp_table = format!("{oauth2_table}_migration_tmp");
    sqlx::query(&format!(
        r#"
        CREATE TABLE {temp_table} (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            user_id TEXT NOT NULL REFERENCES {users_table}(id) ON DELETE CASCADE,
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
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    sqlx::query(&format!(
        "INSERT INTO {temp_table} SELECT * FROM {oauth2_table}"
    ))
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    sqlx::query(&format!("DROP TABLE {oauth2_table}"))
        .execute(pool)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    sqlx::query(&format!(
        "ALTER TABLE {temp_table} RENAME TO {oauth2_table}"
    ))
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Recreate index
    sqlx::query(&format!(
        "CREATE INDEX IF NOT EXISTS idx_{}_user_id ON {}(user_id)",
        oauth2_table.replace(".", "_"),
        oauth2_table
    ))
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    tracing::info!("Migrated {oauth2_table}: added ON DELETE CASCADE to user_id FK");
    Ok(())
}

/// Validates that the OAuth2 account table schema matches what we expect
pub(super) async fn validate_oauth2_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), OAuth2Error> {
    let oauth2_table = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Define expected schema (column name, data type)
    let expected_columns = [
        ("sequence_number", "INTEGER"),
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

pub(super) async fn get_oauth2_account_by_provider_sqlite(
    pool: &Pool<Sqlite>,
    provider: Provider,
    provider_user_id: ProviderUserId,
) -> Result<Option<OAuth2Account>, OAuth2Error> {
    let table_name = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Ensure tables exist before any operations
    create_tables_sqlite(pool).await?;

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

    // Fetch inside the transaction for read-your-writes consistency
    let updated_account = sqlx::query_as::<_, OAuth2Account>(&format!(
        r#"
        SELECT * FROM {table_name} WHERE id = ?
        "#
    ))
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    tx.commit()
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
