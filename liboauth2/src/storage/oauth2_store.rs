use chrono::Utc;
use libstorage::GENERIC_DATA_STORE;
use sqlx::{Pool, Postgres, Sqlite};

use crate::errors::OAuth2Error;
use crate::types::{AccountSearchField, OAuth2Account};

pub struct OAuth2Store;

impl OAuth2Store {
    /// Generate a unique ID for an OAuth2 account
    /// This function checks if the generated ID already exists in the database
    /// and retries up to 3 times if there's a collision
    pub async fn gen_unique_account_id() -> Result<String, OAuth2Error> {
        // Try up to 3 times to generate a unique ID
        for _ in 0..3 {
            let id = uuid::Uuid::new_v4().to_string();

            // Check if an account with this ID already exists
            match Self::get_oauth2_accounts_by(AccountSearchField::Id(id.clone())).await {
                Ok(accounts) if accounts.is_empty() => return Ok(id), // ID is unique, return it
                Ok(_) => continue,                                    // ID exists, try again
                Err(e) => {
                    return Err(OAuth2Error::Database(format!(
                        "Failed to check account ID: {}",
                        e
                    )));
                }
            }
        }

        // If we get here, we failed to generate a unique ID after multiple attempts
        // This is extremely unlikely with UUID v4, but we handle it anyway
        Err(OAuth2Error::Internal(
            "Failed to generate a unique OAuth2 account ID after multiple attempts".to_string(),
        ))
    }

    /// Initialize the OAuth2 database tables
    pub async fn init() -> Result<(), OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            create_tables_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            create_tables_postgres(pool).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }

    /// Get all OAuth2 accounts for a user
    pub async fn get_oauth2_accounts(user_id: &str) -> Result<Vec<OAuth2Account>, OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_oauth2_accounts_by_field_sqlite(
                pool,
                &AccountSearchField::UserId(user_id.to_string()),
            )
            .await
            // get_oauth2_accounts_sqlite(pool, user_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_oauth2_accounts_by_field_postgres(
                pool,
                &AccountSearchField::UserId(user_id.to_string()),
            )
            .await
            // get_oauth2_accounts_postgres(pool, user_id).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }

    pub async fn get_oauth2_accounts_by(
        field: AccountSearchField,
    ) -> Result<Vec<OAuth2Account>, OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;
        if let Some(pool) = store.as_sqlite() {
            get_oauth2_accounts_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            get_oauth2_accounts_by_field_postgres(pool, &field).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }

    /// Get OAuth2 account by provider and provider_user_id
    pub async fn get_oauth2_account_by_provider(
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuth2Account>, OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_oauth2_account_by_provider_sqlite(pool, provider, provider_user_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_oauth2_account_by_provider_postgres(pool, provider, provider_user_id).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }

    /// Create or update an OAuth2 account
    /// Note: This does not create a user. The user_id must be set before calling this method.
    pub async fn upsert_oauth2_account(
        mut account: OAuth2Account,
    ) -> Result<OAuth2Account, OAuth2Error> {
        if account.user_id.is_empty() {
            return Err(OAuth2Error::Storage(
                "user_id must be set before upserting OAuth2 account".to_string(),
            ));
        }

        // Generate a unique ID if one isn't provided
        if account.id.is_empty() {
            account.id = Self::gen_unique_account_id().await?;
        }

        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            upsert_oauth2_account_sqlite(pool, account).await
        } else if let Some(pool) = store.as_postgres() {
            upsert_oauth2_account_postgres(pool, account).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }

    pub async fn delete_oauth2_accounts_by(field: AccountSearchField) -> Result<(), OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            delete_oauth2_accounts_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            delete_oauth2_accounts_by_field_postgres(pool, &field).await
        } else {
            Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            ))
        }
    }
}

// SQLite implementations
async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), OAuth2Error> {
    // Create oauth2_accounts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth2_accounts (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id),
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
    )
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Create index on user_id for faster lookups
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_oauth2_accounts_user_id ON oauth2_accounts(user_id)
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok(())
}

async fn get_oauth2_accounts_by_field_sqlite(
    pool: &Pool<Sqlite>,
    field: &AccountSearchField,
) -> Result<Vec<OAuth2Account>, OAuth2Error> {
    let (query, value) = match field {
        AccountSearchField::Id(id) => ("SELECT * FROM oauth2_accounts WHERE id = ?", id.as_str()),
        AccountSearchField::UserId(user_id) => (
            "SELECT * FROM oauth2_accounts WHERE user_id = ?",
            user_id.as_str(),
        ),
        AccountSearchField::Provider(provider) => (
            "SELECT * FROM oauth2_accounts WHERE provider = ?",
            provider.as_str(),
        ),
        AccountSearchField::ProviderUserId(provider_user_id) => (
            "SELECT * FROM oauth2_accounts WHERE provider_user_id = ?",
            provider_user_id.as_str(),
        ),
        AccountSearchField::Name(name) => (
            "SELECT * FROM oauth2_accounts WHERE name = ?",
            name.as_str(),
        ),
        AccountSearchField::Email(email) => (
            "SELECT * FROM oauth2_accounts WHERE email = ?",
            email.as_str(),
        ),
    };

    sqlx::query_as::<_, OAuth2Account>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

async fn get_oauth2_account_by_provider_sqlite(
    pool: &Pool<Sqlite>,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<OAuth2Account>, OAuth2Error> {
    sqlx::query_as::<_, OAuth2Account>(
        r#"
        SELECT * FROM oauth2_accounts 
        WHERE provider = ? AND provider_user_id = ?
        "#,
    )
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

async fn upsert_oauth2_account_sqlite(
    pool: &Pool<Sqlite>,
    account: OAuth2Account,
) -> Result<OAuth2Account, OAuth2Error> {
    // Begin transaction
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Check if the account already exists
    let existing = sqlx::query_as::<_, OAuth2Account>(
        r#"
        SELECT * FROM oauth2_accounts 
        WHERE provider = ? AND provider_user_id = ?
        "#,
    )
    .bind(&account.provider)
    .bind(&account.provider_user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    let account_id = if let Some(existing) = existing {
        // Update existing account
        sqlx::query(
            r#"
            UPDATE oauth2_accounts SET
                name = ?,
                email = ?,
                picture = ?,
                metadata = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
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
            r#"
            INSERT INTO oauth2_accounts 
            (id, user_id, provider, provider_user_id, name, email, picture, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
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
    let updated_account = sqlx::query_as::<_, OAuth2Account>(
        r#"
        SELECT * FROM oauth2_accounts WHERE id = ?
        "#,
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok(updated_account)
}

async fn delete_oauth2_accounts_by_field_sqlite(
    pool: &Pool<Sqlite>,
    field: &AccountSearchField,
) -> Result<(), OAuth2Error> {
    let (query, value) = match field {
        AccountSearchField::Id(id) => ("DELETE FROM oauth2_accounts WHERE id = ?", id.as_str()),
        AccountSearchField::UserId(user_id) => (
            "DELETE FROM oauth2_accounts WHERE user_id = ?",
            user_id.as_str(),
        ),
        AccountSearchField::Provider(provider) => (
            "DELETE FROM oauth2_accounts WHERE provider = ?",
            provider.as_str(),
        ),
        AccountSearchField::ProviderUserId(provider_user_id) => (
            "DELETE FROM oauth2_accounts WHERE provider_user_id = ?",
            provider_user_id.as_str(),
        ),
        AccountSearchField::Name(name) => {
            ("DELETE FROM oauth2_accounts WHERE name = ?", name.as_str())
        }
        AccountSearchField::Email(email) => (
            "DELETE FROM oauth2_accounts WHERE email = ?",
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

// PostgreSQL implementations
async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), OAuth2Error> {
    // Create oauth2_accounts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth2_accounts (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id),
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            picture TEXT,
            metadata JSONB NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            UNIQUE(provider, provider_user_id)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Create index on user_id for faster lookups
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_oauth2_accounts_user_id ON oauth2_accounts(user_id)
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok(())
}

async fn get_oauth2_accounts_by_field_postgres(
    pool: &Pool<Postgres>,
    field: &AccountSearchField,
) -> Result<Vec<OAuth2Account>, OAuth2Error> {
    let (query, value) = match field {
        AccountSearchField::Id(id) => ("SELECT * FROM oauth2_accounts WHERE id = ?", id.as_str()),
        AccountSearchField::UserId(user_id) => (
            "SELECT * FROM oauth2_accounts WHERE user_id = ?",
            user_id.as_str(),
        ),
        AccountSearchField::Provider(provider) => (
            "SELECT * FROM oauth2_accounts WHERE provider = ?",
            provider.as_str(),
        ),
        AccountSearchField::ProviderUserId(provider_user_id) => (
            "SELECT * FROM oauth2_accounts WHERE provider_user_id = ?",
            provider_user_id.as_str(),
        ),
        AccountSearchField::Name(name) => (
            "SELECT * FROM oauth2_accounts WHERE name = ?",
            name.as_str(),
        ),
        AccountSearchField::Email(email) => (
            "SELECT * FROM oauth2_accounts WHERE email = ?",
            email.as_str(),
        ),
    };

    sqlx::query_as::<_, OAuth2Account>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

async fn get_oauth2_account_by_provider_postgres(
    pool: &Pool<Postgres>,
    provider: &str,
    provider_user_id: &str,
) -> Result<Option<OAuth2Account>, OAuth2Error> {
    sqlx::query_as::<_, OAuth2Account>(
        r#"
        SELECT * FROM oauth2_accounts 
        WHERE provider = $1 AND provider_user_id = $2
        "#,
    )
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))
}

async fn upsert_oauth2_account_postgres(
    pool: &Pool<Postgres>,
    account: OAuth2Account,
) -> Result<OAuth2Account, OAuth2Error> {
    // Begin transaction
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    // Check if the account already exists
    let existing = sqlx::query_as::<_, OAuth2Account>(
        r#"
        SELECT * FROM oauth2_accounts 
        WHERE provider = $1 AND provider_user_id = $2
        "#,
    )
    .bind(&account.provider)
    .bind(&account.provider_user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    let account_id = if let Some(existing) = existing {
        // Update existing account
        sqlx::query(
            r#"
            UPDATE oauth2_accounts SET
                name = $1,
                email = $2,
                picture = $3,
                metadata = $4,
                updated_at = $5
            WHERE id = $6
            "#,
        )
        .bind(&account.name)
        .bind(&account.email)
        .bind(&account.picture)
        .bind(&account.metadata)
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
            r#"
            INSERT INTO oauth2_accounts 
            (id, user_id, provider, provider_user_id, name, email, picture, metadata, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&id)
        .bind(&account.user_id)
        .bind(&account.provider)
        .bind(&account.provider_user_id)
        .bind(&account.name)
        .bind(&account.email)
        .bind(&account.picture)
        .bind(&account.metadata)
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
    let updated_account = sqlx::query_as::<_, OAuth2Account>(
        r#"
        SELECT * FROM oauth2_accounts WHERE id = $1
        "#,
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

    Ok(updated_account)
}

async fn delete_oauth2_accounts_by_field_postgres(
    pool: &Pool<Postgres>,
    field: &AccountSearchField,
) -> Result<(), OAuth2Error> {
    let (query, value) = match field {
        AccountSearchField::Id(id) => ("DELETE FROM oauth2_accounts WHERE id = ?", id.as_str()),
        AccountSearchField::UserId(user_id) => (
            "DELETE FROM oauth2_accounts WHERE user_id = ?",
            user_id.as_str(),
        ),
        AccountSearchField::Provider(provider) => (
            "DELETE FROM oauth2_accounts WHERE provider = ?",
            provider.as_str(),
        ),
        AccountSearchField::ProviderUserId(provider_user_id) => (
            "DELETE FROM oauth2_accounts WHERE provider_user_id = ?",
            provider_user_id.as_str(),
        ),
        AccountSearchField::Name(name) => {
            ("DELETE FROM oauth2_accounts WHERE name = ?", name.as_str())
        }
        AccountSearchField::Email(email) => (
            "DELETE FROM oauth2_accounts WHERE email = ?",
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
