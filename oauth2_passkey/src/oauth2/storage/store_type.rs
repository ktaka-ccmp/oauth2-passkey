use crate::oauth2::errors::OAuth2Error;
use crate::oauth2::types::{AccountSearchField, OAuth2Account};
use crate::storage::GENERIC_DATA_STORE;

use super::postgres::*;
use super::sqlite::*;

pub(crate) struct OAuth2Store;

impl OAuth2Store {
    /// Generate a unique ID for an OAuth2 account
    /// This function checks if the generated ID already exists in the database
    /// and retries up to 3 times if there's a collision
    pub(crate) async fn gen_unique_account_id() -> Result<String, OAuth2Error> {
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
    pub(crate) async fn init() -> Result<(), OAuth2Error> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres()) {
            (Some(pool), _) => {
                create_tables_sqlite(pool).await?;
                validate_oauth2_tables_sqlite(pool).await?;
                Ok(())
            }
            (_, Some(pool)) => {
                create_tables_postgres(pool).await?;
                validate_oauth2_tables_postgres(pool).await?;
                Ok(())
            }
            _ => Err(OAuth2Error::Storage(
                "Unsupported database type".to_string(),
            )),
        }
    }

    /// Get all OAuth2 accounts for a user
    pub(crate) async fn get_oauth2_accounts(
        user_id: &str,
    ) -> Result<Vec<OAuth2Account>, OAuth2Error> {
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

    pub(crate) async fn get_oauth2_accounts_by(
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
    pub(crate) async fn get_oauth2_account_by_provider(
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
    pub(crate) async fn upsert_oauth2_account(
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

    pub(crate) async fn delete_oauth2_accounts_by(
        field: AccountSearchField,
    ) -> Result<(), OAuth2Error> {
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
