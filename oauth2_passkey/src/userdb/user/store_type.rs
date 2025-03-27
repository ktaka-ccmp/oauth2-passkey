use crate::storage::GENERIC_DATA_STORE;
use crate::userdb::{errors::UserError, types::User};

use super::postgres::*;
use super::sqlite::*;

pub struct UserStore;

impl UserStore {
    /// Initialize the user database tables
    pub async fn init() -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            create_tables_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            create_tables_postgres(pool).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Get a user by their ID
    pub async fn get_user(id: &str) -> Result<Option<User>, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_user_sqlite(pool, id).await
        } else if let Some(pool) = store.as_postgres() {
            get_user_postgres(pool, id).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Create or update a user
    pub async fn upsert_user(user: User) -> Result<User, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            upsert_user_sqlite(pool, user).await
        } else if let Some(pool) = store.as_postgres() {
            upsert_user_postgres(pool, user).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    pub async fn delete_user(id: &str) -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            delete_user_sqlite(pool, id).await
        } else if let Some(pool) = store.as_postgres() {
            delete_user_postgres(pool, id).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Validate that the database schema matches what we expect
    /// This should be called during application startup to ensure the database
    /// schema is compatible with the code
    pub async fn validate_schema() -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            super::sqlite::validate_user_tables_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            super::postgres::validate_user_tables_postgres(pool).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }
}
