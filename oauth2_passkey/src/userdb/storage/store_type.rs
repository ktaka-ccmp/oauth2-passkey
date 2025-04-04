use crate::storage::GENERIC_DATA_STORE;
use crate::userdb::{errors::UserError, types::User};

use super::postgres::*;
use super::sqlite::*;

pub(crate) struct UserStore;

impl UserStore {
    /// Initialize the user database tables
    pub(crate) async fn init() -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres()) {
            (Some(pool), _) => {
                create_tables_sqlite(pool).await?;
                validate_user_tables_sqlite(pool).await?;
                Ok(())
            }
            (_, Some(pool)) => {
                create_tables_postgres(pool).await?;
                validate_user_tables_postgres(pool).await?;
                Ok(())
            }
            _ => Err(UserError::Storage("Unsupported database type".to_string())),
        }
    }

    /// Get a user by their ID
    pub(crate) async fn get_user(id: &str) -> Result<Option<User>, UserError> {
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
    pub(crate) async fn upsert_user(user: User) -> Result<User, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        // Perform the upsert operation
        let result = if let Some(pool) = store.as_sqlite() {
            upsert_user_sqlite(pool, user).await
        } else if let Some(pool) = store.as_postgres() {
            upsert_user_postgres(pool, user).await
        } else {
            return Err(UserError::Storage("Unsupported database type".to_string()));
        }?;

        // Check if this is the first user (sequence_number = 1)
        // If so, make them an admin if they aren't already
        if result.sequence_number == Some(1) && !result.is_admin {
            let mut admin_user = result.clone();
            admin_user.is_admin = true;

            // Update the user to make them an admin
            if let Some(pool) = store.as_sqlite() {
                upsert_user_sqlite(pool, admin_user).await
            } else if let Some(pool) = store.as_postgres() {
                upsert_user_postgres(pool, admin_user).await
            } else {
                return Err(UserError::Storage("Unsupported database type".to_string()));
            }
        } else {
            Ok(result)
        }
    }

    pub(crate) async fn delete_user(id: &str) -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            delete_user_sqlite(pool, id).await
        } else if let Some(pool) = store.as_postgres() {
            delete_user_postgres(pool, id).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }
}
