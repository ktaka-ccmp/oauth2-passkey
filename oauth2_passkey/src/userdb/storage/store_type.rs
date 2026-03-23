use crate::session::UserId;
use crate::storage::GENERIC_DATA_STORE;
use crate::userdb::{
    errors::UserError,
    types::{User, UserSearchField},
};

use super::mysql::*;
use super::postgres::*;
use super::sqlite::*;

pub(crate) struct UserStore;

impl UserStore {
    /// Initialize the user database tables
    pub(crate) async fn init() -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres(), store.as_mysql()) {
            (Some(pool), _, _) => {
                create_tables_sqlite(pool).await?;
                validate_user_tables_sqlite(pool).await?;
                if *crate::config::O2P_DEMO_MODE {
                    insert_demo_placeholder_sqlite(pool).await?;
                }
                Ok(())
            }
            (_, Some(pool), _) => {
                create_tables_postgres(pool).await?;
                validate_user_tables_postgres(pool).await?;
                if *crate::config::O2P_DEMO_MODE {
                    insert_demo_placeholder_postgres(pool).await?;
                }
                Ok(())
            }
            (_, _, Some(pool)) => {
                create_tables_mysql(pool).await?;
                validate_user_tables_mysql(pool).await?;
                if *crate::config::O2P_DEMO_MODE {
                    insert_demo_placeholder_mysql(pool).await?;
                }
                Ok(())
            }
            _ => Err(UserError::Storage("Unsupported database type".to_string())),
        }
    }

    pub(crate) async fn get_all_users() -> Result<Vec<User>, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_all_users_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            get_all_users_postgres(pool).await
        } else if let Some(pool) = store.as_mysql() {
            get_all_users_mysql(pool).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Get a user by their ID
    #[tracing::instrument(fields(user_id = %id.as_str()))]
    pub(crate) async fn get_user(id: UserId) -> Result<Option<User>, UserError> {
        Self::get_user_by(UserSearchField::Id(id.as_str().to_string())).await
    }

    #[tracing::instrument(fields(user_field = %field))]
    pub(crate) async fn get_user_by(field: UserSearchField) -> Result<Option<User>, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        let result = if let Some(pool) = store.as_sqlite() {
            get_user_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            get_user_by_field_postgres(pool, &field).await
        } else if let Some(pool) = store.as_mysql() {
            get_user_by_field_mysql(pool, &field).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        };

        match &result {
            Ok(Some(_)) => {
                tracing::info!(found = true, "User lookup completed");
            }
            Ok(None) => {
                tracing::info!(found = false, "User lookup completed - not found");
            }
            Err(e) => {
                tracing::error!(error = %e, "User lookup failed");
            }
        }

        result
    }

    /// Create or update a user
    #[tracing::instrument(skip(user), fields(user_id = %user.id))]
    pub(crate) async fn upsert_user(user: User) -> Result<User, UserError> {
        tracing::debug!(user_account = %user.account, "Upserting user");
        let store = GENERIC_DATA_STORE.lock().await;

        // Perform the upsert operation
        let result = if let Some(pool) = store.as_sqlite() {
            upsert_user_sqlite(pool, user).await
        } else if let Some(pool) = store.as_postgres() {
            upsert_user_postgres(pool, user).await
        } else if let Some(pool) = store.as_mysql() {
            upsert_user_mysql(pool, user).await
        } else {
            return Err(UserError::Storage("Unsupported database type".to_string()));
        }?;

        // Check if this is the first user (sequence_number = 1)
        // If so, make them an admin if they aren't already
        let final_result = if result.sequence_number == Some(1) && !result.is_admin {
            let mut admin_user = result.clone();
            admin_user.is_admin = true;

            // Update the user to make them an admin
            if let Some(pool) = store.as_sqlite() {
                upsert_user_sqlite(pool, admin_user).await
            } else if let Some(pool) = store.as_postgres() {
                upsert_user_postgres(pool, admin_user).await
            } else if let Some(pool) = store.as_mysql() {
                upsert_user_mysql(pool, admin_user).await
            } else {
                return Err(UserError::Storage("Unsupported database type".to_string()));
            }
        } else {
            Ok(result)
        };

        match &final_result {
            Ok(user) => {
                tracing::info!(
                    user_id = %user.id,
                    is_admin = user.is_admin,
                    sequence_number = user.sequence_number,
                    "User upsert completed successfully"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "User upsert failed");
            }
        }

        final_result
    }

    pub(crate) async fn count_admin_users() -> Result<i64, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            count_admin_users_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            count_admin_users_postgres(pool).await
        } else if let Some(pool) = store.as_mysql() {
            count_admin_users_mysql(pool).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Atomically delete a user only if they are not the last admin.
    /// Returns true if deleted, false if they were the last admin.
    pub(crate) async fn delete_user_if_not_last_admin(id: UserId) -> Result<bool, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres(), store.as_mysql()) {
            (Some(pool), _, _) => delete_user_if_not_last_admin_sqlite(pool, id).await,
            (_, Some(pool), _) => delete_user_if_not_last_admin_postgres(pool, id).await,
            (_, _, Some(pool)) => delete_user_if_not_last_admin_mysql(pool, id).await,
            _ => Err(UserError::Storage("Unsupported database type".to_string())),
        }
    }

    pub(crate) async fn delete_user(id: UserId) -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            delete_user_sqlite(pool, id).await
        } else if let Some(pool) = store.as_postgres() {
            delete_user_postgres(pool, id).await
        } else if let Some(pool) = store.as_mysql() {
            delete_user_mysql(pool, id).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }
}

#[cfg(test)]
mod tests;
