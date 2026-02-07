//! Login history store abstraction

use super::super::{LoginHistoryEntry, LoginHistoryError};
use crate::storage::GENERIC_DATA_STORE;

use super::postgres::*;
use super::sqlite::*;

/// Login history store with static async methods
pub(crate) struct LoginHistoryStore;

impl LoginHistoryStore {
    /// Initialize the login history database tables
    pub(crate) async fn init() -> Result<(), LoginHistoryError> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres()) {
            (Some(pool), _) => {
                create_tables_sqlite(pool).await?;
                validate_login_history_tables_sqlite(pool).await?;
                Ok(())
            }
            (_, Some(pool)) => {
                create_tables_postgres(pool).await?;
                validate_login_history_tables_postgres(pool).await?;
                Ok(())
            }
            _ => Err(LoginHistoryError::Storage(
                "Unsupported database type".to_string(),
            )),
        }
    }

    /// Insert a new login history entry
    #[tracing::instrument(skip(entry), fields(user_id = %entry.user_id, auth_method = %entry.auth_method))]
    pub(crate) async fn insert(
        entry: LoginHistoryEntry,
    ) -> Result<LoginHistoryEntry, LoginHistoryError> {
        let store = GENERIC_DATA_STORE.lock().await;

        let result = if let Some(pool) = store.as_sqlite() {
            insert_login_history_sqlite(pool, entry).await
        } else if let Some(pool) = store.as_postgres() {
            insert_login_history_postgres(pool, entry).await
        } else {
            return Err(LoginHistoryError::Storage(
                "Unsupported database type".to_string(),
            ));
        };

        match &result {
            Ok(entry) => {
                tracing::info!(
                    entry_id = entry.id,
                    success = entry.success,
                    "Login history entry recorded"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to record login history");
            }
        }

        result
    }

    /// Get login history for a user with pagination
    #[tracing::instrument(fields(user_id = %user_id))]
    pub(crate) async fn get_by_user(
        user_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
        let store = GENERIC_DATA_STORE.lock().await;

        let result = if let Some(pool) = store.as_sqlite() {
            get_login_history_by_user_sqlite(pool, user_id, limit, offset).await
        } else if let Some(pool) = store.as_postgres() {
            get_login_history_by_user_postgres(pool, user_id, limit, offset).await
        } else {
            return Err(LoginHistoryError::Storage(
                "Unsupported database type".to_string(),
            ));
        };

        match &result {
            Ok(entries) => {
                tracing::debug!(count = entries.len(), "Retrieved login history entries");
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to retrieve login history");
            }
        }

        result
    }
}
