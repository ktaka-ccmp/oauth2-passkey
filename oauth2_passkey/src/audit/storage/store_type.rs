//! Login history store abstraction

use chrono::{DateTime, Utc};

use super::super::{LoginHistoryEntry, LoginHistoryError};
use crate::storage::GENERIC_DATA_STORE;

use super::mysql::*;
use super::postgres::*;
use super::sqlite::*;

/// Login history store with static async methods
pub(crate) struct LoginHistoryStore;

impl LoginHistoryStore {
    /// Initialize the login history database tables
    pub(crate) async fn init() -> Result<(), LoginHistoryError> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres(), store.as_mysql()) {
            (Some(pool), _, _) => {
                create_tables_sqlite(pool).await?;
                validate_login_history_tables_sqlite(pool).await?;
                Ok(())
            }
            (_, Some(pool), _) => {
                create_tables_postgres(pool).await?;
                validate_login_history_tables_postgres(pool).await?;
                Ok(())
            }
            (_, _, Some(pool)) => {
                create_tables_mysql(pool).await?;
                validate_login_history_tables_mysql(pool).await?;
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
        } else if let Some(pool) = store.as_mysql() {
            insert_login_history_mysql(pool, entry).await
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
        } else if let Some(pool) = store.as_mysql() {
            get_login_history_by_user_mysql(pool, user_id, limit, offset).await
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

    /// Get login history for a user with date range filtering
    #[tracing::instrument(fields(user_id = %user_id))]
    pub(crate) async fn get_by_user_with_date_range(
        user_id: &str,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
        let store = GENERIC_DATA_STORE.lock().await;

        let result = if let Some(pool) = store.as_sqlite() {
            get_login_history_by_user_with_date_range_sqlite(pool, user_id, from, to, limit, offset)
                .await
        } else if let Some(pool) = store.as_postgres() {
            get_login_history_by_user_with_date_range_postgres(
                pool, user_id, from, to, limit, offset,
            )
            .await
        } else if let Some(pool) = store.as_mysql() {
            get_login_history_by_user_with_date_range_mysql(pool, user_id, from, to, limit, offset)
                .await
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

    /// Query login history for admin with filters
    #[tracing::instrument]
    pub(crate) async fn query_admin(
        user_id: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        success: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LoginHistoryEntry>, LoginHistoryError> {
        let store = GENERIC_DATA_STORE.lock().await;

        let result = if let Some(pool) = store.as_sqlite() {
            query_login_history_admin_sqlite(pool, user_id, from, to, success, limit, offset).await
        } else if let Some(pool) = store.as_postgres() {
            query_login_history_admin_postgres(pool, user_id, from, to, success, limit, offset)
                .await
        } else if let Some(pool) = store.as_mysql() {
            query_login_history_admin_mysql(pool, user_id, from, to, success, limit, offset).await
        } else {
            return Err(LoginHistoryError::Storage(
                "Unsupported database type".to_string(),
            ));
        };

        match &result {
            Ok(entries) => {
                tracing::debug!(count = entries.len(), "Retrieved admin login history");
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to retrieve admin login history");
            }
        }

        result
    }
}
