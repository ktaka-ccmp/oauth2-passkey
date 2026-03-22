//! Login history retention policy

use super::{LoginHistoryStore, O2P_LOGIN_HISTORY_RETENTION_DAYS};

/// Delete login history entries older than `O2P_LOGIN_HISTORY_RETENTION_DAYS`.
///
/// Returns `Ok(0)` immediately if `O2P_LOGIN_HISTORY_RETENTION_DAYS` is unset or 0 (disabled).
/// Otherwise, deletes entries older than the configured number of days and returns
/// the number of deleted entries.
///
/// This function does not run on a schedule -- the application is responsible for
/// calling it periodically (e.g., via `tokio::time::interval`).
///
/// # Example
///
/// ```rust,no_run
/// use std::time::Duration;
///
/// async fn start_cleanup_task() {
///     tokio::spawn(async {
///         let mut interval = tokio::time::interval(Duration::from_secs(86400));
///         loop {
///             interval.tick().await;
///             match oauth2_passkey::cleanup_old_login_history().await {
///                 Ok(0) => {} // disabled or nothing to delete
///                 Ok(n) => tracing::info!("Deleted {n} old login history entries"),
///                 Err(e) => tracing::error!("Login history cleanup failed: {e}"),
///             }
///         }
///     });
/// }
/// ```
pub async fn cleanup_old_login_history() -> Result<u64, Box<dyn std::error::Error>> {
    let days = *O2P_LOGIN_HISTORY_RETENTION_DAYS;
    if days == 0 {
        return Ok(0);
    }
    Ok(LoginHistoryStore::delete_old_entries(days).await?)
}
