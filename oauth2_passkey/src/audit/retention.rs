//! Login history retention policy

use super::{LoginHistoryStore, O2P_LOGIN_HISTORY_RETENTION_DAYS};

/// Delete login history entries older than `O2P_LOGIN_HISTORY_RETENTION_DAYS`.
///
/// Returns `Ok(0)` immediately if `O2P_LOGIN_HISTORY_RETENTION_DAYS` is unset or 0 (disabled).
/// Otherwise, deletes entries older than the configured number of days and returns
/// the number of deleted entries.
///
/// This function does not run on a schedule -- use [`spawn_login_history_cleanup`]
/// or call it periodically from your application.
pub async fn cleanup_old_login_history() -> Result<u64, Box<dyn std::error::Error>> {
    let days = *O2P_LOGIN_HISTORY_RETENTION_DAYS;
    if days == 0 {
        return Ok(0);
    }
    Ok(LoginHistoryStore::delete_old_entries(days).await?)
}

/// Spawn a background task that runs [`cleanup_old_login_history`] every 24 hours.
///
/// Returns immediately. The task is a no-op if `O2P_LOGIN_HISTORY_RETENTION_DAYS`
/// is unset or 0.
///
/// # Example
///
/// ```rust,no_run
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     oauth2_passkey::init().await?;
///     oauth2_passkey::spawn_login_history_cleanup();
///     // ... start your server
///     Ok(())
/// }
/// ```
pub fn spawn_login_history_cleanup() {
    tokio::spawn(async {
        // Note: tokio::time::interval fires immediately on first tick,
        // so cleanup runs once at startup, then every 24 hours.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
        loop {
            interval.tick().await;
            match cleanup_old_login_history().await {
                Ok(0) => {}
                Ok(n) => tracing::info!("Deleted {n} old login history entries"),
                Err(e) => tracing::error!("Login history cleanup failed: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests;
