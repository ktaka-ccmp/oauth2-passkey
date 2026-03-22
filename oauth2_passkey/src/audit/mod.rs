//! Audit and security logging module
//!
//! This module provides functionality for security-related logging and auditing.
//! Currently it supports login history tracking, recording authentication attempts
//! including the method used (passkey or OAuth2), IP address, user agent, and
//! success/failure status.

mod errors;
mod retention;
mod storage;
mod types;

/// Initialize the audit storage backend
pub(crate) async fn init() -> Result<(), LoginHistoryError> {
    // Force-evaluate so invalid values panic at startup, not on first cleanup
    let _ = *O2P_LOGIN_HISTORY_RETENTION_DAYS;
    LoginHistoryStore::init().await
}

// Public exports
pub use errors::LoginHistoryError;
// Internal-only exports
pub(crate) use storage::LoginHistoryStore;
use storage::O2P_LOGIN_HISTORY_RETENTION_DAYS;
pub(crate) use types::AuthMethod;

// Public exports for external use
pub use retention::cleanup_old_login_history;
pub use retention::spawn_login_history_cleanup;
pub(crate) use types::AuthMethodDetails;
pub(crate) use types::LoginContext;
pub use types::LoginHistoryEntry;
