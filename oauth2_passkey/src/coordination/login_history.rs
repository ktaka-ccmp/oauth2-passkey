//! Login history coordination functions
//!
//! This module provides coordination functions for recording and retrieving login history.

use crate::audit::{
    AuthMethod, LoginContext, LoginHistoryEntry, LoginHistoryError, LoginHistoryStore,
};
use crate::session::{SessionId, UserId, get_user_from_session};

use super::admin::validate_admin_session;
use super::errors::CoordinationError;

/// Record a successful login attempt
///
/// This function records a login event in the login history database.
/// It should be called after a successful authentication (passkey or OAuth2).
#[tracing::instrument(skip(context), fields(user_id = %user_id.as_str(), auth_method = %auth_method))]
pub(crate) async fn record_login_success(
    user_id: UserId,
    auth_method: AuthMethod,
    context: LoginContext,
    credential_id: Option<String>,
    provider: Option<String>,
    provider_user_id: Option<String>,
) -> Result<(), CoordinationError> {
    let entry = LoginHistoryEntry::success(
        user_id.as_str().to_string(),
        auth_method,
        context,
        credential_id,
        provider,
        provider_user_id,
    );

    match LoginHistoryStore::insert(entry).await {
        Ok(_) => {
            tracing::debug!("Login history recorded successfully");
            Ok(())
        }
        Err(e) => {
            // Log but don't fail the login - recording history is non-critical
            tracing::warn!(error = %e, "Failed to record login history (non-fatal)");
            Ok(())
        }
    }
}

/// Get login history for the current user (user's own view)
///
/// Returns login history entries with masked IP addresses for privacy.
#[tracing::instrument(skip(session_cookie), fields(user_id))]
pub async fn get_own_login_history(
    session_cookie: &crate::session::SessionCookie,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<LoginHistoryEntryMasked>, CoordinationError> {
    // Get user from session
    let session_user = get_user_from_session(session_cookie)
        .await
        .map_err(|_| CoordinationError::Unauthorized)?;

    tracing::Span::current().record("user_id", &session_user.id);

    let limit = limit.unwrap_or(50);
    let offset = offset.unwrap_or(0);

    let entries = LoginHistoryStore::get_by_user(&session_user.id, limit, offset)
        .await
        .map_err(|e| CoordinationError::Database(e.to_string()))?;

    // Mask IP addresses for user's own view
    let masked_entries = entries
        .into_iter()
        .map(LoginHistoryEntryMasked::from)
        .collect();

    Ok(masked_entries)
}

/// Get login history for any user (admin view)
///
/// Returns full login history entries including unmasked IP addresses.
/// Requires admin privileges.
#[tracing::instrument(fields(admin_user_id, target_user_id = %target_user_id.as_str()))]
pub async fn get_user_login_history_admin(
    session_id: SessionId,
    target_user_id: UserId,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<LoginHistoryEntry>, CoordinationError> {
    // Validate admin session
    let admin_user = validate_admin_session(session_id).await?;
    tracing::Span::current().record("admin_user_id", &admin_user.id);

    let limit = limit.unwrap_or(50);
    let offset = offset.unwrap_or(0);

    let entries = LoginHistoryStore::get_by_user(target_user_id.as_str(), limit, offset)
        .await
        .map_err(|e| CoordinationError::Database(e.to_string()))?;

    Ok(entries)
}

/// Login history entry with masked IP address for user's own view
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoginHistoryEntryMasked {
    /// Database ID
    pub id: Option<i64>,
    /// User ID who logged in
    pub user_id: String,
    /// Timestamp of the login attempt
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Authentication method used (passkey/oauth2)
    pub auth_method: String,
    /// Masked IP address (last octet hidden)
    pub ip_address: Option<String>,
    /// User-Agent header
    pub user_agent: Option<String>,
    /// Whether the login was successful
    pub success: bool,
    /// Passkey credential ID (for passkey logins)
    pub credential_id: Option<String>,
    /// OAuth2 provider name (for OAuth2 logins)
    pub provider: Option<String>,
    /// OAuth2 provider user ID (for OAuth2 logins)
    pub provider_user_id: Option<String>,
    /// Reason for failure (if success is false)
    pub failure_reason: Option<String>,
}

impl From<LoginHistoryEntry> for LoginHistoryEntryMasked {
    fn from(entry: LoginHistoryEntry) -> Self {
        Self {
            id: entry.id,
            user_id: entry.user_id.clone(),
            timestamp: entry.timestamp,
            auth_method: entry.auth_method.clone(),
            ip_address: entry.masked_ip(),
            user_agent: entry.user_agent.clone(),
            success: entry.success,
            credential_id: entry.credential_id.clone(),
            provider: entry.provider.clone(),
            provider_user_id: entry.provider_user_id.clone(),
            failure_reason: entry.failure_reason.clone(),
        }
    }
}

impl From<LoginHistoryError> for CoordinationError {
    fn from(err: LoginHistoryError) -> Self {
        CoordinationError::Database(err.to_string())
    }
}
