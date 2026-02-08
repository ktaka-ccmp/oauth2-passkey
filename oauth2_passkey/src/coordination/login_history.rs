//! Login history coordination functions
//!
//! This module provides coordination functions for recording and retrieving login history.

use chrono::{DateTime, Utc};

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
pub(super) async fn record_login_success(
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

/// Record a failed login attempt
///
/// Separate from `record_login_success` to enforce type safety: successful logins
/// always require a known `UserId`, while failures may occur without identifying
/// the user (e.g., invalid credential ID or CSRF validation failure).
#[tracing::instrument(skip(context), fields(user_id = user_id.as_ref().map(|u| u.as_str()), auth_method = %auth_method))]
pub(super) async fn record_login_failure(
    user_id: Option<UserId>,
    auth_method: AuthMethod,
    context: LoginContext,
    credential_id: Option<String>,
    failure_reason: String,
) -> Result<(), CoordinationError> {
    let entry = LoginHistoryEntry::failure(
        user_id
            .as_ref()
            .map(|u| u.as_str().to_string())
            .unwrap_or_default(),
        auth_method,
        context,
        credential_id,
        failure_reason,
    );

    match LoginHistoryStore::insert(entry).await {
        Ok(_) => {
            tracing::debug!("Login failure recorded successfully");
            Ok(())
        }
        Err(e) => {
            // Log but don't fail - recording history is non-critical
            tracing::warn!(error = %e, "Failed to record login failure (non-fatal)");
            Ok(())
        }
    }
}

/// Get login history for the current user (user's own view)
#[tracing::instrument(skip(session_cookie), fields(user_id))]
pub async fn get_own_login_history(
    session_cookie: &crate::session::SessionCookie,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<LoginHistoryEntry>, CoordinationError> {
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

    Ok(entries)
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

/// Get login history for the current user with date range filtering
#[tracing::instrument(skip(session_cookie), fields(user_id))]
pub async fn get_own_login_history_with_date_range(
    session_cookie: &crate::session::SessionCookie,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<LoginHistoryEntry>, CoordinationError> {
    // Get user from session
    let session_user = get_user_from_session(session_cookie)
        .await
        .map_err(|_| CoordinationError::Unauthorized)?;

    tracing::Span::current().record("user_id", &session_user.id);

    let limit = limit.unwrap_or(50);
    let offset = offset.unwrap_or(0);

    let entries =
        LoginHistoryStore::get_by_user_with_date_range(&session_user.id, from, to, limit, offset)
            .await
            .map_err(|e| CoordinationError::Database(e.to_string()))?;

    Ok(entries)
}

/// Query login history for admin with filters (audit page)
///
/// Returns full login history entries including unmasked IP addresses.
/// Supports filtering by user, date range, and success status.
/// Requires admin privileges.
#[tracing::instrument(fields(admin_user_id))]
pub async fn query_login_history_admin(
    session_id: SessionId,
    user_id: Option<&str>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    success: Option<bool>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<LoginHistoryEntry>, CoordinationError> {
    // Validate admin session
    let admin_user = validate_admin_session(session_id).await?;
    tracing::Span::current().record("admin_user_id", &admin_user.id);

    let limit = limit.unwrap_or(50);
    let offset = offset.unwrap_or(0);

    let entries = LoginHistoryStore::query_admin(user_id, from, to, success, limit, offset)
        .await
        .map_err(|e| CoordinationError::Database(e.to_string()))?;

    Ok(entries)
}

impl From<LoginHistoryError> for CoordinationError {
    fn from(err: LoginHistoryError) -> Self {
        CoordinationError::Database(err.to_string())
    }
}
