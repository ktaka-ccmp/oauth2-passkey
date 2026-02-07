//! Login history handlers and helpers for Axum

use axum::{
    Json, Router,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use serde::Deserialize;

use oauth2_passkey::{
    LoginContext, LoginHistoryEntry, LoginHistoryEntryMasked, SessionCookie, SessionId, UserId,
    get_own_login_history, get_user_login_history_admin,
};

use crate::session::AuthUser;

/// Query parameters for login history pagination
#[derive(Debug, Deserialize)]
pub struct LoginHistoryQuery {
    /// Maximum number of entries to return (default: 50)
    pub limit: Option<i64>,
    /// Offset for pagination (default: 0)
    pub offset: Option<i64>,
}

/// Create a router for user's own login history
pub(crate) fn user_router() -> Router {
    Router::new().route("/login_history", get(get_my_login_history))
}

/// Create a router for admin login history endpoints
pub(crate) fn admin_router() -> Router {
    Router::new().route("/user/{user_id}/login_history", get(get_user_login_history))
}

/// Extract login context from HTTP headers
///
/// This function extracts the IP address and User-Agent from the request headers
/// for recording in the login history.
pub fn extract_login_context(headers: &HeaderMap) -> LoginContext {
    // Try to get the real IP from X-Forwarded-For, X-Real-IP, or fall back to connection IP
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        });

    // Get the User-Agent header
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    LoginContext::new(ip_address, user_agent)
}

/// Handler for getting the current user's own login history
///
/// Returns login history with masked IP addresses for privacy.
async fn get_my_login_history(
    auth_user: AuthUser,
    Query(query): Query<LoginHistoryQuery>,
) -> Result<Json<Vec<LoginHistoryEntryMasked>>, (StatusCode, String)> {
    let session_cookie = SessionCookie::new(auth_user.session_id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid session: {e}"),
        )
    })?;

    let entries = get_own_login_history(&session_cookie, query.limit, query.offset)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(entries))
}

/// Handler for admin to get any user's login history
///
/// Returns full login history with unmasked IP addresses.
async fn get_user_login_history(
    auth_user: AuthUser,
    Path(user_id): Path<String>,
    Query(query): Query<LoginHistoryQuery>,
) -> Result<Json<Vec<LoginHistoryEntry>>, (StatusCode, String)> {
    if !auth_user.has_admin_privileges() {
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    let session_id = SessionId::new(auth_user.session_id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid session ID: {e}"),
        )
    })?;

    let target_user_id = UserId::new(user_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid user ID: {e}")))?;

    let entries =
        get_user_login_history_admin(session_id, target_user_id, query.limit, query.offset)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(entries))
}
