//! Login history handlers and helpers for Axum

use std::collections::HashMap;

use askama::Template;
use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::Html,
    routing::get,
};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use oauth2_passkey::{
    LoginHistoryEntry, O2P_ROUTE_PREFIX, SessionCookie, SessionId, UserId,
    get_authenticator_info_batch, get_own_login_history, get_own_login_history_with_date_range,
    get_user_login_history_admin, query_login_history_admin,
};

use crate::admin::masking::Masker;
use crate::config::O2P_CUSTOM_CSS_URL;
use crate::session::AuthUser;

/// Query parameters for login history pagination with date range
#[derive(Debug, Deserialize)]
struct LoginHistoryQuery {
    /// Maximum number of entries to return (default: 50)
    limit: Option<i64>,
    /// Offset for pagination (default: 0)
    offset: Option<i64>,
    /// Filter from date (YYYY-MM-DD format)
    from: Option<String>,
    /// Filter to date (YYYY-MM-DD format)
    to: Option<String>,
    /// Timezone offset in minutes from UTC (e.g., JST = 540, EST = -300)
    tz_offset: Option<i32>,
}

/// Query parameters for admin audit page
#[derive(Debug, Deserialize)]
struct AdminAuditQuery {
    /// Maximum number of entries to return (default: 50)
    limit: Option<i64>,
    /// Offset for pagination (default: 0)
    offset: Option<i64>,
    /// Filter by user ID
    user_id: Option<String>,
    /// Filter from date (YYYY-MM-DD format)
    from: Option<String>,
    /// Filter to date (YYYY-MM-DD format)
    to: Option<String>,
    /// Filter by success status (true/false)
    success: Option<bool>,
    /// Timezone offset in minutes from UTC (e.g., JST = 540, EST = -300)
    tz_offset: Option<i32>,
}

/// Parse date string to DateTime<Utc> with timezone offset
///
/// The `tz_offset` parameter is the user's timezone offset in minutes from UTC.
/// For example, JST (UTC+9) is 540, EST (UTC-5) is -300.
/// The date is interpreted as the start or end of day in the user's local timezone,
/// then converted to UTC for database queries.
fn parse_date(date_str: &str, end_of_day: bool, tz_offset: Option<i32>) -> Option<DateTime<Utc>> {
    NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
        .ok()
        .and_then(|date| {
            let time = if end_of_day {
                date.and_hms_opt(23, 59, 59)?
            } else {
                date.and_hms_opt(0, 0, 0)?
            };

            // Apply timezone offset: subtract the offset to convert local time to UTC
            // If user is in JST (UTC+9, offset=540), 00:00 local = 15:00 previous day UTC
            let offset_minutes = tz_offset.unwrap_or(0);
            let utc_time = time - chrono::Duration::minutes(i64::from(offset_minutes));

            Some(Utc.from_utc_datetime(&utc_time))
        })
}

/// A login history entry enriched with resolved authenticator metadata
///
/// Wraps the DB-level `LoginHistoryEntry` and adds display-ready fields
/// so the frontend can render authenticator names and icons directly
/// without needing to perform AAGUID lookups.
#[derive(Serialize)]
struct EnrichedLoginHistoryEntry {
    #[serde(flatten)]
    entry: LoginHistoryEntry,
    /// Resolved authenticator name (e.g., "Windows Hello", "YubiKey 5")
    authenticator_name: Option<String>,
    /// Resolved authenticator icon URL
    authenticator_icon: Option<String>,
}

impl EnrichedLoginHistoryEntry {
    fn masked(self, masker: &Masker) -> Self {
        let mut entry = self.entry;
        entry.user_id = masker.id(&entry.user_id);
        entry.ip_address = entry.ip_address.as_deref().map(|v| masker.ip(v));
        entry.user_agent = entry.user_agent.as_deref().map(|v| masker.user_agent(v));
        entry.email = entry.email.as_deref().map(|v| masker.email(v));
        entry.credential_id = entry.credential_id.as_deref().map(|v| masker.id(v));
        entry.provider_user_id = entry.provider_user_id.as_deref().map(|v| masker.id(v));
        Self {
            entry,
            authenticator_name: self.authenticator_name,
            authenticator_icon: self.authenticator_icon,
        }
    }
}

/// Enrich login history entries with resolved authenticator metadata
async fn enrich_login_history(entries: Vec<LoginHistoryEntry>) -> Vec<EnrichedLoginHistoryEntry> {
    // Collect unique AAGUIDs from entries
    let aaguids: Vec<String> = entries
        .iter()
        .filter_map(|e| e.aaguid.as_ref())
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let authenticators = if aaguids.is_empty() {
        HashMap::new()
    } else {
        get_authenticator_info_batch(&aaguids)
            .await
            .unwrap_or_default()
    };

    entries
        .into_iter()
        .map(|entry| {
            let (name, icon) = entry
                .aaguid
                .as_ref()
                .and_then(|aaguid| authenticators.get(aaguid))
                .map(|info| {
                    let icon_url = info.icon_light.clone().or_else(|| info.icon_dark.clone());
                    (Some(info.name.clone()), icon_url)
                })
                .unwrap_or((None, None));
            EnrichedLoginHistoryEntry {
                entry,
                authenticator_name: name,
                authenticator_icon: icon,
            }
        })
        .collect()
}

/// Create a router for user's own login history
pub(crate) fn user_router() -> Router {
    Router::new()
        .route("/login_history", get(get_my_login_history))
        .route("/login_history_page", get(login_history_page))
}

/// Create a router for admin login history endpoints
pub(crate) fn admin_router() -> Router {
    Router::new()
        .route("/user/{user_id}/login_history", get(get_user_login_history))
        .route("/audit", get(get_admin_audit))
        .route("/audit_page", get(admin_audit_page))
}

/// Handler for getting the current user's own login history
async fn get_my_login_history(
    auth_user: AuthUser,
    Query(query): Query<LoginHistoryQuery>,
) -> Result<Json<Vec<EnrichedLoginHistoryEntry>>, (StatusCode, String)> {
    let session_cookie = SessionCookie::new(auth_user.session_id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid session: {e}"),
        )
    })?;

    // Parse date filters with timezone offset
    let tz_offset = query.tz_offset;
    let from = query
        .from
        .as_ref()
        .and_then(|s| parse_date(s, false, tz_offset));
    let to = query
        .to
        .as_ref()
        .and_then(|s| parse_date(s, true, tz_offset));

    let entries = if from.is_some() || to.is_some() {
        get_own_login_history_with_date_range(&session_cookie, from, to, query.limit, query.offset)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        get_own_login_history(&session_cookie, query.limit, query.offset)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    Ok(Json(enrich_login_history(entries).await))
}

/// Template for user's login history page
#[derive(Template)]
#[template(path = "user_login_history.j2")]
struct UserLoginHistoryTemplate {
    o2p_route_prefix: String,
    custom_css_url: Option<String>,
}

/// Handler for user's login history page
async fn login_history_page(auth_user: AuthUser) -> Result<Html<String>, (StatusCode, String)> {
    let _ = auth_user; // Ensure user is authenticated

    let template = UserLoginHistoryTemplate {
        o2p_route_prefix: O2P_ROUTE_PREFIX.to_string(),
        custom_css_url: O2P_CUSTOM_CSS_URL.clone(),
    };

    template
        .render()
        .map(Html)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// Handler for admin to get any user's login history
///
/// Returns full login history with unmasked IP addresses.
async fn get_user_login_history(
    auth_user: AuthUser,
    Path(user_id): Path<String>,
    Query(query): Query<LoginHistoryQuery>,
) -> Result<Json<Vec<EnrichedLoginHistoryEntry>>, (StatusCode, String)> {
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

    let target_user_id_str = target_user_id.as_str().to_string();
    let entries =
        get_user_login_history_admin(session_id, target_user_id, query.limit, query.offset)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let enriched = enrich_login_history(entries).await;
    let masker = Masker::for_detail(&auth_user.id, &target_user_id_str);
    let enriched: Vec<_> = enriched.into_iter().map(|e| e.masked(&masker)).collect();
    Ok(Json(enriched))
}

/// Handler for admin audit page API
///
/// Returns full login history with filters for security audit.
async fn get_admin_audit(
    auth_user: AuthUser,
    Query(query): Query<AdminAuditQuery>,
) -> Result<Json<Vec<EnrichedLoginHistoryEntry>>, (StatusCode, String)> {
    if !auth_user.has_admin_privileges() {
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    let session_id = SessionId::new(auth_user.session_id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid session ID: {e}"),
        )
    })?;

    // Parse date filters with timezone offset
    let tz_offset = query.tz_offset;
    let from = query
        .from
        .as_ref()
        .and_then(|s| parse_date(s, false, tz_offset));
    let to = query
        .to
        .as_ref()
        .and_then(|s| parse_date(s, true, tz_offset));

    let entries = query_login_history_admin(
        session_id,
        query.user_id.as_deref(),
        from,
        to,
        query.success,
        query.limit,
        query.offset,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let enriched = enrich_login_history(entries).await;
    let enriched: Vec<_> = enriched
        .into_iter()
        .map(|e| {
            let masker = Masker::for_detail(&auth_user.id, &e.entry.user_id);
            e.masked(&masker)
        })
        .collect();
    Ok(Json(enriched))
}

/// Template for admin audit page
#[derive(Template)]
#[template(path = "admin_audit.j2")]
struct AdminAuditTemplate {
    o2p_route_prefix: String,
    custom_css_url: Option<String>,
}

/// Handler for admin audit page
async fn admin_audit_page(auth_user: AuthUser) -> Result<Html<String>, (StatusCode, String)> {
    if !auth_user.has_admin_privileges() {
        return Err((StatusCode::UNAUTHORIZED, "Not authorized".to_string()));
    }

    let template = AdminAuditTemplate {
        o2p_route_prefix: O2P_ROUTE_PREFIX.to_string(),
        custom_css_url: O2P_CUSTOM_CSS_URL.clone(),
    };

    template
        .render()
        .map(Html)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}
