//! Passkey promotion after OAuth2 login (experimental)
//!
//! This module provides a promotion flow that encourages users to register a passkey
//! after successful OAuth2 login. It wraps the existing registration core function
//! and adds `excludeCredentials` to prevent duplicate registrations on the same authenticator.
//!
//! The promotion flow uses a library-controlled intermediate redirect page:
//! after OAuth2 login, `passkey_promotion.js` on the login page redirects to
//! `/promotion/redirect` instead of letting the page reload. This page handles the
//! UA + AAGUID heuristic check, shows a modal (ask mode) or starts registration
//! directly (force mode), then redirects to `O2P_DEFAULT_REDIRECT`.
//!
//! Controlled by `O2P_PASSKEY_PROMOTION` environment variable.
//! Values: `ask` (show modal), `force` (skip modal, direct registration), or unset/`false` (disabled).

use askama::Template;
use axum::{
    Router,
    extract::Json,
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde_json::json;

use oauth2_passkey::{
    O2P_ROUTE_PREFIX, RegistrationMode, RegistrationStartRequest, SessionUser, UserId,
    get_authenticator_info_batch, handle_start_registration_core, list_credentials_core,
};

use super::config::{O2P_CUSTOM_CSS_URL, O2P_DEFAULT_REDIRECT};
use super::error::IntoResponseError;
use super::session::AuthUser;

/// Create a router for passkey promotion endpoints
///
/// Routes:
/// - `GET /promotion/redirect` - Intermediate redirect page for promotion flow
/// - `POST /promotion/register/start` - Start registration with excludeCredentials
/// - `GET /promotion/check` - Check if promotion modal should be shown (UA + AAGUID heuristic)
/// - `GET /promotion/passkey_promotion.js` - Serve the promotion JavaScript (for login page)
pub(super) fn router() -> Router {
    Router::new()
        .route("/promotion/redirect", get(promotion_redirect))
        .route(
            "/promotion/register/start",
            post(promotion_start_registration),
        )
        .route("/promotion/check", get(promotion_check))
        .route(
            "/promotion/passkey_promotion.js",
            get(serve_passkey_promotion_js),
        )
}

#[derive(Template)]
#[template(path = "promotion_redirect.j2")]
struct PromotionRedirectTemplate<'a> {
    o2p_route_prefix: &'a str,
    csrf_token: &'a str,
    default_redirect: &'a str,
    custom_css_url: Option<&'a str>,
}

/// Serve the passkey promotion intermediate redirect page
///
/// This page handles the entire promotion flow after OAuth2 login:
/// 1. Calls the check endpoint to determine if promotion is needed
/// 2. Shows a modal (ask mode) or starts registration directly (force mode)
/// 3. Redirects to `O2P_DEFAULT_REDIRECT` after completion
///
/// If the user is not authenticated, redirects to the login page.
async fn promotion_redirect(user: Option<AuthUser>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(auth_user) => {
            let template = PromotionRedirectTemplate {
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
                csrf_token: &auth_user.csrf_token,
                default_redirect: O2P_DEFAULT_REDIRECT.as_str(),
                custom_css_url: O2P_CUSTOM_CSS_URL.as_deref(),
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html.into_response())
        }
        None => {
            Ok(Redirect::to(&format!("{}/user/login", O2P_ROUTE_PREFIX.as_str())).into_response())
        }
    }
}

/// Check whether the passkey promotion modal should be shown
///
/// Uses a heuristic based on the User-Agent header and the user's existing credential
/// AAGUIDs to determine if the user likely already has a passkey accessible on the
/// current platform/browser. Returns `{ "should_promote": true/false }`.
///
/// This is a best-effort heuristic — not perfect, but significantly reduces unnecessary
/// prompts. The actual duplicate prevention is handled by `excludeCredentials` in the
/// registration flow.
async fn promotion_check(
    auth_user: AuthUser,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mode = if super::config::O2P_PASSKEY_PROMOTION.is_force() {
        "force"
    } else {
        "ask"
    };

    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let user_id = UserId::new(auth_user.id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid user ID: {e}"),
        )
    })?;

    let credentials = list_credentials_core(user_id).await.into_response_error()?;

    // If user has no passkey credentials at all, always promote
    if credentials.is_empty() {
        return Ok(Json(json!({ "should_promote": true, "mode": mode })));
    }

    // Get authenticator info for all AAGUIDs
    let unique_aaguids: Vec<String> = credentials.iter().map(|c| c.aaguid.clone()).collect();
    let auth_info_map = get_authenticator_info_batch(&unique_aaguids)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to fetch authenticator info: {e}"),
            )
        })?;

    // Check if any credential is likely available on the current platform
    let has_available_credential = credentials.iter().any(|c| {
        let name = auth_info_map
            .get(&c.aaguid)
            .map(|info| info.name.as_str())
            .unwrap_or("");
        is_credential_likely_available(name, ua)
    });

    Ok(Json(
        json!({ "should_promote": !has_available_credential, "mode": mode }),
    ))
}

/// Determine if a credential is likely available on the current device based on
/// the authenticator name and User-Agent string.
///
/// This is a best-effort heuristic using keyword matching. It categorizes authenticators
/// into platform families and matches against the UA:
///
/// - **Cross-platform password managers** (1Password, Bitwarden, etc.) → always available
/// - **Apple ecosystem** (iCloud Keychain) → available on macOS, iOS, iPadOS
/// - **Google ecosystem** (Google Password Manager) → available on Android, Chrome
/// - **Windows** (Windows Hello) → available on Windows only
/// - **Unknown** → conservatively assumed not available
fn is_credential_likely_available(authenticator_name: &str, ua: &str) -> bool {
    let name_lower = authenticator_name.to_lowercase();
    let ua_lower = ua.to_lowercase();

    // Cross-platform password managers - available everywhere
    const CROSS_PLATFORM_KEYWORDS: &[&str] = &[
        "1password",
        "bitwarden",
        "dashlane",
        "enpass",
        "keepassxc",
        "keeper",
        "lastpass",
        "logmeonce",
        "nordpass",
        "proton pass",
        "zoho vault",
        "kaspersky",
        "ipasswords",
        "devolutions",
    ];
    if CROSS_PLATFORM_KEYWORDS
        .iter()
        .any(|kw| name_lower.contains(kw))
    {
        return true;
    }

    // Apple ecosystem (iCloud Keychain syncs across Apple devices)
    if name_lower.contains("icloud") || name_lower.contains("apple") {
        return ua_lower.contains("macintosh")
            || ua_lower.contains("iphone")
            || ua_lower.contains("ipad");
    }

    // Google ecosystem (Google PM syncs across Android + Chrome)
    if name_lower.contains("google") {
        return ua_lower.contains("android")
            || ua_lower.contains("cros")
            || ua_lower.contains("chrome/");
    }

    // Samsung (Android only)
    if name_lower.contains("samsung") {
        return ua_lower.contains("android");
    }

    // Windows Hello (Windows only, device-bound)
    if name_lower.contains("windows") || name_lower.contains("microsoft") {
        return ua_lower.contains("windows");
    }

    // Browser-specific authenticators
    if name_lower.contains("chrome on") || name_lower.contains("chromium") {
        return ua_lower.contains("chrome/");
    }
    if name_lower.contains("edge on") {
        return ua_lower.contains("edg/");
    }

    // Unknown authenticator - can't determine, assume not available
    false
}

/// Start passkey registration for promotion flow
///
/// This handler wraps `handle_start_registration_core()` and appends `excludeCredentials`
/// from the user's existing credentials. The authenticator will reject with `InvalidStateError`
/// if it already has a matching credential, eliminating the need for server-side per-device detection.
///
/// Requires authentication (AddToUser mode only).
async fn promotion_start_registration(
    auth_user: AuthUser,
    Json(request): Json<RegistrationStartRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Only allow AddToUser mode for promotion
    if request.mode != RegistrationMode::AddToUser {
        return Err((
            StatusCode::BAD_REQUEST,
            "Promotion registration only supports add_to_user mode".to_string(),
        ));
    }

    let session_user = SessionUser::from(&auth_user);

    // Call existing core function unchanged
    let registration_options = handle_start_registration_core(Some(&session_user), request)
        .await
        .into_response_error()?;

    // Serialize to JSON
    let mut options_json = serde_json::to_value(&registration_options).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to serialize registration options: {e}"),
        )
    })?;

    // Append excludeCredentials from user's existing credentials
    let user_id = UserId::new(auth_user.id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid user ID: {e}"),
        )
    })?;

    let credentials = list_credentials_core(user_id).await.into_response_error()?;

    let exclude_credentials: Vec<serde_json::Value> = credentials
        .iter()
        .map(|c| {
            json!({
                "type_": "public-key",
                "id": c.credential_id
            })
        })
        .collect();

    options_json["excludeCredentials"] = json!(exclude_credentials);

    Ok(Json(options_json))
}

/// Serve the passkey promotion JavaScript file
async fn serve_passkey_promotion_js() -> Response {
    let js_content = include_str!("../static/passkey_promotion.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .unwrap_or_else(|_| Response::new("Failed to build response".into()))
}

#[cfg(test)]
mod tests;
