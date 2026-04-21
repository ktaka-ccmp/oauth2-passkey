use askama::Template;
use axum::{
    Json, Router,
    extract::{Form, Path, Query},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use axum_extra::{TypedHeader, headers};
use std::collections::HashMap;

use oauth2_passkey::{
    AuthResponse, CoordinationError, FedCMCallbackRequest, O2P_ROUTE_PREFIX, OAuth2Account,
    Provider, ProviderInfo, ProviderUserId, UserId, delete_oauth2_account_core, enabled_providers,
    fedcm_authorized_core, get_authorized_core, get_google_client_id, list_accounts_core,
    post_authorized_core, prepare_fedcm_nonce, prepare_oauth2_auth_request,
    verify_page_session_token,
};

/// Human-readable presentation data for an OAuth2 provider.
///
/// Owned by this crate so that CSS class names and display labels stay out of
/// the framework-agnostic core. Downstream crates writing custom login pages
/// can use this type directly or derive their own from `enabled_providers()`.
#[derive(Debug, Clone)]
pub struct ProviderView {
    /// URL path segment that identifies the provider (e.g. `"google"`, `"auth0"`).
    pub name: &'static str,
    /// Human-readable label for login buttons (e.g. `"Google"`, `"Auth0"`).
    pub display_name: &'static str,
    /// CSS classes for the login button (e.g. `"btn-oauth2 btn-google"`).
    pub button_class: &'static str,
}

/// Returns [`ProviderView`] for every currently enabled OAuth2 provider, in
/// stable display order (Google first, then optional providers).
pub fn enabled_provider_views() -> Vec<ProviderView> {
    enabled_providers().into_iter().map(provider_view).collect()
}

fn provider_view(info: ProviderInfo) -> ProviderView {
    ProviderView {
        name: info.name,
        display_name: info.display_name,
        button_class: info.button_class,
    }
}

/// Build the inline `:root { ... }` CSS block injecting `--o2p-custom{N}` /
/// `--o2p-custom{N}-hover` variables for every enabled generic OIDC slot.
///
/// Returns `None` if no slot is enabled (so the template can skip emitting an
/// empty `<style>` tag). Only `ProviderInfo` entries carrying
/// `Some(button_color)` contribute — named providers are styled by the base
/// CSS and theme files.
///
/// The variable suffix is extracted from the second class in `button_class`
/// (e.g. `"btn-oauth2 btn-custom1"` → `"custom1"`). This matches the
/// `.btn-custom{N}` rules declared in `o2p-base.css`.
pub fn custom_css_vars_block() -> Option<String> {
    let mut entries = Vec::new();
    for info in enabled_providers() {
        let (Some(color), Some(hover)) = (info.button_color, info.button_hover_color) else {
            continue;
        };
        let Some(suffix) = info
            .button_class
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.strip_prefix("btn-"))
        else {
            continue;
        };
        entries.push(format!(
            "    --o2p-{suffix}: {color};\n    --o2p-{suffix}-hover: {hover};"
        ));
    }
    if entries.is_empty() {
        None
    } else {
        Some(format!(":root {{\n{}\n}}", entries.join("\n")))
    }
}

use super::config::{O2P_CUSTOM_CSS_URL, O2P_FEDCM, O2P_PASSKEY_PROMOTION};
use super::error::IntoResponseError;
use super::session::AuthUser;

pub(super) fn router() -> Router {
    let router = Router::new()
        .route("/oauth2.js", get(serve_oauth2_js))
        .route("/{provider}", get(oauth2_initiate))
        .route(
            "/{provider}/authorized",
            get(get_authorized).post(post_authorized),
        )
        // Keep the old route returning 410 Gone so bookmarked links get a clear signal.
        .route("/authorized", get(gone).post(gone))
        .route("/popup_close", get(popup_close))
        .route("/accounts", get(list_oauth2_accounts))
        .route(
            "/accounts/{provider}/{provider_user_id}",
            delete(delete_oauth2_account),
        )
        .route("/select", get(oauth2_select));

    if O2P_FEDCM.is_enabled() {
        router
            .route("/fedcm/nonce", get(fedcm_nonce))
            .route("/fedcm/callback", post(fedcm_callback))
    } else {
        router
    }
}

/// Returns 410 Gone for the old `/oauth2/authorized` route.
/// Clients that followed the old redirect should update their redirect_uri.
async fn gone() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "callback URL moved",
            "new_url_pattern": "/oauth2/{provider}/authorized"
        })),
    )
}

#[derive(Template)]
#[template(path = "popup_close.j2")]
struct PopupCloseTemplate {
    message: String,
    is_error: bool,
    o2p_route_prefix: String,
}

async fn popup_close(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Html<String>, (StatusCode, String)> {
    let message = params
        .get("message")
        .cloned()
        .unwrap_or_else(|| "Authentication completed".to_string());
    let is_error = params.get("error").is_some_and(|v| v == "true");
    let template = PopupCloseTemplate {
        message,
        is_error,
        o2p_route_prefix: O2P_ROUTE_PREFIX.to_string(),
    };
    let html = Html(
        template
            .render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    Ok(html)
}

async fn serve_oauth2_js() -> Result<Response, (StatusCode, String)> {
    let static_js = include_str!("../static/oauth2.js");
    let js_content = if O2P_FEDCM.is_enabled() {
        format!(
            "const FEDCM_ENABLED = true;\nconst OAUTH2_CLIENT_ID = '{}';\n{}",
            get_google_client_id(),
            static_js
        )
    } else {
        static_js.to_string()
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.into())
        .into_response_error()
}

async fn oauth2_initiate(
    Path(provider): Path<String>,
    auth_user: Option<AuthUser>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let mode = params.get("mode").cloned();
    let context = params.get("context").cloned();

    if mode.as_deref() == Some("add_to_user") {
        if context.is_none() {
            return Err((StatusCode::BAD_REQUEST, "Missing Context".to_string()));
        }

        if auth_user.is_none() {
            return Err((StatusCode::BAD_REQUEST, "Missing Session".to_string()));
        }

        // Verify that received page_session_token (obfuscated csrf_token) as a part of query param is same as the one in the current user's session cache.
        if let Some(context_value) = &context {
            verify_page_session_token(&headers, Some(context_value))
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        }
    }

    let (auth_url, headers) = prepare_oauth2_auth_request(&provider, headers, mode.as_deref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((headers, Redirect::to(&auth_url)))
}

#[derive(Template)]
#[template(path = "select_provider.j2")]
struct SelectProviderTemplate<'a> {
    o2p_route_prefix: &'a str,
    custom_css_url: Option<&'a str>,
    custom_css_vars: Option<String>,
    providers: Vec<ProviderView>,
    mode: &'a str,
    context: &'a str,
}

async fn oauth2_select(
    auth_user: Option<AuthUser>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, (StatusCode, String)> {
    let mode = params.get("mode").cloned();
    let context = params.get("context").cloned();

    if mode.as_deref() == Some("add_to_user") {
        if context.is_none() {
            return Err((StatusCode::BAD_REQUEST, "Missing Context".to_string()));
        }
        if auth_user.is_none() {
            return Err((StatusCode::BAD_REQUEST, "Missing Session".to_string()));
        }
        if let Some(context_value) = &context {
            verify_page_session_token(&headers, Some(context_value))
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        }
    }

    let providers = enabled_provider_views();
    if providers.len() == 1 {
        let p = &providers[0];
        let url = match context.as_deref() {
            Some(ctx) => format!(
                "{}/oauth2/{}?mode={}&context={}",
                O2P_ROUTE_PREFIX.as_str(),
                p.name,
                mode.as_deref().unwrap_or(""),
                ctx
            ),
            None => format!(
                "{}/oauth2/{}?mode={}",
                O2P_ROUTE_PREFIX.as_str(),
                p.name,
                mode.as_deref().unwrap_or(""),
            ),
        };
        return Ok(Redirect::to(&url).into_response());
    }

    let tmpl = SelectProviderTemplate {
        o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
        custom_css_url: O2P_CUSTOM_CSS_URL.as_deref(),
        custom_css_vars: custom_css_vars_block(),
        providers,
        mode: mode.as_deref().unwrap_or(""),
        context: context.as_deref().unwrap_or(""),
    };
    Ok(Html(
        tmpl.render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    )
    .into_response())
}

async fn get_authorized(
    Path(provider): Path<String>,
    Query(query): Query<AuthResponse>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
) -> (HeaderMap, Redirect) {
    match get_authorized_core(&provider, &query, &cookies, &headers).await {
        Ok((response_headers, message)) => {
            let redirect_url = build_success_redirect_url(&message);
            (response_headers, Redirect::to(&redirect_url))
        }
        Err(e) => {
            tracing::warn!(error = %e, "OAuth2 authorization failed");
            let redirect_url = build_error_redirect_url(&e);
            (HeaderMap::new(), Redirect::to(&redirect_url))
        }
    }
}

/// Handler for OAuth2 callbacks using form_post response mode.
///
/// Note: Unlike the GET handler, this POST handler doesn't receive session cookies because:
/// 1. In form_post mode, the OAuth2 provider redirects the user via a POST request with form data
/// 2. This POST request is a new HTTP request from the browser to our server
/// 3. While browsers automatically include cookies in normal navigation, they don't include
///    cookies from the original request in this cross-domain POST submission
/// 4. Therefore, we can only access headers (which may contain some cookies) but not the
///    typed Cookie header that would be available in a standard browser navigation
async fn post_authorized(
    Path(provider): Path<String>,
    headers: HeaderMap,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Form(form): Form<AuthResponse>,
) -> (HeaderMap, Redirect) {
    match post_authorized_core(&provider, &form, &cookies, &headers).await {
        Ok((response_headers, message)) => {
            let redirect_url = build_success_redirect_url(&message);
            (response_headers, Redirect::to(&redirect_url))
        }
        Err(e) => {
            tracing::warn!(error = %e, "OAuth2 authorization failed (form_post)");
            let redirect_url = build_error_redirect_url(&e);
            (HeaderMap::new(), Redirect::to(&redirect_url))
        }
    }
}

/// Build the redirect URL for a successful OAuth2 authorization
fn build_success_redirect_url(message: &str) -> String {
    if O2P_PASSKEY_PROMOTION.is_enabled() {
        format!(
            "{}/passkey/promotion/popup?message={}",
            O2P_ROUTE_PREFIX.as_str(),
            urlencoding::encode(message)
        )
    } else {
        format!(
            "{}/oauth2/popup_close?message={}",
            O2P_ROUTE_PREFIX.as_str(),
            urlencoding::encode(message)
        )
    }
}

/// Build the redirect URL for a failed OAuth2 authorization
fn build_error_redirect_url(e: &CoordinationError) -> String {
    let user_message = friendly_error_message(e);
    format!(
        "{}/oauth2/popup_close?message={}&error=true",
        O2P_ROUTE_PREFIX.as_str(),
        urlencoding::encode(&user_message)
    )
}

/// Map coordination errors to user-friendly messages for popup display
fn friendly_error_message(e: &CoordinationError) -> String {
    match e {
        CoordinationError::Conflict(msg) if msg.contains("not registered") => {
            "This account is not registered. Please create an account first.".to_string()
        }
        CoordinationError::Conflict(msg) if msg.contains("already registered") => {
            "This account already exists. Please sign in instead.".to_string()
        }
        CoordinationError::Conflict(msg) if msg.contains("different user") => {
            "This account is already linked to a different user.".to_string()
        }
        _ => format!("Authentication failed: {e}"),
    }
}

/// FedCM nonce generation endpoint.
/// Returns a JSON response with a nonce for `navigator.credentials.get()`.
async fn fedcm_nonce() -> Result<Json<oauth2_passkey::FedCMNonceResponse>, (StatusCode, String)> {
    let nonce_response = prepare_fedcm_nonce()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(nonce_response))
}

/// FedCM callback endpoint.
/// Validates the JWT ID token from FedCM and establishes a session.
async fn fedcm_callback(
    headers: HeaderMap,
    Json(request): Json<FedCMCallbackRequest>,
) -> Result<(StatusCode, HeaderMap, Json<serde_json::Value>), (StatusCode, String)> {
    match fedcm_authorized_core(&request, &headers).await {
        Ok((response_headers, message)) => {
            let mut response = serde_json::json!({ "message": message });
            if O2P_PASSKEY_PROMOTION.is_enabled() {
                response["promotion_url"] = serde_json::json!(format!(
                    "{}/passkey/promotion/popup?message={}",
                    O2P_ROUTE_PREFIX.as_str(),
                    urlencoding::encode(&message)
                ));
            }
            Ok((StatusCode::OK, response_headers, Json(response)))
        }
        Err(e) => {
            tracing::warn!(error = %e, "FedCM authorization failed");
            let user_message = friendly_error_message(&e);
            Err((StatusCode::UNAUTHORIZED, user_message))
        }
    }
}

async fn list_oauth2_accounts(
    auth_user: AuthUser,
) -> Result<Json<Vec<OAuth2Account>>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser if present using deref coercion
    // let session_user = auth_user.as_ref().map(|u| u as &SessionUser);

    // Call the core function with the extracted data
    // let accounts = list_accounts_core(session_user)
    let user_id = UserId::new(auth_user.id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid user ID: {e}"),
        )
    })?;
    let accounts = list_accounts_core(user_id).await.into_response_error()?;
    Ok(Json(accounts))
}

/// Delete an OAuth2 account for the authenticated user
///
/// This endpoint requires authentication and verifies that the account
/// belongs to the authenticated user before deleting it.
async fn delete_oauth2_account(
    auth_user: AuthUser,
    Path((provider, provider_user_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let user_id = UserId::new(auth_user.id.clone()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid user ID: {e}"),
        )
    })?;
    let provider_enum = Provider::new(provider)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid provider: {e}")))?;
    let provider_user_id_enum = ProviderUserId::new(provider_user_id).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid provider user ID: {e}"),
        )
    })?;

    delete_oauth2_account_core(user_id, provider_enum, provider_user_id_enum)
        .await
        .map(|()| StatusCode::NO_CONTENT)
        .into_response_error()
}

#[cfg(test)]
mod tests;
