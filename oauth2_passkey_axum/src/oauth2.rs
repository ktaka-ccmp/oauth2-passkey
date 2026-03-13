use askama::Template;
use axum::{
    Json, Router,
    extract::{Form, Path, Query},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, Redirect, Response},
    routing::delete,
    routing::get,
};
use axum_extra::{TypedHeader, headers};
use std::collections::HashMap;

use oauth2_passkey::{
    AuthResponse, CoordinationError, FedCMCallbackRequest, O2P_ROUTE_PREFIX, OAuth2Account,
    Provider, ProviderUserId, UserId, delete_oauth2_account_core, fedcm_authorized_core,
    get_authorized_core, get_google_client_id, list_accounts_core, post_authorized_core,
    prepare_fedcm_nonce, prepare_oauth2_auth_request, verify_page_session_token,
};

use super::config::{O2P_FEDCM, O2P_PASSKEY_PROMOTION};
use super::error::IntoResponseError;
use super::session::AuthUser;

pub(super) fn router() -> Router {
    let router = Router::new()
        .route("/oauth2.js", get(serve_oauth2_js))
        .route("/google", get(google_auth))
        .route("/authorized", get(get_authorized).post(post_authorized))
        .route("/popup_close", get(popup_close))
        .route("/accounts", get(list_oauth2_accounts))
        .route(
            "/accounts/{provider}/{provider_user_id}",
            delete(delete_oauth2_account),
        );

    if O2P_FEDCM.is_enabled() {
        router
            .route("/fedcm/nonce", get(fedcm_nonce))
            .route("/fedcm/callback", axum::routing::post(fedcm_callback))
    } else {
        router
    }
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

async fn google_auth(
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

    let (auth_url, headers) = prepare_oauth2_auth_request(headers, mode.as_deref())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((headers, Redirect::to(&auth_url)))
}

async fn get_authorized(
    Query(query): Query<AuthResponse>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
) -> (HeaderMap, Redirect) {
    match get_authorized_core(&query, &cookies, &headers).await {
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
    headers: HeaderMap,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Form(form): Form<AuthResponse>,
) -> (HeaderMap, Redirect) {
    match post_authorized_core(&form, &cookies, &headers).await {
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
