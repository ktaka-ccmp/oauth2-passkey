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

use libauth::{
    AuthResponse, OAUTH2_ROUTE_PREFIX, OAuth2Account, prepare_oauth2_auth_request,
    verify_context_token_and_page,
};

use libauth::{
    delete_oauth2_account_core, get_authorized_core, list_accounts_core, post_authorized_core,
    prepare_logout_response,
};

use libsession::User as SessionUser;

use crate::AuthUser;

// Helper trait for converting errors to a standard response error format
trait IntoResponseError<T> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)>;
}

impl<T, E: std::fmt::Display> IntoResponseError<T> for Result<T, E> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)> {
        self.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/oauth2.js", get(serve_oauth2_js))
        .route("/google", get(google_auth))
        .route("/authorized", get(get_authorized).post(post_authorized))
        .route("/popup_close", get(popup_close))
        .route("/logout", get(logout))
        .route("/accounts", get(list_oauth2_accounts))
        .route(
            "/accounts/{provider}/{provider_user_id}",
            delete(delete_oauth2_account),
        )
}

#[derive(Template)]
#[template(path = "popup_close.j2")]
struct PopupCloseTemplate {
    message: String,
}

pub(crate) async fn popup_close(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Html<String>, (StatusCode, String)> {
    let message = params
        .get("message")
        .cloned()
        .unwrap_or_else(|| "Authentication completed".to_string());
    let template = PopupCloseTemplate { message };
    let html = Html(template.render().into_response_error()?);
    Ok(html)
}

pub(crate) async fn serve_oauth2_js() -> Result<Response, (StatusCode, String)> {
    let js_content = include_str!("../../static/oauth2.js");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript")
        .body(js_content.to_string().into())
        .into_response_error()
}

pub(crate) async fn google_auth(
    auth_user: Option<AuthUser>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let mode = params.get("mode").cloned();
    let context = params.get("context").cloned();

    if mode.is_some() && mode.as_ref().unwrap() == "add_to_existing_user" {
        if context.is_none() {
            return Err((StatusCode::BAD_REQUEST, "Missing context".to_string()));
        }

        let session_user = auth_user.as_ref().map(|u| u as &SessionUser);
        let user_id: String = session_user.map(|u| u.id.clone()).unwrap_or_default();

        // Verify the user context token
        verify_context_token_and_page(&headers, Some(&context.unwrap()), &user_id)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    }

    let (auth_url, headers) = prepare_oauth2_auth_request(headers)
        .await
        .into_response_error()?;

    Ok((headers, Redirect::to(&auth_url)))
}

pub async fn logout(
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let headers = prepare_logout_response(cookies)
        .await
        .into_response_error()?;
    Ok((headers, Redirect::to("/")))
}

pub async fn get_authorized(
    Query(query): Query<AuthResponse>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let (headers, message) = get_authorized_core(&query, &cookies, &headers).await?;

    Ok((
        headers,
        Redirect::to(&format!(
            "{}/popup_close?message={}",
            OAUTH2_ROUTE_PREFIX.as_str(),
            urlencoding::encode(&message)
        )),
    ))
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
pub async fn post_authorized(
    headers: HeaderMap,
    Form(form): Form<AuthResponse>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let (headers, message) = post_authorized_core(&form, &headers).await?;

    Ok((
        headers,
        Redirect::to(&format!(
            "{}/popup_close?message={}",
            OAUTH2_ROUTE_PREFIX.as_str(),
            urlencoding::encode(&message)
        )),
    ))
}

pub async fn list_oauth2_accounts(
    auth_user: Option<AuthUser>,
) -> Result<Json<Vec<OAuth2Account>>, (StatusCode, String)> {
    // Convert AuthUser to SessionUser if present using deref coercion
    let session_user = auth_user.as_ref().map(|u| u as &SessionUser);

    // Call the core function with the extracted data
    let accounts = list_accounts_core(session_user).await?;
    Ok(Json(accounts))
}

/// Delete an OAuth2 account for the authenticated user
///
/// This endpoint requires authentication and verifies that the account
/// belongs to the authenticated user before deleting it.
pub async fn delete_oauth2_account(
    auth_user: Option<AuthUser>,
    Path((provider, provider_user_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let session_user = auth_user.as_ref().map(|u| u as &SessionUser);

    delete_oauth2_account_core(session_user, &provider, &provider_user_id)
        .await
        .map_err(|e| (e.0, e.1))
        .map(|()| StatusCode::NO_CONTENT)
}
