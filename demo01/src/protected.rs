use askama::Template;
use axum::extract::Form;
use axum::{
    Extension, Router,
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::from_fn,
    response::{Html, IntoResponse},
    routing::get,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use oauth2_passkey_axum::{
    AuthUser,
    CsrfHeaderVerified,
    CsrfToken,
    O2P_ROUTE_PREFIX,
    // Middleware, redirect to O2P_REDIRECT_ANON(default: /)
    is_authenticated_redirect,
    is_authenticated_user_redirect,
};

pub(super) fn router() -> Router<()> {
    Router::new()
        .route("/p1", get(p1))
        .route("/p2", get(p2))
        .route(
            "/p3",
            get(p3)
                .post(p3_post)
                .route_layer(from_fn(is_authenticated_redirect)),
        )
        .route(
            "/p4",
            get(p4).route_layer(from_fn(is_authenticated_user_redirect)),
        )
        .route(
            "/p5",
            get(p5).route_layer(from_fn(is_authenticated_redirect)),
        )
        .route(
            "/p6",
            get(p6)
                .post(p6_post)
                .route_layer(from_fn(is_authenticated_redirect)),
        )
        .nest(
            "/nested",
            nested_router().route_layer(from_fn(is_authenticated_redirect)),
        )
}

pub(super) fn nested_router() -> Router<()> {
    Router::new().route("/p3", get(p3))
}

// Having user as an argument causes redirect to O2P_LOGIN_URL for anonymous users by axum extractor
pub(crate) async fn p1(user: AuthUser) -> impl IntoResponse {
    let html_content = format!(
        "Hey {}!<br/>Your CSRF Token is: {}",
        user.account, user.csrf_token
    );

    // DEMO: Manually adding CSRF token to response headers
    // When using AuthUser extractor (not middleware), you must deliver CSRF tokens via one of:
    // 1. Embed in page content (like showing token in HTML - see line above)
    // 2. X-CSRF-Token response header (demonstrated here)
    // 3. Dedicated endpoint /o2p/user/csrf_token (for SPAs)
    //
    // Middleware-protected routes (p3-p6) get automatic X-CSRF-Token headers,
    // but extractor-protected routes (p1, p2) require manual token delivery.
    let mut headers = HeaderMap::new();
    match HeaderValue::from_str(&user.csrf_token) {
        Ok(header_value) => {
            headers.insert("X-CSRF-Token", header_value);
        }
        Err(e) => {
            tracing::warn!("Failed to create CSRF header value: {}", e);
            // Continue without the header - client will need to use the token from page content
        }
    }

    (headers, Html(html_content))
}

// Having user as an optional argument prevents redirect by axum extractor
pub(crate) async fn p2(user: Option<AuthUser>) -> impl IntoResponse {
    match user {
        Some(u) => Html(format!(
            "Hey {}!<br/>Your CSRF Token is: {}",
            u.account, u.csrf_token
        )),
        None => Html("Hey Anonymous User!".to_string()),
    }
}

#[derive(Template)]
#[template(path = "p3.j2")]
struct P3Template<'a> {
    message: &'a str,
    prefix: &'a str,
}

// Protected page by middleware does not need user argument
pub(crate) async fn p3() -> impl IntoResponse {
    let template = P3Template {
        message: "This is a protected page.",
        prefix: O2P_ROUTE_PREFIX.as_str(),
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub(crate) async fn p3_post() -> impl IntoResponse {
    Html("POST request received").into_response()
}

#[derive(Template)]
#[template(path = "p4.j2")]
struct P4Template<'a> {
    user: AuthUser,
    prefix: &'a str,
}

// Extract user from extension inserted by is_authenticated_with_user middleware
pub(crate) async fn p4(Extension(user): Extension<AuthUser>) -> impl IntoResponse {
    let template = P4Template {
        user,
        prefix: O2P_ROUTE_PREFIX.as_str(),
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Template)]
#[template(path = "p5.j2")]
struct P5Template<'a> {
    message: &'a str,
    csrf_token: &'a str,
    prefix: &'a str,
}

// Protected page by middleware does not need user argument
pub(crate) async fn p5(Extension(csrf_token): Extension<CsrfToken>) -> impl IntoResponse {
    let template = P5Template {
        message: "The CSRF token can also be embedded in a template.",
        csrf_token: csrf_token.as_str(),
        prefix: O2P_ROUTE_PREFIX.as_str(),
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// New struct for p6 form data
#[derive(Deserialize, Debug)]
pub(crate) struct P6FormData {
    message: String,
    csrf_token: Option<String>,
}

#[derive(Template)]
#[template(path = "p6.j2")]
struct P6Template<'a> {
    csrf_token: &'a str,
    prefix: &'a str,
    post_result_message: Option<String>,
    post_success: bool,
}

// GET handler for /p6
pub(crate) async fn p6(
    Extension(csrf_token): Extension<CsrfToken>,
    // Extension(csrf_via_header_verified): Extension<CsrfHeaderVerified>,
    // Extension(user): Extension<AuthUser>,
) -> impl IntoResponse {
    let template = P6Template {
        csrf_token: csrf_token.as_str(),
        prefix: O2P_ROUTE_PREFIX.as_str(),
        post_result_message: None,
        post_success: false,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// POST handler for /p6
pub(crate) async fn p6_post(
    Extension(csrf_token): Extension<CsrfToken>,
    Extension(csrf_via_header_verified): Extension<CsrfHeaderVerified>,
    // Extension(user): Extension<AuthUser>,
    Form(form_data): Form<P6FormData>,
) -> impl IntoResponse {
    let post_result_message_str: String;
    let mut is_success = false;

    tracing::info!(
        "p6_post received: {:?}, CSRF via header: {}",
        form_data,
        csrf_token.as_str()
    );

    if csrf_via_header_verified.0 {
        // This case should ideally not happen for a direct form post without X-CSRF-Token header.
        post_result_message_str = format!(
            "POST successful (CSRF token verified via X-CSRF-Token header). Message: {}",
            form_data.message
        );
        is_success = true;
        tracing::info!("{}", post_result_message_str);
    } else {
        // X-CSRF-Token header was NOT present or not verified.
        // Middleware allowed the request because Content-Type was form-like.
        // We MUST manually verify the CSRF token from the form body.
        match &form_data.csrf_token {
            Some(token_from_form) => {
                if token_from_form
                    .as_bytes()
                    .ct_eq(csrf_token.as_str().as_bytes())
                    .into()
                {
                    post_result_message_str = format!(
                        "POST successful (CSRF token from form field verified). Message: {}",
                        form_data.message
                    );
                    is_success = true;
                    tracing::info!("{}", post_result_message_str);
                } else {
                    post_result_message_str = format!(
                        "CSRF token mismatch! Form token: '{}', Expected: '{}'. Message: {}",
                        token_from_form,
                        csrf_token.as_str(),
                        form_data.message
                    );
                    // is_success remains false
                    tracing::warn!("{}", post_result_message_str);
                }
            }
            None => {
                post_result_message_str = format!(
                    "CSRF token missing from form! This request would typically be rejected. Message: {}",
                    form_data.message
                );
                // is_success remains false
                tracing::warn!("{}", post_result_message_str);
            }
        }
    }

    // Re-render the page with the result message
    let template = P6Template {
        csrf_token: csrf_token.as_str(),
        prefix: O2P_ROUTE_PREFIX.as_str(),
        post_result_message: Some(post_result_message_str),
        post_success: is_success,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
