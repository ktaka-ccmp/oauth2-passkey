use askama::Template;
use axum::{
    Extension, Router,
    http::StatusCode,
    middleware::from_fn,
    response::{Html, IntoResponse},
    routing::get,
};

use oauth2_passkey_axum::{
    AuthUser,
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
            get(p3).route_layer(from_fn(is_authenticated_redirect)),
        )
        .route(
            "/p4",
            get(p4).route_layer(from_fn(is_authenticated_user_redirect)),
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
    Html(format!("Hey {}!", user.session_user.account))
}

// Having user as an optional argument prevents redirect by axum extractor
pub(crate) async fn p2(user: Option<AuthUser>) -> impl IntoResponse {
    match user {
        Some(u) => Html(format!("Hey {}!", u.session_user.account)),
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

#[derive(Template)]
#[template(path = "p4.j2")]
struct P4Template<'a> {
    user: AuthUser,
    // user: SessionUser,
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
