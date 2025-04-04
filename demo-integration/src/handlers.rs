use askama::Template;
use axum::{
    extract::Extension,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};

use oauth2_passkey_axum::{AuthUser, O2P_LOGIN_URL, O2P_ROUTE_PREFIX, O2P_SUMMARY_URL};

#[derive(Template)]
#[template(path = "protected.j2")]
struct ProtectedTemplate<'a> {
    user: AuthUser,
    o2p_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "p1.j2")]
struct P1Template<'a> {
    o2p_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "p2.j2")]
struct P2Template<'a> {
    user: AuthUser,
    o2p_route_prefix: &'a str,
}

pub(crate) async fn index(user: Option<AuthUser>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(_) => Ok(Redirect::to(O2P_SUMMARY_URL.as_str()).into_response()),
        None => Ok(Redirect::to(O2P_LOGIN_URL.as_str()).into_response()),
    }
}

pub(crate) async fn protected(user: AuthUser) -> Result<Html<String>, (StatusCode, String)> {
    let template = ProtectedTemplate {
        user,
        o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
    };
    let html = Html(
        template
            .render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    Ok(html)
}

pub(crate) async fn p1() -> Result<Html<String>, (StatusCode, String)> {
    let template = P1Template {
        o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
    };
    let html = Html(
        template
            .render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    Ok(html)
}

pub(crate) async fn p2(
    // Extract user from extension inserted by is_authenticated_with_user middleware
    Extension(user): Extension<AuthUser>,
) -> Result<Html<String>, (StatusCode, String)> {
    tracing::debug!("User: {:?}", user);
    let template = P2Template {
        user,
        o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
    };
    let html = Html(
        template
            .render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    Ok(html)
}

// Example handler that will redirect to a page defined by AuthRedirect when user is not authenticated
pub(crate) async fn p3(user: AuthUser) -> impl IntoResponse {
    Html(format!("Hey {}!", user.account))
}

// Example handler that will show a message when user is not authenticated
pub(crate) async fn p4(user: Option<AuthUser>) -> impl IntoResponse {
    match user {
        Some(u) => Html(format!("Hey {}!", u.account)),
        None => Html("Not Authenticated!".to_string()),
    }
}
