use askama::Template;
use axum::{
    extract::Extension,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use oauth2_passkey::{O2P_ROUTE_PREFIX, OAUTH2_SUB_ROUTE, PASSKEY_SUB_ROUTE, SUMMARY_SUB_ROUTE};

// User extracted from session by libaxum crate
use oauth2_passkey_axum::AuthUser as User;

#[derive(Template)]
#[template(path = "index_user.j2")]
struct IndexTemplateUser<'a> {
    // user: User,
    message: &'a str,
    oauth_route_prefix: &'a str,
    passkey_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "index_anon.j2")]
struct IndexTemplateAnon<'a> {
    message: &'a str,
    oauth_route_prefix: &'a str,
    passkey_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "protected.j2")]
struct ProtectedTemplate<'a> {
    user: User,
    oauth_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "p1.j2")]
struct P1Template<'a> {
    oauth_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "p2.j2")]
struct P2Template<'a> {
    user: User,
    oauth_route_prefix: &'a str,
}

pub(crate) async fn index(user: Option<User>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(u) => {
            let message = format!("Hey {}!", u.account);
            // Create the route strings first so they live long enough
            let oauth_route = format!("{}{}", O2P_ROUTE_PREFIX.as_str(), OAUTH2_SUB_ROUTE);
            let passkey_route = format!("{}{}", O2P_ROUTE_PREFIX.as_str(), PASSKEY_SUB_ROUTE);

            let template = IndexTemplateUser {
                // user: u.clone(),
                message: &message,
                oauth_route_prefix: &oauth_route,
                passkey_route_prefix: &passkey_route,
            };
            let _html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            // Ok(html.into_response())
            let summary_route = format!("{}{}", O2P_ROUTE_PREFIX.as_str(), SUMMARY_SUB_ROUTE);
            Ok(Redirect::to(&summary_route).into_response())
        }
        None => {
            // Create the route strings first so they live long enough
            let oauth_route = format!("{}{}", O2P_ROUTE_PREFIX.as_str(), OAUTH2_SUB_ROUTE);
            let passkey_route = format!("{}{}", O2P_ROUTE_PREFIX.as_str(), PASSKEY_SUB_ROUTE);

            let template = IndexTemplateAnon {
                message: "Passkey/OAuth2 integration demo!",
                oauth_route_prefix: &oauth_route,
                passkey_route_prefix: &passkey_route,
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html.into_response())
        }
    }
}

pub(crate) async fn protected(user: User) -> Result<Html<String>, (StatusCode, String)> {
    // Create the route string first so it lives long enough
    let oauth_route = format!("{}{}", O2P_ROUTE_PREFIX.as_str(), OAUTH2_SUB_ROUTE);

    let template = ProtectedTemplate {
        user,
        oauth_route_prefix: &oauth_route,
    };
    let html = Html(
        template
            .render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    Ok(html)
}

pub(crate) async fn p1() -> Result<Html<String>, (StatusCode, String)> {
    let oauth_route = format!("{}{}", O2P_ROUTE_PREFIX.as_str(), OAUTH2_SUB_ROUTE);

    let template = P1Template {
        oauth_route_prefix: &oauth_route,
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
    Extension(user): Extension<User>,
) -> Result<Html<String>, (StatusCode, String)> {
    let oauth_route = format!("{}{}", O2P_ROUTE_PREFIX.as_str(), OAUTH2_SUB_ROUTE);

    tracing::debug!("User: {:?}", user);
    let template = P2Template {
        user,
        oauth_route_prefix: &oauth_route,
    };
    let html = Html(
        template
            .render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    Ok(html)
}
