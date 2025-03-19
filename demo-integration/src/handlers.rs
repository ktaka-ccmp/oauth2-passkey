use askama::Template;
use axum::{http::StatusCode, response::Html};
use liboauth2::OAUTH2_ROUTE_PREFIX;
use libpasskey::PASSKEY_ROUTE_PREFIX;

// use libsession::User;
use libaxum::AuthUser as User;

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

pub(crate) async fn index(user: Option<User>) -> Result<Html<String>, (StatusCode, String)> {
    match user {
        Some(u) => {
            let message = format!("Hey {}!", u.account);
            let template = IndexTemplateUser {
                // user: u.clone(),
                message: &message,
                oauth_route_prefix: OAUTH2_ROUTE_PREFIX.as_str(),
                passkey_route_prefix: PASSKEY_ROUTE_PREFIX.as_str(),
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html)
        }
        None => {
            let message = "Click the Login button below.".to_string();
            let template = IndexTemplateAnon {
                message: &message,
                oauth_route_prefix: OAUTH2_ROUTE_PREFIX.as_str(),
                passkey_route_prefix: PASSKEY_ROUTE_PREFIX.as_str(),
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html)
        }
    }
}

pub(crate) async fn protected(user: User) -> Result<Html<String>, (StatusCode, String)> {
    let template = ProtectedTemplate {
        user,
        oauth_route_prefix: OAUTH2_ROUTE_PREFIX.as_str(),
    };
    let html = Html(
        template
            .render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    Ok(html)
}
