use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use oauth2_passkey::O2P_ROUTE_PREFIX;

use crate::config::O2P_REDIRECT_USER;
use crate::session::AuthUser as User;

#[derive(Template)]
#[template(path = "login.j2")]
struct LoginTemplate<'a> {
    message: &'a str,
    o2p_route_prefix: &'a str,
}

pub(super) async fn login(user: Option<User>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(_) => Ok(Redirect::to(O2P_REDIRECT_USER.as_str()).into_response()),
        None => {
            let template = LoginTemplate {
                message: "Passkey/OAuth2 Login Page!",
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
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
