use askama::Template;
use axum::{
    Router,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};

use oauth2_passkey::O2P_ROUTE_PREFIX;

use crate::oauth2::{ProviderView, enabled_provider_views};

use crate::config::{O2P_CUSTOM_CSS_URL, O2P_DEFAULT_REDIRECT};
use crate::session::AuthUser;

pub(super) fn router() -> Router<()> {
    Router::new().route("/login", get(login))
}

#[derive(Template)]
#[template(path = "login.j2")]
struct LoginTemplate<'a> {
    message: &'a str,
    o2p_route_prefix: &'a str,
    custom_css_url: Option<&'a str>,
    providers: Vec<ProviderView>,
}

async fn login(user: Option<AuthUser>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(_) => Ok(Redirect::to(O2P_DEFAULT_REDIRECT.as_str()).into_response()),
        None => {
            let template = LoginTemplate {
                message: "Sign in or create an account",
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
                custom_css_url: O2P_CUSTOM_CSS_URL.as_deref(),
                providers: enabled_provider_views(),
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
