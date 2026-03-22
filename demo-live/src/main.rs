use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};

use dotenvy::dotenv;

use oauth2_passkey_axum::{
    AuthUser, O2P_CUSTOM_CSS_URL, O2P_ROUTE_PREFIX, oauth2_passkey_full_router,
    spawn_login_history_cleanup,
};

mod server;
use askama::Template;
use axum::response::Html;
use server::{init_tracing, spawn_http_server};

#[derive(Template)]
#[template(path = "login.j2")]
struct LoginTemplate<'a> {
    o2p_route_prefix: &'a str,
    custom_css_url: Option<&'a str>,
}

async fn login(user: Option<AuthUser>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(_) => Ok(Redirect::to("/").into_response()),
        None => {
            let template = LoginTemplate {
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
                custom_css_url: O2P_CUSTOM_CSS_URL.as_deref(),
            };
            Ok(Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            )
            .into_response())
        }
    }
}

#[derive(Template)]
#[template(path = "index.j2")]
struct IndexTemplate<'a> {
    user_name: &'a str,
    prefix: &'a str,
    custom_css_url: Option<&'a str>,
}

// AuthUser extractor redirects unauthenticated users to O2P_LOGIN_URL automatically
// Set O2P_LOGIN_URL=/login in .env since login-ui feature is disabled
async fn index(user: AuthUser) -> Result<Response, (StatusCode, String)> {
    let template = IndexTemplate {
        user_name: &user.label,
        prefix: O2P_ROUTE_PREFIX.as_str(),
        custom_css_url: O2P_CUSTOM_CSS_URL.as_deref(),
    };
    match template.render() {
        Ok(html) => Ok(Html(html).into_response()),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing("demo-live");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    spawn_login_history_cleanup();

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login))
        .merge(oauth2_passkey_full_router());

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);
    spawn_http_server(port, app).await?;
    Ok(())
}
