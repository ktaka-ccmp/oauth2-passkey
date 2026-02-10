use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};

use dotenvy::dotenv;

use oauth2_passkey_axum::{
    AuthUser, O2P_CUSTOM_CSS_URL, O2P_LOGIN_URL, O2P_ROUTE_PREFIX, oauth2_passkey_full_router,
};

mod protected;
mod server;
use askama::Template;
use axum::response::Html;
use server::{init_tracing, spawn_http_server};

#[derive(Template)]
#[template(path = "index.j2")]
struct IndexTemplate<'a> {
    message: &'a str,
    prefix: &'a str,
    custom_css_url: Option<&'a str>,
}

// O2P_LOGIN_URL is /o2p/user/login and O2P_ACCOUNT_URL is /o2p/user/account by default
async fn index(user: Option<AuthUser>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(_) => {
            let template = IndexTemplate {
                message: "This is a protected page.",
                prefix: O2P_ROUTE_PREFIX.as_str(),
                custom_css_url: O2P_CUSTOM_CSS_URL.as_deref(),
            };
            match template.render() {
                Ok(html) => Ok(Html(html).into_response()),
                Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
            }
        }
        None => Ok(Redirect::to(O2P_LOGIN_URL.as_str()).into_response()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing("demo-both");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .merge(oauth2_passkey_full_router())
        .merge(protected::router());

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);
    spawn_http_server(port, app).await?;
    Ok(())
}
