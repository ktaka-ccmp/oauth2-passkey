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
    csrf_token: &'a str,
    passkey_promotion_enabled: bool,
}

// O2P_LOGIN_URL is /o2p/user/login and O2P_ACCOUNT_URL is /o2p/user/account by default
async fn index(user: Option<AuthUser>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(auth_user) => {
            let template = IndexTemplate {
                message: "This is a protected page.",
                prefix: O2P_ROUTE_PREFIX.as_str(),
                custom_css_url: O2P_CUSTOM_CSS_URL.as_deref(),
                csrf_token: &auth_user.csrf_token,
                passkey_promotion_enabled: passkey_promotion_enabled(),
            };
            match template.render() {
                Ok(html) => Ok(Html(html).into_response()),
                Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
            }
        }
        None => Ok(Redirect::to(O2P_LOGIN_URL.as_str()).into_response()),
    }
}

fn passkey_promotion_enabled() -> bool {
    std::env::var("O2P_PASSKEY_PROMOTION")
        .map(|val| val.to_lowercase() == "true")
        .unwrap_or(false)
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

    spawn_http_server(3001, app).await?;
    Ok(())
}
