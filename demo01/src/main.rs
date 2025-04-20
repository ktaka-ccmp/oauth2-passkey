use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};

use dotenv::dotenv;

use oauth2_passkey_axum::{
    AuthUser, O2P_ADMIN_URL, O2P_LOGIN_URL, O2P_ROUTE_PREFIX, O2P_SUMMARY_URL,
    oauth2_passkey_router,
};

mod protected;
mod server;
use server::{init_tracing, spawn_http_server, spawn_https_server};

// O2P_LOGIN_URL is /o2p/user/login and O2P_SUMMARY_URL is /o2p/user/summary by default
async fn index(user: Option<AuthUser>) -> Result<Response, (StatusCode, String)> {
    match user {
        Some(_) => Ok(Redirect::to(O2P_SUMMARY_URL.as_str()).into_response()),
        None => Ok(Redirect::to(O2P_LOGIN_URL.as_str()).into_response()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    init_tracing("demo01");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
        .merge(protected::router());

    let http_server = spawn_http_server(3001, app.clone());
    let https_server = spawn_https_server(3443, app).await;

    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}
