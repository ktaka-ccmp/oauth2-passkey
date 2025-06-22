use askama::Template;
use axum::{
    http::StatusCode,
    response::Html,
    routing::{Router, get},
};
use axum_core::response::IntoResponse;
use dotenvy::dotenv;

use oauth2_passkey_axum::{AuthUser, O2P_ROUTE_PREFIX, oauth2_passkey_router};

mod server;
use crate::server::{init_tracing, spawn_http_server, spawn_https_server};

#[derive(Template)]
#[template(path = "index_anon.j2")]
struct IndexAnonTemplate<'a> {
    message: &'a str,
    o2p_route_prefix: &'static str,
}

#[derive(Template)]
#[template(path = "index_user.j2")]
struct IndexUserTemplate<'a> {
    message: &'a str,
    o2p_route_prefix: &'static str,
}

async fn index(user: Option<AuthUser>) -> impl IntoResponse {
    match user {
        Some(u) => {
            let template = IndexUserTemplate {
                message: &format!("Hello, {}!", u.account),
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            (StatusCode::OK, Html(template.render().unwrap())).into_response()
        }
        None => {
            let template = IndexAnonTemplate {
                message: "Hello, anonymous user",
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            (StatusCode::OK, Html(template.render().unwrap())).into_response()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    init_tracing("demo_passkey");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

    // spawn_http_server doesn't need await because it's synchronous - it immediately returns a JoinHandle
    let http_server = spawn_http_server(3001, app.clone());

    // spawn_https_server requires await because it loads TLS certificates asynchronously before returning a JoinHandle
    let https_server = spawn_https_server(3443, app).await;

    // Wait for both servers to complete (which they never will in this case)
    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}
