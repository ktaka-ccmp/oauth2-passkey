use axum::{Router, routing::get};
use dotenvy::dotenv;

use oauth2_passkey_axum::{O2P_ROUTE_PREFIX, oauth2_passkey_router};

mod handlers;
mod server;

use crate::{
    handlers::{index, protected},
    server::{init_tracing, spawn_http_server, spawn_https_server},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install default CryptoProvider for rustls to prevent:
    // "no process-level CryptoProvider available -- call CryptoProvider::install_default() before this point"
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    init_tracing("demo_oauth2");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

    // spawn_http_server doesn't need await because it's synchronous - it immediately returns a JoinHandle
    let http_server = spawn_http_server(3001, app.clone());

    // spawn_https_server requires await because it loads TLS certificates asynchronously before returning a JoinHandle
    let https_server = spawn_https_server(3443, app).await;

    // Wait for both servers to complete (which they never will in this case)
    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}
