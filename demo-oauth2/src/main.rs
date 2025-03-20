use axum::{Router, routing::get};
use dotenv::dotenv;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use libaxum::oauth2_router;
use oauth2_passkey::{OAUTH2_ROUTE_PREFIX, oauth2_init, storage_init, userdb_init};

mod handlers;
mod server;

use crate::{
    handlers::{index, protected},
    server::{Ports, spawn_http_server, spawn_https_server},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install default CryptoProvider for rustls to prevent:
    // "no process-level CryptoProvider available -- call CryptoProvider::install_default() before this point"
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize the OAuth2 library
    oauth2_init().await?;
    storage_init().await?;
    userdb_init().await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .nest(OAUTH2_ROUTE_PREFIX.as_str(), oauth2_router());

    let ports = Ports {
        http: 3001,
        https: 3443,
    };

    let http_server = spawn_http_server(ports.http, app.clone());
    let https_server = spawn_https_server(ports.https, app).await;

    // Wait for both servers to complete (which they never will in this case)
    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}
