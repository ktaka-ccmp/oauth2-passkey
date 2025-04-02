use axum::{Router, routing::get};
use dotenv::dotenv;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use oauth2_passkey_axum::{O2P_ROUTE_PREFIX, oauth2_passkey_router};

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

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        #[cfg(debug_assertions)]
        {
            "oauth2_passkey_axum=trace,oauth2_passkey=trace,demo_oauth2=trace".into()
        }

        #[cfg(not(debug_assertions))]
        {
            "info".into()
        }
    });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenv().ok();
    // Initialize the OAuth2 library
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

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
