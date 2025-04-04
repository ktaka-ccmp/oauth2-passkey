mod handlers;
mod server;

use axum::{Router, middleware::from_fn, routing::get};
use dotenv::dotenv;

use oauth2_passkey_axum::{
    O2P_ROUTE_PREFIX, is_authenticated_redirect, is_authenticated_user_redirect,
    oauth2_passkey_router, passkey_well_known_router,
};

use handlers::{index, p1, p2, p3, p4, protected};
use server::{init_tracing, spawn_http_server, spawn_https_server};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install default CryptoProvider for rustls to prevent errors
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    init_tracing("demo-integration");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .route(
            "/p1",
            get(p1).route_layer(from_fn(is_authenticated_redirect)),
        )
        .route(
            "/p2",
            get(p2).route_layer(from_fn(is_authenticated_user_redirect)),
        )
        .route("/p3", get(p3))
        .route("/p4", get(p4))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
        .nest("/.well-known", passkey_well_known_router()); // Mount the WebAuthn well-known endpoint at root level

    let http_server = spawn_http_server(3001, app.clone());
    let https_server = spawn_https_server(3443, app).await;

    // Wait for both servers to complete (which they never will in this case)
    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}
