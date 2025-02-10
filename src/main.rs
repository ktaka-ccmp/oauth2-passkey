use axum::{routing::get, Router};
use dotenv::dotenv;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use liboauth2::{oauth2_state_init, OAUTH2_ROUTE_PREFIX};
use libsession::session_state_init;

mod handlers;
mod server;
mod state;

use crate::{
    handlers::{index, protected},
    server::{spawn_http_server, spawn_https_server, Ports},
    state::AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let session_state = session_state_init().await.unwrap_or_else(|e| {
        eprintln!("Failed to initialize SessionState: {e}");
        std::process::exit(1)
    });

    let oauth2_state = oauth2_state_init(Arc::new(session_state.clone()))
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to initialize OAuth2State: {e}");
            std::process::exit(1);
        });

    let app_state = AppState { session_state };
    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .with_state(app_state.clone())
        .nest(
            OAUTH2_ROUTE_PREFIX.as_str(),
            liboauth2::router(oauth2_state.clone()),
        )
        .with_state(oauth2_state);

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
