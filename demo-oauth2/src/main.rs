use axum::{Router, routing::get};
use dotenvy::dotenv;

use oauth2_passkey_axum::oauth2_passkey_full_router;

mod handlers;
mod server;

use crate::{
    handlers::{index, protected},
    server::{init_tracing, spawn_http_server},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing("demo_oauth2");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .merge(oauth2_passkey_full_router());

    spawn_http_server(3001, app).await?;
    Ok(())
}
