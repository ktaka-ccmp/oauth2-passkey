mod axum;
mod client;
mod common;
mod config;
mod errors;
mod oauth2;
mod storage;
mod types;

pub use axum::router;
pub use config::OAUTH2_ROUTE_PREFIX;
pub use types::OAuth2State;

/// Initialize the OAuth2 library, including token and session stores.
/// This must be called before using the library.
pub async fn init() -> Result<(), errors::AppError> {
    config::init_token_store().await?;
    libsession::init().await?;
    Ok(())
}
