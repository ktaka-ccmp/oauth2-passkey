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

/// Initialize the OAuth2 library.
///
/// This function must be called before using the library. It:
/// 1. Initializes the token store singleton based on environment configuration
/// 2. Initializes the session store singleton
///
/// # Errors
/// Returns an error if either store initialization fails.
///
/// # Example
/// ```no_run
/// use liboauth2;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Initialize stores before using the library
///     liboauth2::init().await?;
///     Ok(())
/// }
/// ```
pub async fn init() -> Result<(), errors::AppError> {
    config::init_token_store().await?;
    libsession::init().await?;
    Ok(())
}
