mod axum;
mod client;
mod common;
mod config;
mod errors;
mod oauth2;
mod storage;
mod types;

// Re-export only what's necessary for the public API
pub use axum::router; // The main router function for nesting
pub use config::OAUTH2_ROUTE_PREFIX; // Required for route configuration

/// Initialize the OAuth2 library.
///
/// This function must be called before using the library. It:
/// 1. Initializes the token store singleton based on environment configuration
/// 2. Initializes the session store singleton
/// 3. Initializes the user store singleton
///
/// # Errors
/// Returns an error if any store initialization fails.
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
    libuserdb::init()
        .await
        .map_err(|e: libuserdb::AppError| errors::AppError::from(anyhow::anyhow!(e)))?;
    Ok(())
}
