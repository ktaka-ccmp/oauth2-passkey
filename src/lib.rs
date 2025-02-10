mod axum;
mod common;
mod config;
mod errors;
mod session;
mod storage;
mod types;

pub use config::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME};
pub use errors::AppError;
pub use session::{create_new_session, delete_session_from_store, prepare_logout_response};
pub use types::User;

/// Initialize the session library.
///
/// This function must be called before using the library. It:
/// 1. Initializes the session store singleton based on environment configuration
/// 2. Sets up the store with either in-memory or Redis backend based on OAUTH2_SESSION_STORE
///
/// # Errors
/// Returns an error if store initialization fails, for example:
/// - Invalid store type in environment variable
/// - Failed Redis connection if Redis backend is configured
///
/// # Example
/// ```no_run
/// use libsession;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Initialize session store before using the library
///     libsession::init().await?;
///     Ok(())
/// }
/// ```
pub async fn init() -> Result<(), AppError> {
    config::init_session_store().await
}
