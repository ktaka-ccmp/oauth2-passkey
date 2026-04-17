#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::all)]

//! # oauth2-passkey-axum
//!
//! Axum web framework integration for the [`oauth2-passkey`] authentication library.
//!
//! [`oauth2-passkey`]: https://crates.io/crates/oauth2-passkey
//!
//! This crate provides ready-to-use Axum handlers, middleware, and UI components for OAuth2 and passkey authentication
//! in your Axum web applications.
//!
//! ## Quick Start
//!
//! For a complete working example, see the [demo-both application](https://github.com/ktaka-ccmp/oauth2-passkey/tree/master/demo-both)
//! which demonstrates both OAuth2 and passkey authentication in a single application.
//!
//!
//! ## Features
//!
//! - **Drop-in Axum Integration**: Pre-built routers and middleware
//! - **Admin UI**: Optional admin interface for user management
//! - **User UI**: Authentication pages and flows
//! - **Route Protection**: Middleware for protecting routes
//! - **CSRF Protection**: Built-in CSRF token handling
//! - **Static Assets**: CSS and JavaScript for authentication UI
//!
//! ## Basic Usage
//!
//! ```rust,no_run
//! use axum::{Router, response::Html};
//! use oauth2_passkey_axum::{oauth2_passkey_router, init, O2P_ROUTE_PREFIX};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize authentication (reads configuration from environment variables)
//!     init().await?;
//!
//!     // Create your application router
//!     let app: Router = Router::new()
//!         .route("/", axum::routing::get(|| async { Html("Hello World!") }))
//!         // Add authentication routes (default: /o2p, configurable via O2P_ROUTE_PREFIX env var)
//!         .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());
//!         // .merge(other_routes) // Add your other routes here
//!
//!     // Start server
//!     let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
//!     axum::serve(listener, app).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! See the repository documentation and examples for more details.

mod admin;
mod config;
#[cfg(feature = "cors")]
mod cors;
mod error;
mod login_history;
mod middleware;
mod oauth2;
mod passkey;
mod router;
mod session;
mod themes;
mod user;

// Test utilities module (only available in test builds)
#[cfg(test)]
pub(crate) mod test_utils;

// URL constants for different authentication-related pages
pub use config::{
    O2P_ACCOUNT_URL, O2P_ADMIN_URL, O2P_CUSTOM_CSS_URL, O2P_DEFAULT_REDIRECT, O2P_LOGIN_URL,
};

// Authentication middleware for protecting routes
pub use middleware::{
    is_authenticated_401, is_authenticated_redirect, is_authenticated_user_401,
    is_authenticated_user_redirect,
};

// Router for WebAuthn/.well-known endpoints
pub use passkey::passkey_well_known_router;

// Main routers that provide all authentication endpoints
pub use router::{oauth2_passkey_full_router, oauth2_passkey_router};

// Axum extractor for authenticated users
pub use session::AuthUser;

// Re-export the route prefix and types from oauth2_passkey crate
pub use oauth2_passkey::{CsrfHeaderVerified, CsrfToken, O2P_ROUTE_PREFIX};

/// Initialize the authentication system
///
/// This must be called before using any authentication functionality.
/// It initializes the underlying storage (database, cache) and validates
/// configuration (e.g., `O2P_LOGIN_URL` when `login-ui` feature is disabled).
///
/// # Errors
///
/// Returns an error if initialization of any subsystem fails.
///
/// # Panics
///
/// Panics if `O2P_LOGIN_URL` is not set via environment variable when the
/// `login-ui` feature is disabled. This prevents redirect loops at runtime.
pub async fn init() -> Result<(), Box<dyn std::error::Error>> {
    oauth2_passkey::init().await?;

    // Force evaluation of axum-specific config at startup
    let _ = *config::O2P_LOGIN_URL;
    let _ = *config::O2P_ACCOUNT_URL;
    let _ = *config::O2P_ADMIN_URL;
    let _ = *config::O2P_DEFAULT_REDIRECT;
    let _ = *config::O2P_RESPOND_WITH_X_CSRF_TOKEN;
    let _ = *config::O2P_FEDCM;
    let _ = *config::O2P_PASSKEY_PROMOTION;
    #[cfg(feature = "cors")]
    {
        let _ = *cors::CORS_ALLOWED_ORIGINS;
        let _ = *cors::CORS_ALLOW_CREDENTIALS;
    }

    Ok(())
}

// Re-export types and functions for custom summary pages
pub use oauth2_passkey::{
    OAuth2Account, PasskeyCredential, UserId, is_provider_enabled, list_accounts_core,
    list_credentials_core,
};

// Re-export types and functions for custom admin pages
pub use oauth2_passkey::{
    CredentialId, DbUser, ProviderUserId, SessionId, delete_oauth2_account_admin,
    delete_passkey_credential_admin, delete_user_account_admin, get_all_users, get_user,
    update_user_admin_status,
};

// CORS support (requires "cors" feature)
#[cfg(feature = "cors")]
pub use cors::{CORS_ALLOW_CREDENTIALS, CORS_ALLOWED_ORIGINS, cors_layer};

// Re-export login history types and cleanup functions for custom implementations
pub use oauth2_passkey::LoginHistoryEntry;
pub use oauth2_passkey::LoginHistoryError;
pub use oauth2_passkey::cleanup_old_login_history;
pub use oauth2_passkey::spawn_login_history_cleanup;
