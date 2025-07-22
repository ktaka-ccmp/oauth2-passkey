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
mod error;
mod middleware;
mod oauth2;
mod passkey;
mod router;
mod session;
mod user;

// Test utilities module (only available in test builds)
#[cfg(test)]
pub(crate) mod test_utils;

// URL constants for different authentication-related pages
pub use config::{O2P_ADMIN_URL, O2P_LOGIN_URL, O2P_REDIRECT_ANON, O2P_SUMMARY_URL};

// Authentication middleware for protecting routes
pub use middleware::{
    is_authenticated_401, is_authenticated_redirect, is_authenticated_user_401,
    is_authenticated_user_redirect,
};

// Router for WebAuthn/.well-known endpoints
pub use passkey::passkey_well_known_router;

// Main router that provides all authentication endpoints
pub use router::oauth2_passkey_router;

// Axum extractor for authenticated users
pub use session::AuthUser;

// Re-export the route prefix and initialization function from oauth2_passkey crate
pub use oauth2_passkey::{CsrfHeaderVerified, CsrfToken, O2P_ROUTE_PREFIX, init};
