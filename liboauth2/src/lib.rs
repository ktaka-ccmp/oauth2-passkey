// mod axum;
mod client;
mod common;
mod config;
mod errors;
mod oauth2;
mod types;

// Re-export only what's necessary for the public API
// pub use axum::router; // The main router function for nesting
pub use config::OAUTH2_ROUTE_PREFIX; // Required for route configuration

pub use common::header_set_cookie;
pub use config::{OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_NAME};
pub use oauth2::{csrf_checks, get_idinfo_userinfo, prepare_oauth2_auth_request, validate_origin};
pub use types::AuthResponse;

pub async fn init() -> Result<(), errors::OAuth2Error> {
    // Validate required environment variables early
    let _ = *config::OAUTH2_REDIRECT_URI; // This will validate ORIGIN
    let _ = *config::OAUTH2_GOOGLE_CLIENT_ID;
    let _ = *config::OAUTH2_GOOGLE_CLIENT_SECRET;

    Ok(())
}
