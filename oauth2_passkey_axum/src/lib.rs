mod admin;
mod config;
mod error;
mod middleware;
mod oauth2;
mod passkey;
mod router;
mod session;
mod user;

pub use config::{O2P_ADMIN_URL, O2P_LOGIN_URL, O2P_REDIRECT_ANON, O2P_SUMMARY_URL};
pub use middleware::{
    is_authenticated_401, is_authenticated_redirect, is_authenticated_user_401,
    is_authenticated_user_redirect,
};
pub use passkey::passkey_well_known_router;
pub use router::oauth2_passkey_router;
pub use session::AuthUser;

// Re-export the route prefix and initialization function from oauth2_passkey crate
pub use oauth2_passkey::{O2P_ROUTE_PREFIX, init};
