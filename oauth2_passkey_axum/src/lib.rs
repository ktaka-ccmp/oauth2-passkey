mod config;
#[cfg(feature = "default-pages")]
mod default_pages;
mod error;
mod middleware;
mod oauth2;
mod passkey;
mod router;
mod session;
mod user;

pub use config::{O2P_REDIRECT_ANON, O2P_REDIRECT_USER};
pub use middleware::{
    is_authenticated_or_error, is_authenticated_or_redirect, is_authenticated_with_user,
};
pub use passkey::passkey_well_known_router;
pub use router::oauth2_passkey_router;
pub use session::AuthUser;

// Re-export the route prefix and initialization function from oauth2_passkey crate
pub use oauth2_passkey::{O2P_ROUTE_PREFIX, init};
