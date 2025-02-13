mod axum;
mod common;
mod config;
mod errors;
mod passkey;
mod storage;
mod types;

pub use common::AppState;
// pub use types::Config;
pub use passkey::{
    finish_registration, start_authentication, start_registration, verify_authentication,
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
};

pub use axum::router;
pub use config::PASSKEY_ROUTE_PREFIX; // Required for route configuration
