mod attestation;
mod auth;
mod challenge;
mod register;
mod related_origin;
mod types;
mod utils;

pub use types::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
};

pub use related_origin::get_related_origin_json;

pub(crate) use auth::{finish_authentication, start_authentication};

pub(crate) use register::{
    finish_registration, start_registration, verify_session_then_finish_registration,
};
