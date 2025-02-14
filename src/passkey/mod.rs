mod attestation;
mod auth;
mod register;
mod types;

pub use types::{
    AuthenticationOptions, AuthenticatorResponse, AuthenticatorSelection, Config,
    RegisterCredential, RegistrationOptions,
};

pub use auth::{start_authentication, verify_authentication};
pub use register::{finish_registration, start_registration};
