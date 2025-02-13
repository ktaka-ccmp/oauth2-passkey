mod attestation;
mod auth;
mod register;
mod types;

pub use types::AuthenticationOptions;

pub use auth::{start_authentication, verify_authentication, AuthenticatorResponse};

pub use register::{
    finish_registration, start_registration, RegisterCredential, RegistrationOptions,
};
