mod attestation;
mod auth;
mod register;

pub use auth::{
    start_authentication, verify_authentication, AuthenticationOptions, AuthenticatorResponse,
};
pub use register::{
    finish_registration, start_registration, RegisterCredential, RegistrationOptions,
};
