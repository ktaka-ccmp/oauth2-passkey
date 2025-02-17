mod attestation;
mod auth;
mod register;
mod types;

pub use types::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
};

pub use auth::{start_authentication, verify_authentication};
pub use register::{
    // start_registration_with_auth_user,
    create_registration_options,
    finish_registration,
    start_registration,
};
