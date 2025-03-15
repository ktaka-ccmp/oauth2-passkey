mod attestation;
mod auth;
mod challenge;
mod register;
mod related_origin;
mod types;

pub use types::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
};

pub use auth::{finish_authentication, start_authentication};
pub use register::{finish_registration, finish_registration_with_auth_user, start_registration};
pub use related_origin::get_related_origin_json;
