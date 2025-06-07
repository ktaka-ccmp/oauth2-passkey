mod aaguid;
mod attestation;
mod auth;
mod challenge;
mod register;
mod related_origin;
#[cfg(test)]
mod test_utils;
mod types;
mod utils;

pub use aaguid::{AuthenticatorInfo, get_authenticator_info, get_authenticator_info_batch};

pub use types::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
};

pub use related_origin::get_related_origin_json;

pub(crate) use auth::{finish_authentication, start_authentication};

pub(crate) use register::{
    finish_registration, start_registration, verify_session_then_finish_registration,
};

pub(crate) use aaguid::store_aaguids;
