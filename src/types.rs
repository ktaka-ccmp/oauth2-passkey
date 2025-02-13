use serde::{Deserialize, Serialize};
use std::env;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub origin: String,
    pub rp_id: String,
    pub rp_name: String,
    pub authenticator_selection: AuthenticatorSelection,
    pub timeout: u32,
    pub challenge_timeout_seconds: u64,
}

#[derive(Serialize, Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthenticatorSelection {
    pub authenticator_attachment: String,
    pub resident_key: String,
    pub user_verification: String,
    pub require_resident_key: bool,
}
