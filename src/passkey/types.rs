use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationOptions {
    pub(crate) challenge: String,
    pub(crate) timeout: u32,
    pub(crate) rp_id: String,
    pub(crate) allow_credentials: Vec<AllowCredential>,
    pub(crate) user_verification: String,
    pub(crate) auth_id: String,
}

#[derive(Serialize, Debug)]
pub(crate) struct AllowCredential {
    pub(crate) type_: String,
    pub(crate) id: Vec<u8>,
}
