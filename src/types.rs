use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::passkey::Config;
use crate::storage::{ChallengeStore, CredentialStore};

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub(super) struct PublicKeyCredentialUserEntity {
    pub(super) id: String,
    pub(super) name: String,
    #[serde(rename = "displayName")]
    pub(super) display_name: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct StoredChallenge {
    pub(super) challenge: Vec<u8>,
    pub(super) user: PublicKeyCredentialUserEntity,
    pub(super) timestamp: u64,
    pub(super) ttl: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct StoredCredential {
    pub(super) credential_id: Vec<u8>,
    pub(super) public_key: Vec<u8>,
    pub(super) counter: u32,
    pub(super) user: PublicKeyCredentialUserEntity,
}

#[derive(Clone)]
pub struct AppState {
    pub(super) challenge_store: Arc<Mutex<Box<dyn ChallengeStore>>>,
    pub(super) credential_store: Arc<Mutex<Box<dyn CredentialStore>>>,
    pub(super) config: Config,
}
