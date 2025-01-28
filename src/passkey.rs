use base64::engine::{general_purpose::URL_SAFE, Engine};
use ciborium::value::Value as CborValue;
use dotenv::dotenv;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct AppConfig {
    origin: String,
    rp_id: String,
    authenticator_selection: AuthenticatorSelection,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorSelection {
    authenticator_attachment: Option<String>,
    resident_key: String,
    user_verification: String,
    require_resident_key: Option<bool>,
}

#[derive(Default)]
struct AuthStore {
    challenges: HashMap<String, StoredChallenge>,
    credentials: HashMap<String, StoredCredential>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct StoredChallenge {
    challenge: Vec<u8>,
    user: PublicKeyCredentialUserEntity,
    timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct PublicKeyCredentialUserEntity {
    id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct StoredCredential {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    counter: u32,
    user: PublicKeyCredentialUserEntity,
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let padding_len = (4 - input.len() % 4) % 4;
    let padded = format!("{}{}", input, "=".repeat(padding_len));
    URL_SAFE.decode(padded)
}

fn generate_challenge() -> Vec<u8> {
    let rng = ring::rand::SystemRandom::new();
    let mut challenge = vec![0u8; 32];
    rng.fill(&mut challenge)
        .expect("Failed to generate random challenge");
    challenge
}

#[derive(Debug)]
struct AttestationObject {
    fmt: String,
    auth_data: Vec<u8>,
    att_stmt: Vec<(CborValue, CborValue)>,
}

// Public things
pub(crate) mod attestation;
pub mod auth;
pub mod register;

#[derive(Clone)]
pub struct AppState {
    store: Arc<Mutex<AuthStore>>,
    config: AppConfig,
}

pub fn app_state() -> AppState {
    dotenv().ok();

    let origin = env::var("ORIGIN").expect("ORIGIN must be set");
    let rp_id = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or(&origin)
        .to_string();

    let authenticator_selection = AuthenticatorSelection {
        // "platform", "cross-platform" or None.
        // We prefer platform authenticators i.e. to use Google's password manager.
        authenticator_attachment: Some("platform".to_string()),
        // authenticator_attachment: None,

        // Discoverable credentials are supported by platform authenticators, so require it.
        resident_key: "required".to_string(), // "required", "preferred", "discouraged"
        require_resident_key: Some(true),     // true, false

        // user verification doesn't necessarily improve security, because the attacker can change PIN once the password manager is compromised.
        user_verification: "discouraged".to_string(), // "required", "preferred", "discouraged"
    };

    let config = AppConfig {
        origin,
        rp_id,
        authenticator_selection,
    };

    AppState {
        store: Arc::new(Mutex::new(AuthStore::default())),
        config,
    }
}
