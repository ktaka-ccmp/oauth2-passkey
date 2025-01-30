use serde::{Deserialize, Serialize};
use std::env;

use crate::errors::PasskeyError;

#[derive(Clone, Debug)]
pub struct Config {
    pub origin: String,
    pub rp_id: String,
    pub rp_name: String,
    pub authenticator_selection: AuthenticatorSelection,
    pub timeout: u32,
    pub challenge_timeout_seconds: u64,
}

#[derive(Serialize, Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    pub authenticator_attachment: String,
    pub resident_key: String,
    pub user_verification: String,
    pub require_resident_key: bool,
}

impl Config {
    /// Creates a new Config instance from environment variables
    pub fn from_env() -> Result<Self, PasskeyError> {
        dotenv::dotenv().ok();

        let origin = env::var("ORIGIN")
            .map_err(|_| PasskeyError::Config("ORIGIN must be set".to_string()))?;

        let rp_id = origin
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split(':')
            .next()
            .unwrap_or(&origin)
            .to_string();

        let rp_name = env::var("PASSKEY_RP_NAME").unwrap_or(origin.clone());

        let timeout = env::var("PASSKEY_TIMEOUT")
            .map(|v| v.parse::<u32>())
            .unwrap_or(Ok(60000))
            .map_err(|e| PasskeyError::Config(format!("Invalid timeout value: {}", e)))?;

        let challenge_timeout = env::var("PASSKEY_CHALLENGE_TIMEOUT")
            .map(|v| v.parse::<u64>())
            .unwrap_or(Ok(300))
            .map_err(|e| PasskeyError::Config(format!("Invalid challenge timeout value: {}", e)))?;

        let _authenticator_attachment = env::var("PASSKEY_AUTHENTICATOR_ATTACHMENT").map_or(
        Ok("platform".to_string()), // Default to platform
        |v| match v.to_lowercase().as_str() {
            "platform" => Ok("platform".to_string()),
            "cross-platform" => Ok("cross-platform".to_string()),
            "none" => Ok("None".to_string()),
            invalid => Err(PasskeyError::Config(format!(
                "Invalid authenticator attachment: {}. Valid values are: platform, cross-platform, None",
                invalid
            ))),
        })?;

        let authenticator_attachment = match env::var("PASSKEY_AUTHENTICATOR_ATTACHMENT").ok() {
            None => Ok("platform".to_string()),
            Some(v) => match v.to_lowercase().as_str() {
                "platform" => Ok("platform".to_string()),
                "cross-platform" => Ok("cross-platform".to_string()),
                "none" => Ok("None".to_string()), // Ensure "None" is capitalized
                invalid => Err(PasskeyError::Config(format!(
                    "Invalid authenticator attachment: {}.
                    Valid values are: platform, cross-platform, none",
                    invalid
                ))),
            },
        }?;

        let resident_key = env::var("PASSKEY_RESIDENT_KEY").map_or(
            Ok("required".to_string()), // Default to required
            |v| match v.to_lowercase().as_str() {
                "required" => Ok("required".to_string()),
                "preferred" => Ok("preferred".to_string()),
                "discouraged" => Ok("discouraged".to_string()),
                invalid => Err(PasskeyError::Config(format!(
                    "Invalid resident key: {}. Valid values are: required, preferred, discouraged",
                    invalid
                ))),
            },
        )?;

        let require_resident_key = env::var("PASSKEY_REQUIRE_RESIDENT_KEY").map_or(
            Ok(true), // Default to true
            |v| match v.to_lowercase().as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                invalid => Err(PasskeyError::Config(format!(
                    "Invalid require_resident_key: {}. Valid values are: true, false",
                    invalid
                ))),
            },
        )?;

        let user_verification = env::var("PASSKEY_USER_VERIFICATION").map_or(
            Ok("discouraged".to_string()), // Default to discouraged
            |v| match v.to_lowercase().as_str() {
                "required" => Ok("required".to_string()),
                "preferred" => Ok("preferred".to_string()),
                "discouraged" => Ok("discouraged".to_string()),
                invalid => Err(PasskeyError::Config(format!(
                    "Invalid user verification: {}. Valid values are: required, preferred, discouraged",
                    invalid
                ))),
            },
        )?;

        Ok(Config {
            origin,
            rp_id,
            rp_name,
            timeout,
            challenge_timeout_seconds: challenge_timeout,
            authenticator_selection: AuthenticatorSelection {
                authenticator_attachment,
                resident_key,
                require_resident_key,
                user_verification,
            },
        })
    }

    /// Validates the configuration
    pub fn validate(&self) -> Result<(), PasskeyError> {
        if self.origin.is_empty() {
            return Err(PasskeyError::Config("Origin cannot be empty".to_string()));
        }
        if self.rp_id.is_empty() {
            return Err(PasskeyError::Config("RP ID cannot be empty".to_string()));
        }
        if self.timeout == 0 {
            return Err(PasskeyError::Config("Timeout cannot be zero".to_string()));
        }
        if self.challenge_timeout_seconds == 0 {
            return Err(PasskeyError::Config(
                "Challenge timeout cannot be zero".to_string(),
            ));
        }
        Ok(())
    }
}
