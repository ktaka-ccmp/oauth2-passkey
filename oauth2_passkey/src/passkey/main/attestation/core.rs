use ring::digest;
use uuid::Uuid;

use crate::passkey::errors::PasskeyError;

use super::super::types::AttestationObject;
use super::none::verify_none_attestation;
use super::packed::verify_packed_attestation;
use super::tpm::verify_tpm_attestation;
use super::u2f::verify_u2f_attestation;

pub(crate) fn verify_attestation(
    attestation: &AttestationObject,
    client_data: &[u8],
) -> Result<(), PasskeyError> {
    let client_data_hash = digest::digest(&digest::SHA256, client_data);

    match attestation.fmt.as_str() {
        "none" => {
            // for platform authenticators
            tracing::debug!("Using 'none' attestation format");
            verify_none_attestation(attestation)
        }
        "packed" => {
            // for security keys
            tracing::debug!("Using 'packed' attestation format");
            verify_packed_attestation(
                &attestation.auth_data,
                client_data_hash.as_ref(),
                &attestation.att_stmt,
            )
            .map_err(|e| {
                PasskeyError::Verification(format!("Attestation verification failed: {:?}", e))
            })
        }
        "tpm" => {
            // for security keys
            tracing::debug!("Using 'tpm' attestation format");
            verify_tpm_attestation(
                &attestation.auth_data,
                client_data_hash.as_ref(),
                &attestation.att_stmt,
            )
            .map_err(|e| {
                PasskeyError::Verification(format!("Attestation verification failed: {:?}", e))
            })
        }
        "fido-u2f" => {
            // for FIDO U2F security keys
            tracing::debug!("Using 'fido-u2f' attestation format");
            verify_u2f_attestation(
                &attestation.auth_data,
                client_data_hash.as_ref(),
                &attestation.att_stmt,
            )
            .map_err(|e| {
                PasskeyError::Verification(format!("Attestation verification failed: {:?}", e))
            })
        }
        _ => Err(PasskeyError::Format(
            "Unsupported attestation format".to_string(),
        )),
    }
}

pub(crate) fn extract_aaguid(attestation: &AttestationObject) -> Result<String, PasskeyError> {
    let aaguid_bytes = &attestation.auth_data[37..53];
    let aaguid = Uuid::from_slice(aaguid_bytes)
        .map_err(|e| PasskeyError::Verification(format!("Failed to parse AAGUID: {}", e)))?
        .hyphenated()
        .to_string();
    Ok(aaguid)
}
