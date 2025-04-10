use ciborium::value::Value as CborValue;
use ring::digest;

use crate::passkey::config::{PASSKEY_RP_ID, PASSKEY_USER_VERIFICATION};
use crate::passkey::errors::PasskeyError;

use super::super::types::AttestationObject;
use super::utils::extract_public_key_coords;

pub(super) fn verify_none_attestation(attestation: &AttestationObject) -> Result<(), PasskeyError> {
    // Verify attStmt is empty
    if !attestation.att_stmt.is_empty() {
        return Err(PasskeyError::Format(
            "attStmt must be empty for none attestation".to_string(),
        ));
    }

    // Verify RP ID hash
    let rp_id_hash = digest::digest(&digest::SHA256, PASSKEY_RP_ID.as_bytes());
    if attestation.auth_data[..32] != rp_id_hash.as_ref()[..] {
        return Err(PasskeyError::Verification("Invalid RP ID hash".to_string()));
    }

    // Check flags
    let flags = attestation.auth_data[32];
    let user_present = (flags & 0x01) != 0;
    let user_verified = (flags & 0x04) != 0;
    let has_attested_cred_data = (flags & 0x40) != 0;

    if !user_present {
        return Err(PasskeyError::AuthenticatorData(
            "User Present flag not set".to_string(),
        ));
    }

    // Check UV flag if requested
    if *PASSKEY_USER_VERIFICATION == "required" && !user_verified {
        return Err(PasskeyError::AuthenticatorData(
            "User Verification required but flag not set".to_string(),
        ));
    }

    if !has_attested_cred_data {
        return Err(PasskeyError::AuthenticatorData(
            "No attested credential data".to_string(),
        ));
    }

    // Extract AAGUID (starts at byte 37, 16 bytes long)
    // let aaguid = extract_aaguid(attestation)?;
    // tracing::debug!("AAGUID: {:?}", aaguid);

    // Verify credential public key format
    let mut pos = 55; // After AAGUID and 2-byte credential ID length
    let cred_id_len =
        ((attestation.auth_data[53] as usize) << 8) | (attestation.auth_data[54] as usize);
    pos += cred_id_len;

    // Verify COSE key format
    let public_key_cbor: CborValue = ciborium::de::from_reader(&attestation.auth_data[pos..])
        .map_err(|e| PasskeyError::Format(format!("Invalid public key CBOR: {}", e)))?;

    extract_public_key_coords(&public_key_cbor).map_err(|e| {
        PasskeyError::Verification(format!("Invalid public key coordinates: {}", e))
    })?;

    Ok(())
}
