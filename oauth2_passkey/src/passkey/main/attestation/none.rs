use ciborium::value::Value as CborValue;
use ring::digest;

use crate::passkey::config::{PASSKEY_RP_ID, PASSKEY_USER_VERIFICATION};
use crate::passkey::errors::PasskeyError;

use super::super::types::AttestationObject;
use super::utils::extract_public_key_coords;

#[cfg(test)]
use std::sync::Once;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    // Initialize test environment once
    static INIT: Once = Once::new();

    unsafe fn setup() {
        // Set up required environment variables for testing
        unsafe {
            std::env::set_var("ORIGIN", "https://example.com");
            std::env::set_var("PASSKEY_RP_ID", "example.com");
            std::env::set_var("PASSKEY_USER_VERIFICATION", "required");
        }
    }

    // Helper function to create a basic attestation object for testing
    fn create_test_attestation(empty_att_stmt: bool) -> AttestationObject {
        // Ensure test environment is set up
        INIT.call_once(|| {
            // This is safe in the context of tests
            unsafe {
                setup();
            }
        });

        // Create a valid auth_data with proper RP ID hash and flags
        let mut auth_data = Vec::new();

        // Add RP ID hash (SHA-256 of "example.com")
        let rp_id_hash = digest::digest(&digest::SHA256, "example.com".as_bytes());
        auth_data.extend_from_slice(rp_id_hash.as_ref());

        // Add flags (user present, user verified, attested credential data)
        auth_data.push(0x01 | 0x04 | 0x40);

        // Add sign count (4 bytes, big-endian)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        // Add AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0x01; 16]);

        // Add credential ID length (2 bytes, big-endian) and credential ID (16 bytes)
        auth_data.extend_from_slice(&[0x00, 0x10]); // Length: 16 bytes
        auth_data.extend_from_slice(&[0x02; 16]); // Credential ID

        // Add CBOR-encoded public key
        // Create a CBOR map with key-value pairs
        let public_key_entries = vec![
            // kty: EC2 (2)
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            // alg: ES256 (-7)
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            // crv: P-256 (1)
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            // x coordinate (32 bytes)
            (Value::Integer((-2i64).into()), Value::Bytes(vec![0x02; 32])),
            // y coordinate (32 bytes)
            (Value::Integer((-3i64).into()), Value::Bytes(vec![0x03; 32])),
        ];

        let public_key = Value::Map(public_key_entries);
        let mut public_key_bytes = Vec::new();
        ciborium::ser::into_writer(&public_key, &mut public_key_bytes).unwrap();
        auth_data.extend_from_slice(&public_key_bytes);

        // Create the attestation object
        AttestationObject {
            fmt: "none".to_string(),
            auth_data,
            att_stmt: if empty_att_stmt {
                Vec::new()
            } else {
                // For non-empty att_stmt, create a simple key-value pair
                vec![(Value::Text("alg".to_string()), Value::Integer(1i64.into()))]
            },
        }
    }

    #[test]
    fn test_verify_none_attestation_success() {
        // Create a valid attestation object (which also ensures test environment is set up)
        let attestation = create_test_attestation(true);

        // Verify the attestation
        let result = verify_none_attestation(&attestation);

        // Should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_none_attestation_non_empty_att_stmt() {
        // Create an attestation with non-empty att_stmt
        let attestation = create_test_attestation(false);

        // Verify the attestation
        let result = verify_none_attestation(&attestation);

        // Should fail with Format error
        assert!(result.is_err());
        if let Err(PasskeyError::Format(msg)) = result {
            assert!(msg.contains("attStmt must be empty"));
        } else {
            panic!("Expected PasskeyError::Format");
        }
    }

    #[test]
    fn test_verify_none_attestation_invalid_rp_id_hash() {
        // Create a valid attestation object
        let mut attestation = create_test_attestation(true);

        // Corrupt the RP ID hash
        attestation.auth_data[0] ^= 0xFF;

        // Verify the attestation
        let result = verify_none_attestation(&attestation);

        // Should fail with Verification error
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Invalid RP ID hash"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    #[test]
    fn test_verify_none_attestation_user_present_not_set() {
        // Create a valid attestation object
        let mut attestation = create_test_attestation(true);

        // Clear the user present flag
        attestation.auth_data[32] &= !0x01;

        // Verify the attestation
        let result = verify_none_attestation(&attestation);

        // Should fail with AuthenticatorData error
        assert!(result.is_err());
        if let Err(PasskeyError::AuthenticatorData(msg)) = result {
            assert!(msg.contains("User Present flag not set"));
        } else {
            panic!("Expected PasskeyError::AuthenticatorData");
        }
    }

    #[test]
    fn test_verify_none_attestation_no_attested_cred_data() {
        // Create a valid attestation object
        let mut attestation = create_test_attestation(true);

        // Clear the attested credential data flag
        attestation.auth_data[32] &= !0x40;

        // Verify the attestation
        let result = verify_none_attestation(&attestation);

        // Should fail with AuthenticatorData error
        assert!(result.is_err());
        if let Err(PasskeyError::AuthenticatorData(msg)) = result {
            assert!(msg.contains("No attested credential data"));
        } else {
            panic!("Expected PasskeyError::AuthenticatorData");
        }
    }

    #[test]
    fn test_verify_none_attestation_user_verification_required() {
        // This test needs to temporarily modify the PASSKEY_USER_VERIFICATION value
        // We'll use the Once guard to ensure we only run the setup once
        INIT.call_once(|| {
            // No setup needed for this specific test
        });

        // Create a valid attestation object
        let mut attestation = create_test_attestation(true);

        // Clear the user verified flag
        attestation.auth_data[32] &= !0x04;

        // We need to check the actual value of PASSKEY_USER_VERIFICATION
        // If it's "required", we expect an error, otherwise we expect success
        let result = verify_none_attestation(&attestation);

        if *PASSKEY_USER_VERIFICATION == "required" {
            // Should fail with AuthenticatorData error
            assert!(result.is_err());
            if let Err(PasskeyError::AuthenticatorData(msg)) = result {
                assert!(msg.contains("User Verification required but flag not set"));
            } else {
                panic!("Expected PasskeyError::AuthenticatorData");
            }
        } else {
            // Should succeed if user verification is not required
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_verify_none_attestation_invalid_public_key() {
        // Create a valid attestation object
        let mut attestation = create_test_attestation(true);

        // Calculate position of the CBOR public key
        let cred_id_len =
            ((attestation.auth_data[53] as usize) << 8) | (attestation.auth_data[54] as usize);
        let pos = 55 + cred_id_len;

        // Corrupt the public key by truncating the auth_data
        attestation.auth_data.truncate(pos + 5); // Not enough bytes for a valid CBOR key

        // Verify the attestation
        let result = verify_none_attestation(&attestation);

        // Should fail with a Format error
        assert!(result.is_err());
        if let Err(PasskeyError::Format(msg)) = result {
            assert!(msg.contains("Invalid public key CBOR"));
        } else {
            panic!("Expected PasskeyError::Format");
        }
    }
}
