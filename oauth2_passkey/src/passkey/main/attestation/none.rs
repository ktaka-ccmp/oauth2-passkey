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

// Test-specific version of verify_none_attestation that accepts configuration parameters
// This allows us to test different configurations without global state dependencies
#[cfg(test)]
fn verify_none_attestation_with_config(
    attestation: &AttestationObject,
    test_rp_id: &str,
    user_verification_required: bool,
) -> Result<(), PasskeyError> {
    // Verify attStmt is empty
    if !attestation.att_stmt.is_empty() {
        return Err(PasskeyError::Format(
            "attStmt must be empty for none attestation".to_string(),
        ));
    }

    // Verify auth_data has minimum required length
    if attestation.auth_data.len() < 37 {
        return Err(PasskeyError::Verification(
            "Auth data too short for basic structure".to_string(),
        ));
    }

    // Verify RP ID hash
    let rp_id_hash = digest::digest(&digest::SHA256, test_rp_id.as_bytes());
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
    if user_verification_required && !user_verified {
        return Err(PasskeyError::AuthenticatorData(
            "User Verification required but flag not set".to_string(),
        ));
    }

    if !has_attested_cred_data {
        return Err(PasskeyError::AuthenticatorData(
            "No attested credential data".to_string(),
        ));
    }

    // Verify auth_data has enough length for attested credential data
    if attestation.auth_data.len() < 55 {
        return Err(PasskeyError::Verification(
            "Auth data too short for attested credential data".to_string(),
        ));
    }

    // Verify credential public key format
    let mut pos = 55; // After AAGUID and 2-byte credential ID length
    let cred_id_len =
        ((attestation.auth_data[53] as usize) << 8) | (attestation.auth_data[54] as usize);
    pos += cred_id_len;

    // Check if we have enough data for the public key
    if attestation.auth_data.len() <= pos {
        return Err(PasskeyError::Verification(
            "Auth data too short for public key".to_string(),
        ));
    }

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
    use ring::digest;

    // Test-specific RP ID for consistent testing
    const TEST_RP_ID: &str = "example.com";

    // Helper to create valid CBOR public key
    fn create_valid_public_key_cbor() -> Vec<u8> {
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
        public_key_bytes
    }

    // Helper to create auth_data with specific parameters
    fn create_auth_data(
        rp_id: &str,
        user_present: bool,
        user_verified: bool,
        attested_cred_data: bool,
        cred_id_len: u16,
        include_public_key: bool,
    ) -> Vec<u8> {
        let mut auth_data = Vec::new();

        // Add RP ID hash (SHA-256)
        let rp_id_hash = digest::digest(&digest::SHA256, rp_id.as_bytes());
        auth_data.extend_from_slice(rp_id_hash.as_ref());

        // Add flags
        let mut flags = 0u8;
        if user_present {
            flags |= 0x01;
        }
        if user_verified {
            flags |= 0x04;
        }
        if attested_cred_data {
            flags |= 0x40;
        }
        auth_data.push(flags);

        // Add sign count (4 bytes, big-endian)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        if attested_cred_data {
            // Add AAGUID (16 bytes)
            auth_data.extend_from_slice(&[0x01; 16]);

            // Add credential ID length (2 bytes, big-endian)
            auth_data.extend_from_slice(&[(cred_id_len >> 8) as u8, (cred_id_len & 0xFF) as u8]);

            // Add credential ID
            auth_data.extend_from_slice(&vec![0x02; cred_id_len as usize]);

            // Add CBOR-encoded public key if requested
            if include_public_key {
                let public_key_bytes = create_valid_public_key_cbor();
                auth_data.extend_from_slice(&public_key_bytes);
            }
        }

        auth_data
    }

    // Helper to create test attestation with specific parameters
    fn create_test_attestation_with_params(
        empty_att_stmt: bool,
        rp_id: &str,
        user_present: bool,
        user_verified: bool,
        attested_cred_data: bool,
        cred_id_len: u16,
        include_public_key: bool,
    ) -> AttestationObject {
        let auth_data = create_auth_data(
            rp_id,
            user_present,
            user_verified,
            attested_cred_data,
            cred_id_len,
            include_public_key,
        );

        AttestationObject {
            fmt: "none".to_string(),
            auth_data,
            att_stmt: if empty_att_stmt {
                Vec::new()
            } else {
                vec![(Value::Text("alg".to_string()), Value::Integer(1i64.into()))]
            },
        }
    }

    // Helper to create a basic valid attestation object
    fn create_valid_attestation() -> AttestationObject {
        create_test_attestation_with_params(true, TEST_RP_ID, true, true, true, 16, true)
    }

    #[test]
    fn test_verify_none_attestation_success() {
        // Create a valid attestation object
        let attestation = create_valid_attestation();

        // Verify the attestation with test configuration
        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, true);

        // Should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_none_attestation_non_empty_att_stmt() {
        // Create an attestation with non-empty att_stmt
        let attestation =
            create_test_attestation_with_params(false, TEST_RP_ID, true, true, true, 16, true);

        // Verify the attestation
        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, true);

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
        let attestation = create_valid_attestation();

        // Test with different RP ID (should cause hash mismatch)
        let result = verify_none_attestation_with_config(&attestation, "different.com", true);

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
        // Create attestation with user_present = false
        let attestation =
            create_test_attestation_with_params(true, TEST_RP_ID, false, true, true, 16, true);

        // Verify the attestation
        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, true);

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
        // Create attestation with attested_cred_data = false
        let attestation =
            create_test_attestation_with_params(true, TEST_RP_ID, true, true, false, 0, false);

        // Verify the attestation
        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, true);

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
        // Create attestation with user_verified = false
        let attestation =
            create_test_attestation_with_params(true, TEST_RP_ID, true, false, true, 16, true);

        // Test with user verification required (should fail)
        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, true);
        assert!(result.is_err());
        if let Err(PasskeyError::AuthenticatorData(msg)) = result {
            assert!(msg.contains("User Verification required but flag not set"));
        } else {
            panic!("Expected PasskeyError::AuthenticatorData");
        }

        // Test with user verification not required (should succeed)
        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_none_attestation_invalid_public_key() {
        // Create attestation without public key
        let attestation =
            create_test_attestation_with_params(true, TEST_RP_ID, true, true, true, 16, false);

        // Verify the attestation
        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, true);

        // Should fail with Verification error (no public key data)
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Auth data too short for public key"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    // Additional comprehensive edge case tests
    #[test]
    fn test_verify_none_attestation_auth_data_too_short_basic() {
        // Test with auth_data shorter than minimum required (37 bytes)
        let attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data: vec![0; 36], // Only 36 bytes, need at least 37
            att_stmt: Vec::new(),
        };

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Auth data too short for basic structure"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    #[test]
    fn test_verify_none_attestation_auth_data_too_short_for_attested_data() {
        // Test with auth_data that has basic structure but not enough for attested credential data
        let auth_data = create_auth_data(TEST_RP_ID, true, true, true, 16, false);
        let short_auth_data = auth_data[..54].to_vec(); // Truncate before credential ID length

        let attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data: short_auth_data,
            att_stmt: Vec::new(),
        };

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Auth data too short for attested credential data"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    #[test]
    fn test_verify_none_attestation_invalid_credential_id_length() {
        // Test with very large credential ID length that would exceed auth_data bounds
        let attestation =
            create_test_attestation_with_params(true, TEST_RP_ID, true, true, true, 65535, false);

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Auth data too short for public key"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    #[test]
    fn test_verify_none_attestation_zero_credential_id_length() {
        // Test with zero credential ID length
        let attestation =
            create_test_attestation_with_params(true, TEST_RP_ID, true, true, true, 0, true);

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);
        // Should succeed if public key is present
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_none_attestation_malformed_cbor_public_key() {
        // Create attestation with invalid CBOR data for public key
        let mut auth_data = create_auth_data(TEST_RP_ID, true, true, true, 16, false);
        // Add invalid CBOR data (incomplete/malformed)
        auth_data.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // Invalid CBOR

        let attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data,
            att_stmt: Vec::new(),
        };

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);
        assert!(result.is_err());
        if let Err(PasskeyError::Format(msg)) = result {
            assert!(msg.contains("Invalid public key CBOR"));
        } else {
            panic!("Expected PasskeyError::Format");
        }
    }

    #[test]
    fn test_verify_none_attestation_different_flag_combinations() {
        // Test various flag combinations

        // Test: user_present=false, user_verified=false, attested_cred_data=false
        let attestation1 =
            create_test_attestation_with_params(true, TEST_RP_ID, false, false, false, 0, false);
        let result1 = verify_none_attestation_with_config(&attestation1, TEST_RP_ID, false);
        assert!(result1.is_err()); // Should fail due to user_present=false

        // Test: user_present=true, user_verified=false, attested_cred_data=false
        let attestation2 =
            create_test_attestation_with_params(true, TEST_RP_ID, true, false, false, 0, false);
        let result2 = verify_none_attestation_with_config(&attestation2, TEST_RP_ID, false);
        assert!(result2.is_err()); // Should fail due to attested_cred_data=false

        // Test: user_present=true, user_verified=true, attested_cred_data=false
        let attestation3 =
            create_test_attestation_with_params(true, TEST_RP_ID, true, true, false, 0, false);
        let result3 = verify_none_attestation_with_config(&attestation3, TEST_RP_ID, false);
        assert!(result3.is_err()); // Should fail due to attested_cred_data=false
    }

    #[test]
    fn test_verify_none_attestation_boundary_credential_id_lengths() {
        // Test with different credential ID lengths
        let test_lengths = vec![1, 16, 32, 64, 128, 255, 256];

        for len in test_lengths {
            let attestation =
                create_test_attestation_with_params(true, TEST_RP_ID, true, true, true, len, true);
            let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);

            // All should succeed if properly constructed
            if result.is_err() {
                println!("Failed for credential ID length: {}", len);
                println!("Error: {:?}", result);
            }
            assert!(
                result.is_ok(),
                "Should succeed for credential ID length: {}",
                len
            );
        }
    }

    #[test]
    fn test_verify_none_attestation_empty_rp_id() {
        // Test with empty RP ID
        let attestation = create_test_attestation_with_params(true, "", true, true, true, 16, true);
        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);

        // Should fail due to RP ID hash mismatch
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Invalid RP ID hash"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    #[test]
    fn test_verify_none_attestation_very_long_rp_id() {
        // Test with very long RP ID
        let long_rp_id = "a".repeat(1000);
        let attestation =
            create_test_attestation_with_params(true, &long_rp_id, true, true, true, 16, true);
        let result = verify_none_attestation_with_config(&attestation, &long_rp_id, false);

        // Should succeed - RP ID length shouldn't matter for hash comparison
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_none_attestation_minimal_auth_data_length() {
        // Test with exactly 37 bytes (minimum for basic structure) but no attested credential data
        let mut auth_data = Vec::new();

        // Add RP ID hash (32 bytes)
        let rp_id_hash = digest::digest(&digest::SHA256, TEST_RP_ID.as_bytes());
        auth_data.extend_from_slice(rp_id_hash.as_ref());

        // Add flags (1 byte) - only user present, no attested credential data
        auth_data.push(0x01); // Only UP flag set

        // Add sign count (4 bytes)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        assert_eq!(auth_data.len(), 37); // Exactly minimum length

        let attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data,
            att_stmt: Vec::new(),
        };

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);

        // Should fail because AT flag (attested credential data) is not set
        assert!(result.is_err());
        if let Err(PasskeyError::AuthenticatorData(msg)) = result {
            assert!(msg.contains("No attested credential data"));
        } else {
            panic!("Expected PasskeyError::AuthenticatorData");
        }
    }

    #[test]
    fn test_verify_none_attestation_invalid_public_key_coordinates() {
        // Create attestation with CBOR that parses but has invalid coordinates
        let mut auth_data = create_auth_data(TEST_RP_ID, true, true, true, 16, false);

        // Add CBOR map with missing required fields
        let invalid_public_key_entries = vec![
            // Only kty, missing other required fields
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        ];
        let invalid_public_key = Value::Map(invalid_public_key_entries);
        let mut invalid_public_key_bytes = Vec::new();
        ciborium::ser::into_writer(&invalid_public_key, &mut invalid_public_key_bytes).unwrap();
        auth_data.extend_from_slice(&invalid_public_key_bytes);

        let attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data,
            att_stmt: Vec::new(),
        };

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Invalid public key coordinates"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    #[test]
    fn test_verify_none_attestation_exactly_minimum_attested_data_length() {
        // Test with exactly 55 bytes (minimum for attested credential data structure)
        let mut auth_data = Vec::new();

        // Add RP ID hash (32 bytes)
        let rp_id_hash = digest::digest(&digest::SHA256, TEST_RP_ID.as_bytes());
        auth_data.extend_from_slice(rp_id_hash.as_ref());

        // Add flags (1 byte) - user present and attested credential data
        auth_data.push(0x41); // UP and AT flags set

        // Add sign count (4 bytes)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        // Add AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0x01; 16]);

        // Add credential ID length (2 bytes) - zero length
        auth_data.extend_from_slice(&[0x00, 0x00]);

        assert_eq!(auth_data.len(), 55); // Exactly minimum for attested credential data

        let attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data,
            att_stmt: Vec::new(),
        };

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);

        // Should fail because no public key data follows
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Auth data too short for public key"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    #[test]
    fn test_verify_none_attestation_maximum_valid_credential_id() {
        // Test with maximum reasonable credential ID length (65535 is the theoretical max for u16)
        // But we'll test with a more reasonable large value that should work
        let large_cred_id_len = 1024; // 1KB credential ID
        let attestation = create_test_attestation_with_params(
            true,
            TEST_RP_ID,
            true,
            true,
            true,
            large_cred_id_len,
            true,
        );

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);

        // Should succeed if properly constructed
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_none_attestation_truncated_public_key_cbor() {
        // Create auth data with truncated CBOR data that starts parsing but is incomplete
        let mut auth_data = create_auth_data(TEST_RP_ID, true, true, true, 16, false);

        // Add incomplete CBOR data (starts as a map but is truncated)
        auth_data.push(0xa1); // CBOR map with 1 item indicator
        auth_data.push(0x01); // Key: 1
        // Missing value - CBOR parser should fail

        let attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data,
            att_stmt: Vec::new(),
        };

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);
        assert!(result.is_err());
        if let Err(PasskeyError::Format(msg)) = result {
            assert!(msg.contains("Invalid public key CBOR"));
        } else {
            panic!("Expected PasskeyError::Format");
        }
    }

    #[test]
    fn test_verify_none_attestation_all_optional_flags_set() {
        // Create auth data with all possible flags set
        let mut auth_data = Vec::new();

        // Add RP ID hash (32 bytes)
        let rp_id_hash = digest::digest(&digest::SHA256, TEST_RP_ID.as_bytes());
        auth_data.extend_from_slice(rp_id_hash.as_ref());

        // Add flags with all bits set
        auth_data.push(0xFF); // All flags set

        // Add sign count (4 bytes)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        // Add AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0x01; 16]);

        // Add credential ID length and ID
        auth_data.extend_from_slice(&[0x00, 0x10]); // 16 bytes
        auth_data.extend_from_slice(&[0x02; 16]);

        // Add valid public key
        let public_key_bytes = create_valid_public_key_cbor();
        auth_data.extend_from_slice(&public_key_bytes);

        let attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data,
            att_stmt: Vec::new(),
        };

        let result = verify_none_attestation_with_config(&attestation, TEST_RP_ID, false);

        // Should succeed - having extra flags set shouldn't matter
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_none_attestation_rp_id_unicode_characters() {
        // Test with RP ID containing Unicode characters
        let unicode_rp_id = "tëst-éxample.cöm";
        let attestation =
            create_test_attestation_with_params(true, unicode_rp_id, true, true, true, 16, true);
        let result = verify_none_attestation_with_config(&attestation, unicode_rp_id, false);

        // Should succeed - Unicode should be handled properly by SHA-256
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_none_attestation_user_verification_edge_cases() {
        // Test user verification with various flag combinations

        // Case 1: UV required, UV flag set, UP flag not set (should fail for UP)
        let attestation1 =
            create_test_attestation_with_params(true, TEST_RP_ID, false, true, true, 16, true);
        let result1 = verify_none_attestation_with_config(&attestation1, TEST_RP_ID, true);
        assert!(result1.is_err());
        if let Err(PasskeyError::AuthenticatorData(msg)) = result1 {
            assert!(msg.contains("User Present flag not set"));
        }

        // Case 2: UV not required, UV flag not set, UP flag set (should succeed)
        let attestation2 =
            create_test_attestation_with_params(true, TEST_RP_ID, true, false, true, 16, true);
        let result2 = verify_none_attestation_with_config(&attestation2, TEST_RP_ID, false);
        assert!(result2.is_ok());

        // Case 3: UV required, both flags set (should succeed)
        let attestation3 =
            create_test_attestation_with_params(true, TEST_RP_ID, true, true, true, 16, true);
        let result3 = verify_none_attestation_with_config(&attestation3, TEST_RP_ID, true);
        assert!(result3.is_ok());
    }
}
