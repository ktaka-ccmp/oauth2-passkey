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
    // Check if auth_data is long enough to contain an AAGUID
    if attestation.auth_data.len() < 53 {
        return Err(PasskeyError::Verification(
            "Auth data too short to contain AAGUID".to_string(),
        ));
    }

    let aaguid_bytes = &attestation.auth_data[37..53];
    let aaguid = Uuid::from_slice(aaguid_bytes)
        .map_err(|e| PasskeyError::Verification(format!("Failed to parse AAGUID: {}", e)))?
        .hyphenated()
        .to_string();
    Ok(aaguid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    // Helper function to create a test attestation object
    fn create_test_attestation(fmt: &str, auth_data_len: usize) -> AttestationObject {
        let mut auth_data = vec![0; auth_data_len];

        // If we need to test AAGUID extraction, insert a valid UUID at the correct position
        if auth_data_len >= 53 {
            let test_uuid = Uuid::parse_str("f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0").unwrap();
            auth_data[37..53].copy_from_slice(test_uuid.as_bytes());
        }

        AttestationObject {
            fmt: fmt.to_string(),
            auth_data,
            att_stmt: Vec::new(),
        }
    }

    // Test the unsupported format case directly since it doesn't depend on the actual verification functions
    #[test]
    fn test_verify_attestation_unsupported_format() {
        // Create a test attestation with an unsupported format
        let attestation = create_test_attestation("unsupported", 100);
        let client_data = b"test client data";

        // Verify the attestation
        let result = verify_attestation(&attestation, client_data);

        // Assert the result is an error
        assert!(result.is_err());
        if let Err(PasskeyError::Format(msg)) = result {
            assert!(msg.contains("Unsupported attestation format"));
        } else {
            panic!("Expected PasskeyError::Format");
        }
    }

    #[test]
    fn test_extract_aaguid_success() {
        // Create a test attestation with a known UUID
        let attestation = create_test_attestation("none", 100);

        // Extract the AAGUID
        let result = extract_aaguid(&attestation);

        // Assert the result
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "f1d0f1d0-f1d0-f1d0-f1d0-f1d0f1d0f1d0");
    }

    #[test]
    fn test_extract_aaguid_too_short() {
        // Create a test attestation with auth_data that's too short to contain a valid AAGUID
        let attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data: vec![0; 37], // Only 37 bytes, not enough for AAGUID (needs at least 53)
            att_stmt: Vec::new(),
        };

        // Extract the AAGUID - this should fail with an auth data too short error
        let result = extract_aaguid(&attestation);

        // Assert the result is an error
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Auth data too short"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    #[test]
    fn test_verify_attestation_format_recognition() {
        // Test that supported formats are recognized vs unsupported formats
        // We test format recognition without calling the actual verification functions

        // Test unsupported formats (should get Format error)
        let unsupported_formats = vec!["", "unknown", "NONE", "Packed", " none ", "none\0"];

        for format in unsupported_formats {
            let attestation = create_test_attestation(format, 100);
            let client_data = b"test client data";

            let result = verify_attestation(&attestation, client_data);

            // Should get format error for unrecognized formats
            assert!(
                matches!(result, Err(PasskeyError::Format(_))),
                "Expected format error for format: '{}'",
                format
            );

            // Verify the error message
            if let Err(PasskeyError::Format(msg)) = result {
                assert!(msg.contains("Unsupported attestation format"));
            }
        }
    }

    #[test]
    fn test_verify_attestation_client_data_hash_created() {
        // Test that the function processes different client_data
        // We can't easily test the hash integration without complex setup,
        // but we can verify the function processes different inputs
        let attestation = create_test_attestation("unsupported", 100);

        let client_data1 = b"data1";
        let client_data2 = b"data2";
        let empty_data = b"";

        // All should produce format errors (since we use unsupported format)
        // but should process the client_data without panicking
        let result1 = verify_attestation(&attestation, client_data1);
        let result2 = verify_attestation(&attestation, client_data2);
        let result3 = verify_attestation(&attestation, empty_data);

        // All should be format errors
        assert!(matches!(result1, Err(PasskeyError::Format(_))));
        assert!(matches!(result2, Err(PasskeyError::Format(_))));
        assert!(matches!(result3, Err(PasskeyError::Format(_))));
    }

    #[test]
    fn test_extract_aaguid_with_different_uuids() {
        // Test extracting different UUID values from auth_data
        let mut attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data: vec![0; 100],
            att_stmt: Vec::new(),
        };

        // Test with a specific UUID pattern
        let test_uuid = Uuid::parse_str("12345678-1234-5678-9012-123456789012").unwrap();
        attestation.auth_data[37..53].copy_from_slice(test_uuid.as_bytes());

        let result = extract_aaguid(&attestation);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "12345678-1234-5678-9012-123456789012");
    }

    #[test]
    fn test_extract_aaguid_boundary_conditions() {
        // Test exactly at the minimum length boundary
        let mut attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data: vec![0; 53], // Exactly the minimum required length
            att_stmt: Vec::new(),
        };

        // Insert a valid UUID at the correct position
        let test_uuid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        attestation.auth_data[37..53].copy_from_slice(test_uuid.as_bytes());

        let result = extract_aaguid(&attestation);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    }

    #[test]
    fn test_verify_attestation_error_propagation() {
        // Test error handling and propagation for different scenarios

        // Test with invalid format strings
        let invalid_formats = vec!["", "unknown", "NONE", "Packed", " none ", "none\0"];

        for format in invalid_formats {
            let attestation = create_test_attestation(format, 100);
            let client_data = b"test client data";

            let result = verify_attestation(&attestation, client_data);

            // Should get format error for unrecognized formats
            assert!(
                matches!(result, Err(PasskeyError::Format(_))),
                "Expected format error for format: '{}'",
                format
            );
        }
    }

    #[test]
    fn test_extract_aaguid_malformed_data() {
        // Test extract_aaguid with various edge cases and malformed data

        // Test with exactly minimum length but invalid UUID bytes
        let mut attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data: vec![0xFF; 53], // Fill with 0xFF which might be invalid for UUID
            att_stmt: Vec::new(),
        };

        // UUID crate is robust, so this should still work
        let result = extract_aaguid(&attestation);
        assert!(result.is_ok(), "UUID crate should handle 0xFF bytes");

        // Test with one byte less than required
        attestation.auth_data = vec![0; 52];
        let result = extract_aaguid(&attestation);
        assert!(matches!(result, Err(PasskeyError::Verification(_))));

        // Test with much larger auth_data (should still work)
        attestation.auth_data = vec![0; 1000];
        let test_uuid = Uuid::parse_str("fedcba98-7654-3210-fedc-ba9876543210").unwrap();
        attestation.auth_data[37..53].copy_from_slice(test_uuid.as_bytes());

        let result = extract_aaguid(&attestation);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "fedcba98-7654-3210-fedc-ba9876543210");
    }

    #[test]
    fn test_verify_attestation_empty_client_data() {
        // Test with empty client data
        let attestation = create_test_attestation("unsupported", 100);
        let empty_client_data = b"";

        let result = verify_attestation(&attestation, empty_client_data);

        // Should still get format error (not panic on empty data)
        assert!(matches!(result, Err(PasskeyError::Format(_))));
    }

    #[test]
    fn test_verify_attestation_large_client_data() {
        // Test with large client data to ensure no buffer issues
        let attestation = create_test_attestation("unsupported", 100);
        let large_client_data = vec![0x42; 10000]; // 10KB of data

        let result = verify_attestation(&attestation, &large_client_data);

        // Should still get format error (function should handle large data)
        assert!(matches!(result, Err(PasskeyError::Format(_))));
    }
}
