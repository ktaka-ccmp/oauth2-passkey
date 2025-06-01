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

    // Note: The UUID crate's parsing is very robust and will attempt to interpret almost any 16 bytes as a UUID
    // This test verifies that we can extract a UUID string from the attestation data, even if it's not a standard UUID format
    #[test]
    fn test_extract_aaguid_parsing() {
        // Create a test attestation with auth_data of the right length
        let mut attestation = AttestationObject {
            fmt: "none".to_string(),
            auth_data: vec![0; 100],
            att_stmt: Vec::new(),
        };

        // Set all the AAGUID bytes to 0, which should still be parseable as a nil UUID
        for i in 37..53 {
            attestation.auth_data[i] = 0x00;
        }

        // Extract the AAGUID
        let result = extract_aaguid(&attestation);

        // The result should be successful
        assert!(result.is_ok());

        // Verify we got a valid UUID string format
        let uuid_str = result.unwrap();
        assert_eq!(uuid_str.len(), 36); // Standard UUID string length
        assert!(uuid_str.contains('-')); // Should contain hyphens
        assert_eq!(uuid_str, "00000000-0000-0000-0000-000000000000"); // Nil UUID
    }
}
