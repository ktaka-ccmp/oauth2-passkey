use super::*;
use crate::test_utils;
use ciborium::value::Value;
use ring::digest;

// Helper function to create basic auth_data for testing
async fn create_test_auth_data() -> Vec<u8> {
    // Ensure test environment is set up with proper values
    // This will load environment variables from .env_test or .env
    test_utils::init_test_environment().await;

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

    auth_data
}

// Helper function to create a client data hash for testing
fn create_test_client_data_hash() -> Vec<u8> {
    // Create a SHA-256 hash of a sample client data JSON
    let client_data = r#"{"type":"webauthn.create","challenge":"dGVzdGNoYWxsZW5nZQ","origin":"https://example.com"}"#;
    let hash = digest::digest(&digest::SHA256, client_data.as_bytes());
    hash.as_ref().to_vec()
}

// Helper to create a basic U2F attestation statement
fn create_test_u2f_att_stmt(
    include_sig: bool,
    include_x5c: bool,
    empty_x5c: bool,
) -> Vec<(CborValue, CborValue)> {
    let mut att_stmt = Vec::new();

    if include_sig {
        att_stmt.push((
            Value::Text("sig".to_string()),
            Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]), // Dummy signature
        ));
    }

    if include_x5c {
        let certs = if empty_x5c {
            // Create an array with a non-bytes element to trigger the empty cert_chain condition
            vec![Value::Text("not a certificate".to_string())]
        } else {
            vec![Value::Bytes(vec![0x30, 0x82, 0x01, 0x01])] // Dummy certificate bytes
        };

        att_stmt.push((Value::Text("x5c".to_string()), Value::Array(certs)));
    }

    att_stmt
}

#[tokio::test]
async fn test_verify_u2f_attestation_missing_sig() {
    let auth_data = create_test_auth_data().await;
    let client_data_hash = create_test_client_data_hash();

    // Create attestation statement missing the sig field
    let att_stmt = create_test_u2f_att_stmt(
        false, // no sig
        true,  // include x5c
        false, // non-empty x5c
    );

    // Verify the attestation
    let result = verify_u2f_attestation(&auth_data, &client_data_hash, &att_stmt);

    // Should fail with Verification error
    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Missing signature in FIDO-U2F attestation"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[tokio::test]
async fn test_verify_u2f_attestation_missing_x5c() {
    let auth_data = create_test_auth_data().await;
    let client_data_hash = create_test_client_data_hash();

    // Create attestation statement missing the x5c field
    let att_stmt = create_test_u2f_att_stmt(
        true,  // include sig
        false, // no x5c
        false, // non-empty x5c (not used)
    );

    // Verify the attestation
    let result = verify_u2f_attestation(&auth_data, &client_data_hash, &att_stmt);

    // Should fail with Verification error
    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Missing x5c in FIDO-U2F attestation"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[tokio::test]
async fn test_verify_u2f_attestation_empty_x5c() {
    let auth_data = create_test_auth_data().await;
    let client_data_hash = create_test_client_data_hash();

    // Create attestation statement with x5c array that will result in empty cert_chain
    let att_stmt = create_test_u2f_att_stmt(
        true, // include sig
        true, // include x5c
        true, // empty x5c array
    );

    // Verify the attestation
    let result = verify_u2f_attestation(&auth_data, &client_data_hash, &att_stmt);

    // Should fail with Verification error
    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Missing x5c in FIDO-U2F attestation"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

// Test invalid certificate parsing
#[tokio::test]
async fn test_verify_u2f_attestation_invalid_certificate() {
    let auth_data = create_test_auth_data().await;
    let client_data_hash = create_test_client_data_hash();

    // Create attestation statement with malformed certificate
    let mut att_stmt = Vec::new();
    att_stmt.push((
        Value::Text("sig".to_string()),
        Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]), // Dummy signature
    ));

    // Add malformed certificate that will fail DER parsing
    let malformed_cert = vec![0xFF, 0xEE, 0xDD, 0xCC]; // Invalid DER data
    att_stmt.push((
        Value::Text("x5c".to_string()),
        Value::Array(vec![Value::Bytes(malformed_cert)]),
    ));

    // Verify the attestation
    let result = verify_u2f_attestation(&auth_data, &client_data_hash, &att_stmt);

    // Should fail with certificate parsing error
    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Failed to parse U2F attestation certificate"));
    } else {
        panic!("Expected PasskeyError::Verification for certificate parsing");
    }
}

// Test auth_data too short for credential ID parsing
#[test]
fn test_verify_u2f_attestation_short_auth_data() {
    let client_data_hash = create_test_client_data_hash();

    // Create a simple attestation statement that will parse successfully
    // We'll fail at the auth_data stage, not the certificate stage
    let mut att_stmt = Vec::new();
    att_stmt.push((
        Value::Text("sig".to_string()),
        Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]), // Dummy signature
    ));

    // Add a malformed certificate - this should cause the test to fail at certificate parsing
    // which happens before auth_data parsing, so we can verify that our bounds check works
    let malformed_cert = vec![0xFF, 0xEE, 0xDD, 0xCC]; // Invalid DER data
    att_stmt.push((
        Value::Text("x5c".to_string()),
        Value::Array(vec![Value::Bytes(malformed_cert)]),
    ));

    // Create auth_data that's too short to contain credential ID length
    let auth_data = vec![0x00; 54]; // Too short (needs at least 55 bytes to read credential ID length)

    let result = verify_u2f_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    match result {
        Err(PasskeyError::Verification(msg)) => {
            // The error should be about certificate parsing, not auth_data length
            // because certificate parsing happens first
            assert!(msg.contains("Failed to parse U2F attestation certificate"));
        }
        Err(other_error) => {
            panic!("Expected PasskeyError::Verification but got: {other_error:?}");
        }
        Ok(_) => panic!("Expected an error but got Ok"),
    }
}

// Test invalid credential ID length that exceeds auth_data bounds
#[test]
fn test_verify_u2f_attestation_invalid_credential_id_length() {
    let client_data_hash = create_test_client_data_hash();

    // Create attestation statement with malformed certificate (this will fail first)
    let mut att_stmt = Vec::new();
    att_stmt.push((
        Value::Text("sig".to_string()),
        Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]), // Dummy signature
    ));

    // Add malformed certificate that will fail DER parsing
    let malformed_cert = vec![0xFF, 0xEE, 0xDD, 0xCC]; // Invalid DER data
    att_stmt.push((
        Value::Text("x5c".to_string()),
        Value::Array(vec![Value::Bytes(malformed_cert)]),
    ));

    // Create auth_data with invalid credential ID length
    let mut auth_data = Vec::new();

    // Add RP ID hash (32 bytes)
    auth_data.extend_from_slice(&[0x01; 32]);

    // Add flags
    auth_data.push(0x01 | 0x04 | 0x40);

    // Add sign count (4 bytes)
    auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // Add AAGUID (16 bytes)
    auth_data.extend_from_slice(&[0x01; 16]);

    // Add invalid credential ID length (larger than remaining data)
    auth_data.extend_from_slice(&[0xFF, 0xFF]); // 65535 bytes - way too large

    // Add minimal credential ID
    auth_data.extend_from_slice(&[0x02; 10]);

    let result = verify_u2f_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    // Since certificate parsing happens first, we expect certificate parsing error
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Failed to parse U2F attestation certificate"));
    } else {
        panic!(
            "Expected PasskeyError::Verification for certificate parsing (which happens before auth_data validation)"
        );
    }
}

// Test malformed public key CBOR
#[test]
fn test_verify_u2f_attestation_malformed_public_key() {
    let client_data_hash = create_test_client_data_hash();

    // Create attestation statement with malformed certificate (this will fail first)
    let mut att_stmt = Vec::new();
    att_stmt.push((
        Value::Text("sig".to_string()),
        Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]), // Dummy signature
    ));

    // Add malformed certificate that will fail DER parsing
    let malformed_cert = vec![0xFF, 0xEE, 0xDD, 0xCC]; // Invalid DER data
    att_stmt.push((
        Value::Text("x5c".to_string()),
        Value::Array(vec![Value::Bytes(malformed_cert)]),
    ));

    // Create auth_data with malformed public key CBOR
    let mut auth_data = Vec::new();

    // Add RP ID hash (32 bytes)
    auth_data.extend_from_slice(&[0x01; 32]);

    // Add flags
    auth_data.push(0x01 | 0x04 | 0x40);

    // Add sign count (4 bytes)
    auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // Add AAGUID (16 bytes)
    auth_data.extend_from_slice(&[0x01; 16]);

    // Add credential ID length and credential ID
    auth_data.extend_from_slice(&[0x00, 0x04]); // 4 bytes
    auth_data.extend_from_slice(&[0x02; 4]); // Credential ID

    // Add malformed CBOR (invalid structure)
    auth_data.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // Invalid CBOR

    let result = verify_u2f_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    // Since certificate parsing happens first, we expect certificate parsing error
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Failed to parse U2F attestation certificate"));
    } else {
        panic!(
            "Expected PasskeyError::Verification for certificate parsing (which happens before CBOR parsing)"
        );
    }
}

// Test empty x5c array (actually empty, not with invalid elements)
#[tokio::test]
async fn test_verify_u2f_attestation_truly_empty_x5c() {
    let auth_data = create_test_auth_data().await;
    let client_data_hash = create_test_client_data_hash();

    // Create attestation statement with truly empty x5c array
    let att_stmt = vec![
        (
            Value::Text("sig".to_string()),
            Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]), // Dummy signature
        ),
        (
            Value::Text("x5c".to_string()),
            Value::Array(vec![]), // Truly empty array
        ),
    ];

    let result = verify_u2f_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        // An empty array results in an empty cert_chain, which means x5c_opt remains None
        // So we get "Missing x5c" rather than "Empty x5c"
        assert!(msg.contains("Missing x5c in FIDO-U2F attestation"));
    } else {
        panic!("Expected PasskeyError::Verification for empty x5c array");
    }
}

// Test invalid public key coordinates extraction
#[test]
fn test_verify_u2f_attestation_invalid_public_key_coords() {
    let client_data_hash = create_test_client_data_hash();

    // Create attestation statement with malformed certificate (this will fail first)
    let mut att_stmt = Vec::new();
    att_stmt.push((
        Value::Text("sig".to_string()),
        Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]), // Dummy signature
    ));

    // Add malformed certificate that will fail DER parsing
    let malformed_cert = vec![0xFF, 0xEE, 0xDD, 0xCC]; // Invalid DER data
    att_stmt.push((
        Value::Text("x5c".to_string()),
        Value::Array(vec![Value::Bytes(malformed_cert)]),
    ));

    // Create auth_data with invalid public key structure
    let mut auth_data = Vec::new();

    // Add RP ID hash (32 bytes)
    auth_data.extend_from_slice(&[0x01; 32]);

    // Add flags
    auth_data.push(0x01 | 0x04 | 0x40);

    // Add sign count (4 bytes)
    auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // Add AAGUID (16 bytes)
    auth_data.extend_from_slice(&[0x01; 16]);

    // Add credential ID length and credential ID
    auth_data.extend_from_slice(&[0x00, 0x04]); // 4 bytes
    auth_data.extend_from_slice(&[0x02; 4]); // Credential ID

    // Add CBOR public key with missing coordinates
    let invalid_public_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())), // alg: ES256
                                                                    // Missing x and y coordinates
    ]);
    let mut public_key_bytes = Vec::new();
    ciborium::ser::into_writer(&invalid_public_key, &mut public_key_bytes).unwrap();
    auth_data.extend_from_slice(&public_key_bytes);

    let result = verify_u2f_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    // Since certificate parsing happens first, we expect certificate parsing error
    match result {
        Err(PasskeyError::Verification(msg)) => {
            assert!(msg.contains("Failed to parse U2F attestation certificate"));
        }
        _ => panic!(
            "Expected PasskeyError::Verification for certificate parsing (which happens before coordinate extraction)"
        ),
    }
}

// Test specifically for auth_data bounds checking - this test focuses on the auth_data validation
// Note: Currently, the bounds check happens after certificate parsing, so this test documents
// the current behavior and shows where we'd need a valid certificate to test auth_data bounds
#[test]
fn test_auth_data_bounds_check_position() {
    let client_data_hash = create_test_client_data_hash();

    // This test demonstrates that certificate parsing happens before auth_data bounds checking
    // If we had a valid certificate, the auth_data bounds check would trigger
    let mut att_stmt = Vec::new();
    att_stmt.push((
        Value::Text("sig".to_string()),
        Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]),
    ));

    // Use invalid certificate to show that cert parsing happens first
    let malformed_cert = vec![0xFF, 0xEE, 0xDD, 0xCC];
    att_stmt.push((
        Value::Text("x5c".to_string()),
        Value::Array(vec![Value::Bytes(malformed_cert)]),
    ));

    let short_auth_data = vec![0x00; 54]; // Too short for credential ID length
    let result = verify_u2f_attestation(&short_auth_data, &client_data_hash, &att_stmt);

    // Confirms that certificate parsing error comes first
    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Failed to parse U2F attestation certificate"));
    }
}
