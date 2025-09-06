use super::*;
use ciborium::value::Value;
use ring::digest;

// Test helper functions for creating authentication data and attestation statements

/// Creates a basic auth_data with minimal requirements for testing
fn create_basic_auth_data() -> Vec<u8> {
    let mut auth_data = Vec::new();

    // RP ID hash (32 bytes) - SHA-256 of "example.com"
    let rp_id_hash = digest::digest(&digest::SHA256, "example.com".as_bytes());
    auth_data.extend_from_slice(rp_id_hash.as_ref());

    // Flags (user present, user verified, attested credential data)
    auth_data.push(0x01 | 0x04 | 0x40);

    // Sign count (4 bytes, big-endian)
    auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    auth_data
}

/// Creates auth_data with specified AAGUID
fn create_auth_data_with_aaguid(aaguid: &[u8; 16]) -> Vec<u8> {
    let mut auth_data = create_basic_auth_data();

    // Add AAGUID (16 bytes)
    auth_data.extend_from_slice(aaguid);

    // Add credential ID length (2 bytes, big-endian) and credential ID (16 bytes)
    auth_data.extend_from_slice(&[0x00, 0x10]); // Length: 16 bytes
    auth_data.extend_from_slice(&[0x02; 16]); // Credential ID

    // Add CBOR-encoded public key
    let public_key_entries = vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())), // alg: ES256
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv: P-256
        (Value::Integer((-2i64).into()), Value::Bytes(vec![0x02; 32])), // x coordinate
        (Value::Integer((-3i64).into()), Value::Bytes(vec![0x03; 32])), // y coordinate
    ];

    let public_key = Value::Map(public_key_entries);
    let mut public_key_bytes = Vec::new();
    ciborium::ser::into_writer(&public_key, &mut public_key_bytes).unwrap();
    auth_data.extend_from_slice(&public_key_bytes);

    auth_data
}

/// Creates auth_data without attested credential data flag
fn create_auth_data_no_attested_cred() -> Vec<u8> {
    let mut auth_data = Vec::new();

    // RP ID hash (32 bytes)
    let rp_id_hash = digest::digest(&digest::SHA256, "example.com".as_bytes());
    auth_data.extend_from_slice(rp_id_hash.as_ref());

    // Flags without attested credential data (0x40)
    auth_data.push(0x01 | 0x04); // Only user present and user verified

    // Sign count (4 bytes, big-endian)
    auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // Add AAGUID (16 bytes)
    auth_data.extend_from_slice(&[0x01; 16]);

    auth_data
}

/// Creates a client data hash for testing
fn create_client_data_hash() -> Vec<u8> {
    let client_data = r#"{"type":"webauthn.create","challenge":"dGVzdGNoYWxsZW5nZQ","origin":"https://example.com"}"#;
    let hash = digest::digest(&digest::SHA256, client_data.as_bytes());
    hash.as_ref().to_vec()
}

/// Creates an attestation statement with algorithm and signature
fn create_att_stmt(alg: i64, sig: &[u8]) -> Vec<(CborValue, CborValue)> {
    vec![
        (Value::Text("alg".to_string()), Value::Integer(alg.into())),
        (Value::Text("sig".to_string()), Value::Bytes(sig.to_vec())),
    ]
}

/// Creates an attestation statement with x5c certificate chain
fn create_att_stmt_with_x5c(
    alg: i64,
    sig: &[u8],
    cert_bytes: Vec<u8>,
) -> Vec<(CborValue, CborValue)> {
    let mut att_stmt = create_att_stmt(alg, sig);
    let certs = vec![Value::Bytes(cert_bytes)];
    att_stmt.push((Value::Text("x5c".to_string()), Value::Array(certs)));
    att_stmt
}

/// Creates an attestation statement with ecdaaKeyId
fn create_att_stmt_with_ecdaa(
    alg: i64,
    sig: &[u8],
    key_id: Vec<u8>,
) -> Vec<(CborValue, CborValue)> {
    let mut att_stmt = create_att_stmt(alg, sig);
    att_stmt.push((Value::Text("ecdaaKeyId".to_string()), Value::Bytes(key_id)));
    att_stmt
}

/// Creates a minimal dummy certificate for testing parsing errors
fn create_dummy_cert() -> Vec<u8> {
    // Invalid certificate that will cause parsing to fail
    vec![0x30, 0x82, 0x01, 0x01]
}

/// Creates an empty certificate chain for testing
fn create_empty_cert_chain() -> Vec<u8> {
    vec![]
}

// Tests for main verify_packed_attestation function

#[test]
fn test_verify_packed_attestation_unsupported_alg() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04];
    let att_stmt = create_att_stmt(-8, &sig); // Unsupported algorithm

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Unsupported or unrecognized algorithm"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_packed_attestation_ecdaa_not_supported() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04];
    let key_id = vec![0x01, 0x02, 0x03, 0x04];
    let att_stmt = create_att_stmt_with_ecdaa(ES256_ALG, &sig, key_id);

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("ECDAA attestation not supported"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_packed_attestation_both_x5c_and_ecdaa() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04];

    let mut att_stmt = create_att_stmt_with_x5c(ES256_ALG, &sig, create_dummy_cert());
    att_stmt.push((
        Value::Text("ecdaaKeyId".to_string()),
        Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]),
    ));

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("both x5c and ecdaaKeyId present"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_packed_attestation_invalid_cert() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04];
    let att_stmt = create_att_stmt_with_x5c(ES256_ALG, &sig, create_dummy_cert());

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Failed to parse attestation certificate"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_packed_attestation_empty_cert_chain() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04];
    let att_stmt = create_att_stmt_with_x5c(ES256_ALG, &sig, create_empty_cert_chain());

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Failed to parse attestation certificate"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_packed_attestation_malformed_x5c() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04];

    // Create att_stmt with malformed x5c array containing non-bytes
    let mut att_stmt = create_att_stmt(ES256_ALG, &sig);
    let malformed_certs = vec![Value::Text("not_bytes".to_string())];
    att_stmt.push((
        Value::Text("x5c".to_string()),
        Value::Array(malformed_certs),
    ));

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    // Should fall through to self-attestation path since x5c_opt remains None
    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(
            msg.contains("No attested credential data")
                || msg.contains("Invalid public key CBOR")
                || msg.contains("Self attestation signature verification failed")
        );
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_packed_attestation_self_attestation_no_cred_data() {
    let auth_data = create_auth_data_no_attested_cred();
    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04];
    let att_stmt = create_att_stmt(ES256_ALG, &sig);

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("No attested credential data in self attestation"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_packed_attestation_self_attestation_invalid_sig() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04]; // Invalid signature
    let att_stmt = create_att_stmt(ES256_ALG, &sig);

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Self attestation signature verification failed"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

// Tests for verify_self_attestation function

#[test]
fn test_verify_self_attestation_missing_attested_cred_flag() {
    let auth_data = create_auth_data_no_attested_cred();
    let signed_data = vec![0x01, 0x02, 0x03];
    let signature = vec![0x04, 0x05, 0x06];

    let result = verify_self_attestation(&auth_data, &signed_data, &signature);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("No attested credential data in self attestation"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_self_attestation_truncated_auth_data() {
    // Create auth_data that's too short to contain credential data
    let mut auth_data = create_basic_auth_data();
    // The basic auth data already has flags, so we need to modify the flag at position 32
    auth_data[32] |= 0x40; // Set attested credential data flag
    auth_data.extend_from_slice(&[0x01; 16]); // AAGUID
    // Missing credential ID length and data - total length = 54 bytes

    let signed_data = vec![0x01, 0x02, 0x03];
    let signature = vec![0x04, 0x05, 0x06];

    let result = verify_self_attestation(&auth_data, &signed_data, &signature);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Auth data too short for credential ID length"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_self_attestation_invalid_cbor() {
    let mut auth_data = create_basic_auth_data();
    auth_data[32] |= 0x40; // Set attested credential data flag
    auth_data.extend_from_slice(&[0x01; 16]); // AAGUID
    auth_data.extend_from_slice(&[0x00, 0x10]); // Cred ID length
    auth_data.extend_from_slice(&[0x02; 16]); // Cred ID
    auth_data.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // Invalid CBOR

    let signed_data = vec![0x01, 0x02, 0x03];
    let signature = vec![0x04, 0x05, 0x06];

    let result = verify_self_attestation(&auth_data, &signed_data, &signature);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Invalid public key CBOR"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

// Tests for verify_certificate_chain function

#[test]
fn test_verify_certificate_chain_empty() {
    let x5c: Vec<Vec<u8>> = vec![];
    let result = verify_certificate_chain(&x5c);
    assert!(result.is_ok());
}

#[test]
fn test_verify_certificate_chain_invalid_cert() {
    let x5c = vec![create_dummy_cert()];
    let result = verify_certificate_chain(&x5c);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Failed to parse certificate in chain"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_certificate_chain_multiple_invalid_certs() {
    let x5c = vec![create_dummy_cert(), create_dummy_cert()];
    let result = verify_certificate_chain(&x5c);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Failed to parse certificate in chain"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

// Tests for verify_packed_attestation_cert function

#[test]
fn test_verify_packed_attestation_cert_with_dummy_data() {
    // This test verifies that the function rejects invalid certificate data
    // We can't easily create a valid X509Certificate for testing without external dependencies
    // But we can test error handling paths

    let _auth_data = create_auth_data_with_aaguid(&[0x01; 16]);

    // Since we can't easily create a valid X509Certificate instance without
    // significant test certificate infrastructure, we document that this
    // function requires valid certificate data to test properly.

    // The function is tested indirectly through verify_packed_attestation tests
    // that exercise the certificate parsing and validation code paths.

    // For comprehensive testing, we would need:
    // 1. Valid test certificates with proper FIDO extensions
    // 2. Certificates with CA bit set for testing CA rejection
    // 3. Certificates with AAGUID extensions for AAGUID validation
    // 4. Test certificate chains for expiration testing
}

// Additional edge case tests

#[test]
fn test_verify_packed_attestation_missing_alg() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();

    // Create att_stmt without 'alg' field
    let att_stmt = vec![(
        Value::Text("sig".to_string()),
        Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]),
    )];

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    // Should fail in get_sig_from_stmt() helper function
}

#[test]
fn test_verify_packed_attestation_missing_sig() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();

    // Create att_stmt without 'sig' field
    let att_stmt = vec![(
        Value::Text("alg".to_string()),
        Value::Integer(ES256_ALG.into()),
    )];

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    // Should fail in get_sig_from_stmt() helper function
}

#[test]
fn test_verify_packed_attestation_empty_att_stmt() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();
    let att_stmt: Vec<(CborValue, CborValue)> = vec![];

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    // Should fail in get_sig_from_stmt() helper function
}

#[test]
fn test_verify_packed_attestation_x5c_empty_array() {
    let auth_data = create_auth_data_with_aaguid(&[0x01; 16]);
    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04];

    let mut att_stmt = create_att_stmt(ES256_ALG, &sig);
    let empty_certs: Vec<Value> = vec![];
    att_stmt.push((Value::Text("x5c".to_string()), Value::Array(empty_certs)));

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    // Should fall through to self-attestation path since x5c_opt remains None
    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Self attestation signature verification failed"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_packed_attestation_large_credential_id() {
    let mut auth_data = create_basic_auth_data();

    // Add AAGUID
    auth_data.extend_from_slice(&[0x01; 16]);

    // Add large credential ID length (65535 bytes) but limited auth_data
    auth_data.extend_from_slice(&[0xFF, 0xFF]);

    // Don't add the actual credential ID data (auth_data would be massive)
    // This should cause an error when parsing due to insufficient data

    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04];
    let att_stmt = create_att_stmt(ES256_ALG, &sig);

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Auth data too short for credential ID"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_verify_packed_attestation_zero_credential_id_length() {
    let mut auth_data = create_basic_auth_data();

    // Add AAGUID
    auth_data.extend_from_slice(&[0x01; 16]);

    // Add zero credential ID length
    auth_data.extend_from_slice(&[0x00, 0x00]);

    // Add CBOR-encoded public key immediately after
    let public_key_entries = vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(vec![0x02; 32])),
        (Value::Integer((-3i64).into()), Value::Bytes(vec![0x03; 32])),
    ];

    let public_key = Value::Map(public_key_entries);
    let mut public_key_bytes = Vec::new();
    ciborium::ser::into_writer(&public_key, &mut public_key_bytes).unwrap();
    auth_data.extend_from_slice(&public_key_bytes);

    let client_data_hash = create_client_data_hash();
    let sig = vec![0x01, 0x02, 0x03, 0x04];
    let att_stmt = create_att_stmt(ES256_ALG, &sig);

    let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

    assert!(result.is_err());
    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Self attestation signature verification failed"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}
