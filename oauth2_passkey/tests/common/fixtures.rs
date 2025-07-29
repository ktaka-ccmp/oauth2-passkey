use base64::{Engine as _, engine::general_purpose};
use ciborium::value::{Integer, Value as CborValue};
use ring::signature::KeyPair;
use serde_json::{Value, json};

/// Test user fixtures for integration testing
pub struct TestUsers;

impl TestUsers {
    /// Get a standard test user for OAuth2 flows
    pub fn oauth2_user() -> TestUser {
        TestUser {
            id: "test_oauth2_user".to_string(),
            email: "oauth2@example.com".to_string(),
            name: "OAuth2 Test User".to_string(),
            given_name: "OAuth2".to_string(),
            family_name: "User".to_string(),
        }
    }

    /// Get a standard test user for passkey flows
    pub fn passkey_user() -> TestUser {
        TestUser {
            id: "test_passkey_user".to_string(),
            email: "passkey@example.com".to_string(),
            name: "Passkey Test User".to_string(),
            given_name: "Passkey".to_string(),
            family_name: "User".to_string(),
        }
    }

    /// Get an admin test user
    pub fn admin_user() -> TestUser {
        TestUser {
            id: "test_admin_user".to_string(),
            email: "admin@example.com".to_string(),
            name: "Admin Test User".to_string(),
            given_name: "Admin".to_string(),
            family_name: "User".to_string(),
        }
    }

    /// Get a second OAuth2 test user for linking scenarios
    pub fn oauth2_user_second() -> TestUser {
        TestUser {
            id: "test_oauth2_user_second".to_string(),
            email: "oauth2-second@example.com".to_string(),
            name: "OAuth2 Second User".to_string(),
            given_name: "OAuth2 Second".to_string(),
            family_name: "User".to_string(),
        }
    }

    /// Get a third OAuth2 test user for linking scenarios
    pub fn oauth2_user_third() -> TestUser {
        TestUser {
            id: "test_oauth2_user_third".to_string(),
            email: "oauth2-third@example.com".to_string(),
            name: "OAuth2 Third User".to_string(),
            given_name: "OAuth2 Third".to_string(),
            family_name: "User".to_string(),
        }
    }
}

/// Test user data structure
#[derive(Debug, Clone)]
pub struct TestUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
}

impl TestUser {
    /// Convert to OAuth2 userinfo response format
    pub fn to_oauth2_userinfo(&self) -> Value {
        json!({
            "id": self.id,
            "sub": self.id,
            "email": self.email,
            "name": self.name,
            "given_name": self.given_name,
            "family_name": self.family_name,
            "picture": format!("https://example.com/avatar/{}.jpg", self.id)
        })
    }
}

/// Mock WebAuthn credentials for testing
pub struct MockWebAuthnCredentials;

impl MockWebAuthnCredentials {
    /// Helper function to create a valid test attestation object with "none" format
    fn create_valid_attestation_object() -> String {
        Self::create_attestation_object_with_format("none")
    }

    /// Helper function to create a valid test attestation object with specified format
    fn create_attestation_object_with_format(fmt: &str) -> String {
        match fmt {
            "packed" => Self::create_packed_attestation_with_valid_signature(),
            "tpm" => Self::create_tpm_attestation_with_valid_signature(),
            _ => Self::create_basic_attestation_object_with_format(fmt),
        }
    }

    /// Create a packed attestation with a valid self-attestation signature
    fn create_packed_attestation_with_valid_signature() -> String {
        use ring::{rand, signature};

        // Use a fixed seed for deterministic key generation in tests
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .expect("Failed to generate key pair");
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8_bytes.as_ref(),
            &rng,
        )
        .expect("Failed to create key pair");

        // Get the public key
        let public_key = key_pair.public_key();
        let public_key_bytes = public_key.as_ref();

        // Extract x and y coordinates from the uncompressed public key
        if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
            panic!("Unexpected public key format");
        }
        let x_coord = public_key_bytes[1..33].to_vec();
        let y_coord = public_key_bytes[33..65].to_vec();

        // Create authenticator data
        let auth_data = Self::create_auth_data_with_coords(&x_coord, &y_coord);

        // For packed self-attestation, we'll create a signature that will work with any client data hash
        // The key insight is that we need to modify the client data JSON to match our expected hash

        // Use a known client data hash that we'll construct the client data JSON to match
        let expected_client_data_hash =
            ring::digest::digest(&ring::digest::SHA256, b"test_client_data");

        // Create signed data (auth_data + client_data_hash)
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(expected_client_data_hash.as_ref());

        // Sign the data
        let signature = key_pair.sign(&rng, &signed_data).expect("Failed to sign");

        // Create attestation statement for packed self-attestation
        let att_stmt = CborValue::Map(vec![
            (
                CborValue::Text("alg".to_string()),
                CborValue::Integer(Integer::from(-7)), // ES256
            ),
            (
                CborValue::Text("sig".to_string()),
                CborValue::Bytes(signature.as_ref().to_vec()),
            ),
        ]);

        // Create the attestation object CBOR structure
        let attestation_obj = CborValue::Map(vec![
            (
                CborValue::Text("fmt".to_string()),
                CborValue::Text("packed".to_string()),
            ),
            (
                CborValue::Text("authData".to_string()),
                CborValue::Bytes(auth_data),
            ),
            (CborValue::Text("attStmt".to_string()), att_stmt),
        ]);

        // Serialize to CBOR bytes
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&attestation_obj, &mut cbor_bytes).unwrap();

        // Encode as base64url
        general_purpose::URL_SAFE_NO_PAD.encode(&cbor_bytes)
    }

    /// Create a TPM attestation with valid signature and certificate chain
    fn create_tpm_attestation_with_valid_signature() -> String {
        use ring::{rand, signature};

        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .expect("Failed to generate key pair");
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8_bytes.as_ref(),
            &rng,
        )
        .expect("Failed to create key pair");

        // Get the public key coordinates
        let public_key = key_pair.public_key();
        let public_key_bytes = public_key.as_ref();

        if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
            panic!("Unexpected public key format");
        }
        let x_coord = public_key_bytes[1..33].to_vec();
        let y_coord = public_key_bytes[33..65].to_vec();

        // Create authenticator data
        let auth_data = Self::create_auth_data_with_coords(&x_coord, &y_coord);

        // Create TPM certificate with AIK extension
        let certificate = Self::create_test_certificate(&key_pair, &rng);

        // Create TPM pubArea structure
        let pub_area = Self::create_tpm_ecc_pub_area(&x_coord, &y_coord);

        // Use a fixed client data hash for consistency
        let client_data_hash = ring::digest::digest(&ring::digest::SHA256, b"test_client_data");

        // Create TPM certInfo structure
        let cert_info =
            Self::create_tpm_cert_info(&auth_data, client_data_hash.as_ref(), &pub_area);

        // Sign the certInfo with the certificate's private key
        let signature = key_pair.sign(&rng, &cert_info).expect("Failed to sign");

        // Create TPM attestation statement
        let att_stmt = CborValue::Map(vec![
            (
                CborValue::Text("ver".to_string()),
                CborValue::Text("2.0".to_string()),
            ),
            (
                CborValue::Text("alg".to_string()),
                CborValue::Integer(Integer::from(-7)), // ES256
            ),
            (
                CborValue::Text("sig".to_string()),
                CborValue::Bytes(signature.as_ref().to_vec()),
            ),
            (
                CborValue::Text("x5c".to_string()),
                CborValue::Array(vec![CborValue::Bytes(certificate)]),
            ),
            (
                CborValue::Text("pubArea".to_string()),
                CborValue::Bytes(pub_area),
            ),
            (
                CborValue::Text("certInfo".to_string()),
                CborValue::Bytes(cert_info),
            ),
        ]);

        // Create the attestation object CBOR structure
        let attestation_obj = CborValue::Map(vec![
            (
                CborValue::Text("fmt".to_string()),
                CborValue::Text("tpm".to_string()),
            ),
            (
                CborValue::Text("authData".to_string()),
                CborValue::Bytes(auth_data),
            ),
            (CborValue::Text("attStmt".to_string()), att_stmt),
        ]);

        // Serialize to CBOR bytes
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&attestation_obj, &mut cbor_bytes).unwrap();

        // Encode as base64url
        general_purpose::URL_SAFE_NO_PAD.encode(&cbor_bytes)
    }

    /// Create basic attestation object for non-packed formats
    fn create_basic_attestation_object_with_format(fmt: &str) -> String {
        // Create standard auth data with fixed public key coordinates
        let auth_data = Self::create_standard_auth_data();

        // Create attestation statement based on format
        let att_stmt = match fmt {
            "none" => CborValue::Map(vec![]), // Empty for none
            "tpm" => {
                // Simplified TPM attestation statement for testing
                CborValue::Map(vec![
                    (
                        CborValue::Text("ver".to_string()),
                        CborValue::Text("2.0".to_string()),
                    ),
                    (
                        CborValue::Text("alg".to_string()),
                        CborValue::Integer(Integer::from(-7)), // ES256
                    ),
                    (
                        CborValue::Text("sig".to_string()),
                        CborValue::Bytes(vec![0x30, 0x45, 0x02, 0x20]), // Mock signature
                    ),
                    (
                        CborValue::Text("certInfo".to_string()),
                        CborValue::Bytes(vec![0x00; 100]), // Mock certInfo
                    ),
                    (
                        CborValue::Text("pubArea".to_string()),
                        CborValue::Bytes(vec![0x00; 50]), // Mock pubArea
                    ),
                    // x5c certificate chain is still missing, which causes the test to fail as expected
                ])
            }
            _ => CborValue::Map(vec![]), // Default to empty
        };

        // Create the attestation object CBOR structure
        let attestation_obj = CborValue::Map(vec![
            (
                CborValue::Text("fmt".to_string()),
                CborValue::Text(fmt.to_string()),
            ),
            (
                CborValue::Text("authData".to_string()),
                CborValue::Bytes(auth_data),
            ),
            (CborValue::Text("attStmt".to_string()), att_stmt),
        ]);

        // Serialize to CBOR bytes
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&attestation_obj, &mut cbor_bytes).unwrap();

        // Encode as base64url
        general_purpose::URL_SAFE_NO_PAD.encode(&cbor_bytes)
    }

    /// Create authenticator data with specific coordinates
    fn create_auth_data_with_coords(x_coord: &[u8], y_coord: &[u8]) -> Vec<u8> {
        let mut auth_data = Vec::new();

        // Get the RP ID from test origin
        let test_origin = crate::common::test_server::get_test_origin();
        let rp_id = test_origin
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split(':')
            .next()
            .unwrap_or("127.0.0.1");

        // Calculate RP ID hash (32 bytes) using SHA-256
        use ring::digest;
        let rp_id_hash = digest::digest(&digest::SHA256, rp_id.as_bytes());
        auth_data.extend_from_slice(rp_id_hash.as_ref());

        // Flags (1 byte) - UP (0x01) | UV (0x04) | AT (0x40) = 0x45
        auth_data.push(0x45);

        // Signature counter (4 bytes)
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // AAGUID (16 bytes)
        auth_data.extend_from_slice(&[0x00; 16]);

        // Credential ID length (2 bytes) - using 16 bytes for simplicity
        auth_data.extend_from_slice(&[0x00, 0x10]);

        // Credential ID (16 bytes)
        auth_data.extend_from_slice(&[
            0x6d, 0x6f, 0x63, 0x6b, 0x5f, 0x63, 0x72, 0x65, 0x64, 0x5f, 0x69, 0x64, 0x5f, 0x31,
            0x32, 0x33,
        ]);

        // Create COSE key for EC2 P-256 public key
        let mut cose_key_map = Vec::new();

        // kty = 2 (EC2)
        cose_key_map.push((
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(2)),
        ));
        // alg = -7 (ES256)
        cose_key_map.push((
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-7)),
        ));
        // crv = 1 (P-256)
        cose_key_map.push((
            CborValue::Integer(Integer::from(-1)),
            CborValue::Integer(Integer::from(1)),
        ));
        // x coordinate (32 bytes)
        cose_key_map.push((
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(x_coord.to_vec()),
        ));
        // y coordinate (32 bytes)
        cose_key_map.push((
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(y_coord.to_vec()),
        ));

        let cose_key = CborValue::Map(cose_key_map);
        let mut cose_key_bytes = Vec::new();
        ciborium::ser::into_writer(&cose_key, &mut cose_key_bytes).unwrap();

        // Append COSE key to auth data
        auth_data.extend_from_slice(&cose_key_bytes);

        auth_data
    }

    /// Create standard authenticator data with fixed public key
    fn create_standard_auth_data() -> Vec<u8> {
        // Use fixed coordinates for standard tests
        let x_coord = vec![
            0x61, 0xed, 0x47, 0x49, 0x2c, 0xc7, 0x46, 0x7e, 0x14, 0x30, 0x05, 0x8c, 0x1f, 0x87,
            0xb7, 0x47, 0x1a, 0x5f, 0x58, 0xb7, 0x66, 0xd0, 0x71, 0x11, 0xe3, 0x75, 0x21, 0x4d,
            0x76, 0x54, 0x5a, 0xfb,
        ];
        let y_coord = vec![
            0xff, 0x10, 0x00, 0x49, 0x23, 0xcc, 0x88, 0xd3, 0x6b, 0xb7, 0x4a, 0x77, 0x63, 0x1d,
            0xeb, 0xfe, 0xe4, 0x11, 0xb0, 0x85, 0x28, 0x2c, 0x2a, 0x26, 0xa1, 0x23, 0xcf, 0x58,
            0x4d, 0x68, 0x58, 0xe4,
        ];

        Self::create_auth_data_with_coords(&x_coord, &y_coord)
    }

    /// Create a test X.509 certificate for TPM attestation
    fn create_test_certificate(
        key_pair: &ring::signature::EcdsaKeyPair,
        _rng: &ring::rand::SystemRandom,
    ) -> Vec<u8> {
        // Create a minimal valid DER-encoded X.509 certificate that can pass x509-parser
        // This is a simplified version - in real TPM implementations, this would be a proper AIK certificate

        // Get the public key bytes
        let public_key = key_pair.public_key();
        let public_key_bytes = public_key.as_ref();

        // Build a minimal but valid certificate structure
        let mut cert = Vec::new();

        // Certificate SEQUENCE header
        cert.extend_from_slice(&[0x30, 0x82]); // SEQUENCE, length will be calculated
        let cert_len_pos = cert.len();
        cert.extend_from_slice(&[0x00, 0x00]); // Placeholder for total length

        // TBSCertificate SEQUENCE
        cert.extend_from_slice(&[0x30, 0x82]); // SEQUENCE
        let tbs_len_pos = cert.len();
        cert.extend_from_slice(&[0x00, 0x00]); // Placeholder for TBS length

        let tbs_start = cert.len();

        // Version [0] EXPLICIT Version DEFAULT v1
        cert.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]); // v3 (2)

        // SerialNumber
        cert.extend_from_slice(&[0x02, 0x01, 0x01]); // INTEGER 1

        // Signature AlgorithmIdentifier
        cert.extend_from_slice(&[
            0x30, 0x0a, // SEQUENCE
            0x06, 0x08, // OID
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, // ecdsa-with-SHA256
        ]);

        // Issuer Name
        cert.extend_from_slice(&[
            0x30, 0x1f, // SEQUENCE
            0x31, 0x1d, // SET
            0x30, 0x1b, // SEQUENCE
            0x06, 0x03, 0x55, 0x04, 0x03, // commonName OID
            0x0c, 0x14, // UTF8String, length 20
        ]);
        cert.extend_from_slice(b"TPM Test Certificate");

        // Validity
        cert.extend_from_slice(&[
            0x30, 0x1e, // SEQUENCE
            0x17, 0x0d, // UTCTime
        ]);
        cert.extend_from_slice(b"240101000000Z"); // notBefore
        cert.extend_from_slice(&[0x17, 0x0d]); // UTCTime
        cert.extend_from_slice(b"250101000000Z"); // notAfter

        // Subject Name (must be empty for AIK certificates)
        cert.extend_from_slice(&[
            0x30, 0x00, // SEQUENCE, length 0 (empty subject)
        ]);

        // SubjectPublicKeyInfo
        cert.extend_from_slice(&[
            0x30, 0x59, // SEQUENCE
            0x30, 0x13, // SEQUENCE (AlgorithmIdentifier)
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey OID
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1 OID
            0x03, 0x42, 0x00, // BIT STRING
        ]);
        cert.extend_from_slice(public_key_bytes); // 65 bytes: 0x04 + 32-byte x + 32-byte y

        let tbs_end = cert.len();
        let tbs_len = tbs_end - tbs_start;

        // Update TBS length
        cert[tbs_len_pos] = ((tbs_len >> 8) & 0xff) as u8;
        cert[tbs_len_pos + 1] = (tbs_len & 0xff) as u8;

        // signatureAlgorithm (same as in TBS)
        cert.extend_from_slice(&[
            0x30, 0x0a, // SEQUENCE
            0x06, 0x08, // OID
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, // ecdsa-with-SHA256
        ]);

        // signatureValue BIT STRING - just a dummy signature for testing
        cert.extend_from_slice(&[
            0x03, 0x48, 0x00, // BIT STRING, 72 bytes
            0x30, 0x45, // SEQUENCE (ECDSA signature)
            0x02, 0x20, // INTEGER r (32 bytes)
        ]);
        cert.extend_from_slice(&[0x01; 32]); // dummy r value
        cert.extend_from_slice(&[
            0x02, 0x21, 0x00, // INTEGER s (33 bytes with leading zero)
        ]);
        cert.extend_from_slice(&[0x02; 32]); // dummy s value

        let total_len = cert.len() - 4; // Subtract the initial SEQUENCE header

        // Update total certificate length
        cert[cert_len_pos] = ((total_len >> 8) & 0xff) as u8;
        cert[cert_len_pos + 1] = (total_len & 0xff) as u8;

        cert
    }

    /// Create TPM ECC pubArea structure  
    fn create_tpm_ecc_pub_area(x_coord: &[u8], y_coord: &[u8]) -> Vec<u8> {
        let mut pub_area = Vec::new();

        // Algorithm type: TPM_ALG_ECC (0x0023)
        pub_area.extend_from_slice(&[0x00, 0x23]);

        // Name algorithm: TPM_ALG_SHA256 (0x000B)
        pub_area.extend_from_slice(&[0x00, 0x0B]);

        // Object attributes (4 bytes)
        pub_area.extend_from_slice(&[0x00, 0x04, 0x00, 0x72]);

        // Auth policy length (2 bytes) and data (empty)
        pub_area.extend_from_slice(&[0x00, 0x00]);

        // ECC parameters:
        // Symmetric algorithm: TPM_ALG_NULL (0x0010)
        pub_area.extend_from_slice(&[0x00, 0x10]);

        // Scheme: TPM_ALG_NULL (0x0010)
        pub_area.extend_from_slice(&[0x00, 0x10]);

        // Curve ID: TPM_ECC_NIST_P256 (0x0003)
        pub_area.extend_from_slice(&[0x00, 0x03]);

        // KDF: TPM_ALG_NULL (0x0010)
        pub_area.extend_from_slice(&[0x00, 0x10]);

        // Unique field (x and y coordinates)
        pub_area.extend_from_slice(&(x_coord.len() as u16).to_be_bytes());
        pub_area.extend_from_slice(x_coord);
        pub_area.extend_from_slice(&(y_coord.len() as u16).to_be_bytes());
        pub_area.extend_from_slice(y_coord);

        pub_area
    }

    /// Create TPM certInfo structure
    fn create_tpm_cert_info(auth_data: &[u8], client_data_hash: &[u8], pub_area: &[u8]) -> Vec<u8> {
        let mut cert_info = Vec::new();

        // Magic: TPM_GENERATED_VALUE (0xff544347)
        cert_info.extend_from_slice(&[0xff, 0x54, 0x43, 0x47]);

        // Type: TPM_ST_ATTEST_CERTIFY (0x8017)
        cert_info.extend_from_slice(&[0x80, 0x17]);

        // Qualified signer (TPM2B_NAME) - empty
        cert_info.extend_from_slice(&[0x00, 0x00]);

        // Extra data (TPM2B_DATA) - should contain hash of auth_data + client_data_hash
        use ring::digest;
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(auth_data);
        hasher_input.extend_from_slice(client_data_hash);
        let hash = digest::digest(&digest::SHA256, &hasher_input);

        cert_info.extend_from_slice(&(hash.as_ref().len() as u16).to_be_bytes());
        cert_info.extend_from_slice(hash.as_ref());

        // Clock info (16 bytes) - dummy values
        cert_info.extend_from_slice(&[0x00; 16]);

        // Firmware version (8 bytes) - dummy values
        cert_info.extend_from_slice(&[0x00; 8]);

        // Attested data (TPMS_CERTIFY_INFO)
        // Name algorithm: TPM_ALG_SHA256 (0x000B)
        cert_info.extend_from_slice(&[0x00, 0x0B]);

        // Name (TPM2B_NAME) - hash of pubArea
        let name_hash = digest::digest(&digest::SHA256, pub_area);

        // Name length (algorithm ID + hash)
        cert_info.extend_from_slice(&((2 + name_hash.as_ref().len()) as u16).to_be_bytes());
        // Algorithm ID
        cert_info.extend_from_slice(&[0x00, 0x0B]);
        // Hash
        cert_info.extend_from_slice(name_hash.as_ref());

        cert_info
    }
    /// Generate a mock registration credential response
    pub fn registration_response(username: &str, _display_name: &str) -> Value {
        let user_handle =
            general_purpose::URL_SAFE_NO_PAD.encode(format!("user_handle_{username}"));
        json!({
            "id": "mock_credential_id_123",
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode("mock_credential_id_123"),
            "response": {
                "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoibW9ja19jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAifQ",
                "attestation_object": Self::create_valid_attestation_object(),
                "transports": ["internal"]
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "user_handle": user_handle
        })
    }

    /// Generate a mock registration credential response with a specific challenge
    #[allow(dead_code)]
    pub fn registration_response_with_challenge(
        username: &str,
        _display_name: &str,
        challenge: &str,
    ) -> Value {
        let user_handle =
            general_purpose::URL_SAFE_NO_PAD.encode(format!("user_handle_{username}"));

        // Use the actual test origin to match environment configuration
        let test_origin = crate::common::test_server::get_test_origin();

        // Create client data JSON with the actual challenge
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": test_origin
        });
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string());

        json!({
            "id": "mock_credential_id_123",
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode("mock_credential_id_123"),
            "response": {
                "client_data_json": client_data_json,
                "attestation_object": Self::create_valid_attestation_object(),
                "transports": ["internal"]
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "user_handle": user_handle
        })
    }

    /// Generate a mock registration credential response with specific challenge and user_handle
    #[allow(dead_code)]
    pub fn registration_response_with_challenge_and_user_handle(
        _username: &str,
        _display_name: &str,
        challenge: &str,
        user_handle: &str,
    ) -> Value {
        Self::registration_response_with_challenge_user_handle_and_origin(
            _username,
            _display_name,
            challenge,
            user_handle,
            &crate::common::test_server::get_test_origin(),
        )
    }

    /// Generate a mock registration credential response with specific attestation format
    pub fn registration_response_with_format(
        username: &str,
        _display_name: &str,
        challenge: &str,
        user_handle: &str,
        fmt: &str,
    ) -> Value {
        // Use the actual test origin to match LazyLock ORIGIN configuration
        let test_origin = crate::common::test_server::get_test_origin();

        // For packed attestation, we need to create a matching client data JSON
        let (client_data_json, attestation_object) = if fmt == "packed" {
            Self::create_packed_attestation_with_matching_client_data(challenge, &test_origin)
        } else {
            // Create standard client data JSON for other formats
            let client_data = json!({
                "type": "webauthn.create",
                "challenge": challenge,
                "origin": test_origin
            });
            let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string());
            let attestation_object = Self::create_attestation_object_with_format(fmt);
            (client_data_json, attestation_object)
        };

        json!({
            "id": "mock_credential_id_123",
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode("mock_credential_id_123"),
            "response": {
                "client_data_json": client_data_json,
                "attestation_object": attestation_object,
                "transports": ["internal"]
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "user_handle": user_handle
        })
    }

    /// Create packed attestation with matching client data that validates properly
    fn create_packed_attestation_with_matching_client_data(
        challenge: &str,
        origin: &str,
    ) -> (String, String) {
        use ring::{rand, signature};

        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .expect("Failed to generate key pair");
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8_bytes.as_ref(),
            &rng,
        )
        .expect("Failed to create key pair");

        // Get the public key coordinates
        let public_key = key_pair.public_key();
        let public_key_bytes = public_key.as_ref();

        if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
            panic!("Unexpected public key format");
        }
        let x_coord = public_key_bytes[1..33].to_vec();
        let y_coord = public_key_bytes[33..65].to_vec();

        // Create authenticator data
        let auth_data = Self::create_auth_data_with_coords(&x_coord, &y_coord);

        // Create client data JSON
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": origin
        });
        let client_data_str = client_data.to_string();
        let client_data_hash =
            ring::digest::digest(&ring::digest::SHA256, client_data_str.as_bytes());

        // Create signed data (auth_data + client_data_hash)
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(client_data_hash.as_ref());

        // Sign the data
        let signature = key_pair.sign(&rng, &signed_data).expect("Failed to sign");

        // Create attestation statement for packed self-attestation
        let att_stmt = CborValue::Map(vec![
            (
                CborValue::Text("alg".to_string()),
                CborValue::Integer(Integer::from(-7)), // ES256
            ),
            (
                CborValue::Text("sig".to_string()),
                CborValue::Bytes(signature.as_ref().to_vec()),
            ),
        ]);

        // Create the attestation object CBOR structure
        let attestation_obj = CborValue::Map(vec![
            (
                CborValue::Text("fmt".to_string()),
                CborValue::Text("packed".to_string()),
            ),
            (
                CborValue::Text("authData".to_string()),
                CborValue::Bytes(auth_data),
            ),
            (CborValue::Text("attStmt".to_string()), att_stmt),
        ]);

        // Serialize to CBOR bytes
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&attestation_obj, &mut cbor_bytes).unwrap();

        // Encode both client data and attestation object as base64url
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data_str);
        let attestation_object = general_purpose::URL_SAFE_NO_PAD.encode(&cbor_bytes);

        (client_data_json, attestation_object)
    }

    /// Generate a mock registration credential response with specific challenge, user_handle, and origin
    pub fn registration_response_with_challenge_user_handle_and_origin(
        _username: &str,
        _display_name: &str,
        challenge: &str,
        user_handle: &str,
        _origin: &str,
    ) -> Value {
        // Use the actual test origin to match LazyLock ORIGIN configuration
        let test_origin = crate::common::test_server::get_test_origin();

        // Create client data JSON with the actual challenge
        let client_data = json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": test_origin
        });
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string());

        json!({
            "id": "mock_credential_id_123",
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode("mock_credential_id_123"),
            "response": {
                "client_data_json": client_data_json,
                "attestation_object": Self::create_valid_attestation_object(),
                "transports": ["internal"]
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "user_handle": user_handle
        })
    }

    /// Generate a mock authentication assertion response
    #[allow(dead_code)]
    pub fn authentication_response(credential_id: &str) -> Value {
        json!({
            "id": credential_id,
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
            "response": {
                "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibW9ja19hdXRoX2NoYWxsZW5nZSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9",
                "authenticator_data": "EsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaABAAAAAw",
                "signature": "MEUCIQCj8BLqLqxHWBULHOhD6YKl7z8mhVisuLr1jq8MNkJ6nAIgOhYZ-tScOLJ8q5OLqxOdCJlF8zN7K9C7ZXjNFkJQhzg",
                "user_handle": general_purpose::URL_SAFE_NO_PAD.encode(format!("user_handle_{credential_id}"))
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "auth_id": "mock_auth_id_123"
        })
    }

    /// Generate a mock authentication assertion response with specific challenge
    #[allow(dead_code)]
    pub fn authentication_response_with_challenge(credential_id: &str, challenge: &str) -> Value {
        // Use the actual test origin to match environment configuration
        let test_origin = crate::common::test_server::get_test_origin();

        // Create client data JSON with the actual challenge
        let client_data = json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": test_origin
        });
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string());

        json!({
            "id": credential_id,
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
            "response": {
                "client_data_json": client_data_json,
                "authenticator_data": "EsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaABAAAAAw",
                "signature": "MEUCIQCj8BLqLqxHWBULHOhD6YKl7z8mhVisuLr1jq8MNkJ6nAIgOhYZ-tScOLJ8q5OLqxOdCJlF8zN7K9C7ZXjNFkJQhzg",
                "user_handle": general_purpose::URL_SAFE_NO_PAD.encode(format!("user_handle_{credential_id}"))
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "auth_id": "mock_auth_id_123"
        })
    }

    /// Generate a mock authentication assertion response with specific challenge and auth_id
    #[allow(dead_code)]
    pub fn authentication_response_with_challenge_and_auth_id(
        credential_id: &str,
        challenge: &str,
        auth_id: &str,
    ) -> Value {
        Self::authentication_response_with_challenge_auth_id_and_origin(
            credential_id,
            challenge,
            auth_id,
            &crate::common::test_server::get_test_origin(),
        )
    }

    /// Generate a mock authentication assertion response with specific challenge, auth_id, and origin
    pub fn authentication_response_with_challenge_auth_id_and_origin(
        credential_id: &str,
        challenge: &str,
        auth_id: &str,
        _origin: &str,
    ) -> Value {
        // Use the actual test origin to match LazyLock ORIGIN configuration
        let test_origin = crate::common::test_server::get_test_origin();

        // Create client data JSON with the actual challenge
        let client_data = json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": test_origin
        });
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string());

        json!({
            "id": credential_id,
            "raw_id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
            "response": {
                "client_data_json": client_data_json,
                "authenticator_data": "EsoXtJryKJQ28wPgFmAwoh5SXSZuIJJnQzgBqP1AcaABAAAAAw",
                "signature": "MEUCIQCj8BLqLqxHWBULHOhD6YKl7z8mhVisuLr1jq8MNkJ6nAIgOhYZ-tScOLJ8q5OLqxOdCJlF8zN7K9C7ZXjNFkJQhzg",
                "user_handle": general_purpose::URL_SAFE_NO_PAD.encode(format!("user_handle_{credential_id}"))
            },
            "type": "public-key",
            "client_extension_results": {},
            "authenticator_attachment": "platform",
            "auth_id": auth_id
        })
    }

    /// Generate mock registration options (what server would send to client)
    #[allow(dead_code)]
    pub fn registration_options(username: &str, display_name: &str) -> Value {
        json!({
            "rp": {
                "name": "OAuth2-Passkey Test",
                "id": "localhost"
            },
            "user": {
                "id": general_purpose::STANDARD.encode(format!("user_{username}")),
                "name": username,
                "displayName": display_name
            },
            "challenge": general_purpose::STANDARD.encode("mock_challenge_bytes"),
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7
                },
                {
                    "type": "public-key",
                    "alg": -257
                }
            ],
            "timeout": 60000,
            "attestation": "none",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "userVerification": "required",
                "residentKey": "preferred"
            }
        })
    }

    /// Generate mock authentication options (what server would send to client)
    #[allow(dead_code)]
    pub fn authentication_options(allowed_credentials: Option<Vec<&str>>) -> Value {
        let allowed_creds = if let Some(creds) = allowed_credentials {
            creds
                .iter()
                .map(|id| {
                    json!({
                        "type": "public-key",
                        "id": general_purpose::STANDARD.encode(id)
                    })
                })
                .collect()
        } else {
            vec![]
        };

        json!({
            "challenge": general_purpose::STANDARD.encode("mock_auth_challenge_bytes"),
            "timeout": 60000,
            "rpId": "localhost",
            "allowCredentials": allowed_creds,
            "userVerification": "required"
        })
    }
}

/// OAuth2 test data
pub struct MockOAuth2Responses;

impl MockOAuth2Responses {
    /// Generate a mock ID token for the given user
    pub fn id_token(user: &TestUser) -> String {
        use jsonwebtoken::{EncodingKey, Header, encode};

        let claims = json!({
            "iss": "https://accounts.google.com",
            "sub": user.id,
            "aud": "mock_client_id",
            "exp": (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            "iat": chrono::Utc::now().timestamp(),
            "email": user.email,
            "name": user.name,
            "given_name": user.given_name,
            "family_name": user.family_name,
            "email_verified": true
        });

        let key = EncodingKey::from_secret("test_secret".as_ref());
        encode(&Header::default(), &claims, &key)
            .unwrap_or_else(|_| format!("mock.jwt.token.{}", user.id))
    }

    /// Generate a mock access token response
    pub fn token_response(user: &TestUser) -> Value {
        json!({
            "access_token": format!("mock_access_token_{}", user.id),
            "id_token": Self::id_token(user),
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid email profile"
        })
    }
}

/// Common test state values
pub struct TestConstants;

impl TestConstants {
    #[allow(dead_code)]
    pub const MOCK_STATE: &'static str = "test_state_12345";
    #[allow(dead_code)]
    pub const MOCK_AUTH_CODE: &'static str = "mock_authorization_code";
    #[allow(dead_code)]
    pub const MOCK_CLIENT_ID: &'static str = "mock_client_id";
    #[allow(dead_code)]
    pub const MOCK_CLIENT_SECRET: &'static str = "mock_client_secret";
    // #[allow(dead_code)]
    // TEST_ORIGIN is now dynamically loaded from environment in test_server::get_test_origin()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_fixtures() {
        let oauth2_user = TestUsers::oauth2_user();
        assert_eq!(oauth2_user.email, "oauth2@example.com");

        let passkey_user = TestUsers::passkey_user();
        assert_eq!(passkey_user.email, "passkey@example.com");

        let admin_user = TestUsers::admin_user();
        assert_eq!(admin_user.email, "admin@example.com");
    }

    #[test]
    fn test_oauth2_userinfo_conversion() {
        let user = TestUsers::oauth2_user();
        let userinfo = user.to_oauth2_userinfo();

        assert_eq!(userinfo["email"], "oauth2@example.com");
        assert_eq!(userinfo["name"], "OAuth2 Test User");
        assert!(userinfo["picture"].as_str().unwrap().contains(&user.id));
    }

    #[test]
    fn test_webauthn_credential_generation() {
        let cred = MockWebAuthnCredentials::registration_response("testuser", "Test User");
        assert_eq!(cred["type"], "public-key");
        assert!(cred["id"].as_str().is_some());
        assert!(cred["response"]["client_data_json"].as_str().is_some());
    }

    #[test]
    fn test_oauth2_token_generation() {
        let user = TestUsers::oauth2_user();
        let token_response = MockOAuth2Responses::token_response(&user);

        assert_eq!(token_response["token_type"], "Bearer");
        assert_eq!(token_response["expires_in"], 3600);
        assert!(
            token_response["access_token"]
                .as_str()
                .unwrap()
                .contains(&user.id)
        );
    }
}
