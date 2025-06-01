use ciborium::value::Value as CborValue;
use ring::signature::UnparsedPublicKey;
use std::time::SystemTime;
use uuid::Uuid;
use webpki::EndEntityCert;
use x509_parser::{certificate::X509Certificate, prelude::*, time::ASN1Time};

use crate::passkey::errors::PasskeyError;

use super::utils::{extract_public_key_coords, get_sig_from_stmt};

// Constants for FIDO OIDs id-fido-gen-ce-aaguid
const OID_FIDO_GEN_CE_AAGUID: &str = "1.3.6.1.4.1.45724.1.1.4";
const ES256_ALG: i64 = -7;

/// Verifies a packed attestation statement
///
/// # Arguments
/// * `auth_data` - A reference to the authenticator data
/// * `client_data_hash` - A reference to the client data hash
/// * `att_stmt` - A reference to the attestation statement
///
/// # Returns
/// * `Result<(), PasskeyError>` - An empty result or an error if the attestation is invalid
///
/// # Errors
/// * `PasskeyError::Verification` - If the attestation is invalid
///
pub(super) fn verify_packed_attestation(
    auth_data: &[u8],
    client_data_hash: &[u8],
    att_stmt: &Vec<(CborValue, CborValue)>,
) -> Result<(), PasskeyError> {
    // 1) Get the alg and sig from the existing helper
    let (alg, sig) = get_sig_from_stmt(att_stmt)?;

    // 2) Build the data that was signed
    let mut signed_data = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    signed_data.extend_from_slice(auth_data);
    signed_data.extend_from_slice(client_data_hash);

    // 3) Make sure it's an ECDSA P-256 / SHA256 attestation
    if alg != ES256_ALG {
        return Err(PasskeyError::Verification(format!(
            "Unsupported or unrecognized algorithm: {}",
            alg
        )));
    }

    // 4) Extract x5c and verify its presence for packed attestation
    let mut x5c_opt: Option<Vec<Vec<u8>>> = None;
    let mut ecdaa_key_id: Option<Vec<u8>> = None;

    for (k, v) in att_stmt {
        if let (CborValue::Text(key_str), CborValue::Array(certs)) = (k, v) {
            if key_str == "x5c" {
                let mut cert_chain = Vec::new();
                for cert in certs {
                    if let CborValue::Bytes(cert_bytes) = cert {
                        cert_chain.push(cert_bytes.clone());
                    }
                }
                if !cert_chain.is_empty() {
                    x5c_opt = Some(cert_chain);
                }
            }
        } else if let (CborValue::Text(key_str), CborValue::Bytes(id)) = (k, v) {
            if key_str == "ecdaaKeyId" {
                ecdaa_key_id = Some(id.clone());
            }
        }
    }

    // 5) Based on attestation type, verify accordingly
    match (x5c_opt, ecdaa_key_id) {
        (Some(x5c), None) => {
            // Full attestation with certificate chain
            tracing::debug!("Full attestation with certificate chain");

            let attestn_cert_bytes = &x5c[0];
            let attestn_cert =
                EndEntityCert::try_from(attestn_cert_bytes.as_ref()).map_err(|e| {
                    PasskeyError::Verification(format!(
                        "Failed to parse attestation certificate: {:?}",
                        e
                    ))
                })?;

            // Parse with x509-parser for additional verifications
            let (_, x509_cert) = X509Certificate::from_der(attestn_cert_bytes).map_err(|e| {
                PasskeyError::Verification(format!("Failed to parse X509 certificate: {}", e))
            })?;

            // Verify certificate attributes according to FIDO standard
            verify_packed_attestation_cert(&x509_cert, auth_data)?;

            // Verify the signature
            attestn_cert
                .verify_signature(&webpki::ECDSA_P256_SHA256, &signed_data, &sig)
                .map_err(|_| {
                    PasskeyError::Verification("Attestation signature invalid".to_string())
                })?;

            // Verify certificate chain if intermediates are present
            if x5c.len() > 1 {
                verify_certificate_chain(&x5c)?;
            }
        }
        (None, Some(_)) => {
            return Err(PasskeyError::Verification(
                "ECDAA attestation not supported".to_string(),
            ));
        }
        (None, None) => {
            tracing::debug!("Self attestation");
            verify_self_attestation(auth_data, &signed_data, &sig)?;
        }
        (Some(_), Some(_)) => {
            return Err(PasskeyError::Verification(
                "Invalid attestation: both x5c and ecdaaKeyId present".to_string(),
            ));
        }
    }

    Ok(())
}

fn verify_packed_attestation_cert(
    cert: &X509Certificate,
    auth_data: &[u8],
) -> Result<(), PasskeyError> {
    // Check that it's not a CA certificate
    if let Some(basic_constraints) = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.as_bytes() == oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS.as_bytes())
    {
        if basic_constraints.value.contains(&0x01) {
            return Err(PasskeyError::Verification(
                "Certificate must not be a CA certificate".to_string(),
            ));
        }
    }

    // Verify AAGUID if present
    if let Some(fido_ext) = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_string() == OID_FIDO_GEN_CE_AAGUID)
    {
        let auth_data_aaguid = &auth_data[37..53];
        let cert_aaguid = fido_ext.value;

        // The format of this extension typically includes:
        // 0x04: This byte indicates the ASN.1 tag for an OCTET STRING.
        // 0x10: This byte represents the length of the OCTET STRING in hexadecimal, which is 16 bytes (decimal 16).
        // #[cfg(debug_assertions)]
        // println!("auth_data_aaguid: {:?}, cert_aaguid: {:?}", auth_data_aaguid, &cert_aaguid[2..]);

        let auth_data_uuid = Uuid::from_slice(auth_data_aaguid)
            .map_err(|e| PasskeyError::Verification(format!("Failed to parse AAGUID: {}", e)))?
            .hyphenated()
            .to_string();
        tracing::debug!("Authenticator AAGUID: {:?}", auth_data_uuid);

        let cert_uuid = Uuid::from_slice(&cert_aaguid[2..18])
            .map_err(|e| PasskeyError::Verification(format!("Failed to parse AAGUID: {}", e)))?
            .hyphenated()
            .to_string();
        tracing::debug!("Certificate AAGUID: {:?}", cert_uuid);

        if auth_data_aaguid != &cert_aaguid[2..] {
            return Err(PasskeyError::Verification(
                "AAGUID mismatch between certificate and authenticator data".to_string(),
            ));
        }
    }

    Ok(())
}

fn verify_certificate_chain(x5c: &[Vec<u8>]) -> Result<(), PasskeyError> {
    if x5c.is_empty() {
        return Ok(());
    }

    for cert_bytes in x5c {
        let (_, cert) = X509Certificate::from_der(cert_bytes).map_err(|e| {
            PasskeyError::Verification(format!("Failed to parse certificate in chain: {}", e))
        })?;

        // Convert SystemTime to ASN1Time
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| PasskeyError::Verification(format!("System time error: {}", e)))?;

        let timestamp = ASN1Time::from_timestamp(now.as_secs() as i64)
            .map_err(|e| PasskeyError::Verification(format!("Failed to convert time: {}", e)))?;

        if !cert.validity().is_valid_at(timestamp) {
            return Err(PasskeyError::Verification(
                "Certificate in chain is expired or not yet valid".to_string(),
            ));
        }
    }

    Ok(())
}

fn verify_self_attestation(
    auth_data: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), PasskeyError> {
    let flags = auth_data[32];
    let has_attested_cred_data = (flags & 0x40) != 0;

    if !has_attested_cred_data {
        return Err(PasskeyError::Verification(
            "No attested credential data in self attestation".to_string(),
        ));
    }

    let mut pos = 37; // Skip RP ID hash (32) + flags (1) + counter (4)
    pos += 16; // Skip AAGUID

    let cred_id_len = ((auth_data[pos] as usize) << 8) | (auth_data[pos + 1] as usize);
    pos += 2 + cred_id_len;

    let public_key_cbor: CborValue = ciborium::de::from_reader(&auth_data[pos..]).map_err(|e| {
        PasskeyError::Verification(format!(
            "Invalid public key CBOR in self attestation: {}",
            e
        ))
    })?;

    let (x_coord, y_coord) = extract_public_key_coords(&public_key_cbor)?;

    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04); // Uncompressed point format
    public_key.extend_from_slice(&x_coord);
    public_key.extend_from_slice(&y_coord);

    let verification_algorithm = &ring::signature::ECDSA_P256_SHA256_ASN1;
    let public_key = UnparsedPublicKey::new(verification_algorithm, &public_key);

    public_key.verify(signed_data, signature).map_err(|_| {
        PasskeyError::Verification("Self attestation signature verification failed".to_string())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;
    use ring::digest;
    use std::sync::Once;

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

    // Helper function to create basic auth_data for testing
    fn create_test_auth_data() -> Vec<u8> {
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

        auth_data
    }

    // Helper function to create a client data hash for testing
    fn create_test_client_data_hash() -> Vec<u8> {
        // Create a SHA-256 hash of a sample client data JSON
        let client_data = r#"{"type":"webauthn.create","challenge":"dGVzdGNoYWxsZW5nZQ","origin":"https://example.com"}"#;
        let hash = digest::digest(&digest::SHA256, client_data.as_bytes());
        hash.as_ref().to_vec()
    }

    // Helper to create an attestation statement with alg and sig
    fn create_test_att_stmt(
        alg: i64,
        sig: &[u8],
        include_x5c: bool,
    ) -> Vec<(CborValue, CborValue)> {
        let mut att_stmt = vec![
            (Value::Text("alg".to_string()), Value::Integer(alg.into())),
            (Value::Text("sig".to_string()), Value::Bytes(sig.to_vec())),
        ];

        if include_x5c {
            // Create a simple self-signed certificate for testing
            // In a real test, we would need to generate a proper x509 certificate
            let cert_bytes = vec![0x30, 0x82, 0x01, 0x01]; // Dummy certificate bytes
            let certs = vec![Value::Bytes(cert_bytes)];
            att_stmt.push((Value::Text("x5c".to_string()), Value::Array(certs)));
        }

        att_stmt
    }

    #[test]
    fn test_verify_packed_attestation_unsupported_alg() {
        let auth_data = create_test_auth_data();
        let client_data_hash = create_test_client_data_hash();

        // Create attestation statement with unsupported algorithm
        let unsupported_alg = -8; // Not ES256
        let sig = vec![0x01, 0x02, 0x03, 0x04]; // Dummy signature
        let att_stmt = create_test_att_stmt(unsupported_alg, &sig, false);

        // Verify the attestation
        let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

        // Should fail with Verification error
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Unsupported or unrecognized algorithm"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    #[test]
    fn test_verify_packed_attestation_ecdaa_not_supported() {
        let auth_data = create_test_auth_data();
        let client_data_hash = create_test_client_data_hash();

        // Create attestation statement with ES256 algorithm
        let sig = vec![0x01, 0x02, 0x03, 0x04]; // Dummy signature
        let mut att_stmt = create_test_att_stmt(ES256_ALG, &sig, false);

        // Add ecdaaKeyId to trigger the ECDAA path
        att_stmt.push((
            Value::Text("ecdaaKeyId".to_string()),
            Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]),
        ));

        // Verify the attestation
        let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

        // Should fail with Verification error
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("ECDAA attestation not supported"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }

    #[test]
    fn test_verify_packed_attestation_both_x5c_and_ecdaa() {
        let auth_data = create_test_auth_data();
        let client_data_hash = create_test_client_data_hash();

        // Create attestation statement with ES256 algorithm and x5c
        let sig = vec![0x01, 0x02, 0x03, 0x04]; // Dummy signature
        let mut att_stmt = create_test_att_stmt(ES256_ALG, &sig, true);

        // Add ecdaaKeyId to trigger the error case
        att_stmt.push((
            Value::Text("ecdaaKeyId".to_string()),
            Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]),
        ));

        // Verify the attestation
        let result = verify_packed_attestation(&auth_data, &client_data_hash, &att_stmt);

        // Should fail with Verification error
        assert!(result.is_err());
        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("both x5c and ecdaaKeyId present"));
        } else {
            panic!("Expected PasskeyError::Verification");
        }
    }
}
