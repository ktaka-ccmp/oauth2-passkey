use ciborium::value::Value as CborValue;
use webpki::EndEntityCert;
use x509_parser::{certificate::X509Certificate, prelude::*};

use crate::passkey::errors::PasskeyError;

use super::utils::extract_public_key_coords;

/// Verifies a FIDO-U2F attestation statement
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
pub(super) fn verify_u2f_attestation(
    auth_data: &[u8],
    client_data_hash: &[u8],
    att_stmt: &Vec<(CborValue, CborValue)>,
) -> Result<(), PasskeyError> {
    tracing::debug!("Verifying FIDO-U2F attestation");
    
    // Debug: Log the attestation statement structure
    for (i, (k, v)) in att_stmt.iter().enumerate() {
        tracing::debug!("U2F att_stmt[{}]: key={:?}, value={:?}", i, k, v);
    }

    // For U2F, extract sig and x5c directly
    let mut sig: Option<Vec<u8>> = None;
    let mut x5c_opt: Option<Vec<Vec<u8>>> = None;

    for (k, v) in att_stmt {
        if let CborValue::Text(key_str) = k {
            match key_str.as_str() {
                "sig" => {
                    if let CborValue::Bytes(s) = v {
                        sig = Some(s.clone());
                        tracing::debug!("Found sig: {} bytes", s.len());
                    }
                },
                "x5c" => {
                    if let CborValue::Array(certs) = v {
                        let mut cert_chain = Vec::new();
                        for cert in certs {
                            if let CborValue::Bytes(cert_bytes) = cert {
                                cert_chain.push(cert_bytes.clone());
                            }
                        }
                        if !cert_chain.is_empty() {
                            x5c_opt = Some(cert_chain.clone());
                            tracing::debug!("Found x5c with {} certificates", cert_chain.len());
                        }
                    }
                },
                _ => {
                    tracing::debug!("Unexpected key in U2F attestation: {}", key_str);
                }
            }
        }
    }

    // Check if we have the required fields
    let sig = sig.ok_or_else(|| {
        PasskeyError::Verification("Missing signature in FIDO-U2F attestation".to_string())
    })?;

    let x5c = x5c_opt.ok_or_else(|| {
        PasskeyError::Verification("Missing x5c in FIDO-U2F attestation".to_string())
    })?;

    if x5c.is_empty() {
        return Err(PasskeyError::Verification(
            "Empty x5c in FIDO-U2F attestation".to_string(),
        ));
    }

    // Extract the attestation certificate
    let attestn_cert_bytes = &x5c[0];
    let attestn_cert = EndEntityCert::try_from(attestn_cert_bytes.as_ref()).map_err(|e| {
        PasskeyError::Verification(format!(
            "Failed to parse U2F attestation certificate: {:?}",
            e
        ))
    })?;

    // Parse with x509-parser for additional verifications
    let (_, x509_cert) = X509Certificate::from_der(attestn_cert_bytes).map_err(|e| {
        PasskeyError::Verification(format!("Failed to parse X509 certificate: {}", e))
    })?;

    // Verify certificate is not a CA certificate
    if let Some(basic_constraints) = x509_cert
        .extensions()
        .iter()
        .find(|ext| ext.oid.as_bytes() == oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS.as_bytes())
    {
        if basic_constraints.value.contains(&0x01) {
            return Err(PasskeyError::Verification(
                "U2F certificate must not be a CA certificate".to_string(),
            ));
        }
    }

    // According to FIDO U2F spec, we need to verify the signature over:
    // - The RPID hash (first 32 bytes of auth_data)
    // - The client data hash
    // - The key handle (credential ID)
    // - The public key

    // Extract credential ID length and credential ID
    let credential_id_length = ((auth_data[53] as u16) << 8) | (auth_data[54] as u16);
    let credential_id_end = 55 + credential_id_length as usize;
    
    if auth_data.len() <= credential_id_end {
        return Err(PasskeyError::Verification("Invalid auth_data length".to_string()));
    }

    // Construct verification data according to U2F format
    let mut verification_data = Vec::new();
    
    // U2F verification data starts with a reserved byte (0x00)
    verification_data.push(0x00);
    
    // Add the application parameter (RP ID hash)
    verification_data.extend_from_slice(&auth_data[0..32]);
    
    // Add the challenge parameter (client data hash)
    verification_data.extend_from_slice(client_data_hash);
    
    // Add the credential ID
    let credential_id = &auth_data[55..credential_id_end];
    verification_data.extend_from_slice(credential_id);
    
    // Add the public key
    let public_key_cbor = ciborium::from_reader(&auth_data[credential_id_end..])
        .map_err(|e| PasskeyError::Format(format!("Failed to parse public key CBOR: {}", e)))?;
    
    let (x_coord, y_coord) = extract_public_key_coords(&public_key_cbor)?;
    
    // For U2F, we need to use the raw coordinates
    verification_data.push(0x04); // Uncompressed point format
    verification_data.extend_from_slice(&x_coord);
    verification_data.extend_from_slice(&y_coord);

    // Verify the signature
    attestn_cert
        .verify_signature(&webpki::ECDSA_P256_SHA256, &verification_data, &sig)
        .map_err(|_| {
            PasskeyError::Verification("U2F attestation signature invalid".to_string())
        })?;

    tracing::debug!("FIDO-U2F attestation verification successful");
    Ok(())
}
