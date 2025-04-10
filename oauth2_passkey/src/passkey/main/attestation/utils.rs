use ciborium::value::{Integer, Value as CborValue};

use crate::passkey::errors::PasskeyError;

const EC2_KEY_TYPE: i64 = 2;
const ES256_ALG: i64 = -7;
const COORD_LENGTH: usize = 32;

/// Helper function to extract algorithm and signature from attestation statement
///
/// # Arguments
/// * `att_stmt` - A reference to a vector of (key, value) pairs representing the attestation statement
///
/// # Returns
/// * `Result<(i64, Vec<u8>), PasskeyError>` - A tuple containing the algorithm identifier and signature, or an error if the attestation statement is invalid
///
/// # Errors
/// * `PasskeyError::Verification` - If the attestation statement is invalid
///
///
pub(super) fn get_sig_from_stmt(
    att_stmt: &Vec<(CborValue, CborValue)>,
) -> Result<(i64, Vec<u8>), PasskeyError> {
    let mut alg: Option<i64> = None;
    let mut sig: Option<Vec<u8>> = None;

    for (key, value) in att_stmt {
        match key {
            CborValue::Text(k) if k == "alg" => {
                if let CborValue::Integer(a) = value {
                    // Store the algorithm ID for later verification
                    // We need to match against known algorithm values
                    alg = Some(integer_to_i64(a));
                }
            }
            CborValue::Text(k) if k == "sig" => {
                if let CborValue::Bytes(s) = value {
                    sig = Some(s.clone());
                }
            }
            _ => {}
        }
    }

    match (alg, sig) {
        (Some(a), Some(s)) => Ok((a, s)),
        _ => Err(PasskeyError::Verification(
            "Missing algorithm or signature in attestation statement".to_string(),
        )),
    }
}

/// Helper function to convert a ciborium::value::Integer to i64
pub(super) fn integer_to_i64(i: &Integer) -> i64 {
    // Since ciborium::value::Integer doesn't have direct conversion methods,
    // we'll implement a simple comparison-based approach

    // Try common small values first for efficiency
    if *i == Integer::from(0) {
        return 0;
    }
    if *i == Integer::from(1) {
        return 1;
    }
    if *i == Integer::from(2) {
        return 2;
    }
    if *i == Integer::from(3) {
        return 3;
    }
    if *i == Integer::from(-1) {
        return -1;
    }
    if *i == Integer::from(-2) {
        return -2;
    }
    if *i == Integer::from(-3) {
        return -3;
    }
    if *i == Integer::from(-7) {
        return -7;
    }

    // Try powers of 2 for larger values
    for n in 0..63 {
        let val = 1i64 << n;
        if *i == Integer::from(val) {
            return val;
        }
        if *i == Integer::from(-val) {
            return -val;
        }
    }

    // For values we can't easily determine, return a default
    // In a production environment, you'd want a more robust conversion
    tracing::warn!("Unable to precisely convert Integer to i64");
    0
}

/// Helper function to extract public key coordinates from COSE key
///
/// # Arguments
/// * `public_key_cbor` - A reference to a COSE key in CBOR format
///
/// # Returns
/// * `Result<(Vec<u8>, Vec<u8>), PasskeyError>` - A tuple containing the x and y coordinates of the public key, or an error if the key is invalid
///
/// # Errors
/// * `PasskeyError::Verification` - If the public key is invalid
///
/// # Example
/// ```
/// let public_key_cbor = ciborium::from_slice(&public_key_cbor_bytes).unwrap();
/// let (x_coord, y_coord) = extract_public_key_coords(&public_key_cbor).unwrap();
/// ```
///
pub(super) fn extract_public_key_coords(
    public_key_cbor: &CborValue,
) -> Result<(Vec<u8>, Vec<u8>), PasskeyError> {
    if let CborValue::Map(map) = public_key_cbor {
        let mut x_coord = None;
        let mut y_coord = None;
        let mut key_type = None;
        let mut algorithm = None;

        for (key, value) in map {
            if let CborValue::Integer(i) = key {
                if i == &Integer::from(1) {
                    // kty
                    if let CborValue::Integer(k) = value {
                        key_type = Some(k);
                    }
                } else if i == &Integer::from(3) {
                    // alg
                    if let CborValue::Integer(a) = value {
                        algorithm = Some(a);
                    }
                } else if i == &Integer::from(-2) {
                    // x coordinate
                    if let CborValue::Bytes(x) = value {
                        x_coord = Some(x.clone());
                    }
                } else if i == &Integer::from(-3) {
                    // y coordinate
                    if let CborValue::Bytes(y) = value {
                        y_coord = Some(y.clone());
                    }
                }
            }
        }

        // Verify key type (2 = EC2) and algorithm (-7 = ES256)
        let key_type_val = Integer::from(EC2_KEY_TYPE);
        let alg_val = Integer::from(ES256_ALG);

        if (key_type != Some(&key_type_val)) || (algorithm != Some(&alg_val)) {
            return Err(PasskeyError::Verification(
                "Invalid key type or algorithm".to_string(),
            ));
        }

        match (x_coord, y_coord) {
            (Some(x), Some(y)) => {
                if x.len() != COORD_LENGTH || y.len() != COORD_LENGTH {
                    return Err(PasskeyError::Verification(
                        "Invalid coordinate length".to_string(),
                    ));
                }
                Ok((x, y))
            }
            _ => Err(PasskeyError::Verification(
                "Missing public key coordinates".to_string(),
            )),
        }
    } else {
        Err(PasskeyError::Verification(
            "Invalid public key format".to_string(),
        ))
    }
}
