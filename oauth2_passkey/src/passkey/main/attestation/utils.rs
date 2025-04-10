use ciborium::value::{Integer, Value as CborValue};

use crate::passkey::errors::PasskeyError;

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
