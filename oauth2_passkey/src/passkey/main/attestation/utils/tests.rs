use super::*;
use ciborium::value::Value as CborValue;

#[test]
fn test_get_sig_from_stmt_success() {
    // Create a valid attestation statement with alg and sig
    let att_stmt = vec![
        (
            CborValue::Text("alg".to_string()),
            CborValue::Integer(Integer::from(-7)), // ES256
        ),
        (
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(vec![0x01, 0x02, 0x03, 0x04]), // Dummy signature
        ),
    ];

    let result = get_sig_from_stmt(&att_stmt);
    assert!(result.is_ok());

    let (alg, sig) = result.unwrap();
    assert_eq!(alg, -7);
    assert_eq!(sig, vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn test_get_sig_from_stmt_missing_alg() {
    // Create an attestation statement missing the alg field
    let att_stmt = vec![(
        CborValue::Text("sig".to_string()),
        CborValue::Bytes(vec![0x01, 0x02, 0x03, 0x04]), // Dummy signature
    )];

    let result = get_sig_from_stmt(&att_stmt);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Missing algorithm or signature"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_get_sig_from_stmt_missing_sig() {
    // Create an attestation statement missing the sig field
    let att_stmt = vec![(
        CborValue::Text("alg".to_string()),
        CborValue::Integer(Integer::from(-7)), // ES256
    )];

    let result = get_sig_from_stmt(&att_stmt);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Missing algorithm or signature"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_get_sig_from_stmt_wrong_types() {
    // Create an attestation statement with wrong types
    let att_stmt = vec![
        (
            CborValue::Text("alg".to_string()),
            CborValue::Text("ES256".to_string()), // Wrong type for alg
        ),
        (
            CborValue::Text("sig".to_string()),
            CborValue::Integer(Integer::from(123)), // Wrong type for sig
        ),
    ];

    let result = get_sig_from_stmt(&att_stmt);
    assert!(result.is_err());
}

#[test]
fn test_get_sig_from_stmt_empty_statement() {
    // Test with empty attestation statement
    let att_stmt = vec![];

    let result = get_sig_from_stmt(&att_stmt);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Missing algorithm or signature"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_get_sig_from_stmt_irrelevant_keys() {
    // Test with attestation statement containing irrelevant keys but missing required ones
    let att_stmt = vec![
        (
            CborValue::Text("fmt".to_string()),
            CborValue::Text("packed".to_string()),
        ),
        (CborValue::Text("x5c".to_string()), CborValue::Array(vec![])),
    ];

    let result = get_sig_from_stmt(&att_stmt);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Missing algorithm or signature"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_get_sig_from_stmt_empty_signature() {
    // Test with empty signature bytes
    let att_stmt = vec![
        (
            CborValue::Text("alg".to_string()),
            CborValue::Integer(Integer::from(-7)), // ES256
        ),
        (
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(vec![]), // Empty signature
        ),
    ];

    let result = get_sig_from_stmt(&att_stmt);
    assert!(result.is_ok());

    let (alg, sig) = result.unwrap();
    assert_eq!(alg, -7);
    assert_eq!(sig, Vec::<u8>::new()); // Function allows empty signature, validation happens elsewhere
}

#[test]
fn test_integer_to_i64_common_values() {
    // Test common values
    assert_eq!(integer_to_i64(&Integer::from(0)), 0);
    assert_eq!(integer_to_i64(&Integer::from(1)), 1);
    assert_eq!(integer_to_i64(&Integer::from(2)), 2);
    assert_eq!(integer_to_i64(&Integer::from(3)), 3);
    assert_eq!(integer_to_i64(&Integer::from(-1)), -1);
    assert_eq!(integer_to_i64(&Integer::from(-2)), -2);
    assert_eq!(integer_to_i64(&Integer::from(-3)), -3);
    assert_eq!(integer_to_i64(&Integer::from(-7)), -7);

    // Test TPM-specific values
    assert_eq!(integer_to_i64(&Integer::from(-257)), -257);
    assert_eq!(integer_to_i64(&Integer::from(999)), 999);
}

#[test]
fn test_integer_to_i64_fallback_case() {
    // Test that large primes that aren't powers of 2 trigger fallback
    // The function should return 0 and log a warning for unknown values
    // We'll use a value that's definitely not a small value or power of 2
    let weird_value = 1000000007; // Large prime

    // Since the function returns 0 for unrecognized values, we expect 0
    assert_eq!(integer_to_i64(&Integer::from(weird_value)), 0);

    // Also test with a known non-power-of-2 that's not in our small values list
    let another_value = 123456789;
    assert_eq!(integer_to_i64(&Integer::from(another_value)), 0);
}

#[test]
fn test_integer_to_i64_simplified_powers_of_two() {
    // Test a few key powers of 2 (consolidated from the verbose previous test)
    assert_eq!(integer_to_i64(&Integer::from(4)), 4); // 2^2
    assert_eq!(integer_to_i64(&Integer::from(8)), 8); // 2^3
    assert_eq!(integer_to_i64(&Integer::from(256)), 256); // 2^8
    assert_eq!(integer_to_i64(&Integer::from(1024)), 1024); // 2^10

    // Test negative powers of 2
    assert_eq!(integer_to_i64(&Integer::from(-4)), -4);
    assert_eq!(integer_to_i64(&Integer::from(-8)), -8);
}

#[test]
fn test_extract_public_key_coords_success() {
    // Create a valid COSE key
    let public_key_entries = vec![
        // kty: EC2 (2)
        (
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(2)),
        ),
        // alg: ES256 (-7)
        (
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-7)),
        ),
        // x coordinate (32 bytes)
        (
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(vec![0x01; 32]),
        ),
        // y coordinate (32 bytes)
        (
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(vec![0x02; 32]),
        ),
    ];

    let public_key = CborValue::Map(public_key_entries);

    let result = extract_public_key_coords(&public_key);
    assert!(result.is_ok());

    let (x, y) = result.unwrap();
    assert_eq!(x, vec![0x01; 32]);
    assert_eq!(y, vec![0x02; 32]);
}

#[test]
fn test_extract_public_key_coords_invalid_key_type() {
    // Create a COSE key with invalid key type
    let public_key_entries = vec![
        // kty: Not EC2
        (
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(1)),
        ),
        // alg: ES256 (-7)
        (
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-7)),
        ),
        // x coordinate (32 bytes)
        (
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(vec![0x01; 32]),
        ),
        // y coordinate (32 bytes)
        (
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(vec![0x02; 32]),
        ),
    ];

    let public_key = CborValue::Map(public_key_entries);

    let result = extract_public_key_coords(&public_key);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Invalid key type or algorithm"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_extract_public_key_coords_invalid_algorithm() {
    // Create a COSE key with invalid algorithm
    let public_key_entries = vec![
        // kty: EC2 (2)
        (
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(2)),
        ),
        // alg: Not ES256
        (
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-8)),
        ),
        // x coordinate (32 bytes)
        (
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(vec![0x01; 32]),
        ),
        // y coordinate (32 bytes)
        (
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(vec![0x02; 32]),
        ),
    ];

    let public_key = CborValue::Map(public_key_entries);

    let result = extract_public_key_coords(&public_key);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Invalid key type or algorithm"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_extract_public_key_coords_missing_x() {
    // Create a COSE key missing x coordinate
    let public_key_entries = vec![
        // kty: EC2 (2)
        (
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(2)),
        ),
        // alg: ES256 (-7)
        (
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-7)),
        ),
        // y coordinate (32 bytes)
        (
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(vec![0x02; 32]),
        ),
    ];

    let public_key = CborValue::Map(public_key_entries);

    let result = extract_public_key_coords(&public_key);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Missing public key coordinates"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_extract_public_key_coords_missing_y() {
    // Create a COSE key missing y coordinate
    let public_key_entries = vec![
        // kty: EC2 (2)
        (
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(2)),
        ),
        // alg: ES256 (-7)
        (
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-7)),
        ),
        // x coordinate (32 bytes)
        (
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(vec![0x01; 32]),
        ),
    ];

    let public_key = CborValue::Map(public_key_entries);

    let result = extract_public_key_coords(&public_key);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Missing public key coordinates"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_extract_public_key_coords_invalid_coordinate_length() {
    // Create a COSE key with invalid coordinate length
    let public_key_entries = vec![
        // kty: EC2 (2)
        (
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(2)),
        ),
        // alg: ES256 (-7)
        (
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-7)),
        ),
        // x coordinate (invalid length)
        (
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(vec![0x01; 16]),
        ),
        // y coordinate (32 bytes)
        (
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(vec![0x02; 32]),
        ),
    ];

    let public_key = CborValue::Map(public_key_entries);

    let result = extract_public_key_coords(&public_key);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Invalid coordinate length"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_extract_public_key_coords_invalid_format() {
    // Create an invalid public key (not a map)
    let public_key = CborValue::Array(vec![
        CborValue::Integer(Integer::from(1)),
        CborValue::Integer(Integer::from(2)),
    ]);

    let result = extract_public_key_coords(&public_key);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Invalid public key format"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_extract_public_key_coords_missing_both_coordinates() {
    // Create a COSE key missing both x and y coordinates
    let public_key_entries = vec![
        // kty: EC2 (2)
        (
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(2)),
        ),
        // alg: ES256 (-7)
        (
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-7)),
        ),
    ];

    let public_key = CborValue::Map(public_key_entries);

    let result = extract_public_key_coords(&public_key);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Missing public key coordinates"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_extract_public_key_coords_zero_length_coordinates() {
    // Create a COSE key with zero-length coordinates
    let public_key_entries = vec![
        // kty: EC2 (2)
        (
            CborValue::Integer(Integer::from(1)),
            CborValue::Integer(Integer::from(2)),
        ),
        // alg: ES256 (-7)
        (
            CborValue::Integer(Integer::from(3)),
            CborValue::Integer(Integer::from(-7)),
        ),
        // x coordinate (zero length)
        (
            CborValue::Integer(Integer::from(-2)),
            CborValue::Bytes(vec![]),
        ),
        // y coordinate (32 bytes)
        (
            CborValue::Integer(Integer::from(-3)),
            CborValue::Bytes(vec![0x02; 32]),
        ),
    ];

    let public_key = CborValue::Map(public_key_entries);

    let result = extract_public_key_coords(&public_key);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Invalid coordinate length"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}

#[test]
fn test_extract_public_key_coords_boundary_lengths() {
    // Test coordinate lengths at boundaries (31 and 33 bytes)
    let test_cases = vec![(31, "too short"), (33, "too long")];

    for (length, description) in test_cases {
        let public_key_entries = vec![
            // kty: EC2 (2)
            (
                CborValue::Integer(Integer::from(1)),
                CborValue::Integer(Integer::from(2)),
            ),
            // alg: ES256 (-7)
            (
                CborValue::Integer(Integer::from(3)),
                CborValue::Integer(Integer::from(-7)),
            ),
            // x coordinate (boundary length)
            (
                CborValue::Integer(Integer::from(-2)),
                CborValue::Bytes(vec![0x01; length]),
            ),
            // y coordinate (32 bytes)
            (
                CborValue::Integer(Integer::from(-3)),
                CborValue::Bytes(vec![0x02; 32]),
            ),
        ];

        let public_key = CborValue::Map(public_key_entries);

        let result = extract_public_key_coords(&public_key);
        assert!(
            result.is_err(),
            "Should fail for {description} coordinate length"
        );

        if let Err(PasskeyError::Verification(msg)) = result {
            assert!(msg.contains("Invalid coordinate length"));
        } else {
            panic!("Expected PasskeyError::Verification for {description} length");
        }
    }
}

#[test]
fn test_extract_public_key_coords_empty_map() {
    // Test with completely empty map
    let public_key = CborValue::Map(vec![]);

    let result = extract_public_key_coords(&public_key);
    assert!(result.is_err());

    if let Err(PasskeyError::Verification(msg)) = result {
        assert!(msg.contains("Invalid key type or algorithm"));
    } else {
        panic!("Expected PasskeyError::Verification");
    }
}
