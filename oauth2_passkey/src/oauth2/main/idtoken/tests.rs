use super::*;

/// Test finding an existing JWK in a JWK set
///
/// This test verifies that `find_jwk` correctly finds a JWK when it exists in the set.
/// It creates a JWK set with two keys in memory, searches for an existing key ID,
/// and verifies that the correct JWK is returned with matching properties.
///
#[test]
fn test_find_jwk_existing_key() {
    let jwks = Jwks {
        keys: vec![
            Jwk {
                kty: "RSA".to_string(),
                kid: "key1".to_string(),
                alg: Some("RS256".to_string()),
                n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
                crv: None,
                k: None,
            },
            Jwk {
                kty: "RSA".to_string(),
                kid: "key2".to_string(),
                alg: Some("RS256".to_string()),
                n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
                crv: None,
                k: None,
            },
        ],
    };

    let result = find_jwk(&jwks, "key1");
    assert!(result.is_some());
    assert_eq!(result.unwrap().kid, "key1");
    assert_eq!(result.unwrap().alg, Some("RS256".to_string()));
}

/// Test finding a non-existing JWK in a JWK set
///
/// This test verifies that `find_jwk` correctly returns None when searching for a key ID
/// that doesn't exist in the JWK set. It creates a JWK set with one key in memory,
/// searches for a non-existing key ID, and verifies that None is returned.
///
#[test]
fn test_find_jwk_non_existing_key() {
    let jwks = Jwks {
        keys: vec![
            Jwk {
                kty: "RSA".to_string(),
                kid: "key1".to_string(),
                alg: Some("RS256".to_string()),
                n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
                crv: None,
                k: None,
            },
        ],
    };

    let result = find_jwk(&jwks, "non_existing_key");
    assert!(result.is_none());
}

/// Test finding a JWK in an empty JWK set
///
/// This test verifies that `find_jwk` correctly returns None when searching in an empty
/// JWK set. It creates an empty JWK set in memory, searches for any key ID,
/// and verifies that None is returned.
///
#[test]
fn test_find_jwk_empty_jwks() {
    let jwks = Jwks { keys: vec![] };

    let result = find_jwk(&jwks, "any_key");
    assert!(result.is_none());
}

/// Test decoding a valid base64 URL-safe string
///
/// This test verifies that `decode_base64_url_safe` correctly decodes a valid base64
/// URL-safe encoded string. It tests with a known input/output pair and verifies
/// the decoded bytes match the expected result.
///
#[test]
fn test_decode_base64_url_safe_valid() {
    // Test valid base64 URL-safe encoding
    let input = "SGVsbG9Xb3JsZA"; // "HelloWorld" in base64
    let result = decode_base64_url_safe(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), b"HelloWorld");
}

/// Test decoding an empty base64 URL-safe string
///
/// This test verifies that `decode_base64_url_safe` correctly handles an empty string
/// input, returning an empty Vec<u8> as expected.
///
#[test]
fn test_decode_base64_url_safe_empty() {
    let result = decode_base64_url_safe("");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Vec::<u8>::new());
}

/// Test decoding an invalid base64 URL-safe string
///
/// This test verifies that `decode_base64_url_safe` correctly rejects invalid base64
/// input by returning a Base64Error. It tests with malformed input that contains
/// invalid characters for base64 encoding.
///
#[test]
fn test_decode_base64_url_safe_invalid() {
    // Test invalid base64 input
    let input = "Invalid@Base64!";
    let result = decode_base64_url_safe(input);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TokenVerificationError::Base64Error(_)
    ));
}

/// Test decoding a base64 URL-safe string with padding
///
/// This test verifies that the URL_SAFE_NO_PAD decoder correctly handles base64
/// strings without padding. It tests with "Hello" encoded as base64 without
/// padding and verifies the correct decoding.
///
#[test]
fn test_decode_base64_url_safe_padding() {
    // Test that URL_SAFE_NO_PAD works correctly
    let input = "SGVsbG8"; // "Hello" in base64 without padding
    let result = decode_base64_url_safe(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), b"Hello");
}

/// Test JWK to decoding key conversion with missing 'n' component
///
/// This test verifies that `convert_jwk_to_decoding_key` returns a MissingKeyComponent
/// error when the required 'n' component is missing from an RSA JWK.
///
#[test]
fn test_convert_jwk_to_decoding_key_missing_n_component() {
    let jwk = Jwk {
        kty: "RSA".to_string(),
        kid: "test_key".to_string(),
        alg: Some("RS256".to_string()),
        n: None, // Missing n component
        e: Some("AQAB".to_string()),
        x: None,
        y: None,
        crv: None,
        k: None,
    };

    let result = convert_jwk_to_decoding_key(&jwk);
    assert!(result.is_err());
    match result {
        Err(TokenVerificationError::MissingKeyComponent(ref s)) => assert_eq!(s, "n"),
        _ => panic!("Expected MissingKeyComponent error for 'n'"),
    }
}

/// Test JWK to decoding key conversion with missing 'e' component
///
/// This test verifies that `convert_jwk_to_decoding_key` returns a MissingKeyComponent
/// error when the required 'e' component is missing from an RSA JWK.
///
#[test]
fn test_convert_jwk_to_decoding_key_missing_e_component() {
    let jwk = Jwk {
        kty: "RSA".to_string(),
        kid: "test_key".to_string(),
        alg: Some("RS256".to_string()),
        n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
        e: None, // Missing e component
        x: None,
        y: None,
        crv: None,
        k: None,
    };

    let result = convert_jwk_to_decoding_key(&jwk);
    assert!(result.is_err());
    match result {
        Err(TokenVerificationError::MissingKeyComponent(ref s)) => assert_eq!(s, "e"),
        Err(ref e) => panic!("Expected MissingKeyComponent error for 'e', got: {e:?}"),
        _ => panic!("Expected error"),
    }
}

/// Test JWK to decoding key conversion with missing 'x' component for ES256
///
/// This test verifies that `convert_jwk_to_decoding_key` returns a MissingKeyComponent
/// error when the required 'x' component is missing from an EC JWK using ES256.
///
#[test]
fn test_convert_jwk_to_decoding_key_missing_x_component_es256() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        kid: "test_key".to_string(),
        alg: Some("ES256".to_string()),
        n: None,
        e: None,
        x: None, // Missing x component
        y: Some("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4".to_string()),
        crv: Some("P-256".to_string()),
        k: None,
    };

    let result = convert_jwk_to_decoding_key(&jwk);
    assert!(result.is_err());
    match result {
        Err(TokenVerificationError::MissingKeyComponent(ref s)) => assert_eq!(s, "x"),
        _ => panic!("Expected MissingKeyComponent error for 'x'"),
    }
}

/// Test JWK to decoding key conversion with missing 'y' component for ES256
///
/// This test verifies that `convert_jwk_to_decoding_key` returns a MissingKeyComponent
/// error when the required 'y' component is missing from an EC JWK using ES256.
///
#[test]
fn test_convert_jwk_to_decoding_key_missing_y_component_es256() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        kid: "test_key".to_string(),
        alg: Some("ES256".to_string()),
        n: None,
        e: None,
        x: Some("WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXw".to_string()),
        y: None, // Missing y component
        crv: Some("P-256".to_string()),
        k: None,
    };

    let result = convert_jwk_to_decoding_key(&jwk);
    assert!(result.is_err());
    match result {
        Err(TokenVerificationError::MissingKeyComponent(ref s)) => assert_eq!(s, "y"),
        _ => panic!("Expected MissingKeyComponent error for 'y'"),
    }
}

/// Test JWK to decoding key conversion with missing 'k' component for HS256
///
/// This test verifies that `convert_jwk_to_decoding_key` returns a MissingKeyComponent
/// error when the required 'k' component is missing from an HMAC JWK using HS256.
///
#[test]
fn test_convert_jwk_to_decoding_key_missing_k_component_hs256() {
    let jwk = Jwk {
        kty: "oct".to_string(),
        kid: "test_key".to_string(),
        alg: Some("HS256".to_string()),
        n: None,
        e: None,
        x: None,
        y: None,
        crv: None,
        k: None, // Missing k component
    };

    let result = convert_jwk_to_decoding_key(&jwk);
    assert!(result.is_err());
    match result {
        Err(TokenVerificationError::MissingKeyComponent(ref s)) => assert_eq!(s, "k"),
        _ => panic!("Expected MissingKeyComponent error for 'k'"),
    }
}

/// Test JWK to decoding key conversion with unsupported algorithm
///
/// This test verifies that `convert_jwk_to_decoding_key` returns an UnsupportedAlgorithm
/// error when given a JWK with an algorithm that is not supported.
///
#[test]
fn test_convert_jwk_to_decoding_key_unsupported_algorithm() {
    let jwk = Jwk {
        kty: "RSA".to_string(),
        kid: "test_key".to_string(),
        alg: Some("UNSUPPORTED".to_string()),
        n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
        e: Some("AQAB".to_string()),
        x: None,
        y: None,
        crv: None,
        k: None,
    };

    let result = convert_jwk_to_decoding_key(&jwk);
    assert!(result.is_err());
    match result {
        Err(TokenVerificationError::UnsupportedAlgorithm(ref s)) => {
            assert_eq!(s, "UNSUPPORTED")
        }
        _ => panic!("Expected UnsupportedAlgorithm error"),
    }
}

/// Test JWK to decoding key conversion with valid HS256 key
///
/// This test verifies that `convert_jwk_to_decoding_key` successfully converts
/// a valid HMAC JWK with HS256 algorithm to a DecodingKey.
///
#[test]
fn test_convert_jwk_to_decoding_key_hs256_valid() {
    let jwk = Jwk {
        kty: "oct".to_string(),
        kid: "test_key".to_string(),
        alg: Some("HS256".to_string()),
        n: None,
        e: None,
        x: None,
        y: None,
        crv: None,
        k: Some("c2VjcmV0a2V5MTIz".to_string()), // "secretkey123" in base64
    };

    let result = convert_jwk_to_decoding_key(&jwk);
    assert!(result.is_ok());
}

/// Test JWK to decoding key conversion when `alg` is absent.
///
/// Some providers (notably Microsoft Entra) publish JWKS entries without
/// the optional `alg` field. `convert_jwk_to_decoding_key` must infer the
/// algorithm from `kty`: RSA -> RS256.
///
#[test]
fn test_convert_jwk_to_decoding_key_alg_none_rsa_defaults_to_rs256() {
    let jwk = Jwk {
        kty: "RSA".to_string(),
        kid: "test_key".to_string(),
        alg: None, // Provider omitted `alg`; should default to RS256.
        n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
        e: Some("AQAB".to_string()),
        x: None,
        y: None,
        crv: None,
        k: None,
    };

    let result = convert_jwk_to_decoding_key(&jwk);
    assert!(
        result.is_ok(),
        "expected RSA with alg: None to succeed via RS256 default, got: {result:?}"
    );
}

/// Test token decoding with too few parts
///
/// This test verifies that `decode_token` returns InvalidTokenFormat error
/// when given a token with only 2 parts instead of the required 3.
///
#[test]
fn test_decode_token_invalid_format_too_few_parts() {
    let token = "header.payload"; // Only 2 parts instead of 3
    let result = decode_token(token);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TokenVerificationError::InvalidTokenFormat
    ));
}

/// Test token decoding with too many parts
///
/// This test verifies that `decode_token` returns InvalidTokenFormat error
/// when given a token with 4 parts instead of the required 3.
///
#[test]
fn test_decode_token_invalid_format_too_many_parts() {
    let token = "header.payload.signature.extra"; // 4 parts instead of 3
    let result = decode_token(token);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TokenVerificationError::InvalidTokenFormat
    ));
}

/// Test token decoding with invalid base64 payload
///
/// This test verifies that `decode_token` returns a Base64Error when the payload
/// contains invalid base64 characters that cannot be decoded.
///
#[test]
fn test_decode_token_invalid_base64_payload() {
    let token = "header.invalid@base64.signature";
    let result = decode_token(token);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TokenVerificationError::Base64Error(_)
    ));
}

/// Test token decoding with invalid JSON payload
///
/// This test verifies that `decode_token` returns a JsonError when the payload
/// contains valid base64 but invalid JSON that cannot be parsed.
///
#[test]
fn test_decode_token_invalid_json_payload() {
    // Valid base64 but invalid JSON
    let invalid_json_b64 = "aW52YWxpZGpzb24"; // "invalidjson" in base64
    let token = format!("header.{invalid_json_b64}.signature");
    let result = decode_token(&token);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TokenVerificationError::JsonError(_)
    ));
}

/// Test token decoding with valid payload
///
/// This test verifies that `decode_token` successfully decodes a token with a valid
/// JSON payload, creating a proper OidcIdInfo struct with the expected field values.
///
#[test]
fn test_decode_token_valid_payload() {
    // Create a valid OidcIdInfo JSON payload
    let id_info_json = r#"{
        "iss": "https://accounts.google.com",
        "sub": "123456789",
        "azp": "client_id",
        "aud": "audience",
        "email": "test@example.com",
        "email_verified": true,
        "name": "Test User",
        "given_name": "Test",
        "family_name": "User",
        "iat": 1640995200,
        "exp": 1641001200
    }"#;

    // Encode to base64 URL-safe
    let payload_b64 = URL_SAFE_NO_PAD.encode(id_info_json.as_bytes());
    let token = format!("header.{payload_b64}.signature");

    let result = decode_token(&token);
    assert!(result.is_ok());
    let id_info = result.unwrap();
    assert_eq!(id_info.iss, "https://accounts.google.com");
    assert_eq!(id_info.sub, "123456789");
    assert_eq!(id_info.email, Some("test@example.com".to_string()));
    assert_eq!(id_info.email_verified, Some(true));
    assert_eq!(id_info.name, Some("Test User".to_string()));
}

/// Test signature verification with invalid token format
///
/// This test verifies that `verify_signature` returns InvalidTokenFormat error
/// when given a token with insufficient parts for signature verification.
///
#[test]
fn test_verify_signature_invalid_token_format() {
    let token = "header.payload"; // Only 2 parts instead of 3
    let decoding_key = DecodingKey::from_secret(b"secret");
    let result = verify_signature(token, &decoding_key, Algorithm::HS256);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TokenVerificationError::InvalidTokenFormat
    ));
}

/// Test signature verification with invalid base64 signature
///
/// This test verifies that `verify_signature` returns a Base64Error when the signature
/// part contains invalid base64 characters that cannot be decoded.
///
#[test]
fn test_verify_signature_invalid_base64_signature() {
    let token = "header.payload.invalid@base64";
    let decoding_key = DecodingKey::from_secret(b"secret");
    let result = verify_signature(token, &decoding_key, Algorithm::HS256);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TokenVerificationError::Base64Error(_)
    ));
}

/// Test signature verification with valid HS256 signature
///
/// This test verifies that `verify_signature` correctly validates a JWT token
/// signed with HS256 when using the correct secret key.
///
#[test]
fn test_verify_signature_valid_hs256() {
    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
    }

    let secret = b"test_secret_key_for_hs256_verification";
    let claims = TestClaims {
        sub: "test_user".to_string(),
    };
    let header = jsonwebtoken::Header::new(Algorithm::HS256);
    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .expect("Failed to encode JWT");

    let decoding_key = DecodingKey::from_secret(secret);
    let result = verify_signature(&token, &decoding_key, Algorithm::HS256);
    assert!(result.is_ok(), "Verification should succeed: {result:?}");
    assert!(
        result.unwrap(),
        "Signature should be valid with correct key"
    );
}

/// Test signature verification rejects wrong HS256 key
///
/// This test verifies that `verify_signature` correctly rejects a JWT token
/// when verified with a different secret key than the one used for signing.
/// This guarantees the signature validation logic actually protects against
/// token tampering.
///
#[test]
fn test_verify_signature_wrong_key_hs256() {
    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
    }

    let signing_secret = b"correct_secret_key";
    let wrong_secret = b"wrong_secret_key";
    let claims = TestClaims {
        sub: "test_user".to_string(),
    };
    let header = jsonwebtoken::Header::new(Algorithm::HS256);
    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(signing_secret),
    )
    .expect("Failed to encode JWT");

    let wrong_key = DecodingKey::from_secret(wrong_secret);
    let result = verify_signature(&token, &wrong_key, Algorithm::HS256);
    assert!(
        result.is_ok(),
        "Wrong key should not cause an error: {result:?}"
    );
    assert!(
        !result.unwrap(),
        "Signature should be invalid with wrong key"
    );
}

/// Test TokenVerificationError display formatting
///
/// This test verifies that all TokenVerificationError variants produce the correct
/// error message strings when converted to string representation.
///
#[test]
fn test_token_verification_error_display() {
    // Test various error message formats
    let error = TokenVerificationError::InvalidTokenFormat;
    assert_eq!(error.to_string(), "Invalid token format");

    let error = TokenVerificationError::InvalidTokenSignature;
    assert_eq!(error.to_string(), "Invalid token signature");

    let error =
        TokenVerificationError::InvalidTokenAudience("expected".to_string(), "actual".to_string());
    assert_eq!(
        error.to_string(),
        "Invalid token audience, expected: expected, actual: actual"
    );

    let error =
        TokenVerificationError::InvalidTokenIssuer("expected".to_string(), "actual".to_string());
    assert_eq!(
        error.to_string(),
        "Invalid token issuer, expected: expected, actual: actual"
    );

    let error = TokenVerificationError::TokenExpired;
    assert_eq!(error.to_string(), "Token expired");

    let error = TokenVerificationError::TokenNotYetValidNotBeFore(1000, 2000);
    assert_eq!(
        error.to_string(),
        "Token not yet valid, now: 1000, nbf: 2000"
    );

    let error = TokenVerificationError::TokenNotYetValidIssuedAt(1000, 2000);
    assert_eq!(
        error.to_string(),
        "Token not yet valid, now: 1000, iat: 2000"
    );

    let error = TokenVerificationError::NoMatchingKey;
    assert_eq!(error.to_string(), "No matching key found in JWKS");

    let error = TokenVerificationError::MissingKeyComponent("n".to_string());
    assert_eq!(error.to_string(), "Missing key component: n");

    let error = TokenVerificationError::UnsupportedAlgorithm("UNKNOWN".to_string());
    assert_eq!(error.to_string(), "Unsupported algorithm: UNKNOWN");

    let error = TokenVerificationError::JwksParsing("parse error".to_string());
    assert_eq!(error.to_string(), "JWKS parsing error: parse error");
}

/// Test JwksCache serialization and deserialization
///
/// This test verifies that JwksCache can be properly converted to and from CacheData,
/// ensuring the serialization roundtrip maintains data integrity.
///
#[test]
fn test_jwks_cache_conversion() {
    // Test JwksCache to CacheData conversion
    let jwks = Jwks {
        keys: vec![
            Jwk {
                kty: "RSA".to_string(),
                kid: "key1".to_string(),
                alg: Some("RS256".to_string()),
                n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
                crv: None,
                k: None,
            },
        ],
    };

    let expires_at = Utc::now() + chrono::Duration::seconds(600);
    let jwks_cache = JwksCache {
        jwks: jwks.clone(),
        expires_at,
    };

    // Test From conversion
    let cache_data: CacheData = jwks_cache.clone().into();
    assert!(!cache_data.value.is_empty());

    // Test TryFrom conversion back
    let restored_cache: Result<JwksCache, TokenVerificationError> = cache_data.try_into();
    assert!(restored_cache.is_ok());
    let restored = restored_cache.unwrap();
    assert_eq!(restored.jwks.keys.len(), 1);
    assert_eq!(restored.jwks.keys[0].kid, "key1");
}

/// Test JwksCache conversion with invalid JSON
///
/// This test verifies that attempting to convert invalid JSON to JwksCache
/// returns a JwksParsing error as expected.
///
#[test]
fn test_jwks_cache_invalid_json() {
    let invalid_cache_data = CacheData {
        value: "invalid json".to_string(),
    };

    let result: Result<JwksCache, TokenVerificationError> = invalid_cache_data.try_into();
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TokenVerificationError::JwksParsing(_)
    ));
}
