use super::*;
use chrono::{TimeZone, Utc};
use http::header::{HeaderMap, SET_COOKIE};

#[test]
fn test_base64url_encode_decode() {
    // Test with simple string
    let original = b"hello world";
    let encoded = base64url_encode(original.to_vec()).expect("Failed to encode");
    let decoded = base64url_decode(&encoded).expect("Failed to decode");
    assert_eq!(decoded, original);

    // Test with empty input
    let empty_encoded = base64url_encode(vec![]).expect("Failed to encode empty");
    let empty_decoded = base64url_decode(&empty_encoded).expect("Failed to decode empty");
    assert!(empty_decoded.is_empty());
}

#[test]
fn test_base64url_decode_invalid() {
    // Test with invalid base64url string
    let invalid_base64 = "This is not base64url!";
    let result = base64url_decode(invalid_base64);
    assert!(matches!(result, Err(UtilError::Format(_))));
}

#[test]
fn test_gen_random_string() {
    // Test different lengths
    for &len in &[0, 1, 10, 32, 64] {
        let result = gen_random_string(len);
        assert!(
            result.is_ok(),
            "Failed to generate random string of length {len}"
        );
        let s = result.unwrap();
        assert_eq!(s.len(), if len == 0 { 0 } else { (len * 4).div_ceil(3) });
    }

    // Verify strings are different
    let s1 = gen_random_string(32).unwrap();
    let s2 = gen_random_string(32).unwrap();
    assert_ne!(s1, s2, "Random strings should be different");
}

#[test]
fn test_header_set_cookie() {
    let mut headers = HeaderMap::new();
    let name = "test_cookie".to_string();
    let value = "test_value".to_string();
    let expires_at = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
    let max_age = 3600;

    let result = header_set_cookie(
        &mut headers,
        name.clone(),
        value.clone(),
        expires_at,
        max_age,
        None,
    );

    assert!(result.is_ok());

    let cookies: Vec<_> = headers
        .get_all(SET_COOKIE)
        .into_iter()
        .filter_map(|v| v.to_str().ok())
        .collect();

    assert_eq!(cookies.len(), 1);
    let cookie = cookies[0];
    assert!(cookie.starts_with(&format!("{name}={value}")));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("Path=/"));
    assert!(cookie.contains(&format!("Max-Age={max_age}")));
}

#[test]
fn test_header_set_cookie_invalid() {
    let mut headers = HeaderMap::new();
    // This should succeed even with spaces in the cookie name
    // since we're not validating cookie names in this version
    let result = header_set_cookie(
        &mut headers,
        "invalid name".to_string(),
        "value".to_string(),
        Utc::now(),
        3600,
        None,
    );

    assert!(
        result.is_ok(),
        "Should accept any cookie name in this version"
    );
}

#[test]
fn test_header_set_cookie_with_domain() {
    let mut headers = HeaderMap::new();
    let name = "session_cookie".to_string();
    let value = "session_value".to_string();
    let expires_at = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
    let max_age = 3600;
    let domain = Some(".example.com");

    let result = header_set_cookie(
        &mut headers,
        name.clone(),
        value.clone(),
        expires_at,
        max_age,
        domain,
    );

    assert!(result.is_ok());

    let cookies: Vec<_> = headers
        .get_all(SET_COOKIE)
        .into_iter()
        .filter_map(|v| v.to_str().ok())
        .collect();

    assert_eq!(cookies.len(), 1);
    let cookie = cookies[0];
    assert!(cookie.starts_with(&format!("{name}={value}")));
    assert!(cookie.contains("Domain=.example.com"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
}
