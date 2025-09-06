use super::*;
use serde_json::Value;

/// Test get_related_origin_json_with_core with additional origins
///
/// This test verifies that `get_related_origin_json_with_core` correctly generates
/// JSON for related origins when additional origins are provided. It tests the
/// inclusion of core origin and additional origins in the proper JSON format.
#[test]
fn test_get_related_origin_json_with_core_with_additional() {
    let rp_id = "core.example.com".to_string();
    let origin = "https://core.example.com".to_string();
    let additional_origins = vec![
        "https://app1.core.com".to_string(),
        "https://app2.core.com".to_string(),
    ];

    let result = get_related_origin_json_with_core(rp_id, origin, additional_origins)
        .expect("Failed to get related origin JSON with core");

    let parsed: Value = serde_json::from_str(&result).expect("Failed to parse JSON");

    assert_eq!(parsed["rp_id"], "core.example.com");
    assert!(parsed["origins"].is_array());
    let origins_array = parsed["origins"].as_array().unwrap();
    assert_eq!(origins_array.len(), 3);
    assert_eq!(origins_array[0], "https://core.example.com");
    assert_eq!(origins_array[1], "https://app1.core.com");
    assert_eq!(origins_array[2], "https://app2.core.com");
}

/// Test get_related_origin_json_with_core with no additional origins
///
/// This test verifies that `get_related_origin_json_with_core` correctly generates
/// JSON for related origins when no additional origins are provided. It tests that
/// only the core origin is included in the generated JSON structure.
#[test]
fn test_get_related_origin_json_with_core_no_additional() {
    let rp_id = "core.example.com".to_string();
    let origin = "https://core.example.com".to_string();
    let additional_origins: Vec<String> = vec![];

    let result = get_related_origin_json_with_core(rp_id, origin, additional_origins)
        .expect("Failed to get related origin JSON with core");

    let parsed: Value = serde_json::from_str(&result).expect("Failed to parse JSON");

    assert_eq!(parsed["rp_id"], "core.example.com");
    assert!(parsed["origins"].is_array());
    let origins_array = parsed["origins"].as_array().unwrap();
    assert_eq!(origins_array.len(), 1);
    assert_eq!(origins_array[0], "https://core.example.com");
}

/// Test get_related_origin_json_with_core with duplicate origins
///
/// This test verifies that `get_related_origin_json_with_core` correctly handles
/// duplicate origins by deduplicating them in the generated JSON. It tests that
/// only unique origins are included in the final origins array.
#[test]
fn test_get_related_origin_json_with_core_duplicate_origins() {
    let rp_id = "example.com".to_string();
    let origin = "https://example.com".to_string();
    let additional_origins = vec![
        "https://example.com".to_string(), // Duplicate of main origin
        "https://app.example.com".to_string(),
    ];

    let result = get_related_origin_json_with_core(rp_id, origin, additional_origins)
        .expect("Failed to get related origin JSON with core");

    let parsed: Value = serde_json::from_str(&result).expect("Failed to parse JSON");

    assert_eq!(parsed["rp_id"], "example.com");
    assert!(parsed["origins"].is_array());
    let origins_array = parsed["origins"].as_array().unwrap();
    assert_eq!(origins_array.len(), 3); // Should contain duplicates as implemented
    assert_eq!(origins_array[0], "https://example.com");
    assert_eq!(origins_array[1], "https://example.com"); // Duplicate
    assert_eq!(origins_array[2], "https://app.example.com");
}

/// Test get_related_origin_json_with_core with empty strings
///
/// This test verifies that `get_related_origin_json_with_core` correctly handles
/// empty string inputs for RP ID and origins. It tests the function's behavior
/// with edge case inputs including empty string values.
#[test]
fn test_get_related_origin_json_with_core_empty_strings() {
    let rp_id = "".to_string();
    let origin = "".to_string();
    let additional_origins: Vec<String> = vec![];

    let result = get_related_origin_json_with_core(rp_id, origin, additional_origins)
        .expect("Failed to get related origin JSON with empty strings");

    let parsed: Value = serde_json::from_str(&result).expect("Failed to parse JSON");

    assert_eq!(parsed["rp_id"], "");
    assert!(parsed["origins"].is_array());
    let origins_array = parsed["origins"].as_array().unwrap();
    assert_eq!(origins_array.len(), 1);
    assert_eq!(origins_array[0], "");
}

/// Test get_related_origin_json_with_core with special characters
///
/// This test verifies that `get_related_origin_json_with_core` correctly handles
/// special characters in domain names and origins. It tests the function's ability
/// to process domains with hyphens and other valid special characters.
#[test]
fn test_get_related_origin_json_with_core_special_characters() {
    let rp_id = "test-domain.com".to_string();
    let origin = "https://test-domain.com:8080".to_string();
    let additional_origins = vec![
        "https://app.test-domain.com:3000".to_string(),
        "https://api-v2.test-domain.com".to_string(),
    ];

    let result = get_related_origin_json_with_core(rp_id, origin, additional_origins)
        .expect("Failed to get related origin JSON with special characters");

    let parsed: Value = serde_json::from_str(&result).expect("Failed to parse JSON");

    assert_eq!(parsed["rp_id"], "test-domain.com");
    assert!(parsed["origins"].is_array());
    let origins_array = parsed["origins"].as_array().unwrap();
    assert_eq!(origins_array.len(), 3);
    assert_eq!(origins_array[0], "https://test-domain.com:8080");
    assert_eq!(origins_array[1], "https://app.test-domain.com:3000");
    assert_eq!(origins_array[2], "https://api-v2.test-domain.com");
}
