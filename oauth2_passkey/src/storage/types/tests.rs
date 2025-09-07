use super::*;

#[test]
fn test_cache_key_validation_redis_commands() {
    // Test that Redis command keywords are rejected when they appear as standalone words
    let dangerous_keys = vec![
        "SET",           // Exact command
        "SET value",     // Command at start
        "key SET",       // Command at end
        "key SET value", // Command in middle
        "GET\nvalue",    // Command with newline
    ];

    for key in dangerous_keys {
        let result = CacheKey::new(key.to_string());
        assert!(
            result.is_err(),
            "Should reject key containing Redis command: {key}"
        );
    }

    // Test that legitimate keys with command substrings are accepted
    let safe_keys = vec![
        "test-session-test-admin-get-1755225833867", // Contains "GET" but not standalone
        "user_settings",                             // Contains "SET" but not standalone
        "delete_item",                               // Contains "DEL" but not standalone
    ];

    for key in safe_keys {
        let result = CacheKey::new(key.to_string());
        assert!(
            result.is_ok(),
            "Should accept safe key with command substring: {key}"
        );
    }
}

#[test]
fn test_cache_key_validation_dangerous_chars() {
    // Test that dangerous characters are rejected
    let dangerous_keys = vec![
        "key\nwith\nnewlines",
        "key\rwith\rcarriage\rreturns",
        "key with spaces",
        "key\twith\ttabs",
    ];

    for key in dangerous_keys {
        let result = CacheKey::new(key.to_string());
        assert!(
            result.is_err(),
            "Should reject key with dangerous chars: {key:?}"
        );
    }
}

#[test]
fn test_cache_key_validation_length_limit() {
    // Test length limit (250 characters)
    let long_key = "a".repeat(251);
    let result = CacheKey::new(long_key);
    assert!(
        result.is_err(),
        "Should reject key longer than 250 characters"
    );

    // Test acceptable length
    let ok_key = "a".repeat(250);
    let result = CacheKey::new(ok_key);
    assert!(
        result.is_ok(),
        "Should accept key with exactly 250 characters"
    );
}

#[test]
fn test_cache_key_validation_valid_keys() {
    // Test that valid keys are accepted
    let valid_keys = vec![
        "session_123",
        "user-profile_456",
        "oauth2_token_abc",
        "aaguid_def",
        "", // Empty key allowed
    ];

    for key in valid_keys {
        let result = CacheKey::new(key.to_string());
        assert!(result.is_ok(), "Should accept valid key: {key}");
    }
}

#[test]
fn test_cache_prefix_validation_consistency() {
    // Test that CachePrefix has the same validation as CacheKey

    // Redis commands should be rejected only when standalone
    let result = CachePrefix::new("SET".to_string());
    assert!(
        result.is_err(),
        "Should reject prefix with standalone Redis command"
    );

    // But substrings should be accepted
    let result = CachePrefix::new("user_settings".to_string());
    assert!(
        result.is_ok(),
        "Should accept prefix with command substring"
    );

    // Dangerous characters should be rejected
    let result = CachePrefix::new("prefix with spaces".to_string());
    assert!(result.is_err(), "Should reject prefix with dangerous chars");

    // Length limit should be enforced
    let long_prefix = "a".repeat(251);
    let result = CachePrefix::new(long_prefix);
    assert!(
        result.is_err(),
        "Should reject prefix longer than 250 characters"
    );

    // Valid prefixes should be accepted
    let result = CachePrefix::new("session".to_string());
    assert!(result.is_ok(), "Should accept valid prefix");
}

#[test]
fn test_cache_validation_memory_redis_consistency() {
    // This test verifies that both Memory and Redis cache backends now have
    // identical validation through the typed interface

    // Create a key that would have been vulnerable in Memory cache before Phase 2
    let malicious_key = "user123\nSET malicious_key malicious_value";

    // Both CachePrefix and CacheKey should reject this
    let prefix_result = CachePrefix::new("session".to_string());
    let key_result = CacheKey::new(malicious_key.to_string());

    assert!(prefix_result.is_ok(), "Valid prefix should be accepted");
    assert!(
        key_result.is_err(),
        "Malicious key should be rejected by validation"
    );

    // This proves that Memory deployments now have the same protection as Redis deployments
}

#[test]
fn test_validation_happens_at_caller_boundary() {
    // Test that validation happens when callers construct typed arguments,
    // not inside the unified cache operation wrappers

    // This malicious input should be rejected at construction time
    let malicious_inputs = vec![
        "SET malicious",
        "key\nwith\nnewlines",
        "key with spaces",
        "key\twith\ttabs",
    ];

    for input in malicious_inputs {
        let prefix_result = CachePrefix::new(input.to_string());
        let key_result = CacheKey::new(input.to_string());

        // Both should reject dangerous inputs at construction
        if input.contains("SET") {
            assert!(
                prefix_result.is_err() || key_result.is_err(),
                "Should reject Redis command: {input}"
            );
        } else {
            assert!(
                prefix_result.is_err(),
                "Should reject dangerous chars in prefix: {input}"
            );
            assert!(
                key_result.is_err(),
                "Should reject dangerous chars in key: {input}"
            );
        }
    }

    // Valid inputs should work
    let valid_inputs = vec!["session", "user_123", "oauth2_token", "challenge_abc"];

    for input in valid_inputs {
        let prefix_result = CachePrefix::new(input.to_string());
        let key_result = CacheKey::new(input.to_string());

        assert!(prefix_result.is_ok(), "Should accept valid prefix: {input}");
        assert!(key_result.is_ok(), "Should accept valid key: {input}");
    }
}

#[test]
fn test_cache_data_serialization() {
    let cache_data = CacheData {
        value: "test_value".to_string(),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&cache_data).unwrap();
    println!("Serialized: {json}");

    // Should only contain the value field (no expires_at)
    assert!(json.contains("\"value\":\"test_value\""));
    assert!(!json.contains("expires_at")); // No longer included

    // Deserialize back
    let deserialized: CacheData = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.value, cache_data.value);
}
