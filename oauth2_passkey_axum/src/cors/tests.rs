#[test]
fn test_cors_allowed_origins_parsing() {
    // This test demonstrates the parsing logic
    let input = "https://app.example.com, https://admin.example.com";
    let origins: Vec<String> = input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    assert_eq!(origins.len(), 2);
    assert_eq!(origins[0], "https://app.example.com");
    assert_eq!(origins[1], "https://admin.example.com");
}
