use crate::common::TestServer;
use reqwest;
use serde_json;
use serial_test::serial;

/// Test OIDC Discovery endpoint functionality with Axum mock server
///
/// This test validates that the OIDC Discovery endpoint is properly configured
/// and returns the expected OAuth2 endpoint URLs for dynamic discovery.
#[tokio::test]
#[serial]
async fn test_oidc_discovery_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment - this starts the Axum mock server
    let server = TestServer::start().await?;
    let discovery_url = "http://127.0.0.1:9876/.well-known/openid-configuration";

    println!("🔍 Testing OIDC Discovery endpoint at: {discovery_url}");

    // Fetch the OIDC Discovery document from the Axum mock server
    let client = reqwest::Client::new();
    let response = client.get(discovery_url).send().await?;

    println!("OIDC Discovery response status: {}", response.status());
    assert!(
        response.status().is_success(),
        "OIDC Discovery endpoint should return 200"
    );

    // Parse the discovery document
    let discovery_doc: serde_json::Value = response.json().await?;
    println!(
        "OIDC Discovery document: {}",
        serde_json::to_string_pretty(&discovery_doc)?
    );

    // Validate required OIDC Discovery fields
    assert!(
        discovery_doc["issuer"].is_string(),
        "issuer field should be present"
    );
    assert!(
        discovery_doc["authorization_endpoint"].is_string(),
        "authorization_endpoint should be present"
    );
    assert!(
        discovery_doc["token_endpoint"].is_string(),
        "token_endpoint should be present"
    );
    assert!(
        discovery_doc["userinfo_endpoint"].is_string(),
        "userinfo_endpoint should be present"
    );
    assert!(
        discovery_doc["jwks_uri"].is_string(),
        "jwks_uri should be present"
    );

    // Validate endpoint URLs match the Axum mock server
    let base_url = "http://127.0.0.1:9876";
    assert_eq!(discovery_doc["issuer"].as_str().unwrap(), base_url);
    assert_eq!(
        discovery_doc["authorization_endpoint"].as_str().unwrap(),
        format!("{base_url}/oauth2/auth")
    );
    assert_eq!(
        discovery_doc["token_endpoint"].as_str().unwrap(),
        format!("{base_url}/oauth2/token")
    );
    assert_eq!(
        discovery_doc["userinfo_endpoint"].as_str().unwrap(),
        format!("{base_url}/oauth2/userinfo")
    );
    assert_eq!(
        discovery_doc["jwks_uri"].as_str().unwrap(),
        format!("{base_url}/oauth2/v3/certs")
    );

    // Validate supported features
    assert!(
        discovery_doc["scopes_supported"].is_array(),
        "scopes_supported should be present"
    );
    assert!(
        discovery_doc["response_types_supported"].is_array(),
        "response_types_supported should be present"
    );
    assert!(
        discovery_doc["id_token_signing_alg_values_supported"].is_array(),
        "id_token_signing_alg_values_supported should be present"
    );

    println!("✅ OIDC Discovery endpoint validation PASSED");
    println!("  - Issuer URL: {}", discovery_doc["issuer"]);
    println!(
        "  - Authorization endpoint: {}",
        discovery_doc["authorization_endpoint"]
    );
    println!("  - Token endpoint: {}", discovery_doc["token_endpoint"]);
    println!(
        "  - Userinfo endpoint: {}",
        discovery_doc["userinfo_endpoint"]
    );
    println!("  - JWKS URI: {}", discovery_doc["jwks_uri"]);

    // Cleanup
    server.shutdown().await;
    Ok(())
}

/// Test that OAuth2 configuration uses OIDC Discovery dynamically with Axum mock server
///
/// This test validates that the OAuth2 configuration system properly
/// discovers endpoints from the OIDC Discovery document instead of
/// using hardcoded URLs.
///
/// IMPORTANT: This test MUST run first to initialize oauth2_passkey with OIDC Discovery.
/// Named with 'a_' prefix to ensure alphabetical ordering.
#[tokio::test]
#[serial]
async fn a_test_oauth2_uses_oidc_discovery() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment - this initializes the Axum mock server
    let server = TestServer::start().await?;

    println!("🔍 Testing OAuth2 configuration with OIDC Discovery");
    println!("Axum mock OAuth2 server URL: http://127.0.0.1:9876");

    // Start an OAuth2 flow to trigger endpoint discovery
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let oauth2_start_response = client
        .get(format!(
            "{}/auth/oauth2/google?mode=create_user_or_login",
            server.base_url
        ))
        .send()
        .await?;

    println!(
        "OAuth2 start response status: {}",
        oauth2_start_response.status()
    );

    // Should redirect to OAuth2 provider
    assert!(
        oauth2_start_response.status().is_redirection(),
        "OAuth2 start should redirect"
    );

    let auth_url = oauth2_start_response
        .headers()
        .get("location")
        .expect("No location header in OAuth2 redirect")
        .to_str()
        .expect("Invalid location header");

    println!("Authorization URL: {auth_url}");

    // Validate that the authorization URL uses the Axum mock server (discovered endpoint)
    assert!(
        auth_url.starts_with("http://127.0.0.1:9876"),
        "Authorization URL should use discovered endpoint from Axum mock server: {auth_url}"
    );
    assert!(
        auth_url.contains("/oauth2/auth"),
        "Authorization URL should use the discovered authorization endpoint"
    );
    assert!(
        auth_url.contains("client_id="),
        "Authorization URL should contain client_id parameter"
    );
    assert!(
        auth_url.contains("nonce="),
        "Authorization URL should contain nonce parameter for OIDC compliance"
    );

    println!("✅ OAuth2 configuration is using OIDC Discovery correctly");
    println!("  - Authorization endpoint discovered and used: ✓");
    println!("  - Dynamic URL configuration: ✓");
    println!("  - OIDC compliance (nonce parameter): ✓");

    // Cleanup
    server.shutdown().await;
    Ok(())
}
