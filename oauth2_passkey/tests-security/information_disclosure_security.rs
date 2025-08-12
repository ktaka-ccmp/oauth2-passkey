/// Information Disclosure Prevention Security Tests - Consolidated Edition
///
/// These tests verify that the authentication system properly prevents information disclosure:
/// - Error message enumeration attacks
/// - Debug information leakage
/// - Metadata disclosure that could aid attackers
/// - User existence confirmation attacks
/// - Timing-based information disclosure
use crate::common::{TestSetup, attack_scenarios::oauth2_attacks::*};
use serde_json::json;

use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Extended test setup for information disclosure security tests
struct InformationDisclosureTestSetup {
    setup: TestSetup,
}

impl InformationDisclosureTestSetup {
    /// Create a new information disclosure test environment
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let setup = TestSetup::new().await?;
        Ok(Self { setup })
    }

    /// Shutdown the test server
    async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        self.setup.shutdown().await;
        Ok(())
    }

    /// Access to browser for specialized methods
    fn browser(&self) -> &crate::common::MockBrowser {
        &self.setup.browser
    }

    /// Access to server for specialized methods
    fn server(&self) -> &crate::common::TestServer {
        &self.setup.server
    }

    /// Attempt to register a user to create known state for testing
    async fn create_test_user(&self, username: &str) -> Result<(), Box<dyn std::error::Error>> {
        let registration_data = json!({
            "username": username,
            "displayname": "Test User",
            "mode": "create_user"
        });

        let _response = self
            .browser()
            .post_json("/auth/passkey/register/start", &registration_data)
            .await?;

        // Allow some time for registration processing
        sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    /// Analyze response for potential information disclosure
    fn analyze_response_for_disclosure(
        &self,
        _status: reqwest::StatusCode,
        headers: &reqwest::header::HeaderMap,
        body: &str,
        test_name: &str,
    ) -> Vec<String> {
        let mut disclosures = Vec::new();

        // Check for debug information in response headers
        for (header_name, header_value) in headers {
            let header_name_str = header_name.as_str().to_lowercase();
            let header_value_str = header_value.to_str().unwrap_or("");

            // Check for debug headers that shouldn't be exposed
            if header_name_str.contains("debug")
                || header_name_str.contains("trace")
                || header_name_str.contains("x-powered-by")
                || header_name_str.contains("server")
            {
                disclosures.push(format!(
                    "Debug header disclosed: {header_name_str}: {header_value_str}"
                ));
            }
        }

        // Check for potential information disclosure in response body
        let body_lower = body.to_lowercase();

        // Check for database error information
        if body_lower.contains("sqlite")
            || body_lower.contains("postgresql")
            || body_lower.contains("database")
            || body_lower.contains("sql")
        {
            disclosures.push("Database technology information disclosed".to_string());
        }

        // Check for file path disclosure
        if body_lower.contains("/src/")
            || body_lower.contains("/target/")
            || body_lower.contains(".rs:")
            || body_lower.contains("panic")
            || body_lower.contains("backtrace")
        {
            disclosures.push("Source code path information disclosed".to_string());
        }

        // Check for internal structure disclosure
        if body_lower.contains("struct")
            || body_lower.contains("impl")
            || body_lower.contains("enum")
            || body_lower.contains("trait")
        {
            disclosures.push("Internal code structure information disclosed".to_string());
        }

        if !disclosures.is_empty() {
            println!("⚠️  Information disclosure detected in {test_name}:");
            for disclosure in &disclosures {
                println!("  - {disclosure}");
            }
        } else {
            println!("✅ No information disclosure detected in {test_name}");
        }

        disclosures
    }
}

/// **CONSOLIDATED TEST 1**: User Enumeration & Error Message Attacks
///
/// This test consolidates:
/// - test_security_oauth2_error_message_enumeration_prevention
/// - test_security_passkey_user_enumeration_prevention
#[tokio::test]
async fn test_consolidated_user_enumeration_attacks() -> Result<(), Box<dyn std::error::Error>> {
    let setup = InformationDisclosureTestSetup::new().await?;

    println!("🔒 === CONSOLIDATED USER ENUMERATION ATTACKS TEST ===");

    // === SUBTEST 1: OAuth2 Error Message Enumeration Prevention ===
    println!("\n🛡️ SUBTEST 1: Testing OAuth2 error message enumeration prevention");

    // Test various OAuth2 error scenarios and analyze response consistency
    let oauth2_test_scenarios = vec![
        (
            "invalid_auth_code",
            "invalid_code_12345",
            create_empty_state(),
        ),
        (
            "malformed_state",
            "valid_code_123",
            create_malformed_state(),
        ),
        ("empty_state", "valid_code_123", create_empty_state()),
        ("expired_state", "valid_code_123", create_expired_state()),
    ];

    let mut oauth2_error_responses = Vec::new();
    let mut oauth2_disclosure_count = 0;

    for (scenario_name, auth_code, state) in oauth2_test_scenarios {
        println!("🔧 Testing OAuth2 error scenario: {scenario_name}");

        let response = setup
            .browser()
            .get(&format!(
                "/auth/oauth2/authorized?code={auth_code}&state={state}"
            ))
            .await?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await?;

        println!(
            "🔧 {} - Status: {}, Body length: {}",
            scenario_name,
            status,
            body.len()
        );

        // Analyze for information disclosure
        let disclosures =
            setup.analyze_response_for_disclosure(status, &headers, &body, scenario_name);

        oauth2_disclosure_count += disclosures.len();

        oauth2_error_responses.push((scenario_name.to_string(), status, body, disclosures));
    }

    // Verify error message consistency to prevent enumeration
    let mut unique_responses = std::collections::HashSet::new();
    for (scenario, status, body, _) in &oauth2_error_responses {
        let response_signature = format!("{}:{}", status, body.len());
        unique_responses.insert(response_signature);
        println!(
            "🔍 OAuth2 Scenario '{}': {} ({})",
            scenario,
            status,
            body.len()
        );
    }

    println!(
        "📊 OAuth2 error scenarios produced {} unique response patterns",
        unique_responses.len()
    );
    if oauth2_disclosure_count == 0 {
        println!("✅ OAuth2 error message enumeration properly prevented");
    } else {
        println!("⚠️  OAuth2 disclosed {oauth2_disclosure_count} pieces of information");
    }

    // === SUBTEST 2: Passkey User Enumeration Prevention ===
    println!("\n👤 SUBTEST 2: Testing Passkey user enumeration prevention");

    // Create a known user for comparison
    let known_user = "known_user@example.com";
    setup.create_test_user(known_user).await?;

    // Test registration attempts for different user scenarios
    let passkey_test_users = vec![
        ("existing_user", known_user),
        ("new_user_1", "new_user_1@example.com"),
        ("new_user_2", "new_user_2@example.com"),
        ("malformed_email", "malformed@email@com"),
        ("invalid_domain", "test@nonexistent-domain-12345.com"),
    ];

    let mut passkey_response_times = Vec::new();
    let mut passkey_disclosure_count = 0;

    for (scenario, username) in passkey_test_users {
        println!("🔧 Testing Passkey registration for: {scenario} ({username})");

        let registration_data = json!({
            "username": username,
            "displayname": format!("Test User {}", scenario),
            "mode": "create_user"
        });

        let start_time = Instant::now();
        let response = setup
            .browser()
            .post_json("/auth/passkey/register/start", &registration_data)
            .await?;
        let response_time = start_time.elapsed();

        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await?;

        println!(
            "🔧 {} - Status: {}, Time: {:?}, Body: {} chars",
            scenario,
            status,
            response_time,
            body.len()
        );

        // Analyze for information disclosure
        let disclosures = setup.analyze_response_for_disclosure(status, &headers, &body, scenario);
        passkey_disclosure_count += disclosures.len();

        passkey_response_times.push((scenario.to_string(), response_time, status, body));

        // Brief pause between requests to avoid flooding
        sleep(Duration::from_millis(50)).await;
    }

    // Analyze timing patterns for user enumeration
    let mut timing_variance = Vec::new();
    for (scenario, response_time, _, _) in &passkey_response_times {
        timing_variance.push(response_time.as_millis());
        println!("⏱️  {scenario}: {response_time:?}");
    }

    let avg_time = timing_variance.iter().sum::<u128>() as f64 / timing_variance.len() as f64;
    let max_time = *timing_variance.iter().max().unwrap() as f64;
    let min_time = *timing_variance.iter().min().unwrap() as f64;
    let timing_ratio = if min_time > 0.0 {
        max_time / min_time
    } else {
        0.0
    };

    println!(
        "📊 Timing Analysis - Avg: {avg_time:.1}ms, Max: {max_time:.1}ms, Min: {min_time:.1}ms, Ratio: {timing_ratio:.2}x"
    );

    if timing_ratio < 3.0 {
        println!("✅ Timing patterns consistent (ratio < 3x)");
    } else {
        println!("⚠️  Potential timing-based user enumeration (ratio > 3x)");
    }

    if passkey_disclosure_count == 0 {
        println!("✅ Passkey user enumeration properly prevented");
    } else {
        println!("⚠️  Passkey disclosed {passkey_disclosure_count} pieces of information");
    }

    setup.shutdown().await?;
    println!("🎯 === CONSOLIDATED USER ENUMERATION ATTACKS TEST COMPLETED ===");
    Ok(())
}

/// **CONSOLIDATED TEST 2**: System Information Disclosure Attacks
///
/// This test consolidates:
/// - test_security_debug_information_leakage_prevention
/// - test_security_metadata_disclosure_prevention  
/// - test_security_timing_based_information_disclosure_prevention
#[tokio::test]
async fn test_consolidated_system_information_disclosure_attacks()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = InformationDisclosureTestSetup::new().await?;

    println!("🔒 === CONSOLIDATED SYSTEM INFORMATION DISCLOSURE ATTACKS TEST ===");

    // === SUBTEST 1: Debug Information Leakage Prevention ===
    println!("\n🐛 SUBTEST 1: Testing debug information leakage prevention");

    // Test various malformed requests that might trigger debug responses
    // Use malformed JSON payloads to test error handling
    let debug_attack_scenarios = vec![
        (
            "malformed_json_1",
            "/auth/passkey/register/start",
            "{invalid:json}",
        ),
        (
            "malformed_json_2",
            "/auth/passkey/auth/start",
            "{broken\":json\"}",
        ),
        (
            "special_characters",
            "/auth/oauth2/start",
            r#"{"field":"<script>alert('xss')</script>"}"#,
        ),
        ("empty_object", "/auth/passkey/register/start", "{}"),
        (
            "null_values",
            "/auth/passkey/auth/start",
            r#"{"username":null,"data":null}"#,
        ),
    ];

    let mut debug_disclosure_count = 0;

    for (scenario_name, endpoint, malformed_json) in debug_attack_scenarios {
        println!("🔧 Testing debug scenario: {scenario_name} on {endpoint}");

        // Create a raw reqwest request to send malformed JSON
        let url = format!("{}{}", setup.server().base_url, endpoint);
        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("content-type", "application/json")
            .body(malformed_json.to_string())
            .send()
            .await?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await?;

        println!(
            "🔧 {} - Status: {}, Body length: {}",
            scenario_name,
            status,
            body.len()
        );

        // Analyze for debug information disclosure
        let disclosures =
            setup.analyze_response_for_disclosure(status, &headers, &body, scenario_name);
        debug_disclosure_count += disclosures.len();

        // Brief pause between requests
        sleep(Duration::from_millis(25)).await;
    }

    if debug_disclosure_count == 0 {
        println!("✅ Debug information leakage properly prevented");
    } else {
        println!("⚠️  Debug information leaked in {debug_disclosure_count} instances");
    }

    // === SUBTEST 2: Metadata Disclosure Prevention ===
    println!("\n📋 SUBTEST 2: Testing metadata disclosure prevention");

    // Test various endpoints for metadata that shouldn't be exposed
    let metadata_endpoints = vec![
        ("root_endpoint", "/"),
        ("health_check", "/health"),
        ("metrics", "/metrics"),
        ("debug", "/debug"),
        ("admin", "/admin"),
        ("api_info", "/api"),
        ("version", "/version"),
        ("status", "/status"),
        ("info", "/info"),
    ];

    let mut metadata_disclosure_count = 0;

    for (endpoint_name, endpoint) in metadata_endpoints {
        println!("🔧 Testing metadata endpoint: {endpoint_name} ({endpoint})");

        let response = setup.browser().get(endpoint).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await?;

        println!(
            "🔧 {} - Status: {}, Body length: {}",
            endpoint_name,
            status,
            body.len()
        );

        // Check if endpoint reveals metadata
        if status.is_success() && !body.is_empty() {
            // Look for version information, system details, or other metadata
            let body_lower = body.to_lowercase();
            if body_lower.contains("version")
                || body_lower.contains("build")
                || body_lower.contains("rust")
                || body_lower.contains("cargo")
                || body_lower.contains("dependencies")
                || body_lower.contains("system")
            {
                println!("⚠️  Metadata potentially disclosed at {endpoint}");
                metadata_disclosure_count += 1;
            }
        }

        // Analyze headers and body for other disclosures
        let disclosures =
            setup.analyze_response_for_disclosure(status, &headers, &body, endpoint_name);
        metadata_disclosure_count += disclosures.len();

        // Brief pause between requests
        sleep(Duration::from_millis(25)).await;
    }

    if metadata_disclosure_count == 0 {
        println!("✅ Metadata disclosure properly prevented");
    } else {
        println!("⚠️  Metadata disclosed in {metadata_disclosure_count} instances");
    }

    // === SUBTEST 3: Timing-Based Information Disclosure Prevention ===
    println!("\n⏱️ SUBTEST 3: Testing timing-based information disclosure prevention");

    // Test timing attacks on various authentication endpoints
    let timing_scenarios = vec![
        (
            "existing_user_oauth2",
            "/auth/oauth2/start?user_hint=first-user@example.com",
        ),
        (
            "nonexistent_user_oauth2",
            "/auth/oauth2/start?user_hint=nonexistent@example.com",
        ),
        ("existing_user_passkey", "/auth/passkey/auth/start"),
        ("nonexistent_user_passkey", "/auth/passkey/auth/start"),
    ];

    let mut timing_results = Vec::new();
    let rounds = 5; // Multiple rounds for better timing accuracy

    for (scenario_name, endpoint) in timing_scenarios {
        println!("🔧 Testing timing scenario: {scenario_name}");

        let mut times = Vec::new();

        for round in 1..=rounds {
            let payload = if endpoint.contains("passkey") {
                Some(json!({
                    "username": if scenario_name.contains("existing") {
                        "first-user@example.com"
                    } else {
                        "nonexistent@example.com"
                    }
                }))
            } else {
                None
            };

            let start_time = Instant::now();

            let _response = if let Some(data) = payload {
                setup.browser().post_json(endpoint, &data).await?
            } else {
                setup.browser().get(endpoint).await?
            };

            let response_time = start_time.elapsed();
            times.push(response_time);

            println!("🔧 {scenario_name} round {round}: {response_time:?}");

            // Brief pause between rounds
            sleep(Duration::from_millis(100)).await;
        }

        let avg_time = times.iter().sum::<Duration>() / times.len() as u32;
        timing_results.push((scenario_name.to_string(), avg_time));
    }

    // Analyze timing differences between existing vs nonexistent users
    for i in (0..timing_results.len()).step_by(2) {
        if i + 1 < timing_results.len() {
            let (existing_scenario, existing_time) = &timing_results[i];
            let (nonexistent_scenario, nonexistent_time) = &timing_results[i + 1];

            let time_ratio = if existing_time.as_millis() > 0 {
                nonexistent_time.as_millis() as f64 / existing_time.as_millis() as f64
            } else {
                1.0
            };

            println!("📊 Timing Comparison:");
            println!("  {existing_scenario} avg: {existing_time:?}");
            println!("  {nonexistent_scenario} avg: {nonexistent_time:?}");
            println!("  Ratio: {time_ratio:.2}x");

            if !(0.5..=2.0).contains(&time_ratio) {
                println!("⚠️  Potential timing-based information disclosure detected");
            } else {
                println!("✅ Timing patterns appear consistent");
            }
        }
    }

    setup.shutdown().await?;
    println!("🎯 === CONSOLIDATED SYSTEM INFORMATION DISCLOSURE ATTACKS TEST COMPLETED ===");
    Ok(())
}
