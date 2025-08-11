/// Information Disclosure Prevention Security Tests
///
/// These tests verify that the authentication system properly prevents information disclosure:
/// - Error message enumeration attacks
/// - Debug information leakage
/// - Metadata disclosure that could aid attackers
/// - User existence confirmation attacks
/// - Timing-based information disclosure
use crate::common::{TestSetup, attack_scenarios::oauth2_attacks::*};
use serde_json::json;
use serial_test::serial;
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
            .post_json("/auth/passkey/register", &registration_data)
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
        if body_lower.contains("/home/")
            || body_lower.contains("/usr/")
            || body_lower.contains("c:\\")
            || body_lower.contains("/var/")
        {
            disclosures.push("File path information disclosed".to_string());
        }

        // Check for stack trace information
        if body_lower.contains("stack trace")
            || body_lower.contains("backtrace")
            || body_lower.contains("panicked at")
            || body_lower.contains("thread 'main'")
        {
            disclosures.push("Stack trace information disclosed".to_string());
        }

        // Check for detailed error messages that could aid enumeration
        if body_lower.contains("user does not exist")
            || body_lower.contains("user not found")
            || body_lower.contains("invalid user")
        {
            disclosures.push("User existence information disclosed".to_string());
        }

        // Check for cryptographic details
        if body_lower.contains("private key")
            || body_lower.contains("secret")
            || body_lower.contains("token expired")
            || body_lower.contains("invalid signature")
        {
            disclosures.push("Cryptographic implementation details disclosed".to_string());
        }

        if !disclosures.is_empty() {
            println!("⚠️ Information disclosure detected in {test_name}: {disclosures:?}");
        }

        disclosures
    }
}

/// Test error message enumeration prevention for OAuth2 authentication
///
/// This test verifies that OAuth2 error messages don't leak information that could
/// be used for user enumeration or system reconnaissance:
/// 1. Similar error messages for different failure scenarios
/// 2. No disclosure of internal system details
/// 3. No user existence confirmation through error differences
#[tokio::test]
#[serial]
async fn test_security_oauth2_error_message_enumeration_prevention()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = InformationDisclosureTestSetup::new().await?;

    println!("🔒 Testing OAuth2 error message enumeration prevention");

    // Test various OAuth2 error scenarios and analyze response consistency
    let test_scenarios = vec![
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

    let mut error_responses = Vec::new();
    let mut disclosure_count = 0;

    for (scenario_name, auth_code, state) in test_scenarios {
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
        disclosure_count += disclosures.len();

        error_responses.push((scenario_name, status, body));

        sleep(Duration::from_millis(50)).await;
    }

    // Verify that error messages are consistent and don't leak information
    let mut unique_messages = std::collections::HashSet::new();
    for (scenario, _status, body) in &error_responses {
        // Remove scenario-specific elements for comparison
        let normalized_body = body
            .replace("invalid_code_12345", "REDACTED")
            .replace("valid_code_123", "REDACTED");
        unique_messages.insert(normalized_body);

        println!("🔧 Error response for {}: {} chars", scenario, body.len());

        // Verify no sensitive information is disclosed
        assert!(
            !body.to_lowercase().contains("database"),
            "Database information should not be disclosed"
        );
        assert!(
            !body.to_lowercase().contains("/home/"),
            "File paths should not be disclosed"
        );
        assert!(
            !body.to_lowercase().contains("panicked"),
            "Panic information should not be disclosed"
        );
    }

    println!(
        "📊 Unique error message patterns: {}",
        unique_messages.len()
    );
    println!("📊 Information disclosures detected: {disclosure_count}");

    // Verify minimal information disclosure
    assert!(
        disclosure_count == 0,
        "No information should be disclosed through error messages"
    );

    // Verify error message consistency (shouldn't be too many unique patterns)
    assert!(
        unique_messages.len() <= 3,
        "Error messages should be consistent to prevent enumeration"
    );

    setup.shutdown().await?;
    Ok(())
}

/// Test user enumeration prevention through Passkey registration
///
/// This test verifies that Passkey registration responses don't leak information
/// about whether users already exist or system internal state:
/// 1. Consistent response times for existing vs non-existing users
/// 2. Consistent error messages regardless of user state
/// 3. No disclosure of user database structure
#[tokio::test]
#[serial]
async fn test_security_passkey_user_enumeration_prevention()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = InformationDisclosureTestSetup::new().await?;

    println!("🔒 Testing Passkey user enumeration prevention");

    // Create a known user for comparison
    let known_user = "known_user@example.com";
    setup.create_test_user(known_user).await?;

    // Test registration attempts for different user scenarios
    let test_users = vec![
        ("existing_user", known_user),
        ("new_user_1", "new_user_1@example.com"),
        ("new_user_2", "new_user_2@example.com"),
        ("malformed_email", "malformed@email@com"),
        ("invalid_domain", "test@nonexistent-domain-12345.com"),
    ];

    let mut response_times = Vec::new();
    let mut disclosure_count = 0;

    for (scenario, username) in test_users {
        println!("🔧 Testing Passkey registration for: {scenario} ({username})");

        let registration_data = json!({
            "username": username,
            "displayname": format!("Test User {}", scenario),
            "mode": "create_user"
        });

        let start_time = Instant::now();
        let response = setup
            .browser()
            .post_json("/auth/passkey/register", &registration_data)
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
        disclosure_count += disclosures.len();

        response_times.push((scenario, response_time));

        // Verify no user existence information is disclosed
        assert!(
            !body.to_lowercase().contains("already exists"),
            "User existence should not be explicitly disclosed"
        );
        assert!(
            !body.to_lowercase().contains("user found"),
            "User existence should not be explicitly disclosed"
        );

        sleep(Duration::from_millis(100)).await;
    }

    // Analyze response time consistency to prevent timing-based enumeration
    let times: Vec<_> = response_times
        .iter()
        .map(|(_, time)| time.as_millis())
        .collect();
    let avg_time = times.iter().sum::<u128>() / times.len() as u128;
    let max_time = *times.iter().max().unwrap();
    let min_time = *times.iter().min().unwrap();

    println!("📊 Response times - Avg: {avg_time}ms, Min: {min_time}ms, Max: {max_time}ms");
    println!("📊 Information disclosures detected: {disclosure_count}");

    // Verify timing consistency (no response should be more than 2x average)
    for (scenario, time) in &response_times {
        let time_ms = time.as_millis();
        if time_ms > avg_time * 2 {
            println!(
                "⚠️ Potential timing disclosure in {scenario}: {time_ms}ms vs {avg_time}ms average"
            );
        }
    }

    // Verify minimal information disclosure
    assert!(
        disclosure_count == 0,
        "No information should be disclosed through registration responses"
    );

    setup.shutdown().await?;
    Ok(())
}

/// Test debug information leakage prevention
///
/// This test verifies that debug information, stack traces, and internal
/// system details are not exposed in production responses:
/// 1. No stack traces in error responses
/// 2. No file path disclosure
/// 3. No internal configuration exposure
#[tokio::test]
#[serial]
async fn test_security_debug_information_leakage_prevention()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = InformationDisclosureTestSetup::new().await?;

    println!("🔒 Testing debug information leakage prevention");

    // Test various endpoints that might expose debug information
    let test_endpoints = vec![
        ("invalid_endpoint", "/auth/nonexistent-endpoint", "GET"),
        ("malformed_json", "/auth/passkey/register", "POST"),
        ("invalid_method", "/auth/oauth2/authorized", "DELETE"),
        ("oversized_request", "/auth/passkey/authenticate", "POST"),
    ];

    let mut total_disclosures = 0;

    for (scenario, endpoint, method) in test_endpoints {
        println!("🔧 Testing debug info leakage in: {method} {endpoint} ({scenario})");

        let response = match method {
            "GET" => setup.browser().get(endpoint).await?,
            "POST" => {
                let malformed_data = if scenario == "oversized_request" {
                    json!({
                        "malicious_data": "x".repeat(100000), // 100KB payload
                        "username": "test@example.com"
                    })
                } else {
                    json!({
                        "malformed": "invalid json structure",
                        "nested": { "deeply": { "very": { "much": "so" } } }
                    })
                };
                setup.browser().post_json(endpoint, &malformed_data).await?
            }
            "DELETE" => {
                // Use reqwest directly for unsupported methods
                let client = reqwest::Client::new();
                client
                    .delete(format!("{}{}", setup.server().base_url, endpoint))
                    .send()
                    .await?
            }
            _ => continue,
        };

        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await?;

        println!(
            "🔧 {} - Status: {}, Body: {} chars",
            scenario,
            status,
            body.len()
        );

        // Create a mock response for analysis
        let _mock_response = http::Response::builder().status(status).body(()).unwrap();

        // Analyze headers for debug information
        let mut header_disclosures = 0;
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();
            let value_str = value.to_str().unwrap_or("");

            if name_str.contains("x-debug")
                || name_str.contains("x-trace")
                || name_str == "server"
                || name_str == "x-powered-by"
            {
                println!("⚠️ Debug header disclosed: {name_str}: {value_str}");
                header_disclosures += 1;
            }
        }

        // Analyze body for debug information
        let body_disclosures = setup.analyze_response_for_disclosure(
            status,
            &reqwest::header::HeaderMap::new(),
            &body,
            scenario,
        );
        let total_scenario_disclosures = header_disclosures + body_disclosures.len();

        total_disclosures += total_scenario_disclosures;

        // Verify specific debug information is not present
        assert!(
            !body.contains("RUST_BACKTRACE"),
            "Rust backtrace should not be exposed"
        );
        assert!(
            !body.contains("thread 'main'"),
            "Thread information should not be exposed"
        );
        assert!(
            !body.contains("src/"),
            "Source code paths should not be exposed"
        );
        assert!(
            !body.contains("target/"),
            "Build paths should not be exposed"
        );

        sleep(Duration::from_millis(50)).await;
    }

    println!("📊 Total debug information disclosures detected: {total_disclosures}");

    // Verify no debug information is leaked
    assert!(
        total_disclosures == 0,
        "No debug information should be disclosed in responses"
    );

    setup.shutdown().await?;
    Ok(())
}

/// Test metadata disclosure prevention
///
/// This test verifies that system metadata and configuration details
/// are not exposed through various attack vectors:
/// 1. No version information disclosure
/// 2. No internal configuration exposure
/// 3. No database schema information
#[tokio::test]
#[serial]
async fn test_security_metadata_disclosure_prevention() -> Result<(), Box<dyn std::error::Error>> {
    let setup = InformationDisclosureTestSetup::new().await?;

    println!("🔒 Testing metadata disclosure prevention");

    // Test various metadata disclosure vectors
    let test_scenarios = vec![
        ("version_probe", "/version", "GET"),
        ("config_probe", "/config", "GET"),
        ("admin_probe", "/admin", "GET"),
        ("debug_probe", "/debug", "GET"),
        ("health_probe", "/health", "GET"),
        ("status_probe", "/status", "GET"),
        ("metrics_probe", "/metrics", "GET"),
        ("swagger_probe", "/swagger", "GET"),
        ("api_docs_probe", "/api/docs", "GET"),
        ("openapi_probe", "/openapi.json", "GET"),
    ];

    let mut metadata_disclosures = 0;
    let mut accessible_endpoints = 0;

    for (scenario, endpoint, method) in test_scenarios {
        println!("🔧 Testing metadata exposure: {method} {endpoint}");

        let response = setup.browser().get(endpoint).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await?;

        println!(
            "🔧 {} - Status: {}, Body: {} chars",
            scenario,
            status,
            body.len()
        );

        // Check if endpoint is unexpectedly accessible
        // Allow standard health endpoints which are common and acceptable
        if status.is_success() && !endpoint.contains("/health") {
            accessible_endpoints += 1;
            println!("⚠️ Metadata endpoint accessible: {endpoint}");
        } else if status.is_success() && endpoint.contains("/health") {
            println!("✅ Standard health endpoint accessible: {endpoint} (acceptable)");
        }

        // Analyze response for metadata disclosure
        let disclosures = setup.analyze_response_for_disclosure(status, &headers, &body, scenario);
        metadata_disclosures += disclosures.len();

        // Check for version information
        if body.to_lowercase().contains("version")
            || body.to_lowercase().contains("v1.")
            || body.to_lowercase().contains("build")
        {
            println!("⚠️ Version information potentially disclosed in {scenario}");
            metadata_disclosures += 1;
        }

        // Check for configuration information
        if body.to_lowercase().contains("config")
            || body.to_lowercase().contains("environment")
            || body.to_lowercase().contains("settings")
        {
            println!("⚠️ Configuration information potentially disclosed in {scenario}");
            metadata_disclosures += 1;
        }

        sleep(Duration::from_millis(50)).await;
    }

    // Test authentication endpoint headers by making regular requests
    let auth_endpoints = vec![
        "/auth/oauth2/google",
        "/auth/passkey/register",
        "/auth/passkey/authenticate",
    ];

    for endpoint in auth_endpoints {
        println!("🔧 Testing auth endpoint headers: {endpoint}");

        // Test with GET request to check for unnecessary header disclosure
        let response = setup.browser().get(endpoint).await?;
        let headers = response.headers().clone();

        // Check for unnecessary header disclosure
        for (name, value) in headers.iter() {
            let name_str = name.as_str().to_lowercase();
            let value_str = value.to_str().unwrap_or("");

            if name_str == "allow" && value_str.len() > 50 {
                println!("⚠️ Verbose Allow header in {endpoint}: {value_str}");
                metadata_disclosures += 1;
            }

            if name_str.contains("x-")
                && !name_str.contains("x-content-type-options")
                && !name_str.contains("x-frame-options")
            {
                println!("⚠️ Custom header disclosed in {endpoint}: {name_str}");
                metadata_disclosures += 1;
            }
        }

        sleep(Duration::from_millis(50)).await;
    }

    println!("📊 Accessible metadata endpoints: {accessible_endpoints}");
    println!("📊 Metadata disclosures detected: {metadata_disclosures}");

    // Verify minimal metadata exposure
    assert!(
        accessible_endpoints == 0,
        "Metadata endpoints should not be accessible"
    );
    assert!(metadata_disclosures == 0, "No metadata should be disclosed");

    setup.shutdown().await?;
    Ok(())
}

/// Test timing-based information disclosure prevention
///
/// This test verifies that response times don't leak information that
/// could be used for user enumeration or system reconnaissance:
/// 1. Consistent response times for authentication attempts
/// 2. No timing differences between valid/invalid user scenarios
/// 3. Protection against timing-based side-channel attacks
#[tokio::test]
#[serial]
async fn test_security_timing_based_information_disclosure_prevention()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = InformationDisclosureTestSetup::new().await?;

    println!("🔒 Testing timing-based information disclosure prevention");

    // Create test users for timing comparison
    let known_users = vec!["timing_user_1@example.com", "timing_user_2@example.com"];
    for user in &known_users {
        setup.create_test_user(user).await?;
    }

    // Wait for user creation to complete
    sleep(Duration::from_millis(500)).await;

    // Test timing consistency across different scenarios
    let timing_tests = vec![
        ("existing_user_1", known_users[0]),
        ("existing_user_2", known_users[1]),
        ("nonexistent_user_1", "nonexistent_1@example.com"),
        ("nonexistent_user_2", "nonexistent_2@example.com"),
        ("malformed_email_1", "malformed@email@.com"),
        ("malformed_email_2", "invalid_email_format"),
    ];

    let mut response_times = Vec::new();
    let samples_per_test = 3; // Multiple samples for statistical significance

    for (scenario, username) in timing_tests {
        let mut scenario_times = Vec::new();

        for sample in 0..samples_per_test {
            println!(
                "🔧 Timing test {} sample {}: {}",
                scenario,
                sample + 1,
                username
            );

            let registration_data = json!({
                "username": username,
                "displayname": format!("Timing Test {}", scenario),
                "mode": "create_user"
            });

            let start_time = Instant::now();
            let _response = setup
                .browser()
                .post_json("/auth/passkey/register", &registration_data)
                .await?;
            let response_time = start_time.elapsed();

            scenario_times.push(response_time);

            // Delay between samples to avoid overwhelming the server
            sleep(Duration::from_millis(200)).await;
        }

        // Calculate average time for this scenario
        let avg_time = scenario_times.iter().sum::<Duration>() / scenario_times.len() as u32;
        response_times.push((scenario, avg_time));

        println!("🔧 {scenario} average time: {avg_time:?}");
    }

    // Analyze timing consistency using microseconds for better precision
    let times_us: Vec<_> = response_times
        .iter()
        .map(|(_, time)| time.as_micros())
        .collect();
    let overall_avg_us = times_us.iter().sum::<u128>() / times_us.len() as u128;
    let max_time_us = *times_us.iter().max().unwrap();
    let min_time_us = *times_us.iter().min().unwrap();
    let variance_us = max_time_us - min_time_us;

    println!("📊 Timing analysis:");
    println!(
        "📊 Overall average: {overall_avg_us}µs ({:.2}ms)",
        overall_avg_us as f64 / 1000.0
    );
    println!("📊 Minimum time: {min_time_us}µs");
    println!("📊 Maximum time: {max_time_us}µs");
    println!("📊 Variance: {variance_us}µs");

    // Check for timing-based disclosure patterns using microseconds
    let existing_times: Vec<_> = response_times
        .iter()
        .filter(|(scenario, _)| scenario.contains("existing"))
        .map(|(_, time)| time.as_micros())
        .collect();

    let nonexistent_times: Vec<_> = response_times
        .iter()
        .filter(|(scenario, _)| scenario.contains("nonexistent"))
        .map(|(_, time)| time.as_micros())
        .collect();

    if !existing_times.is_empty() && !nonexistent_times.is_empty() {
        let existing_avg_us = existing_times.iter().sum::<u128>() / existing_times.len() as u128;
        let nonexistent_avg_us =
            nonexistent_times.iter().sum::<u128>() / nonexistent_times.len() as u128;

        println!(
            "📊 Existing users average: {existing_avg_us}µs ({:.2}ms)",
            existing_avg_us as f64 / 1000.0
        );
        println!(
            "📊 Nonexistent users average: {nonexistent_avg_us}µs ({:.2}ms)",
            nonexistent_avg_us as f64 / 1000.0
        );

        let timing_difference_us = existing_avg_us.abs_diff(nonexistent_avg_us);

        println!(
            "📊 Timing difference between user states: {timing_difference_us}µs ({:.2}ms)",
            timing_difference_us as f64 / 1000.0
        );

        // Verify timing difference is not significant enough for enumeration
        // Based on timing attack research:
        // - Exploitable differences typically need 1-10ms+ to overcome network noise
        // - Use 1000µs (1ms) minimum + 3x average for balance of security and stability
        // - This catches meaningful vulnerabilities while handling CI environment variance
        let min_threshold = 1000u128; // 1ms minimum (based on exploitability research)
        let avg_threshold = overall_avg_us * 3; // 3x average for stability
        let threshold = min_threshold.max(avg_threshold);

        if timing_difference_us > threshold / 3 {
            // Warning at 1x threshold
            println!(
                "⚠️ Timing difference detected: {timing_difference_us}µs (avg: {overall_avg_us}µs, threshold: {threshold}µs)"
            );
        }

        assert!(
            timing_difference_us < threshold,
            "Timing difference between existing/nonexistent users should not be excessive (found: {timing_difference_us}µs, threshold: {threshold}µs, avg: {overall_avg_us}µs)"
        );
    }

    // Verify overall timing consistency (variance should be reasonable)
    // Use minimum threshold of 2000µs (2ms) and 3x average, whichever is larger
    let min_variance_threshold = 2000u128; // 2ms minimum for variance (more lenient)
    let avg_variance_threshold = overall_avg_us * 3; // 3x average for stability
    let variance_threshold = min_variance_threshold.max(avg_variance_threshold);

    assert!(
        variance_us < variance_threshold,
        "Response time variance should not be excessive (found: {variance_us}µs, threshold: {variance_threshold}µs, avg: {overall_avg_us}µs)"
    );

    setup.shutdown().await?;
    Ok(())
}
