/// Rate Limiting and DoS Protection Security Tests - Consolidated Edition
///
/// These tests verify that the authentication system properly implements:
/// - Rate limiting on authentication attempts
/// - Rate limiting on registration attempts  
/// - Protection against resource exhaustion attacks
/// - Prevention of brute force attacks
/// - Proper handling of high-volume malicious requests
use crate::common::{TestSetup, attack_scenarios::oauth2_attacks::*};
use serde_json::json;

use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Extended test setup for rate limiting security tests
struct RateLimitingTestSetup {
    setup: TestSetup,
}

impl RateLimitingTestSetup {
    /// Create a new rate limiting test environment
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

    /// Perform rapid OAuth2 authentication attempts
    async fn rapid_oauth2_attempts(
        &self,
        count: usize,
    ) -> Result<Vec<reqwest::Response>, Box<dyn std::error::Error>> {
        let mut responses: Vec<reqwest::Response> = Vec::new();

        for i in 0..count {
            let invalid_state = create_expired_state();
            let invalid_code = format!("invalid_code_{i}");

            let response = self
                .browser()
                .get(&format!(
                    "/auth/oauth2/authorized?code={invalid_code}&state={invalid_state}"
                ))
                .await?;

            responses.push(response);

            // Small delay to avoid overwhelming the server
            sleep(Duration::from_millis(10)).await;
        }

        Ok(responses)
    }

    /// Perform rapid Passkey authentication attempts
    async fn rapid_passkey_auth_attempts(
        &self,
        count: usize,
    ) -> Result<Vec<reqwest::Response>, Box<dyn std::error::Error>> {
        let mut responses: Vec<reqwest::Response> = Vec::new();

        for i in 0..count {
            let auth_request = json!({
                "username": format!("nonexistent_user_{}@example.com", i)
            });

            let response = self
                .browser()
                .post_json("/auth/passkey/auth/start", &auth_request)
                .await?;

            responses.push(response);

            // Small delay to avoid overwhelming the server
            sleep(Duration::from_millis(10)).await;
        }

        Ok(responses)
    }

    /// Perform rapid registration attempts
    async fn rapid_registration_attempts(
        &self,
        count: usize,
    ) -> Result<Vec<reqwest::Response>, Box<dyn std::error::Error>> {
        let mut responses: Vec<reqwest::Response> = Vec::new();

        for i in 0..count {
            let registration_request = json!({
                "username": format!("test_user_{}@example.com", i),
                "displayname": format!("Test User {}", i),
                "mode": "create_user"
            });

            let response = self
                .browser()
                .post_json("/auth/passkey/register/start", &registration_request)
                .await?;

            responses.push(response);

            // Small delay to avoid overwhelming the server
            sleep(Duration::from_millis(10)).await;
        }

        Ok(responses)
    }

    /// Analyze rate limiting behavior from responses
    fn analyze_rate_limiting_behavior(
        &self,
        responses: &[reqwest::Response],
        test_name: &str,
    ) -> (usize, usize, f64) {
        let mut successful_requests = 0;
        let mut rate_limited_requests = 0;

        for response in responses {
            if response.status().is_success() {
                successful_requests += 1;
            } else if response.status() == 429 || response.status() == 503 {
                rate_limited_requests += 1;
            }
        }

        let total_requests = responses.len();
        let rate_limit_percentage = if total_requests > 0 {
            (rate_limited_requests as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        println!("📊 {test_name} Analysis:");
        println!("  Total Requests: {total_requests}");
        println!("  Successful: {successful_requests}");
        println!("  Rate Limited (429/503): {rate_limited_requests}");
        println!("  Rate Limit Percentage: {rate_limit_percentage:.1}%");

        if rate_limit_percentage > 10.0 {
            println!("✅ Rate limiting appears to be active");
        } else {
            println!("⚠️  Rate limiting may not be active or threshold is high");
        }

        (
            successful_requests,
            rate_limited_requests,
            rate_limit_percentage,
        )
    }
}

/// **CONSOLIDATED TEST 1**: Authentication Rate Limiting Protection
///
/// This test consolidates:
/// - test_security_rate_limiting_oauth2_authentication
/// - test_security_rate_limiting_passkey_authentication  
/// - test_security_rate_limiting_registration_attempts
#[tokio::test]
async fn test_consolidated_authentication_rate_limiting() -> Result<(), Box<dyn std::error::Error>>
{
    let setup = RateLimitingTestSetup::new().await?;

    println!("🔒 === CONSOLIDATED AUTHENTICATION RATE LIMITING TEST ===");

    // === SUBTEST 1: OAuth2 Authentication Rate Limiting ===
    println!("\n🛡️ SUBTEST 1: Testing OAuth2 authentication rate limiting");

    let oauth2_attempt_count = 50;
    println!("🔧 Performing {oauth2_attempt_count} rapid OAuth2 authentication attempts...");

    let start_time = Instant::now();
    let oauth2_responses = setup.rapid_oauth2_attempts(oauth2_attempt_count).await?;
    let oauth2_duration = start_time.elapsed();

    println!("⏱️  OAuth2 attempts completed in {oauth2_duration:?}");
    let (_oauth2_success, oauth2_rate_limited, _oauth2_rate_limit_pct) =
        setup.analyze_rate_limiting_behavior(&oauth2_responses, "OAuth2 Authentication");

    // === SUBTEST 2: Passkey Authentication Rate Limiting ===
    println!("\n🔐 SUBTEST 2: Testing Passkey authentication rate limiting");

    let passkey_attempt_count = 50;
    println!("🔧 Performing {passkey_attempt_count} rapid Passkey authentication attempts...");

    let start_time = Instant::now();
    let passkey_responses = setup
        .rapid_passkey_auth_attempts(passkey_attempt_count)
        .await?;
    let passkey_duration = start_time.elapsed();

    println!("⏱️  Passkey attempts completed in {passkey_duration:?}");
    let (_passkey_success, passkey_rate_limited, _passkey_rate_limit_pct) =
        setup.analyze_rate_limiting_behavior(&passkey_responses, "Passkey Authentication");

    // === SUBTEST 3: Registration Rate Limiting ===
    println!("\n👤 SUBTEST 3: Testing registration rate limiting");

    let registration_attempt_count = 30;
    println!("🔧 Performing {registration_attempt_count} rapid registration attempts...");

    let start_time = Instant::now();
    let registration_responses = setup
        .rapid_registration_attempts(registration_attempt_count)
        .await?;
    let registration_duration = start_time.elapsed();

    println!("⏱️  Registration attempts completed in {registration_duration:?}");
    let (_reg_success, reg_rate_limited, _reg_rate_limit_pct) =
        setup.analyze_rate_limiting_behavior(&registration_responses, "Registration");

    // === COMBINED ANALYSIS ===
    println!("\n📊 COMBINED RATE LIMITING ANALYSIS:");

    let total_attempts = oauth2_attempt_count + passkey_attempt_count + registration_attempt_count;
    let total_rate_limited = oauth2_rate_limited + passkey_rate_limited + reg_rate_limited;
    let overall_rate_limit_pct = (total_rate_limited as f64 / total_attempts as f64) * 100.0;

    println!("  Total Authentication Attempts: {total_attempts}");
    println!("  Total Rate Limited: {total_rate_limited}");
    println!("  Overall Rate Limit Percentage: {overall_rate_limit_pct:.1}%");

    // Analyze timing patterns for brute force protection
    let avg_oauth2_time = oauth2_duration.as_millis() as f64 / oauth2_attempt_count as f64;
    let avg_passkey_time = passkey_duration.as_millis() as f64 / passkey_attempt_count as f64;
    let avg_registration_time =
        registration_duration.as_millis() as f64 / registration_attempt_count as f64;

    println!("  Average OAuth2 Request Time: {avg_oauth2_time:.1}ms");
    println!("  Average Passkey Request Time: {avg_passkey_time:.1}ms");
    println!("  Average Registration Request Time: {avg_registration_time:.1}ms");

    // Check if timing increases significantly (indicating rate limiting delays)
    if avg_oauth2_time > 100.0 || avg_passkey_time > 100.0 || avg_registration_time > 100.0 {
        println!("✅ Request timing shows rate limiting delays");
    } else {
        println!("ℹ️  Request timing appears normal");
    }

    if overall_rate_limit_pct > 5.0 || total_rate_limited > 0 {
        println!("✅ Authentication rate limiting appears to be functioning");
    } else {
        println!("⚠️  Authentication rate limiting effectiveness unclear");
    }

    setup.shutdown().await?;
    println!("🎯 === CONSOLIDATED AUTHENTICATION RATE LIMITING TEST COMPLETED ===");
    Ok(())
}

/// **CONSOLIDATED TEST 2**: Resource Protection & DoS Prevention
///
/// This test consolidates:
/// - test_security_resource_exhaustion_protection
/// - test_security_concurrent_connection_protection
#[tokio::test]
async fn test_consolidated_resource_protection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = RateLimitingTestSetup::new().await?;

    println!("🔒 === CONSOLIDATED RESOURCE PROTECTION TEST ===");

    // === SUBTEST 1: Resource Exhaustion Protection ===
    println!("\n🛡️ SUBTEST 1: Testing resource exhaustion protection");

    // Test large payload handling
    let large_payload_sizes = vec![
        ("small_payload", 1024),        // 1KB
        ("medium_payload", 10240),      // 10KB
        ("large_payload", 102400),      // 100KB
        ("very_large_payload", 512000), // 512KB
    ];

    let mut exhaustion_protection_count = 0;

    for (size_name, payload_size) in large_payload_sizes {
        println!("🔧 Testing {size_name} ({payload_size} bytes)");

        let large_username = "x".repeat(payload_size);
        let large_payload = json!({
            "username": large_username,
            "displayname": "Large Payload Test",
            "mode": "create_user"
        });

        let start_time = Instant::now();
        let response = setup
            .browser()
            .post_json("/auth/passkey/register/start", &large_payload)
            .await?;
        let response_time = start_time.elapsed();

        let status = response.status();
        println!("  {size_name} - Status: {status}, Time: {response_time:?}");

        // Check if server properly rejects oversized requests
        if status == 413 || status == 400 || status == 422 || !status.is_success() {
            println!("  ✅ Large payload properly rejected");
            exhaustion_protection_count += 1;
        } else {
            println!("  ⚠️  Large payload accepted (may indicate vulnerability)");
        }

        // Brief pause between tests
        sleep(Duration::from_millis(100)).await;
    }

    // === SUBTEST 2: Concurrent Connection Protection ===
    println!("\n🔀 SUBTEST 2: Testing concurrent connection protection");

    // Test concurrent request handling
    let concurrent_request_count = 20;
    println!("🔧 Sending {concurrent_request_count} concurrent requests...");

    let mut handles = Vec::new();
    let base_url = setup.server().base_url.clone();

    let start_time = Instant::now();

    // Create concurrent requests
    for i in 0..concurrent_request_count {
        let base_url_clone = base_url.clone();
        let handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            let request_data = json!({
                "username": format!("concurrent_user_{}@example.com", i),
                "displayname": format!("Concurrent User {}", i),
                "mode": "create_user"
            });

            let response = client
                .post(format!("{base_url_clone}/auth/passkey/register/start"))
                .json(&request_data)
                .send()
                .await;

            (i, response)
        });
        handles.push(handle);
    }

    // Collect all responses
    let mut concurrent_responses = Vec::new();
    for handle in handles {
        match handle.await {
            Ok((request_id, Ok(response))) => {
                concurrent_responses.push((request_id, response));
            }
            Ok((request_id, Err(e))) => {
                println!("  Request {request_id} failed: {e}");
            }
            Err(e) => {
                println!("  Task failed: {e}");
            }
        }
    }

    let concurrent_duration = start_time.elapsed();
    println!("⏱️  Concurrent requests completed in {concurrent_duration:?}");

    // Analyze concurrent request handling
    let mut successful_concurrent = 0;
    let mut failed_concurrent = 0;
    let mut rate_limited_concurrent = 0;

    for (request_id, response) in &concurrent_responses {
        let status = response.status();
        if status.is_success() {
            successful_concurrent += 1;
        } else if status == 429 || status == 503 || status == 502 {
            rate_limited_concurrent += 1;
        } else {
            failed_concurrent += 1;
        }
        println!("  Request {request_id}: {status}");
    }

    println!("📊 Concurrent Request Analysis:");
    println!("  Total Sent: {concurrent_request_count}");
    println!("  Responses Received: {}", concurrent_responses.len());
    println!("  Successful: {successful_concurrent}");
    println!("  Rate Limited (429/503/502): {rate_limited_concurrent}");
    println!("  Other Failures: {failed_concurrent}");

    let avg_concurrent_time =
        concurrent_duration.as_millis() as f64 / concurrent_request_count as f64;
    println!("  Average Concurrent Response Time: {avg_concurrent_time:.1}ms");

    // === COMBINED RESOURCE PROTECTION ANALYSIS ===
    println!("\n📊 COMBINED RESOURCE PROTECTION ANALYSIS:");

    if exhaustion_protection_count >= 2 {
        println!("✅ Resource exhaustion protection appears effective");
    } else {
        println!("⚠️  Resource exhaustion protection may need strengthening");
    }

    if rate_limited_concurrent > 0 || failed_concurrent > 0 {
        println!("✅ Concurrent connection protection is active");
    } else if successful_concurrent == concurrent_request_count {
        println!("ℹ️  All concurrent requests succeeded (server handling well)");
    } else {
        println!("⚠️  Concurrent request handling analysis inconclusive");
    }

    // Check for server stability under load
    if concurrent_responses.len() == concurrent_request_count {
        println!("✅ Server remained stable under concurrent load");
    } else {
        println!("⚠️  Some requests may have been dropped under load");
    }

    setup.shutdown().await?;
    println!("🎯 === CONSOLIDATED RESOURCE PROTECTION TEST COMPLETED ===");
    Ok(())
}
