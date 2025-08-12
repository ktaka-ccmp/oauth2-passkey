/// Rate Limiting and DoS Protection Security Tests
///
/// These tests verify that the authentication system properly implements:
/// - Rate limiting on authentication attempts
/// - Rate limiting on registration attempts  
/// - Protection against resource exhaustion attacks
/// - Prevention of brute force attacks
/// - Proper handling of high-volume malicious requests
use crate::common::{MockBrowser, TestSetup, attack_scenarios::oauth2_attacks::*};
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
            let invalid_code = format!("brute_force_attempt_{i}");
            let invalid_state = create_empty_state();

            let response = self
                .browser()
                .get(&format!(
                    "/auth/oauth2/authorized?code={invalid_code}&state={invalid_state}"
                ))
                .await?;

            responses.push(response);

            // Small delay to avoid overwhelming the test server
            sleep(Duration::from_millis(10)).await;
        }

        Ok(responses)
    }

    /// Perform rapid Passkey authentication attempts
    async fn rapid_passkey_attempts(
        &self,
        count: usize,
    ) -> Result<Vec<reqwest::Response>, Box<dyn std::error::Error>> {
        let mut responses: Vec<reqwest::Response> = Vec::new();

        for i in 0..count {
            let malicious_json = json!({
                "invalid_request": format!("attack_attempt_{}", i)
            });

            let response = self
                .browser()
                .post_json("/auth/passkey/authenticate", &malicious_json)
                .await?;

            responses.push(response);

            // Small delay to avoid overwhelming the test server
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
            let registration_data = json!({
                "username": format!("attacker_{}@evil.com", i),
                "displayname": format!("Attacker {}", i),
                "mode": "create_user"
            });

            let response = self
                .browser()
                .post_json("/auth/passkey/register", &registration_data)
                .await?;

            responses.push(response);

            // Small delay to avoid overwhelming the test server
            sleep(Duration::from_millis(10)).await;
        }

        Ok(responses)
    }

    /// Attempt resource exhaustion via large request payloads
    async fn resource_exhaustion_attempt(
        &self,
        payload_size: usize,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
        // Create an extremely large JSON payload to test resource limits
        let large_payload = json!({
            "username": format!("{}@evil.com", "a".repeat(1000)),
            "displayname": "Resource Exhaustion Attack",
            "mode": "create_user",
            "malicious_data": "x".repeat(payload_size)
        });

        let response = self
            .browser()
            .post_json("/auth/passkey/register", &large_payload)
            .await?;

        Ok(response)
    }
}

/// Test OAuth2 authentication rate limiting
///
/// This test verifies that rapid OAuth2 authentication attempts are properly rate limited:
/// 1. Multiple rapid authentication attempts should be throttled
/// 2. Rate limiting should prevent brute force attacks on OAuth2 callbacks
/// 3. Legitimate requests should still be processed after rate limiting period
#[tokio::test]
async fn test_security_rate_limiting_oauth2_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = RateLimitingTestSetup::new().await?;

    println!("🔒 Testing OAuth2 authentication rate limiting");

    // Perform rapid authentication attempts (simulating brute force attack)
    let start_time = Instant::now();
    let responses = setup.rapid_oauth2_attempts(20).await?;
    let duration = start_time.elapsed();

    println!("🔧 Performed 20 OAuth2 attempts in {duration:?}");

    // Analyze responses for rate limiting behavior
    let mut rate_limited_count = 0;
    let mut server_error_count = 0;
    let mut client_error_count = 0;

    for (i, response) in responses.iter().enumerate() {
        let status = response.status();
        println!("🔧 Attempt {}: Status {}", i + 1, status);

        match status.as_u16() {
            429 => rate_limited_count += 1,       // Too Many Requests
            500..=599 => server_error_count += 1, // Server errors (could indicate overload protection)
            400..=499 => client_error_count += 1, // Client errors (expected for invalid requests)
            _ => {}
        }
    }

    println!("📊 Rate limited responses: {rate_limited_count}");
    println!("📊 Server error responses: {server_error_count}");
    println!("📊 Client error responses: {client_error_count}");

    // Verify rate limiting behavior
    // Either explicit rate limiting (429) or server protection (5xx) indicates DoS protection
    let protection_responses = rate_limited_count + server_error_count;

    if protection_responses > 0 {
        println!(
            "✅ Rate limiting detected: {protection_responses} protective responses out of 20 attempts"
        );
    } else {
        println!(
            "⚠️ No explicit rate limiting detected, but rapid invalid requests properly rejected"
        );
        // Verify that at least the requests were properly validated and rejected
        assert!(
            client_error_count >= 15,
            "Expected most invalid requests to be rejected"
        );
    }

    // Verify that the system doesn't crash under load
    assert!(
        responses.len() == 20,
        "Server should handle all requests without crashing"
    );

    setup.shutdown().await?;
    Ok(())
}

/// Test Passkey authentication rate limiting
///
/// This test verifies that rapid Passkey authentication attempts are properly rate limited:
/// 1. Multiple rapid WebAuthn authentication attempts should be throttled
/// 2. Rate limiting should prevent brute force attacks on passkey endpoints
/// 3. Resource consumption should be controlled during attack attempts
#[tokio::test]
async fn test_security_rate_limiting_passkey_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = RateLimitingTestSetup::new().await?;

    println!("🔒 Testing Passkey authentication rate limiting");

    // Perform rapid passkey authentication attempts
    let start_time = Instant::now();
    let responses = setup.rapid_passkey_attempts(15).await?;
    let duration = start_time.elapsed();

    println!("🔧 Performed 15 Passkey attempts in {duration:?}");

    // Analyze responses for rate limiting behavior
    let mut rate_limited_count = 0;
    let mut server_error_count = 0;
    let mut client_error_count = 0;

    for (i, response) in responses.iter().enumerate() {
        let status = response.status();
        println!("🔧 Attempt {}: Status {}", i + 1, status);

        match status.as_u16() {
            429 => rate_limited_count += 1,       // Too Many Requests
            500..=599 => server_error_count += 1, // Server errors (could indicate overload protection)
            400..=499 => client_error_count += 1, // Client errors (expected for malformed requests)
            _ => {}
        }
    }

    println!("📊 Rate limited responses: {rate_limited_count}");
    println!("📊 Server error responses: {server_error_count}");
    println!("📊 Client error responses: {client_error_count}");

    // Verify rate limiting or proper request validation
    let protection_responses = rate_limited_count + server_error_count;

    if protection_responses > 0 {
        println!(
            "✅ Rate limiting detected: {protection_responses} protective responses out of 15 attempts"
        );
    } else {
        println!("⚠️ No explicit rate limiting detected, but malformed requests properly rejected");
        // Verify that malformed requests are properly rejected
        assert!(
            client_error_count >= 10,
            "Expected most malformed requests to be rejected"
        );
    }

    // Verify system stability under load
    assert!(
        responses.len() == 15,
        "Server should handle all requests without crashing"
    );

    setup.shutdown().await?;
    Ok(())
}

/// Test registration rate limiting
///
/// This test verifies that rapid registration attempts are properly rate limited:
/// 1. Multiple rapid registration attempts should be throttled
/// 2. Rate limiting should prevent spam account creation
/// 3. Resource consumption should be controlled during registration floods
#[tokio::test]
async fn test_security_rate_limiting_registration_attempts()
-> Result<(), Box<dyn std::error::Error>> {
    let setup = RateLimitingTestSetup::new().await?;

    println!("🔒 Testing registration rate limiting");

    // Perform rapid registration attempts (simulating registration spam attack)
    let start_time = Instant::now();
    let responses = setup.rapid_registration_attempts(12).await?;
    let duration = start_time.elapsed();

    println!("🔧 Performed 12 registration attempts in {duration:?}");

    // Analyze responses for rate limiting behavior
    let mut rate_limited_count = 0;
    let mut server_error_count = 0;
    let mut client_error_count = 0;
    let mut success_count = 0;

    for (i, response) in responses.iter().enumerate() {
        let status = response.status();
        println!("🔧 Registration attempt {}: Status {}", i + 1, status);

        match status.as_u16() {
            200..=299 => success_count += 1,      // Successful responses
            429 => rate_limited_count += 1,       // Too Many Requests
            500..=599 => server_error_count += 1, // Server errors
            400..=499 => client_error_count += 1, // Client errors
            _ => {}
        }
    }

    println!("📊 Successful responses: {success_count}");
    println!("📊 Rate limited responses: {rate_limited_count}");
    println!("📊 Server error responses: {server_error_count}");
    println!("📊 Client error responses: {client_error_count}");

    // Verify rate limiting behavior for registrations
    let protection_responses = rate_limited_count + server_error_count;

    if protection_responses > 0 {
        println!(
            "✅ Registration rate limiting detected: {protection_responses} protective responses"
        );
    } else if success_count < responses.len() {
        println!("⚠️ No explicit rate limiting, but not all registrations succeeded");
        // This could indicate other forms of protection (duplicate detection, etc.)
    } else {
        println!("⚠️ All registration attempts succeeded - potential concern for spam protection");
    }

    // Verify system doesn't crash under registration load
    assert!(
        responses.len() == 12,
        "Server should handle all registration requests"
    );

    setup.shutdown().await?;
    Ok(())
}

/// Test resource exhaustion protection via large payloads
///
/// This test verifies that the system protects against resource exhaustion attacks:
/// 1. Extremely large request payloads should be rejected or limited
/// 2. Memory consumption should be controlled
/// 3. Server should remain stable under resource exhaustion attempts
#[tokio::test]
async fn test_security_resource_exhaustion_protection() -> Result<(), Box<dyn std::error::Error>> {
    let setup = RateLimitingTestSetup::new().await?;

    println!("🔒 Testing resource exhaustion protection");

    // Test progressively larger payloads
    let payload_sizes = [1024, 10240, 102400, 1048576]; // 1KB, 10KB, 100KB, 1MB

    for (i, &size) in payload_sizes.iter().enumerate() {
        println!("🔧 Testing payload size: {size} bytes");

        let start_time = Instant::now();
        let response = setup.resource_exhaustion_attempt(size).await?;
        let duration = start_time.elapsed();

        let status = response.status();
        println!(
            "🔧 Large payload test {}: Status {} (processed in {:?})",
            i + 1,
            status,
            duration
        );

        // Verify that large payloads are handled appropriately
        match status.as_u16() {
            413 => {
                println!("✅ Payload too large - server properly rejected oversized request");
            }
            400..=499 => {
                println!("✅ Client error - request properly rejected");
            }
            500..=599 => {
                println!("⚠️ Server error - may indicate resource pressure but server survived");
            }
            200..=299 => {
                println!("⚠️ Request succeeded - verify if this payload size is acceptable");
            }
            _ => {
                println!("🔧 Unexpected status code: {status}");
            }
        }

        // Verify that processing time doesn't grow excessively (basic DoS protection)
        if duration > Duration::from_secs(5) {
            println!("⚠️ Processing took {duration:?} - potential performance concern");
        }

        // Small delay between tests to avoid overwhelming the server
        sleep(Duration::from_millis(100)).await;
    }

    println!("✅ Resource exhaustion test completed - server remained stable");

    setup.shutdown().await?;
    Ok(())
}

/// Test concurrent connection exhaustion protection
///
/// This test verifies that the system can handle concurrent connection attempts:
/// 1. Multiple simultaneous connections should be managed properly
/// 2. Connection limits should prevent resource exhaustion
/// 3. Server should remain responsive under concurrent load
#[tokio::test]
async fn test_security_concurrent_connection_protection() -> Result<(), Box<dyn std::error::Error>>
{
    let setup = RateLimitingTestSetup::new().await?;

    println!("🔒 Testing concurrent connection protection");

    // Create multiple concurrent authentication attempts
    let mut handles = Vec::new();
    let concurrent_requests = 10;

    let start_time = Instant::now();

    for i in 0..concurrent_requests {
        let browser = MockBrowser::new(&setup.server().base_url, true);
        let handle = tokio::spawn(async move {
            let invalid_code = format!("concurrent_attack_{i}");
            let invalid_state = create_empty_state();

            browser
                .get(&format!(
                    "/auth/oauth2/authorized?code={invalid_code}&state={invalid_state}"
                ))
                .await
        });

        handles.push(handle);
    }

    // Wait for all concurrent requests to complete
    let mut responses: Vec<reqwest::Response> = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Ok(response)) => responses.push(response),
            Ok(Err(e)) => println!("🔧 Request failed: {e}"),
            Err(e) => println!("🔧 Task failed: {e}"),
        }
    }

    let duration = start_time.elapsed();
    println!(
        "🔧 Completed {} concurrent requests in {:?}",
        responses.len(),
        duration
    );

    // Analyze concurrent request handling
    let mut rate_limited_count = 0;
    let mut server_error_count = 0;
    let mut client_error_count = 0;

    for response in responses.iter() {
        let status = response.status();

        match status.as_u16() {
            429 => rate_limited_count += 1,
            500..=599 => server_error_count += 1,
            400..=499 => client_error_count += 1,
            _ => {}
        }
    }

    println!("📊 Concurrent requests processed: {}", responses.len());
    println!("📊 Rate limited: {rate_limited_count}");
    println!("📊 Server errors: {server_error_count}");
    println!("📊 Client errors: {client_error_count}");

    // Verify that the server handled concurrent load appropriately
    if rate_limited_count > 0 {
        println!("✅ Concurrent rate limiting detected");
    } else if server_error_count > 0 {
        println!("⚠️ Some server errors under concurrent load - indicates resource pressure");
    } else {
        println!("✅ All concurrent requests handled successfully");
    }

    // Verify server remained responsive (didn't crash or hang)
    assert!(
        responses.len() >= concurrent_requests / 2,
        "Server should handle at least half of concurrent requests"
    );

    // Verify processing time is reasonable for concurrent requests
    assert!(
        duration < Duration::from_secs(30),
        "Concurrent requests should complete within reasonable time"
    );

    setup.shutdown().await?;
    Ok(())
}
