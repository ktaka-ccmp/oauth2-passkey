/// Security test utilities for creating attack scenarios and validating failures
use reqwest::{StatusCode, header::HeaderMap};

/// Expected security error types for validation
#[derive(Debug, Clone)]
pub enum ExpectedSecurityError {
    /// 400 Bad Request - malformed or invalid input
    BadRequest,
    /// 401 Unauthorized - authentication required
    Unauthorized,
    /// Custom status code with expected message pattern
    Custom(StatusCode, Option<String>),
}

/// Security test result for consistent validation
#[derive(Debug)]
pub struct SecurityTestResult {
    pub status_code: StatusCode,
    pub response_body: String,
    pub headers: HeaderMap,
    pub security_failure_detected: bool,
    pub no_session_created: bool,
    pub proper_error_response: bool,
}

impl SecurityTestResult {
    /// Create a security test result from HTTP response components
    pub fn new(status_code: StatusCode, response_body: String, headers: HeaderMap) -> Self {
        let security_failure_detected = status_code.is_client_error()
            || status_code.is_server_error()
            || status_code.is_redirection(); // Redirects often indicate security controls are working
        let no_session_created = !Self::has_session_cookie(&headers);
        let proper_error_response = Self::has_proper_error_response(&response_body, status_code);

        Self {
            status_code,
            response_body,
            headers,
            security_failure_detected,
            no_session_created,
            proper_error_response,
        }
    }

    /// Check if response has session cookie (should not for security failures)
    fn has_session_cookie(headers: &HeaderMap) -> bool {
        let session_cookie_name =
            std::env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "__Host-SessionId".to_string());

        headers.get_all("set-cookie").iter().any(|cookie| {
            let cookie_str = cookie.to_str().unwrap_or("");
            cookie_str.contains(&session_cookie_name) && !cookie_str.contains("Max-Age=0")
        })
    }

    /// Check if response has proper error format (no sensitive info leakage)
    fn has_proper_error_response(body: &str, status: StatusCode) -> bool {
        if status.is_success() {
            return false; // Security failures should not return success
        }

        // Security responses should not leak sensitive information
        // Check for absence of internal error details, stack traces, etc.
        let has_sensitive_leak = body.contains("sql")
            || body.contains("database")
            || body.contains("internal server")
            || body.contains("stack trace")
            || body.contains("debug")
            || body.contains("panic");

        !has_sensitive_leak
    }

    /// Validate the security test result against expected error
    pub fn validate_security_failure(&self, expected: &ExpectedSecurityError) -> bool {
        match expected {
            ExpectedSecurityError::BadRequest => {
                self.status_code == StatusCode::BAD_REQUEST && self.security_failure_detected
            }
            ExpectedSecurityError::Unauthorized => {
                self.status_code == StatusCode::UNAUTHORIZED && self.security_failure_detected
            }
            ExpectedSecurityError::Custom(expected_status, message_pattern) => {
                let status_matches = self.status_code == *expected_status;
                let message_matches = message_pattern
                    .as_ref()
                    .map(|pattern| self.response_body.contains(pattern))
                    .unwrap_or(true);
                // For custom status codes, the security behavior is validated differently
                // Success responses (200 OK) that we expect indicate the security test needs revision
                let security_validated = if expected_status.is_success() {
                    true // Allow success codes if explicitly expected
                } else {
                    self.security_failure_detected
                };
                status_matches && message_matches && security_validated
            }
        }
    }

    /// Print detailed security test result for debugging
    pub fn print_security_details(&self, test_name: &str) {
        println!("🔍 Security Test Result: {test_name}");
        println!("  Status Code: {}", self.status_code);
        println!(
            "  Security Failure Detected: {}",
            self.security_failure_detected
        );
        println!("  No Session Created: {}", self.no_session_created);
        println!("  Proper Error Response: {}", self.proper_error_response);

        if !self.response_body.is_empty() {
            println!("  Response Body Length: {} chars", self.response_body.len());
            // Only print first 200 chars to avoid overwhelming output
            if self.response_body.len() > 200 {
                println!(
                    "  Response Body (truncated): {}...",
                    &self.response_body[..200]
                );
            } else {
                println!("  Response Body: {}", self.response_body);
            }
        }
    }
}

/// Assert that a security test properly failed with expected error
pub fn assert_security_failure(
    result: &SecurityTestResult,
    expected: &ExpectedSecurityError,
    test_context: &str,
) {
    result.print_security_details(test_context);

    assert!(
        result.validate_security_failure(expected),
        "Security test '{}' failed validation. Expected: {:?}, Got status: {}, Body: {}",
        test_context,
        expected,
        result.status_code,
        result.response_body
    );

    assert!(
        result.no_session_created,
        "Security test '{}' should not create session on failure. Headers: {:?}",
        test_context, result.headers
    );

    assert!(
        result.proper_error_response,
        "Security test '{}' should not leak sensitive information. Body: {}",
        test_context, result.response_body
    );

    println!("✅ Security test '{test_context}' properly rejected malicious request");
}

/// Assert that no active session exists after security failure
pub async fn assert_no_session_established(browser: &crate::common::MockBrowser) {
    let user_info_response = browser.get("/auth/user/info").await.unwrap();
    assert_eq!(
        user_info_response.status(),
        StatusCode::UNAUTHORIZED,
        "Should not have active session after security failure"
    );
}

/// Create a SecurityTestResult from a reqwest::Response
pub async fn create_security_result_from_response(
    response: reqwest::Response,
) -> Result<SecurityTestResult, Box<dyn std::error::Error>> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await?;

    Ok(SecurityTestResult::new(status, body, headers))
}
