use super::session_utils::{has_csrf_management, verify_session_cookie_security};

/// Generic validation result for authentication flows
///
/// This structure provides consistent validation across OAuth2 and passkey authentication,
/// checking common success characteristics like redirects, session cookies, and CSRF management.
#[derive(Debug)]
pub struct AuthValidationResult {
    pub is_success: bool,
    pub status_code: reqwest::StatusCode,
    pub has_valid_redirect: bool,
    pub has_session_cookie: bool,
    pub has_expected_message: bool,
    pub has_csrf_management: bool,
    pub details: Vec<String>,
}

impl AuthValidationResult {
    /// Create validation result from HTTP response for OAuth2 flows
    pub fn from_oauth2_response(
        status: reqwest::StatusCode,
        headers: &reqwest::header::HeaderMap,
        expected_message: &str,
    ) -> Self {
        let mut result = Self {
            is_success: false,
            status_code: status,
            has_valid_redirect: false,
            has_session_cookie: false,
            has_expected_message: false,
            has_csrf_management: false,
            details: Vec::new(),
        };

        // Check status code (OAuth2 expects 303 See Other)
        result.has_valid_redirect = status == reqwest::StatusCode::SEE_OTHER;
        if result.has_valid_redirect {
            result
                .details
                .push("✅ 303 See Other redirect: PASSED".to_string());
        } else {
            result
                .details
                .push(format!("❌ Expected 303 See Other, got: {}", status));
        }

        // Check session cookie
        let session_cookie_name =
            std::env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "__Host-SessionId".to_string());

        result.has_session_cookie = verify_session_cookie_security(headers, &session_cookie_name);
        if result.has_session_cookie {
            result
                .details
                .push("✅ Session cookie with security flags: PASSED".to_string());
        } else {
            result
                .details
                .push("❌ Session cookie missing security flags".to_string());
        }

        // Check location header for OAuth2 popup close pattern
        if let Some(location) = headers.get("location").and_then(|h| h.to_str().ok()) {
            result.has_expected_message = location.contains("/auth/oauth2/popup_close")
                && location.contains(expected_message);

            if result.has_expected_message {
                result.details.push(format!(
                    "✅ Success redirect with expected message ({}): PASSED",
                    expected_message
                ));
            } else {
                result
                    .details
                    .push(format!("❌ Unexpected redirect location: {}", location));
            }
        } else {
            result
                .details
                .push("❌ No location header found".to_string());
        }

        // Check CSRF management
        result.has_csrf_management = has_csrf_management(headers);
        if result.has_csrf_management {
            result
                .details
                .push("✅ CSRF token management: PASSED".to_string());
        } else {
            result
                .details
                .push("❌ No CSRF cookie management found".to_string());
        }

        // Overall success for OAuth2
        result.is_success = result.has_valid_redirect
            && result.has_session_cookie
            && result.has_expected_message
            && result.has_csrf_management;

        result
    }

    /// Print validation details to console
    pub fn print_details(&self) {
        for detail in &self.details {
            println!("  {}", detail);
        }
    }
}

/// Validate OAuth2 success characteristics (legacy function for backward compatibility)
/// Returns vector of success/failure check messages
pub fn validate_oauth2_success(
    status: &reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    expected_message_pattern: &str,
) -> Vec<String> {
    let result =
        AuthValidationResult::from_oauth2_response(*status, headers, expected_message_pattern);
    result.details
}

/// Handle expected registration failures based on attestation format
///
/// This function processes expected failures during passkey registration for different
/// attestation formats (none, packed, tpm) and validates that they fail at the correct stage.
pub fn handle_expected_passkey_failure(
    format: &str,
    error_msg: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        "none" => {
            if error_msg.contains("verification")
                || error_msg.contains("credential")
                || error_msg.contains("CBOR")
            {
                println!(
                    "ⓘ {format} attestation failed as expected - reached CBOR validation step"
                );
            } else if error_msg.contains("Invalid origin") {
                println!(
                    "ⓘ {format} attestation failed as expected - origin validation rejected request"
                );
            } else {
                println!("❌ FAILURE: Unexpected error in {format} attestation");
                println!("Error: {error_msg}");
                return Err(
                    format!("{format} attestation failed unexpectedly: {error_msg}").into(),
                );
            }
        }
        "packed" => {
            if error_msg.contains("signature") || error_msg.contains("verification") {
                println!(
                    "ⓘ {format} attestation failed as expected - reached signature verification step"
                );
            } else {
                println!("❌ FAILURE: Unexpected error in {format} attestation");
                println!("Error: {error_msg}");
                return Err(
                    format!("{format} attestation failed unexpectedly: {error_msg}").into(),
                );
            }
        }
        "tpm" => {
            if error_msg.contains("TPM")
                || error_msg.contains("certInfo")
                || error_msg.contains("pubArea")
            {
                println!(
                    "ⓘ {format} attestation failed as expected - reached TPM verification step"
                );
            } else {
                println!("❌ FAILURE: Unexpected error in {format} attestation");
                println!("Error: {error_msg}");
                return Err(
                    format!("{format} attestation failed unexpectedly: {error_msg}").into(),
                );
            }
        }
        _ => {
            println!("❌ FAILURE: Unknown attestation format: {format}");
            return Err(format!("Unknown attestation format: {format}").into());
        }
    }
    Ok(())
}
