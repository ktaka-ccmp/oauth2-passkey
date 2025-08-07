// Allow dead code warnings for shared test utilities
#![allow(dead_code)]

/// Security-focused integration tests for oauth2-passkey library
///
/// These tests verify that security controls properly reject malicious, malformed,
/// or security-violating requests across OAuth2, Passkey, and Session flows.
///
/// These tests complement the positive integration tests by focusing on:
/// - Invalid/tampered security tokens and parameters
/// - Cross-origin attacks and origin validation
/// - Session boundary violations
/// - Authentication bypass attempts
/// - Authorization escalation attempts
///
/// All tests in this module are "negative tests" that expect security failures.
mod common;

// Security test modules
mod cross_flow_security;
mod information_disclosure_security;
mod oauth2_security;
mod passkey_security;
mod rate_limiting_security;
mod session_security;
