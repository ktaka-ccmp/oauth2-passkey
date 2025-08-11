/// OAuth2 security tests - negative tests for OAuth2 authentication flows
///
/// These tests verify that OAuth2 security controls properly reject:
/// - Invalid/tampered state parameters
/// - CSRF token mismatches and missing tokens
/// - Nonce verification failures in ID tokens
/// - Invalid authorization codes
/// - PKCE code challenge verification failures
/// - Redirect URI validation failures
/// - Origin header validation failures
use crate::common::{
    MockBrowser, TestSetup, attack_scenarios::oauth2_attacks::*, security_utils::*,
};
use serial_test::serial;
use std::env;
