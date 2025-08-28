use super::*;
use crate::session::SessionError;
use crate::utils::UtilError;
use std::error::Error;

/// Test error source chain preservation in From trait conversions
///
/// This test verifies that when converting from UtilError and SessionError to OAuth2Error
/// using the From trait, the error source chain is properly preserved. It creates errors
/// in memory and tests that the original error can be accessed via the source() method.
///
#[test]
fn test_error_source_chaining() {
    // Test that From conversions preserve error sources
    let util_err = UtilError::Format("format error".to_string());
    let oauth2_err: OAuth2Error = util_err.into();

    // The source should be the original UtilError
    match oauth2_err.source() {
        Some(source) => {
            assert_eq!(source.to_string(), "Invalid format: format error");
        }
        None => panic!("Expected error to have a source"),
    }

    let session_err = SessionError::Storage("session error".to_string());
    let oauth2_err: OAuth2Error = session_err.into();

    // The source should be the original SessionError
    match oauth2_err.source() {
        Some(source) => {
            assert_eq!(source.to_string(), "Storage error: session error");
        }
        None => panic!("Expected error to have a source"),
    }
}
