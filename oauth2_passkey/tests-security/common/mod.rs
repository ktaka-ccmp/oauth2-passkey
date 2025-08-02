pub mod attack_scenarios;
/// Common utilities and helpers for security testing
///
/// This module provides utilities for creating security attack scenarios,
/// tampering with security tokens, and validating security failure responses.
pub mod security_utils;

// Direct path imports from the existing test common modules
#[path = "../../tests/common/mock_browser.rs"]
pub mod mock_browser;

#[path = "../../tests/common/test_server.rs"]
pub mod test_server;

#[path = "../../tests/common/fixtures.rs"]
pub mod fixtures;

#[path = "../../tests/common/constants.rs"]
pub mod constants;

#[path = "../../tests/common/validation_utils.rs"]
pub mod validation_utils;

#[path = "../../tests/common/session_utils.rs"]
pub mod session_utils;

#[path = "../../tests/common/webauthn_helpers.rs"]
pub mod webauthn_helpers;

#[path = "../../tests/common/axum_mock_server.rs"]
pub mod axum_mock_server;

// Re-export the commonly used types
pub use fixtures::*;
pub use mock_browser::MockBrowser;
pub use test_server::TestServer;
