pub mod axum_mock_server;
pub mod constants;
pub mod fixtures;
pub mod mock_browser;
pub mod secure_auth;
pub mod session_utils;
pub mod test_server;
pub mod test_setup;
pub mod validation_utils;
pub mod webauthn_helpers;

// OAuth2 authentication helper for first user (secure approach)
// Secure authentication helpers - NO BACKDOORS, only authentic authentication flows
pub use secure_auth::create_admin_session_via_oauth2;

pub use fixtures::*;
pub use mock_browser::MockBrowser;
pub use test_server::TestServer;
pub use test_setup::{MultiBrowserTestSetup, TestSetup};
