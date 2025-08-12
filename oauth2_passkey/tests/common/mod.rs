pub(crate) mod axum_mock_server;
pub(crate) mod constants;
pub(crate) mod fixtures;
pub(crate) mod mock_browser;
pub(crate) mod secure_auth;
pub(crate) mod session_utils;
pub(crate) mod test_server;
pub(crate) mod test_setup;
pub(crate) mod validation_utils;
// pub(crate) mod webauthn_helpers;

// OAuth2 authentication helper for first user (secure approach)
// Secure authentication helpers - NO BACKDOORS, only authentic authentication flows
pub(crate) use secure_auth::{create_admin_session_via_oauth2, create_admin_session_via_passkey};

pub(crate) use fixtures::*;
pub(crate) use mock_browser::MockBrowser;
pub(crate) use test_server::TestServer;
pub(crate) use test_setup::{MultiBrowserTestSetup, TestSetup};
