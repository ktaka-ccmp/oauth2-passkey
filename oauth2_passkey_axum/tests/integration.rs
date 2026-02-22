/// Integration tests for oauth2-passkey library
///
/// These tests verify complete authentication flows in an isolated test environment
/// with mocked external services and in-memory databases.
mod common;

// Import specific integration test modules
// use integration::oauth2_flows;
// use integration::passkey_flows;
// use integration::combined_flows;

mod integration {
    pub mod api_client_flows;
    pub mod combined_flows;
    pub mod oauth2_flows;
    pub mod passkey_flows;
}
