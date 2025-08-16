#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::all)]

//! # oauth2-passkey
//!
//! A minimal-dependency, security-focused authentication library for Rust web applications
//! supporting both OAuth2 and WebAuthn/Passkey authentication.
//!
//! This framework-agnostic core library provides authentication coordination between
//! OAuth2, WebAuthn/Passkey, and session management, with flexible storage backends.
//!
//! ## Key Features
//!
//! - 🔐 **Secure Session Management**: Automatic cookie handling with CSRF protection
//! - 🌐 **OAuth2 Authentication**: Google OAuth2/OIDC support
//! - 🔑 **WebAuthn/Passkey Authentication**: FIDO2 compliant
//! - 📦 **Minimal Dependencies**: Security-focused design philosophy
//! - 🔌 **Flexible Storage**: Support for SQLite, PostgreSQL, Redis, and in-memory caching
//!
//! ## Usage
//!
//! This crate provides the core authentication functionality that can be used directly
//! or through framework-specific integration crates like [`oauth2-passkey-axum`](https://crates.io/crates/oauth2-passkey-axum).
//!
//! ```rust,no_run
//! use oauth2_passkey::{init, SessionUser};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize authentication (reads configuration from environment variables)
//!     init().await?;
//!
//!     // Now authentication functions can be used
//!     // (usually through a web framework integration)
//!
//!     Ok(())
//! }
//! ```
//!
//! See the repository documentation for more details on configuration and advanced usage.

mod config;
mod coordination;
mod oauth2;
mod passkey;
mod session;
mod storage;
mod userdb;
mod utils;

// Test utilities module (only available in test builds)
#[cfg(test)]
mod test_utils;

// Core coordination components for authentication
pub use coordination::{
    CoordinationError, RegistrationStartRequest, get_all_users, get_user,
    handle_finish_authentication_core, handle_finish_registration_core,
    handle_start_authentication_core, handle_start_registration_core, list_credentials_core,
};

// User and account management operations
pub use coordination::{
    delete_oauth2_account_admin, delete_oauth2_account_core, delete_passkey_credential_admin,
    delete_passkey_credential_core, delete_user_account, delete_user_account_admin,
    get_authorized_core, list_accounts_core, post_authorized_core, update_passkey_credential_core,
    update_user_account, update_user_admin_status,
};

// Environment variable configurable route prefix for all auth routes (defaults to "/o2p")
pub use config::O2P_ROUTE_PREFIX;

// OAuth2 authentication types and functions
pub use oauth2::{
    AuthResponse, OAuth2Account, OAuth2Mode, OAuth2State, Provider, ProviderUserId,
    prepare_oauth2_auth_request,
};

// WebAuthn/Passkey types and functions
pub use passkey::{
    AuthenticationOptions, AuthenticatorInfo, AuthenticatorResponse, ChallengeId, ChallengeType,
    CredentialId, PasskeyCredential, RegisterCredential, RegistrationOptions,
    get_authenticator_info, get_authenticator_info_batch, get_related_origin_json,
};

// Session management types and functions for authentication state
pub use session::{
    AuthenticationStatus, CsrfHeaderVerified, CsrfToken, SESSION_COOKIE_NAME, SessionCookie,
    SessionError, SessionId, User as SessionUser, UserId, generate_page_session_token,
    get_csrf_token_from_session, get_user_and_csrf_token_from_session, get_user_from_session,
    is_authenticated_basic, is_authenticated_basic_then_csrf,
    is_authenticated_basic_then_user_and_csrf, is_authenticated_strict,
    is_authenticated_strict_then_csrf, prepare_logout_response, verify_page_session_token,
};

// User database representation of a user account
pub use userdb::User as DbUser;

/// Initialize the authentication coordination layer
///
/// This function must be called before using any authentication functionality.
/// It initializes all storage backends and configurations based on environment variables.
///
/// # Returns
///
/// - `Ok(())` if initialization was successful
/// - `Err` with details if initialization failed
///
/// # Environment Variables
///
/// Required environment variables:
/// - `ORIGIN`: Base URL of your application (e.g., `https://example.com`)
///
/// Storage variables (choose one database and one cache):
/// - `GENERIC_DATA_STORE_TYPE`: "sqlite" or "postgres"
/// - `GENERIC_DATA_STORE_URL`: Connection string for the database
/// - `GENERIC_CACHE_STORE_TYPE`: "memory" or "redis"
/// - `GENERIC_CACHE_STORE_URL`: Connection string for the cache
///
/// See README.md for complete configuration options.
///
/// # Example
///
/// ```rust,no_run
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Load environment variables from .env file
///     dotenvy::dotenv().ok();
///
///     // Initialize authentication
///     oauth2_passkey::init().await?;
///
///     // Now you can use the authentication functions
///     Ok(())
/// }
/// ```
pub async fn init() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the underlying stores
    userdb::init().await?;
    oauth2::init().await?;
    passkey::init().await?;
    Ok(())
}
