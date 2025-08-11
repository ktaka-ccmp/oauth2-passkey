//! Authentication coordination module
//!
//! This module provides high-level functions that coordinate between different
//! authentication mechanisms (OAuth2, Passkey) and user management.
//! It serves as the main entry point for most authentication operations.
//!
//! The module is divided into several submodules:
//! - `admin`: Admin-specific operations like user management and credential administration
//! - `errors`: Error types specific to coordination operations
//! - `oauth2`: OAuth2 authentication flow coordination
//! - `passkey`: WebAuthn/Passkey authentication flow coordination
//! - `user`: User account management operations

mod admin;
mod errors;
mod oauth2;
mod passkey;
mod user;

pub use oauth2::{
    delete_oauth2_account_core, get_authorized_core, list_accounts_core, post_authorized_core,
};

pub use admin::{
    delete_oauth2_account_admin, delete_passkey_credential_admin, delete_user_account_admin,
    get_all_users, get_user, update_user_admin_status,
};

pub use passkey::{
    RegistrationStartRequest, delete_passkey_credential_core, handle_finish_authentication_core,
    handle_finish_registration_core, handle_start_authentication_core,
    handle_start_registration_core, list_credentials_core, update_passkey_credential_core,
};
pub use user::{delete_user_account, update_user_account};

// Auth helper functions are now used internally by coordination functions
// They are not exported as they should not be used directly by external code
pub use errors::CoordinationError;
