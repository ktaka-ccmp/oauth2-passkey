//! Audit and security logging module
//!
//! This module provides functionality for security-related logging and auditing.
//! Currently it supports login history tracking, recording authentication attempts
//! including the method used (passkey or OAuth2), IP address, user agent, and
//! success/failure status.

mod errors;
mod storage;
mod types;

// Internal-only exports
pub(crate) use errors::LoginHistoryError;
pub(crate) use storage::LoginHistoryStore;
pub(crate) use types::AuthMethod;

// Public exports for external use
pub(crate) use types::LoginContext;
pub use types::LoginHistoryEntry;
