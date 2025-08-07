//! Authorization helper functions
//!
//! This module provides helper functions for secure authorization patterns that validate
//! session data against the database to prevent privilege escalation attacks.
//!
//! These functions implement the security pattern described in the authorization-security-patterns
//! documentation to ensure that session data is always validated against fresh database state.

use super::errors::CoordinationError;
use crate::session::get_user_from_session;
use crate::userdb::{User, UserStore};

/// Validates that a session belongs to an admin user by checking fresh database state.
///
/// This function prevents privilege escalation attacks by always validating session data
/// against the database rather than trusting cached session information.
///
/// # Arguments
/// * `session_id` - The session ID to validate
///
/// # Returns
/// * `Ok(User)` - The admin user information from the database
/// * `Err(CoordinationError::Unauthorized)` - If the user is not an admin
/// * `Err(CoordinationError)` - If session validation or database lookup fails
///
/// # Security
/// This function performs two critical security validations:
/// 1. Session validation: Ensures the session exists and is valid
/// 2. Fresh database lookup: Fetches current user state to prevent stale/tampered data
pub async fn validate_admin_session(session_id: &str) -> Result<User, CoordinationError> {
    // Get user from session (this already does database validation)
    let session_user = get_user_from_session(session_id)
        .await
        .map_err(|_| CoordinationError::Unauthorized.log())?;

    // Get fresh user data from database to ensure we have current state
    let user = UserStore::get_user(&session_user.id)
        .await?
        .ok_or_else(|| CoordinationError::Unauthorized.log())?;

    // Check if user has admin privileges (using fresh database data)
    if !user.is_admin {
        tracing::debug!(user_id = %user.id, "User is not authorized (not an admin)");
        return Err(CoordinationError::Unauthorized.log());
    }

    tracing::debug!(user_id = %user.id, "Admin session validated successfully");
    Ok(user)
}

/// Validates that a session belongs to the owner of a specific resource.
///
/// This function ensures that only the resource owner can perform operations on their
/// own data by validating session ownership against fresh database state.
///
/// # Arguments
/// * `session_id` - The session ID to validate
/// * `resource_user_id` - The user ID that owns the resource
///
/// # Returns
/// * `Ok(User)` - The owner user information from the database
/// * `Err(CoordinationError::Unauthorized)` - If the user is not the resource owner
/// * `Err(CoordinationError)` - If session validation or database lookup fails
pub async fn validate_owner_session(
    session_id: &str,
    resource_user_id: &str,
) -> Result<User, CoordinationError> {
    // Get user from session (this already does database validation)
    let session_user = get_user_from_session(session_id)
        .await
        .map_err(|_| CoordinationError::Unauthorized.log())?;

    // Get fresh user data from database to ensure we have current state
    let user = UserStore::get_user(&session_user.id)
        .await?
        .ok_or_else(|| CoordinationError::Unauthorized.log())?;

    // Check if user owns the resource
    if user.id != resource_user_id {
        tracing::debug!(
            session_user_id = %user.id,
            resource_user_id = %resource_user_id,
            "User is not authorized (not resource owner)"
        );
        return Err(CoordinationError::Unauthorized.log());
    }

    tracing::debug!(user_id = %user.id, "Owner session validated successfully");
    Ok(user)
}

/// Validates that a session belongs to either an admin or the owner of a specific resource.
///
/// This function allows operations to be performed by either administrators (who can manage
/// any resource) or the resource owner (who can manage their own resources).
///
/// # Arguments
/// * `session_id` - The session ID to validate
/// * `resource_user_id` - The user ID that owns the resource
///
/// # Returns
/// * `Ok(User)` - The user information from the database (either admin or owner)
/// * `Err(CoordinationError::Unauthorized)` - If the user is neither admin nor owner
/// * `Err(CoordinationError)` - If session validation or database lookup fails
pub async fn validate_admin_or_owner_session(
    session_id: &str,
    resource_user_id: &str,
) -> Result<User, CoordinationError> {
    // Get user from session (this already does database validation)
    let session_user = get_user_from_session(session_id)
        .await
        .map_err(|_| CoordinationError::Unauthorized.log())?;

    // Get fresh user data from database to ensure we have current state
    let user = UserStore::get_user(&session_user.id)
        .await?
        .ok_or_else(|| CoordinationError::Unauthorized.log())?;

    // Check if user is admin OR owns the resource
    if !user.is_admin && user.id != resource_user_id {
        tracing::debug!(
            session_user_id = %user.id,
            resource_user_id = %resource_user_id,
            is_admin = %user.is_admin,
            "User is not authorized (neither admin nor resource owner)"
        );
        return Err(CoordinationError::Unauthorized.log());
    }

    tracing::debug!(
        user_id = %user.id,
        is_admin = %user.is_admin,
        is_owner = %(user.id == resource_user_id),
        "Admin or owner session validated successfully"
    );
    Ok(user)
}
