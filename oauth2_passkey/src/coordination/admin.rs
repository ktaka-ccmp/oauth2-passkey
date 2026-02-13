use std::collections::HashMap;

use crate::oauth2::{AccountSearchField, OAuth2Store, ProviderUserId};
use crate::passkey::{CredentialId, CredentialSearchField, PasskeyStore};
use crate::userdb::{User, UserStore};

use super::errors::CoordinationError;
use crate::session::{
    SessionId, User as SessionUser, UserId, cleanup_stale_sessions,
    delete_session_from_store_by_session_id, get_user_from_session,
};

/// Retrieves a list of all users in the system.
///
/// This admin-level function fetches all user accounts from the database.
/// It provides a comprehensive view of all registered users and their details.
/// Requires administrative privileges.
///
/// # Arguments
///
/// * `session_id` - The session ID of the administrator performing the action
///
/// # Returns
///
/// * `Ok(Vec<User>)` - A vector containing all user accounts
/// * `Err(CoordinationError::Unauthorized)` - If the user doesn't have admin privileges
/// * `Err(CoordinationError)` - If a database error occurs
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{get_all_users, SessionId};
///
/// async fn list_all_users(session_id: &str) -> Vec<String> {
///     let session_id = SessionId::new(session_id.to_string()).expect("Valid session ID");
///     match get_all_users(session_id).await {
///         Ok(users) => users.iter().map(|user| user.account.clone()).collect(),
///         Err(_) => Vec::new()
///     }
/// }
/// ```
pub async fn get_all_users(session_id: SessionId) -> Result<Vec<User>, CoordinationError> {
    // Validate admin session with fresh database lookup
    let _admin_user = validate_admin_session(session_id).await?;

    UserStore::get_all_users()
        .await
        .map_err(|e| CoordinationError::Database(e.to_string()))
}

/// Retrieves a specific user by their ID.
///
/// This function fetches a user's account information from the database using their
/// unique identifier. It's used for user profile viewing, account management,
/// and administrative tasks. Requires administrative privileges.
///
/// # Arguments
///
/// * `session_id` - The session ID of the administrator performing the action
/// * `user_id` - The unique identifier of the user to retrieve
///
/// # Returns
///
/// * `Ok(Some(User))` - The user's account information if found
/// * `Ok(None)` - If no user exists with the provided ID
/// * `Err(CoordinationError::Unauthorized)` - If the user doesn't have admin privileges
/// * `Err(CoordinationError)` - If a database error occurs
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{get_user, SessionId, UserId};
///
/// async fn fetch_user_profile(session_id: &str, id: &str) -> Option<String> {
///     let session_id = SessionId::new(session_id.to_string()).expect("Valid session ID");
///     let user_id = UserId::new(id.to_string()).expect("Valid user ID");
///     match get_user(session_id, user_id).await {
///         Ok(Some(user)) => Some(user.account),
///         _ => None
///     }
/// }
/// ```
pub async fn get_user(
    session_id: SessionId,
    user_id: UserId,
) -> Result<Option<User>, CoordinationError> {
    // Validate admin session with fresh database lookup
    let _admin_user = validate_admin_session(session_id).await?;

    UserStore::get_user(user_id)
        .await
        .map_err(|e| CoordinationError::Database(e.to_string()))
}

/// Deletes a passkey credential as an administrator.
///
/// This administrative function allows a system administrator to delete any user's
/// passkey credential. It requires the calling user to have administrative privileges.
/// This is useful for managing compromised credentials or helping users who are
/// locked out of their accounts.
///
/// # Arguments
///
/// * `session_id` - The session ID of the administrator performing the action
/// * `credential_id` - The ID of the passkey credential to delete
///
/// # Returns
///
/// * `Ok(())` - If the credential was successfully deleted
/// * `Err(CoordinationError::Unauthorized)` - If the user doesn't have admin privileges
/// * `Err(CoordinationError)` - If another error occurs during deletion
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{delete_passkey_credential_admin, SessionId, CredentialId};
///
/// async fn remove_credential(session_id: &str, credential_id: &str) -> bool {
///     let session_id = SessionId::new(session_id.to_string()).expect("Valid session ID");
///     let credential_id = CredentialId::new(credential_id.to_string()).expect("Valid credential ID");
///     delete_passkey_credential_admin(session_id, credential_id).await.is_ok()
/// }
/// ```
pub async fn delete_passkey_credential_admin(
    session_id: SessionId,
    credential_id: CredentialId,
) -> Result<(), CoordinationError> {
    // Validate admin session with fresh database lookup
    let admin_user = validate_admin_session(session_id).await?;

    tracing::debug!(
        "Admin user: {} is deleting credential with ID: {}",
        admin_user.id,
        credential_id.as_str()
    );

    let credential = PasskeyStore::get_credentials_by(CredentialSearchField::CredentialId(
        credential_id.clone(),
    ))
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "Passkey".to_string(),
            resource_id: credential_id.as_str().to_string(),
        }
        .log()
    })?;

    // Should we verify a context token here?

    // Delete the credential using the raw credential ID format from the database
    let credential_id = CredentialId::new(credential.credential_id.clone())
        .map_err(|e| CoordinationError::Validation(format!("Invalid credential ID: {e}")))?;
    PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(credential_id)).await?;

    tracing::debug!("Successfully deleted credential");

    Ok(())
}

/// Deletes an OAuth2 account as an administrator.
///
/// This administrative function allows a system administrator to delete any user's
/// OAuth2 account. It requires the calling user to have administrative privileges.
/// This is useful for managing compromised accounts or removing unauthorized
/// OAuth2 connections.
///
/// # Arguments
///
/// * `session_id` - The session ID of the administrator performing the action
/// * `provider_user_id` - The unique provider-specific user ID of the OAuth2 account to delete
///
/// # Returns
///
/// * `Ok(())` - If the OAuth2 account was successfully deleted
/// * `Err(CoordinationError::Unauthorized)` - If the user doesn't have admin privileges
/// * `Err(CoordinationError)` - If another error occurs during deletion
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{delete_oauth2_account_admin, SessionId, ProviderUserId};
///
/// async fn remove_oauth2_account(session_id: &str, provider_id: &str) -> bool {
///     let session_id = SessionId::new(session_id.to_string()).expect("Valid session ID");
///     let provider_id = ProviderUserId::new(provider_id.to_string()).expect("Valid provider ID");
///     delete_oauth2_account_admin(session_id, provider_id).await.is_ok()
/// }
/// ```
pub async fn delete_oauth2_account_admin(
    session_id: SessionId,
    provider_user_id: ProviderUserId,
) -> Result<(), CoordinationError> {
    // Validate admin session with fresh database lookup
    let admin_user = validate_admin_session(session_id).await?;

    tracing::debug!(
        "Admin user: {} is deleting OAuth2 account with ID: {}",
        admin_user.id,
        provider_user_id.as_str()
    );

    // Delete the OAuth2 account
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::ProviderUserId(
        provider_user_id.clone(),
    ))
    .await?;

    tracing::info!(
        "Successfully deleted OAuth2 account {} for user {}",
        provider_user_id.as_str(),
        admin_user.id
    );
    Ok(())
}

/// Completely deletes a user account as an administrator.
///
/// This administrative function permanently removes a user account and all associated
/// data (including OAuth2 accounts and passkey credentials). This is a destructive
/// operation that cannot be undone. Requires administrative privileges.
///
/// # Arguments
///
/// * `session_id` - The session ID of the administrator performing the action
/// * `user_id` - The unique identifier of the user account to delete
///
/// # Returns
///
/// * `Ok(())` - If the user account was successfully deleted
/// * `Err(CoordinationError::Unauthorized)` - If the user doesn't have admin privileges
/// * `Err(CoordinationError::ResourceNotFound)` - If the user doesn't exist
/// * `Err(CoordinationError::Conflict)` - If trying to delete the last admin user
/// * `Err(CoordinationError)` - If another error occurs during deletion
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{delete_user_account_admin, SessionId, UserId};
///
/// async fn purge_account(session_id: &str, user_id: &str) -> Result<(), String> {
///     let session_id = SessionId::new(session_id.to_string()).expect("Valid session ID");
///     let user_id = UserId::new(user_id.to_string()).expect("Valid user ID");
///     delete_user_account_admin(session_id, user_id).await.map_err(|e| e.to_string())
/// }
/// ```
pub async fn delete_user_account_admin(
    session_id: SessionId,
    user_id: UserId,
) -> Result<(), CoordinationError> {
    // Validate admin session with fresh database lookup
    let _admin_user = validate_admin_session(session_id).await?;
    // Check if the user exists
    let user = UserStore::get_user(user_id.clone()).await?.ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: user_id.as_str().to_string(),
        }
        .log()
    })?;

    // Prevent deleting the last admin user
    if user.has_admin_privileges() {
        let admin_count = UserStore::count_admin_users()
            .await
            .map_err(|e| CoordinationError::Database(e.to_string()))?;
        if admin_count <= 1 {
            return Err(CoordinationError::Conflict(
                "Cannot delete the last admin user".to_string(),
            )
            .log());
        }
    }

    tracing::debug!("Deleting user account: {:#?}", user);

    // Delete all OAuth2 accounts for this user
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::UserId(user_id.clone())).await?;

    // Delete all Passkey credentials for this user
    PasskeyStore::delete_credential_by(CredentialSearchField::UserId(user_id.clone())).await?;

    // Finally, delete the user account
    UserStore::delete_user(user_id).await?;

    Ok(())
}

/// Updates a user's administrative status.
///
/// This function allows an administrator to grant or revoke administrative privileges
/// for another user. For security reasons, the last admin user in the system cannot
/// be demoted (to prevent admin lockout).
///
/// # Arguments
///
/// * `session_id` - The session ID of the administrator performing the action
/// * `user_id` - The ID of the user whose admin status will be changed
/// * `is_admin` - The new admin status (`true` = admin, `false` = regular user)
///
/// # Returns
///
/// * `Ok(User)` - The updated user account information
/// * `Err(CoordinationError::Unauthorized)` - If the caller doesn't have admin privileges
/// * `Err(CoordinationError::ResourceNotFound)` - If the target user doesn't exist
/// * `Err(CoordinationError::Conflict)` - If trying to demote the last admin user
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{update_user_admin_status, SessionId, UserId};
///
/// async fn make_user_admin(session_id: &str, user_id: &str) -> bool {
///     let session_id = SessionId::new(session_id.to_string()).expect("Valid session ID");
///     let user_id = UserId::new(user_id.to_string()).expect("Valid user ID");
///     update_user_admin_status(session_id, user_id, true).await.is_ok()
/// }
/// ```
pub async fn update_user_admin_status(
    session_id: SessionId,
    user_id: UserId,
    is_admin: bool,
) -> Result<User, CoordinationError> {
    // Validate admin session with fresh database lookup
    let _admin_user = validate_admin_session(session_id).await?;

    // Get the current user
    let user = UserStore::get_user(user_id.clone()).await?.ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: user_id.as_str().to_string(),
        }
        .log()
    })?;

    // Prevent demoting the last admin user
    if !is_admin && user.has_admin_privileges() {
        let admin_count = UserStore::count_admin_users()
            .await
            .map_err(|e| CoordinationError::Database(e.to_string()))?;
        if admin_count <= 1 {
            return Err(CoordinationError::Conflict(
                "Cannot demote the last admin user".to_string(),
            )
            .log());
        }
    }

    // Update the user with the new admin status
    let updated_user = User { is_admin, ..user };

    // Save the updated user
    let user = UserStore::upsert_user(updated_user).await?;

    Ok(user)
}

/// Gets active session counts for all users.
///
/// This function returns a map of user IDs to their active session counts.
///
/// # Arguments
///
/// * `session_id` - The session ID of the administrator performing the action
///
/// # Returns
///
/// * `Ok(HashMap<String, usize>)` - A map of user IDs to their active session counts
/// * `Err(CoordinationError::Unauthorized)` - If the caller doesn't have admin privileges
/// * `Err(CoordinationError)` - If an error occurs during the operation
pub async fn get_all_active_sessions(
    session_id: SessionId,
) -> Result<HashMap<String, usize>, CoordinationError> {
    // Validate admin session
    let _admin_user = validate_admin_session(session_id).await?;

    // Get all users
    let users = UserStore::get_all_users()
        .await
        .map_err(|e| CoordinationError::Database(e.to_string()))?;

    let mut result = HashMap::new();

    for user in users {
        let session_ids = cleanup_stale_sessions(&user.id).await?;
        result.insert(user.id, session_ids.len());
    }

    Ok(result)
}

/// Forces logout of a user by deleting all their active sessions.
///
/// This administrative function invalidates all active sessions for a specific user,
/// effectively logging them out from all devices. This is useful for security incidents,
/// account compromises, or when a user requests to be logged out remotely.
///
/// # Arguments
///
/// * `session_id` - The session ID of the administrator performing the action
/// * `user_id` - The unique identifier of the user to force logout
///
/// # Returns
///
/// * `Ok(usize)` - The number of sessions that were terminated
/// * `Err(CoordinationError::Unauthorized)` - If the caller doesn't have admin privileges
/// * `Err(CoordinationError)` - If an error occurs during the operation
pub async fn force_logout_user(
    session_id: SessionId,
    user_id: UserId,
) -> Result<usize, CoordinationError> {
    // Validate admin session
    let admin_user = validate_admin_session(session_id).await?;

    tracing::info!(
        admin_id = %admin_user.id,
        target_user_id = %user_id.as_str(),
        "Admin forcing logout for user"
    );

    // Get all active sessions for the user
    let session_ids = cleanup_stale_sessions(user_id.as_str()).await?;
    let session_count = session_ids.len();

    // Delete each session
    for sid in session_ids {
        let session_id = SessionId::new(sid.clone())
            .map_err(|e| CoordinationError::Validation(format!("Invalid session ID: {e}")))?;
        if let Err(e) = delete_session_from_store_by_session_id(session_id).await {
            tracing::warn!(session_id = %sid, error = %e, "Failed to delete session");
            // Continue with other sessions even if one fails
        }
    }

    tracing::info!(
        admin_id = %admin_user.id,
        target_user_id = %user_id.as_str(),
        sessions_terminated = session_count,
        "User sessions terminated successfully"
    );

    Ok(session_count)
}

/// Validates that a session belongs to an admin user.
///
/// This is a helper function used by admin and login_history modules.
/// It validates session data using get_user_from_session which already
/// performs fresh database lookup to ensure current user state.
pub(super) async fn validate_admin_session(
    session_id: SessionId,
) -> Result<SessionUser, CoordinationError> {
    // Get user from session (this already does fresh database validation)
    let session_cookie = crate::SessionCookie::new(session_id.as_str().to_string())
        .map_err(|_| CoordinationError::Unauthorized.log())?;
    let session_user = get_user_from_session(&session_cookie)
        .await
        .map_err(|_| CoordinationError::Unauthorized.log())?;

    // Check if user has admin privileges (session_user already has fresh database data)
    if !session_user.has_admin_privileges() {
        tracing::debug!(user_id = %session_user.id, "User is not authorized (not an admin)");
        return Err(CoordinationError::Unauthorized.log());
    }

    tracing::debug!(user_id = %session_user.id, "Admin session validated successfully");

    Ok(session_user)
}

#[cfg(test)]
mod tests;
