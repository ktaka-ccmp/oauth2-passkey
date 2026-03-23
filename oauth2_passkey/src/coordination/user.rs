#[cfg(test)]
use crate::passkey::CredentialId;
use crate::passkey::{CredentialSearchField, PasskeyStore};
use crate::userdb::{User as DbUser, UserStore};

use super::errors::CoordinationError;
use crate::session::{SessionId, UserId, get_user_from_session};

/// Update a user's account and label
///
/// This function allows users to update their own account information.
/// Only the account owner can perform this operation.
///
/// # Arguments
///
/// * `session_id` - The session ID of the user performing the action
/// * `user_id` - The ID of the user whose account will be updated
/// * `account` - The new account name (optional)
/// * `label` - The new label (optional)
///
/// # Returns
///
/// * `Ok(DbUser)` - The updated user account information
/// * `Err(CoordinationError::Unauthorized)` - If the user is not the account owner
/// * `Err(CoordinationError::ResourceNotFound)` - If the target user doesn't exist
/// * `Err(CoordinationError)` - If another error occurs during the update
pub async fn update_user_account(
    session_id: SessionId,
    user_id: UserId,
    account: Option<String>,
    label: Option<String>,
) -> Result<DbUser, CoordinationError> {
    // Get user from session (already does fresh database lookup)
    let session_cookie = crate::SessionCookie::new(session_id.as_str().to_string())
        .map_err(|_| CoordinationError::Unauthorized.log())?;
    let session_user = get_user_from_session(&session_cookie)
        .await
        .map_err(|_| CoordinationError::Unauthorized.log())?;

    // Validate owner session - user can only update their own account
    if session_user.id != user_id.as_str() {
        tracing::debug!(
            session_user_id = %session_user.id,
            target_user_id = %user_id.as_str(),
            "User is not authorized (not resource owner)"
        );
        return Err(CoordinationError::Unauthorized.log());
    }

    // Convert SessionUser to DbUser for database operations
    let user = DbUser::from(session_user);

    // Update the user with the new values
    let updated_user = DbUser {
        account: account.unwrap_or(user.account),
        label: label.unwrap_or(user.label),
        ..user
    };

    // Save the updated user
    let user = UserStore::upsert_user(updated_user).await?;

    Ok(user)
}

/// Delete a user account and all associated OAuth2 accounts and Passkey credentials
///
/// This function allows either an administrator (who can delete any user) or the user
/// themselves (who can delete their own account) to perform the deletion.
///
/// # Arguments
///
/// * `session_id` - The session ID of the user performing the action
/// * `user_id` - The ID of the user account to delete
///
/// # Returns
///
/// * `Ok(Vec<String>)` - A list of deleted passkey credential IDs for client-side notification
/// * `Err(CoordinationError::Unauthorized)` - If the user is neither admin nor account owner
/// * `Err(CoordinationError::ResourceNotFound)` - If the target user doesn't exist
/// * `Err(CoordinationError::Conflict)` - If trying to delete the last admin user
/// * `Err(CoordinationError)` - If another error occurs during deletion
///
/// Returns a list of deleted passkey credential IDs for client-side notification
pub async fn delete_user_account(
    session_id: SessionId,
    user_id: UserId,
) -> Result<Vec<String>, CoordinationError> {
    // Get user from session (already does fresh database lookup)
    let session_cookie = crate::SessionCookie::new(session_id.as_str().to_string())
        .map_err(|_| CoordinationError::Unauthorized.log())?;
    let session_user = get_user_from_session(&session_cookie)
        .await
        .map_err(|_| CoordinationError::Unauthorized.log())?;

    // Validate admin or owner session - admin can delete any user, user can delete their own account
    if !session_user.has_admin_privileges() && session_user.id != user_id.as_str() {
        tracing::debug!(
            session_user_id = %session_user.id,
            target_user_id = %user_id.as_str(),
            has_admin_privileges = %session_user.has_admin_privileges(),
            "User is not authorized (neither admin nor resource owner)"
        );
        return Err(CoordinationError::Unauthorized.log());
    }

    // For owner deletion, use session user data (no second DB query needed)
    // For admin deletion of other user, we need to fetch the target user
    let user = if session_user.id == user_id.as_str() {
        // Self-deletion: convert SessionUser to DbUser
        DbUser::from(session_user)
    } else {
        // Admin deleting another user: fetch target user
        UserStore::get_user(user_id.clone()).await?.ok_or_else(|| {
            CoordinationError::ResourceNotFound {
                resource_type: "User".to_string(),
                resource_id: user_id.as_str().to_string(),
            }
            .log()
        })?
    };

    // Prevent deleting the last admin user (applies to both self-deletion and admin deletion)
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

    // Get all Passkey credential IDs before deletion (for client-side Signal API notification)
    let credentials =
        PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id.clone())).await?;
    let credential_ids: Vec<String> = credentials
        .iter()
        .map(|c| c.credential_id.clone())
        .collect();

    // Delete the user account. Related OAuth2 accounts and Passkey credentials
    // are automatically removed via ON DELETE CASCADE foreign key constraints.
    UserStore::delete_user(user_id).await?;

    // Returns a list of deleted passkey credential IDs for client-side notification
    Ok(credential_ids)
}

// generate a unique user ID, with built-in collision detection
pub(super) async fn gen_new_user_id() -> Result<String, CoordinationError> {
    // Try up to 3 times to generate a unique ID
    for _ in 0..3 {
        let id = uuid::Uuid::new_v4().to_string();
        // let id = crate::utils::gen_random_string(32)?;

        // Check if a user with this ID already exists
        let user_id = UserId::new(id.clone()).map_err(|e| {
            CoordinationError::Internal(format!("Failed to create user ID from UUID: {e}"))
        })?;
        match UserStore::get_user(user_id).await {
            Ok(None) => return Ok(id), // ID is unique, return it
            Ok(Some(_)) => continue,   // ID exists, try again
            Err(e) => {
                return Err(
                    CoordinationError::Database(format!("Failed to check user ID: {e}")).log(),
                );
            }
        }
    }

    // If we get here, we failed to generate a unique ID after multiple attempts
    // This is extremely unlikely with UUID v4, but we handle it anyway
    Err(CoordinationError::Coordination(
        "Failed to generate a unique user ID after multiple attempts".to_string(),
    )
    .log())
}

#[cfg(test)]
mod tests;
