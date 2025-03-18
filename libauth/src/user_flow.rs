use uuid::Uuid;

use liboauth2::{AccountSearchField, OAuth2Store};
use libpasskey::{CredentialSearchField, PasskeyStore};
use libuserdb::{User, UserStore};

use super::errors::{AuthError, UserFlowError};

/// Update a user's account and label
pub async fn update_user_account(
    user_id: &str,
    account: Option<String>,
    label: Option<String>,
) -> Result<User, UserFlowError> {
    // Get the current user
    let user = UserStore::get_user(user_id)
        .await
        .map_err(|e| UserFlowError::Database(e.to_string()))?
        .ok_or_else(|| UserFlowError::UserNotFound(user_id.to_string()))?;

    // Update the user with the new values
    let updated_user = User {
        account: account.unwrap_or(user.account),
        label: label.unwrap_or(user.label),
        ..user
    };

    // Save the updated user
    UserStore::upsert_user(updated_user)
        .await
        .map_err(|e| UserFlowError::Database(e.to_string()))
}

/// Delete a user account and all associated OAuth2 accounts and Passkey credentials
pub async fn delete_user_account(user_id: &str) -> Result<(), UserFlowError> {
    // Check if the user exists
    let user = UserStore::get_user(user_id)
        .await
        .map_err(|e| UserFlowError::Database(e.to_string()))?
        .ok_or_else(|| UserFlowError::UserNotFound(user_id.to_string()))?;

    tracing::debug!("Deleting user account: {:#?}", user);

    // Delete all OAuth2 accounts for this user
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::UserId(user_id.to_string()))
        .await
        .map_err(|e| UserFlowError::Database(e.to_string()))?;

    // Delete all Passkey credentials for this user
    PasskeyStore::delete_credential_by(CredentialSearchField::UserId(user_id.to_string()))
        .await
        .map_err(|e| UserFlowError::Database(e.to_string()))?;

    // Finally, delete the user account
    UserStore::delete_user(user_id)
        .await
        .map_err(|e| UserFlowError::Database(e.to_string()))?;

    Ok(())
}

// generate a unique user ID, with built-in collision detection
pub(super) async fn gen_new_user_id() -> Result<String, AuthError> {
    // Try up to 3 times to generate a unique ID
    for _ in 0..3 {
        let id = Uuid::new_v4().to_string();

        // Check if a user with this ID already exists
        match UserStore::get_user(&id).await {
            Ok(None) => return Ok(id), // ID is unique, return it
            Ok(Some(_)) => continue,   // ID exists, try again
            Err(e) => {
                return Err(AuthError::Database(format!(
                    "Failed to check user ID: {}",
                    e
                )));
            }
        }
    }

    // If we get here, we failed to generate a unique ID after multiple attempts
    // This is extremely unlikely with UUID v4, but we handle it anyway
    Err(AuthError::Coordination(
        "Failed to generate a unique user ID after multiple attempts".to_string(),
    ))
}
