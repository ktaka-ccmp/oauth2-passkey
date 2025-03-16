use liboauth2::{AccountSearchField, OAuth2Store};
use libpasskey::{CredentialSearchField, PasskeyStore};
use libuserdb::{User, UserStore};
use thiserror::Error;

/// Errors that can occur during user account operations
#[derive(Error, Debug)]
pub enum UserFlowError {
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),
    #[error("OAuth2 account not found: {0}")]
    OAuth2AccountNotFound(String),
}

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
