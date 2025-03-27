use crate::oauth2::{AccountSearchField, OAuth2Store};
use crate::passkey::{CredentialSearchField, PasskeyStore};
use crate::userdb::{User, UserStore};
use crate::utils::gen_random_string;

use super::errors::CoordinationError;

/// Update a user's account and label
pub async fn update_user_account(
    user_id: &str,
    account: Option<String>,
    label: Option<String>,
) -> Result<User, CoordinationError> {
    // Get the current user
    let user = UserStore::get_user(user_id).await?.ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: user_id.to_string(),
        }
        .log()
    })?;

    // Update the user with the new values
    let updated_user = User {
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
/// Returns a list of deleted passkey credential IDs for client-side notification
pub async fn delete_user_account(user_id: &str) -> Result<Vec<String>, CoordinationError> {
    // Check if the user exists
    let user = UserStore::get_user(user_id).await?.ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: user_id.to_string(),
        }
        .log()
    })?;

    tracing::debug!("Deleting user account: {:#?}", user);

    // Get all Passkey credentials for this user before deleting them
    let credentials =
        PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id.to_string()))
            .await?;
    let credential_ids: Vec<String> = credentials
        .iter()
        .map(|c| c.credential_id.clone())
        .collect();

    // Delete all OAuth2 accounts for this user
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::UserId(user_id.to_string())).await?;

    // Delete all Passkey credentials for this user
    PasskeyStore::delete_credential_by(CredentialSearchField::UserId(user_id.to_string())).await?;

    // Finally, delete the user account
    UserStore::delete_user(user_id).await?;

    Ok(credential_ids)
}

// generate a unique user ID, with built-in collision detection
pub(super) async fn gen_new_user_id() -> Result<String, CoordinationError> {
    // Try up to 3 times to generate a unique ID
    for _ in 0..3 {
        // let id = Uuid::new_v4().to_string();
        let id = gen_random_string(32)?;

        // Check if a user with this ID already exists
        match UserStore::get_user(&id).await {
            Ok(None) => return Ok(id), // ID is unique, return it
            Ok(Some(_)) => continue,   // ID exists, try again
            Err(e) => {
                return Err(
                    CoordinationError::Database(format!("Failed to check user ID: {}", e)).log(),
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
