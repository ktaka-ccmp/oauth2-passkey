use crate::oauth2::{AccountSearchField, OAuth2Store};
use crate::passkey::{CredentialSearchField, PasskeyStore};
use crate::session::User as SessionUser;
use crate::userdb::{User, UserStore};

use super::errors::CoordinationError;

pub async fn get_all_users() -> Result<Vec<User>, CoordinationError> {
    UserStore::get_all_users()
        .await
        .map_err(|e| CoordinationError::Database(e.to_string()))
}

pub async fn get_user(user_id: &str) -> Result<Option<User>, CoordinationError> {
    UserStore::get_user(user_id)
        .await
        .map_err(|e| CoordinationError::Database(e.to_string()))
}

pub async fn delete_passkey_credential_admin(
    user: &SessionUser,
    credential_id: &str,
) -> Result<(), CoordinationError> {
    if !user.is_admin {
        tracing::debug!("User is not authorized to delete OAuth2 accounts");
        return Err(CoordinationError::Unauthorized.log());
    }

    tracing::debug!(
        "Admin user: {} is deleting credential with ID: {}",
        user.id,
        credential_id
    );

    let credential = PasskeyStore::get_credentials_by(CredentialSearchField::CredentialId(
        credential_id.to_owned(),
    ))
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "Passkey".to_string(),
            resource_id: credential_id.to_string(),
        }
        .log()
    })?;

    // Should we verify a context token here?

    // Delete the credential using the raw credential ID format from the database
    PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
        credential.credential_id.clone(),
    ))
    .await?;

    tracing::debug!("Successfully deleted credential");

    Ok(())
}

pub async fn delete_oauth2_account_admin(
    user: &SessionUser,
    provider_user_id: &str,
) -> Result<(), CoordinationError> {
    if !user.is_admin {
        tracing::debug!("User is not authorized to delete OAuth2 accounts");
        return Err(CoordinationError::Unauthorized.log());
    }

    tracing::debug!(
        "Admin user: {} is deleting OAuth2 account with ID: {}",
        user.id,
        provider_user_id
    );

    // Delete the OAuth2 account
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::ProviderUserId(
        provider_user_id.to_string(),
    ))
    .await?;

    tracing::info!(
        "Successfully deleted OAuth2 account {} for user {}",
        provider_user_id,
        user.id
    );
    Ok(())
}

pub async fn delete_user_account_admin(user_id: &str) -> Result<(), CoordinationError> {
    // Check if the user exists
    let user = UserStore::get_user(user_id).await?.ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: user_id.to_string(),
        }
        .log()
    })?;

    tracing::debug!("Deleting user account: {:#?}", user);

    // Delete all OAuth2 accounts for this user
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::UserId(user_id.to_string())).await?;

    // Delete all Passkey credentials for this user
    PasskeyStore::delete_credential_by(CredentialSearchField::UserId(user_id.to_string())).await?;

    // Finally, delete the user account
    UserStore::delete_user(user_id).await?;

    Ok(())
}

pub async fn update_user_admin_status(
    admin_user: &SessionUser,
    user_id: &str,
    is_admin: bool,
) -> Result<User, CoordinationError> {
    // Verify that the user has admin privileges
    if !admin_user.is_admin {
        tracing::debug!("User is not authorized to update admin status");
        return Err(CoordinationError::Unauthorized.log());
    }

    // Get the current user
    let user = UserStore::get_user(user_id).await?.ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: user_id.to_string(),
        }
        .log()
    })?;

    // Prevent changing admin status of the first user (sequence_number = 1)
    if user.sequence_number == Some(1) {
        tracing::debug!("Cannot change admin status of the first user");
        return Err(CoordinationError::Coordination(
            "Cannot change admin status of the first user for security reasons".to_string(),
        )
        .log());
    }

    // Update the user with the new admin status
    let updated_user = User { is_admin, ..user };

    // Save the updated user
    let user = UserStore::upsert_user(updated_user).await?;

    Ok(user)
}
