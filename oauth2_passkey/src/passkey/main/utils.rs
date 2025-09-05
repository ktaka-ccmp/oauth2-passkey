use crate::passkey::PasskeyError;
use crate::passkey::PasskeyStore;
use crate::passkey::{CredentialSearchField, types::UserIdCredentialIdStr};

async fn get_credential_id_strs_by(
    field: CredentialSearchField,
) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {
    let stored_credentials = PasskeyStore::get_credentials_by(field).await?;

    let credential_id_strs = stored_credentials
        .into_iter()
        .map(|cred| UserIdCredentialIdStr {
            user_id: cred.user_id,
            credential_id: cred.credential_id,
        })
        .collect();

    Ok(credential_id_strs)
}

pub(super) async fn name2cid_str_vec(
    name: &str,
) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {
    get_credential_id_strs_by(CredentialSearchField::UserName(
        crate::passkey::UserName::new(name.to_string()).expect("Valid username"),
    ))
    .await
}

#[cfg(test)]
mod tests;
