use chrono::{DateTime, Utc};

use crate::passkey::PasskeyCredential;
use crate::storage::GENERIC_DATA_STORE;

use crate::passkey::errors::PasskeyError;
use crate::passkey::types::{CredentialId, CredentialSearchField};

use super::mysql::*;
use super::postgres::*;
use super::sqlite::*;

pub struct PasskeyStore;

impl PasskeyStore {
    pub(crate) async fn init() -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres(), store.as_mysql()) {
            (Some(pool), _, _) => {
                create_tables_sqlite(pool).await?;
                validate_passkey_tables_sqlite(pool).await?;
                Ok(())
            }
            (_, Some(pool), _) => {
                create_tables_postgres(pool).await?;
                validate_passkey_tables_postgres(pool).await?;
                Ok(())
            }
            (_, _, Some(pool)) => {
                create_tables_mysql(pool).await?;
                validate_passkey_tables_mysql(pool).await?;
                Ok(())
            }
            _ => Err(PasskeyError::Storage(
                "Unsupported database type".to_string(),
            )),
        }
    }

    pub(crate) async fn store_credential(
        credential_id: CredentialId,
        credential: PasskeyCredential,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            store_credential_sqlite(pool, credential_id, &credential).await
        } else if let Some(pool) = store.as_postgres() {
            store_credential_postgres(pool, credential_id, &credential).await
        } else if let Some(pool) = store.as_mysql() {
            store_credential_mysql(pool, credential_id, &credential).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn get_credential(
        credential_id: CredentialId,
    ) -> Result<Option<PasskeyCredential>, PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_credential_sqlite(pool, credential_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_credential_postgres(pool, credential_id).await
        } else if let Some(pool) = store.as_mysql() {
            get_credential_mysql(pool, credential_id).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn get_credentials_by(
        field: CredentialSearchField,
    ) -> Result<Vec<PasskeyCredential>, PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_credentials_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            get_credentials_by_field_postgres(pool, &field).await
        } else if let Some(pool) = store.as_mysql() {
            get_credentials_by_field_mysql(pool, &field).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    /// Atomically update credential counter only if the new value is greater.
    ///
    /// Uses `UPDATE ... WHERE counter < ?` to perform the check and update in a
    /// single SQL statement, avoiding TOCTOU races from separate GET/CHECK/UPDATE.
    ///
    /// Returns `true` if the update was applied, `false` if the stored counter
    /// was not less than the new value.
    pub(crate) async fn atomic_update_credential_counter(
        credential_id: CredentialId,
        new_counter: u32,
    ) -> Result<bool, PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            atomic_update_credential_counter_sqlite(pool, credential_id, new_counter).await
        } else if let Some(pool) = store.as_postgres() {
            atomic_update_credential_counter_postgres(pool, credential_id, new_counter).await
        } else if let Some(pool) = store.as_mysql() {
            atomic_update_credential_counter_mysql(pool, credential_id, new_counter).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn delete_credential_by(
        field: CredentialSearchField,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            delete_credential_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            delete_credential_by_field_postgres(pool, &field).await
        } else if let Some(pool) = store.as_mysql() {
            delete_credential_by_field_mysql(pool, &field).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn update_credential(
        credential_id: CredentialId,
        name: &str,
        display_name: &str,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            update_credential_user_details_sqlite(pool, credential_id, name, display_name).await
        } else if let Some(pool) = store.as_postgres() {
            update_credential_user_details_postgres(pool, credential_id, name, display_name).await
        } else if let Some(pool) = store.as_mysql() {
            update_credential_user_details_mysql(pool, credential_id, name, display_name).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn update_credential_last_used_at(
        credential_id: CredentialId,
        last_used_at: DateTime<Utc>,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            update_credential_last_used_at_sqlite(pool, credential_id, last_used_at).await
        } else if let Some(pool) = store.as_postgres() {
            update_credential_last_used_at_postgres(pool, credential_id, last_used_at).await
        } else if let Some(pool) = store.as_mysql() {
            update_credential_last_used_at_mysql(pool, credential_id, last_used_at).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }
}

#[cfg(test)]
mod tests;
