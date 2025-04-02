use crate::passkey::PasskeyCredential;
use crate::storage::GENERIC_DATA_STORE;

use crate::passkey::errors::PasskeyError;
use crate::passkey::types::CredentialSearchField;

use super::postgres::*;
use super::sqlite::*;

pub struct PasskeyStore;

impl PasskeyStore {
    pub(crate) async fn init() -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres()) {
            (Some(pool), _) => {
                create_tables_sqlite(pool).await?;
                validate_passkey_tables_sqlite(pool).await?;
                Ok(())
            }
            (_, Some(pool)) => {
                create_tables_postgres(pool).await?;
                validate_passkey_tables_postgres(pool).await?;
                Ok(())
            }
            _ => Err(PasskeyError::Storage(
                "Unsupported database type".to_string(),
            )),
        }
    }

    pub(crate) async fn store_credential(
        credential_id: String,
        credential: PasskeyCredential,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            store_credential_sqlite(pool, &credential_id, &credential).await
        } else if let Some(pool) = store.as_postgres() {
            store_credential_postgres(pool, &credential_id, &credential).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn get_credential(
        credential_id: &str,
    ) -> Result<Option<PasskeyCredential>, PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_credential_sqlite(pool, credential_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_credential_postgres(pool, credential_id).await
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
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn update_credential_counter(
        credential_id: &str,
        counter: u32,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            update_credential_counter_sqlite(pool, credential_id, counter).await
        } else if let Some(pool) = store.as_postgres() {
            update_credential_counter_postgres(pool, credential_id, counter).await
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
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn update_credential(
        credential_id: &str,
        name: &str,
        display_name: &str,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            update_credential_user_details_sqlite(pool, credential_id, name, display_name).await
        } else if let Some(pool) = store.as_postgres() {
            update_credential_user_details_postgres(pool, credential_id, name, display_name).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }
}
