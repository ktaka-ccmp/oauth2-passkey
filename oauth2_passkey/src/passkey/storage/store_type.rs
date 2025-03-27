use crate::passkey::PasskeyCredential;
use crate::storage::GENERIC_DATA_STORE;

use crate::passkey::errors::PasskeyError;
use crate::passkey::types::CredentialSearchField;

use super::postgres::*;
use super::sqlite::*;

pub struct PasskeyStore;

impl PasskeyStore {
    pub async fn init() -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        // Create table based on database type
        if let Some(pool) = store.as_sqlite() {
            create_tables_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            create_tables_postgres(pool).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub async fn store_credential(
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

    pub async fn get_credential(
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

    pub async fn get_credentials_by(
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

    pub async fn update_credential_counter(
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

    pub async fn delete_credential_by(field: CredentialSearchField) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            delete_credential_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            delete_credential_by_field_postgres(pool, &field).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    /// Validates the database schema for the passkey tables
    pub async fn validate_schema() -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            validate_passkey_tables_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            validate_passkey_tables_postgres(pool).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }
}
