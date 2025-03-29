use crate::storage::validate_sqlite_table_schema;
use crate::userdb::DB_TABLE_USERS;
use sqlx::{Pool, Sqlite};

use crate::passkey::errors::PasskeyError;
use crate::passkey::types::{CredentialSearchField, PasskeyCredential};

use super::config::DB_TABLE_PASSKEY_CREDENTIALS;

// SQLite implementations
pub(super) async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();
    let users_table = DB_TABLE_USERS.as_str();

    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            credential_id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES {}(id),
            public_key TEXT NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0,
            user_handle TEXT NOT NULL,
            user_name TEXT NOT NULL,
            user_display_name TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES {}(id)
        )
        "#,
        passkey_table, users_table, users_table
    ))
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    sqlx::query(&format!(
        r#"
        CREATE INDEX IF NOT EXISTS idx_{}_user_name ON {}(user_name);
        CREATE INDEX IF NOT EXISTS idx_{}_user_id ON {}(user_id);
        "#,
        passkey_table.replace(".", "_"),
        passkey_table,
        passkey_table.replace(".", "_"),
        passkey_table
    ))
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

/// Validates that the Passkey credential table schema matches what we expect
pub(super) async fn validate_passkey_tables_sqlite(
    pool: &Pool<Sqlite>,
) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    // Define expected schema (column name, data type)
    let expected_columns = vec![
        ("credential_id", "TEXT"),
        ("user_id", "TEXT"),
        ("public_key", "TEXT"),
        ("counter", "INTEGER"),
        ("user_handle", "TEXT"),
        ("user_name", "TEXT"),
        ("user_display_name", "TEXT"),
        ("created_at", "TIMESTAMP"),
        ("updated_at", "TIMESTAMP"),
    ];

    validate_sqlite_table_schema(
        pool,
        passkey_table,
        &expected_columns,
        PasskeyError::Storage,
    )
    .await
}

pub(super) async fn store_credential_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
    credential: &PasskeyCredential,
) -> Result<(), PasskeyError> {
    let counter_i64 = credential.counter as i64;
    let public_key = &credential.public_key;
    let user_id = &credential.user_id;
    let user_handle = &credential.user.user_handle;
    let user_name = &credential.user.name;
    let user_display_name = &credential.user.display_name;
    let created_at = &credential.created_at;
    let updated_at = &credential.updated_at;
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query(&format!(
        r#"
        INSERT OR REPLACE INTO {}
        (credential_id, user_id, public_key, counter, user_handle, user_name, user_display_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
        passkey_table
    ))
    .bind(credential_id)
    .bind(user_id)
    .bind(public_key)
    .bind(counter_i64)
    .bind(user_handle)
    .bind(user_name)
    .bind(user_display_name)
    .bind(created_at)
    .bind(updated_at)
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

pub(super) async fn get_credential_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
) -> Result<Option<PasskeyCredential>, PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query_as::<_, PasskeyCredential>(&format!(
        r#"SELECT * FROM {} WHERE credential_id = ?"#,
        passkey_table
    ))
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))
}

pub(super) async fn get_credentials_by_field_sqlite(
    pool: &Pool<Sqlite>,
    field: &CredentialSearchField,
) -> Result<Vec<PasskeyCredential>, PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();
    let (query, value) = match field {
        CredentialSearchField::CredentialId(credential_id) => (
            &format!(r#"SELECT * FROM {} WHERE credential_id = ?"#, passkey_table),
            credential_id.as_str(),
        ),
        CredentialSearchField::UserId(id) => (
            &format!(r#"SELECT * FROM {} WHERE user_id = ?"#, passkey_table),
            id.as_str(),
        ),
        CredentialSearchField::UserHandle(handle) => (
            &format!(r#"SELECT * FROM {} WHERE user_handle = ?"#, passkey_table),
            handle.as_str(),
        ),
        CredentialSearchField::UserName(name) => (
            &format!(r#"SELECT * FROM {} WHERE user_name = ?"#, passkey_table),
            name.as_str(),
        ),
    };

    sqlx::query_as::<_, PasskeyCredential>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

pub(super) async fn update_credential_counter_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
    counter: u32,
) -> Result<(), PasskeyError> {
    let counter_i64 = counter as i64;
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query(&format!(
        r#"
        UPDATE {}
        SET counter = ?, updated_at = CURRENT_TIMESTAMP
        WHERE credential_id = ?
        "#,
        passkey_table
    ))
    .bind(counter_i64)
    .bind(credential_id)
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

pub(super) async fn delete_credential_by_field_sqlite(
    pool: &Pool<Sqlite>,
    field: &CredentialSearchField,
) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();
    let (query, value) = match field {
        CredentialSearchField::CredentialId(credential_id) => (
            &format!(r#"DELETE FROM {} WHERE credential_id = ?"#, passkey_table),
            credential_id.as_str(),
        ),
        CredentialSearchField::UserId(id) => (
            &format!(r#"DELETE FROM {} WHERE user_id = ?"#, passkey_table),
            id.as_str(),
        ),
        CredentialSearchField::UserHandle(handle) => (
            &format!(r#"DELETE FROM {} WHERE user_handle = ?"#, passkey_table),
            handle.as_str(),
        ),
        CredentialSearchField::UserName(name) => (
            &format!(r#"DELETE FROM {} WHERE user_name = ?"#, passkey_table),
            name.as_str(),
        ),
    };

    sqlx::query(query)
        .bind(value)
        .execute(pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}
