use crate::storage::validate_sqlite_table_schema;
use crate::userdb::DB_TABLE_USERS;
use chrono::{DateTime, Utc};
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
            aaguid TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
        ("aaguid", "TEXT"),
        ("created_at", "TIMESTAMP"),
        ("updated_at", "TIMESTAMP"),
        ("last_used_at", "TIMESTAMP"),
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
    let aaguid = &credential.aaguid;
    let created_at = &credential.created_at;
    let updated_at = &credential.updated_at;
    let last_used_at = &credential.last_used_at;
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query(&format!(
        r#"
        INSERT OR REPLACE INTO {}
        (credential_id, user_id, public_key, counter, user_handle, user_name, user_display_name, aaguid, created_at, updated_at, last_used_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    .bind(aaguid)
    .bind(created_at)
    .bind(updated_at)
    .bind(last_used_at)
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

pub(super) async fn update_credential_user_details_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
    name: &str,
    display_name: &str,
) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query(&format!(
        r#"UPDATE {} SET user_name = $1, user_display_name = $2 WHERE credential_id = $3"#,
        passkey_table
    ))
    .bind(name)
    .bind(display_name)
    .bind(credential_id)
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

pub(super) async fn update_credential_last_used_at_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
    last_used_at: DateTime<Utc>,
) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query(&format!(
        r#"
        UPDATE {}
        SET last_used_at = ?, updated_at = CURRENT_TIMESTAMP
        WHERE credential_id = ?
        "#,
        passkey_table
    ))
    .bind(last_used_at)
    .bind(credential_id)
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Removed unused import: chrono::TimeZone

    // Test the query construction for different search fields in SQLite
    #[test]
    fn test_query_construction_for_credential_search_fields_sqlite() {
        let passkey_table = "passkeys";

        // Test CredentialId search field
        let credential_id = "test_credential_id".to_string();
        let field = CredentialSearchField::CredentialId(credential_id.clone());
        let (query, value) = match &field {
            CredentialSearchField::CredentialId(id) => (
                &format!(r#"SELECT * FROM {} WHERE credential_id = ?"#, passkey_table),
                id.as_str(),
            ),
            _ => panic!("Unexpected field type"),
        };
        assert_eq!(query, "SELECT * FROM passkeys WHERE credential_id = ?");
        assert_eq!(value, credential_id);

        // Test UserId search field
        let user_id = "test_user_id".to_string();
        let field = CredentialSearchField::UserId(user_id.clone());
        let (query, value) = match &field {
            CredentialSearchField::UserId(id) => (
                &format!(r#"SELECT * FROM {} WHERE user_id = ?"#, passkey_table),
                id.as_str(),
            ),
            _ => panic!("Unexpected field type"),
        };
        assert_eq!(query, "SELECT * FROM passkeys WHERE user_id = ?");
        assert_eq!(value, user_id);

        // Test UserHandle search field
        let user_handle = "test_user_handle".to_string();
        let field = CredentialSearchField::UserHandle(user_handle.clone());
        let (query, value) = match &field {
            CredentialSearchField::UserHandle(handle) => (
                &format!(r#"SELECT * FROM {} WHERE user_handle = ?"#, passkey_table),
                handle.as_str(),
            ),
            _ => panic!("Unexpected field type"),
        };
        assert_eq!(query, "SELECT * FROM passkeys WHERE user_handle = ?");
        assert_eq!(value, user_handle);

        // Test UserName search field
        let user_name = "test_user_name".to_string();
        let field = CredentialSearchField::UserName(user_name.clone());
        let (query, value) = match &field {
            CredentialSearchField::UserName(name) => (
                &format!(r#"SELECT * FROM {} WHERE user_name = ?"#, passkey_table),
                name.as_str(),
            ),
            _ => panic!("Unexpected field type"),
        };
        assert_eq!(query, "SELECT * FROM passkeys WHERE user_name = ?");
        assert_eq!(value, user_name);
    }

    // Test SQLite counter conversion (i64 to u32)
    #[test]
    fn test_sqlite_counter_conversion() {
        // Test valid counter conversion
        let counter_i64: i64 = 42;
        let counter_u32 = counter_i64 as u32;
        assert_eq!(counter_u32, 42);

        // Test maximum counter value
        let max_counter_i64: i64 = u32::MAX as i64;
        let max_counter_u32 = max_counter_i64 as u32;
        assert_eq!(max_counter_u32, u32::MAX);

        // Test counter overflow (this would be a potential issue in real code)
        // In SQLite, counters should never exceed u32::MAX, but we test the conversion behavior
        let overflow_counter_i64: i64 = (u32::MAX as i64) + 1;
        let overflow_counter_u32 = overflow_counter_i64 as u32;
        assert_eq!(overflow_counter_u32, 0); // Wraps around to 0
    }
}
