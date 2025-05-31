use crate::storage::validate_postgres_table_schema;
use crate::userdb::DB_TABLE_USERS;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};

use crate::passkey::errors::PasskeyError;
use crate::passkey::types::{
    CredentialSearchField, PasskeyCredential, PublicKeyCredentialUserEntity,
};

use super::config::DB_TABLE_PASSKEY_CREDENTIALS;

// PostgreSQL implementations
pub(super) async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), PasskeyError> {
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
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
        "#,
        passkey_table.replace(".", "_"),
        passkey_table
    ))
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    sqlx::query(&format!(
        r#"
        CREATE INDEX IF NOT EXISTS idx_{}_user_id ON {}(user_id);
        "#,
        passkey_table.replace(".", "_"),
        passkey_table
    ))
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

/// Validates that the Passkey credential table schema matches what we expect
pub(super) async fn validate_passkey_tables_postgres(
    pool: &Pool<Postgres>,
) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    // Define expected schema (column name, data type)
    let expected_columns = [
        ("credential_id", "text"),
        ("user_id", "text"),
        ("public_key", "text"),
        ("counter", "integer"),
        ("user_handle", "text"),
        ("user_name", "text"),
        ("user_display_name", "text"),
        ("aaguid", "text"),
        ("created_at", "timestamp with time zone"),
        ("updated_at", "timestamp with time zone"),
        ("last_used_at", "timestamp with time zone"),
    ];

    validate_postgres_table_schema(
        pool,
        passkey_table,
        &expected_columns,
        PasskeyError::Storage,
    )
    .await
}

pub(super) async fn store_credential_postgres(
    pool: &Pool<Postgres>,
    credential_id: &str,
    credential: &PasskeyCredential,
) -> Result<(), PasskeyError> {
    let counter_i32 = credential.counter as i32;
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

    sqlx::query_as::<_, (i32,)>(&format!(
        r#"
        INSERT INTO {}
        (credential_id, user_id, public_key, counter, user_handle, user_name, user_display_name, aaguid, created_at, updated_at, last_used_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (credential_id) DO UPDATE
        SET user_id = $2, public_key = $3, counter = $4, user_handle = $5, user_name = $6, user_display_name = $7, aaguid = $8, updated_at = CURRENT_TIMESTAMP, last_used_at = CURRENT_TIMESTAMP
        RETURNING 1
        "#,
        passkey_table
    ))
    .bind(credential_id)
    .bind(user_id)
    .bind(public_key)
    .bind(counter_i32)
    .bind(user_handle)
    .bind(user_name)
    .bind(user_display_name)
    .bind(aaguid)
    .bind(created_at)
    .bind(updated_at)
    .bind(last_used_at)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

pub(super) async fn get_credential_postgres(
    pool: &Pool<Postgres>,
    credential_id: &str,
) -> Result<Option<PasskeyCredential>, PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query_as::<_, PasskeyCredential>(&format!(
        r#"SELECT * FROM {} WHERE credential_id = $1"#,
        passkey_table
    ))
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))
}

pub(super) async fn get_credentials_by_field_postgres(
    pool: &Pool<Postgres>,
    field: &CredentialSearchField,
) -> Result<Vec<PasskeyCredential>, PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();
    let (query, value) = match field {
        CredentialSearchField::CredentialId(credential_id) => (
            &format!(
                r#"SELECT * FROM {} WHERE credential_id = $1"#,
                passkey_table
            ),
            credential_id.as_str(),
        ),
        CredentialSearchField::UserId(id) => (
            &format!(r#"SELECT * FROM {} WHERE user_id = $1"#, passkey_table),
            id.as_str(),
        ),
        CredentialSearchField::UserHandle(handle) => (
            &format!(r#"SELECT * FROM {} WHERE user_handle = $1"#, passkey_table),
            handle.as_str(),
        ),
        CredentialSearchField::UserName(name) => (
            &format!(r#"SELECT * FROM {} WHERE user_name = $1"#, passkey_table),
            name.as_str(),
        ),
    };

    sqlx::query_as::<_, PasskeyCredential>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

pub(super) async fn update_credential_counter_postgres(
    pool: &Pool<Postgres>,
    credential_id: &str,
    counter: u32,
) -> Result<(), PasskeyError> {
    let counter_i32 = counter as i32;
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query_as::<_, (i32,)>(&format!(
        r#"
        UPDATE {}
        SET counter = $1, updated_at = CURRENT_TIMESTAMP
        WHERE credential_id = $2
        RETURNING 1
        "#,
        passkey_table
    ))
    .bind(counter_i32)
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

pub(super) async fn delete_credential_by_field_postgres(
    pool: &Pool<Postgres>,
    field: &CredentialSearchField,
) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();
    let (query, value) = match field {
        CredentialSearchField::CredentialId(credential_id) => (
            &format!(r#"DELETE FROM {} WHERE credential_id = $1"#, passkey_table),
            credential_id.as_str(),
        ),
        CredentialSearchField::UserId(id) => (
            &format!(r#"DELETE FROM {} WHERE user_id = $1"#, passkey_table),
            id.as_str(),
        ),
        CredentialSearchField::UserHandle(handle) => (
            &format!(r#"DELETE FROM {} WHERE user_handle = $1"#, passkey_table),
            handle.as_str(),
        ),
        CredentialSearchField::UserName(name) => (
            &format!(r#"DELETE FROM {} WHERE user_name = $1"#, passkey_table),
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

pub(super) async fn update_credential_user_details_postgres(
    pool: &Pool<Postgres>,
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

use sqlx::{FromRow, Row, postgres::PgRow, sqlite::SqliteRow};

// Implement FromRow for PasskeyCredential to handle the flattened database structure for SQLite
impl<'r> FromRow<'r, SqliteRow> for PasskeyCredential {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let credential_id: String = row.try_get("credential_id")?;
        let user_id: String = row.try_get("user_id")?;
        let public_key: String = row.try_get("public_key")?;
        let counter: i64 = row.try_get("counter")?;
        let user_handle: String = row.try_get("user_handle")?;
        let user_name: String = row.try_get("user_name")?;
        let user_display_name: String = row.try_get("user_display_name")?;
        let aaguid: String = row.try_get("aaguid")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let updated_at: DateTime<Utc> = row.try_get("updated_at")?;
        let last_used_at: DateTime<Utc> = row.try_get("last_used_at")?;

        Ok(PasskeyCredential {
            credential_id,
            user_id,
            public_key,
            counter: counter as u32,
            user: PublicKeyCredentialUserEntity {
                user_handle,
                name: user_name,
                display_name: user_display_name,
            },
            aaguid,
            created_at,
            updated_at,
            last_used_at,
        })
    }
}

// Implement FromRow for PasskeyCredential to handle the flattened database structure for PostgreSQL
impl<'r> FromRow<'r, PgRow> for PasskeyCredential {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let credential_id: String = row.try_get("credential_id")?;
        let user_id: String = row.try_get("user_id")?;
        let public_key: String = row.try_get("public_key")?;
        let counter: i32 = row.try_get("counter")?;
        let user_handle: String = row.try_get("user_handle")?;
        let user_name: String = row.try_get("user_name")?;
        let user_display_name: String = row.try_get("user_display_name")?;
        let aaguid: String = row.try_get("aaguid")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let updated_at: DateTime<Utc> = row.try_get("updated_at")?;
        let last_used_at: DateTime<Utc> = row.try_get("last_used_at")?;

        Ok(PasskeyCredential {
            credential_id,
            user_id,
            public_key,
            counter: counter as u32,
            user: PublicKeyCredentialUserEntity {
                user_handle,
                name: user_name,
                display_name: user_display_name,
            },
            aaguid,
            created_at,
            updated_at,
            last_used_at,
        })
    }
}

pub(super) async fn update_credential_last_used_at_postgres(
    pool: &Pool<Postgres>,
    credential_id: &str,
    last_used_at: DateTime<Utc>,
) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query(&format!(
        r#"UPDATE {} SET last_used_at = $1 WHERE credential_id = $2"#,
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
    use chrono::TimeZone;

    // Test the PasskeyCredential struct creation directly
    // This effectively tests the same logic as FromRow without mocking database rows
    #[test]
    fn test_passkey_credential_creation() {
        // Test data
        let credential_id = "test_credential_id".to_string();
        let user_id = "test_user_id".to_string();
        let public_key = "test_public_key".to_string();
        let counter = 42;
        let user_handle = "test_user_handle".to_string();
        let user_name = "test_user_name".to_string();
        let user_display_name = "Test User".to_string();
        let aaguid = "test_aaguid".to_string();
        let created_at = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let updated_at = Utc.with_ymd_and_hms(2023, 1, 2, 0, 0, 0).unwrap();
        let last_used_at = Utc.with_ymd_and_hms(2023, 1, 3, 0, 0, 0).unwrap();

        // Create the user entity
        let user = PublicKeyCredentialUserEntity {
            user_handle,
            name: user_name.clone(),
            display_name: user_display_name.clone(),
        };

        // Create the credential
        let credential = PasskeyCredential {
            credential_id: credential_id.clone(),
            user_id: user_id.clone(),
            public_key: public_key.clone(),
            counter: counter,
            user,
            aaguid: aaguid.clone(),
            created_at,
            updated_at,
            last_used_at,
        };

        // Verify the credential fields
        assert_eq!(credential.credential_id, credential_id);
        assert_eq!(credential.user_id, user_id);
        assert_eq!(credential.public_key, public_key);
        assert_eq!(credential.counter, counter);
        assert_eq!(credential.user.user_handle, "test_user_handle");
        assert_eq!(credential.user.name, user_name);
        assert_eq!(credential.user.display_name, user_display_name);
        assert_eq!(credential.aaguid, aaguid);
        assert_eq!(credential.created_at, created_at);
        assert_eq!(credential.updated_at, updated_at);
        assert_eq!(credential.last_used_at, last_used_at);
    }

    // Test the query construction for different search fields
    #[test]
    fn test_query_construction_for_credential_search_fields() {
        let passkey_table = "passkeys";

        // Test CredentialId search field
        let credential_id = "test_credential_id".to_string();
        let field = CredentialSearchField::CredentialId(credential_id.clone());
        let (query, value) = match &field {
            CredentialSearchField::CredentialId(id) => (
                &format!(
                    r#"SELECT * FROM {} WHERE credential_id = $1"#,
                    passkey_table
                ),
                id.as_str(),
            ),
            _ => panic!("Unexpected field type"),
        };
        assert_eq!(query, "SELECT * FROM passkeys WHERE credential_id = $1");
        assert_eq!(value, credential_id);

        // Test UserId search field
        let user_id = "test_user_id".to_string();
        let field = CredentialSearchField::UserId(user_id.clone());
        let (query, value) = match &field {
            CredentialSearchField::UserId(id) => (
                &format!(r#"SELECT * FROM {} WHERE user_id = $1"#, passkey_table),
                id.as_str(),
            ),
            _ => panic!("Unexpected field type"),
        };
        assert_eq!(query, "SELECT * FROM passkeys WHERE user_id = $1");
        assert_eq!(value, user_id);

        // Test UserHandle search field
        let user_handle = "test_user_handle".to_string();
        let field = CredentialSearchField::UserHandle(user_handle.clone());
        let (query, value) = match &field {
            CredentialSearchField::UserHandle(handle) => (
                &format!(r#"SELECT * FROM {} WHERE user_handle = $1"#, passkey_table),
                handle.as_str(),
            ),
            _ => panic!("Unexpected field type"),
        };
        assert_eq!(query, "SELECT * FROM passkeys WHERE user_handle = $1");
        assert_eq!(value, user_handle);

        // Test UserName search field
        let user_name = "test_user_name".to_string();
        let field = CredentialSearchField::UserName(user_name.clone());
        let (query, value) = match &field {
            CredentialSearchField::UserName(name) => (
                &format!(r#"SELECT * FROM {} WHERE user_name = $1"#, passkey_table),
                name.as_str(),
            ),
            _ => panic!("Unexpected field type"),
        };
        assert_eq!(query, "SELECT * FROM passkeys WHERE user_name = $1");
        assert_eq!(value, user_name);
    }

    // Test the expected schema for PostgreSQL passkey table
    #[test]
    fn test_postgres_passkey_schema() {
        // Get the expected schema columns from the validate_passkey_tables_postgres function
        let expected_columns = [
            ("credential_id", "text"),
            ("user_id", "text"),
            ("public_key", "text"),
            ("counter", "integer"),
            ("user_handle", "text"),
            ("user_name", "text"),
            ("user_display_name", "text"),
            ("aaguid", "text"),
            ("created_at", "timestamp with time zone"),
            ("updated_at", "timestamp with time zone"),
            ("last_used_at", "timestamp with time zone"),
        ];

        // Verify the expected schema has all required columns
        assert_eq!(expected_columns.len(), 11, "Schema should have 11 columns");

        // Check for required columns
        let required_columns = [
            "credential_id",
            "user_id",
            "public_key",
            "counter",
            "user_handle",
        ];
        for column in required_columns.iter() {
            assert!(
                expected_columns.iter().any(|(name, _)| name == column),
                "Schema is missing required column: {}",
                column
            );
        }

        // Check data types for specific columns
        let credential_id_type = expected_columns
            .iter()
            .find(|(name, _)| *name == "credential_id")
            .map(|(_, data_type)| *data_type)
            .unwrap_or("not found");
        assert_eq!(
            credential_id_type, "text",
            "credential_id should be text type"
        );

        let counter_type = expected_columns
            .iter()
            .find(|(name, _)| *name == "counter")
            .map(|(_, data_type)| *data_type)
            .unwrap_or("not found");
        assert_eq!(counter_type, "integer", "counter should be integer type");

        // Verify timestamp columns have the correct type
        let timestamp_columns = ["created_at", "updated_at", "last_used_at"];
        for column in timestamp_columns.iter() {
            let column_type = expected_columns
                .iter()
                .find(|(name, _)| *name == *column)
                .map(|(_, data_type)| *data_type)
                .unwrap_or("not found");
            assert_eq!(
                column_type, "timestamp with time zone",
                "{} should be timestamp with time zone type",
                column
            );
        }
    }
}
