use crate::storage::validate_mysql_table_schema;
use crate::userdb::DB_TABLE_USERS;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, MySql, Pool, Row, mysql::MySqlRow};

use crate::passkey::errors::PasskeyError;
use crate::passkey::types::{
    CredentialId, CredentialSearchField, PasskeyCredential, PublicKeyCredentialUserEntity,
};

use super::config::DB_TABLE_PASSKEY_CREDENTIALS;

// MySQL implementations
pub(super) async fn create_tables_mysql(pool: &Pool<MySql>) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();
    let users_table = DB_TABLE_USERS.as_str();

    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {passkey_table} (
            sequence_number BIGINT PRIMARY KEY AUTO_INCREMENT,
            credential_id VARCHAR(768) NOT NULL UNIQUE,
            user_id VARCHAR(255) NOT NULL,
            public_key TEXT NOT NULL,
            counter INT NOT NULL DEFAULT 0,
            user_handle VARCHAR(255) NOT NULL,
            user_name VARCHAR(255) NOT NULL,
            user_display_name VARCHAR(255) NOT NULL,
            aaguid VARCHAR(255) NOT NULL,
            rp_id VARCHAR(255) NOT NULL DEFAULT '',
            created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            last_used_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            FOREIGN KEY (user_id) REFERENCES {users_table}(id)
        )
        "#
    ))
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    // Create indexes (ignore errors if they already exist)
    let idx_user_name = format!("idx_{}_user_name", passkey_table.replace('.', "_"));
    let idx_user_id = format!("idx_{}_user_id", passkey_table.replace('.', "_"));

    let _ = sqlx::query(&format!(
        r#"CREATE INDEX {idx_user_name} ON {passkey_table}(user_name)"#,
    ))
    .execute(pool)
    .await;

    let _ = sqlx::query(&format!(
        r#"CREATE INDEX {idx_user_id} ON {passkey_table}(user_id)"#,
    ))
    .execute(pool)
    .await;

    Ok(())
}

/// Migrates the passkey credentials table to add the rp_id column if it doesn't exist.
/// This is needed for existing databases that were created before rp_id was added.
pub(super) async fn migrate_passkey_tables_mysql(pool: &Pool<MySql>) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    // Check if rp_id column exists using INFORMATION_SCHEMA
    let has_rp_id: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = 'rp_id'",
    )
    .bind(passkey_table)
    .fetch_one(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    if !has_rp_id {
        sqlx::query(&format!(
            "ALTER TABLE {passkey_table} ADD COLUMN rp_id VARCHAR(255) NOT NULL DEFAULT ''"
        ))
        .execute(pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;
    }

    Ok(())
}

/// Validates that the Passkey credential table schema matches what we expect
pub(super) async fn validate_passkey_tables_mysql(pool: &Pool<MySql>) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    // Define expected schema (column name, data type)
    let expected_columns = vec![
        ("sequence_number", "bigint"),
        ("credential_id", "varchar"),
        ("user_id", "varchar"),
        ("public_key", "text"),
        ("counter", "int"),
        ("user_handle", "varchar"),
        ("user_name", "varchar"),
        ("user_display_name", "varchar"),
        ("aaguid", "varchar"),
        ("rp_id", "varchar"),
        ("created_at", "datetime"),
        ("updated_at", "datetime"),
        ("last_used_at", "datetime"),
    ];

    validate_mysql_table_schema(
        pool,
        passkey_table,
        &expected_columns,
        PasskeyError::Storage,
    )
    .await
}

pub(super) async fn store_credential_mysql(
    pool: &Pool<MySql>,
    credential_id: CredentialId,
    credential: &PasskeyCredential,
) -> Result<(), PasskeyError> {
    let counter_i32 = credential.counter as i32;
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    // Use SELECT+UPDATE/INSERT transaction pattern for MySQL/MariaDB compatibility.
    // The "AS new" syntax (MySQL 8.0.19+) is not supported by MariaDB,
    // and VALUES() is deprecated in MySQL 8.0.20+.
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    let existing = sqlx::query_as::<_, PasskeyCredential>(&format!(
        r#"SELECT * FROM {passkey_table} WHERE credential_id = ? FOR UPDATE"#
    ))
    .bind(credential_id.as_str())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    if existing.is_some() {
        sqlx::query(&format!(
            r#"
            UPDATE {passkey_table} SET
                user_id = ?, public_key = ?, counter = ?,
                user_handle = ?, user_name = ?, user_display_name = ?,
                aaguid = ?, rp_id = ?,
                updated_at = CURRENT_TIMESTAMP(6), last_used_at = CURRENT_TIMESTAMP(6)
            WHERE credential_id = ?
            "#
        ))
        .bind(&credential.user_id)
        .bind(&credential.public_key)
        .bind(counter_i32)
        .bind(&credential.user.user_handle)
        .bind(&credential.user.name)
        .bind(&credential.user.display_name)
        .bind(&credential.aaguid)
        .bind(&credential.rp_id)
        .bind(credential_id.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;
    } else {
        sqlx::query(&format!(
            r#"
            INSERT INTO {passkey_table}
            (credential_id, user_id, public_key, counter, user_handle, user_name, user_display_name, aaguid, rp_id, created_at, updated_at, last_used_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        ))
        .bind(credential_id.as_str())
        .bind(&credential.user_id)
        .bind(&credential.public_key)
        .bind(counter_i32)
        .bind(&credential.user.user_handle)
        .bind(&credential.user.name)
        .bind(&credential.user.display_name)
        .bind(&credential.aaguid)
        .bind(&credential.rp_id)
        .bind(credential.created_at)
        .bind(credential.updated_at)
        .bind(credential.last_used_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;
    }

    tx.commit()
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

pub(super) async fn get_credential_mysql(
    pool: &Pool<MySql>,
    credential_id: CredentialId,
) -> Result<Option<PasskeyCredential>, PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query_as::<_, PasskeyCredential>(&format!(
        r#"SELECT * FROM {passkey_table} WHERE credential_id = ?"#
    ))
    .bind(credential_id.as_str())
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))
}

pub(super) async fn get_credentials_by_field_mysql(
    pool: &Pool<MySql>,
    field: &CredentialSearchField,
) -> Result<Vec<PasskeyCredential>, PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();
    let (query, value) = match field {
        CredentialSearchField::CredentialId(credential_id) => (
            &format!(r#"SELECT * FROM {passkey_table} WHERE credential_id = ?"#),
            credential_id.as_str(),
        ),
        CredentialSearchField::UserId(id) => (
            &format!(r#"SELECT * FROM {passkey_table} WHERE user_id = ?"#),
            id.as_str(),
        ),
        CredentialSearchField::UserHandle(handle) => (
            &format!(r#"SELECT * FROM {passkey_table} WHERE user_handle = ?"#),
            handle.as_str(),
        ),
        CredentialSearchField::UserName(name) => (
            &format!(r#"SELECT * FROM {passkey_table} WHERE user_name = ?"#),
            name.as_str(),
        ),
    };

    sqlx::query_as::<_, PasskeyCredential>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

pub(super) async fn atomic_update_credential_counter_mysql(
    pool: &Pool<MySql>,
    credential_id: CredentialId,
    new_counter: u32,
) -> Result<bool, PasskeyError> {
    let counter_i64 = new_counter as i64;
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    let result = sqlx::query(&format!(
        r#"
        UPDATE {passkey_table}
        SET counter = ?, updated_at = CURRENT_TIMESTAMP(6)
        WHERE credential_id = ? AND counter < ?
        "#
    ))
    .bind(counter_i64)
    .bind(credential_id.as_str())
    .bind(counter_i64)
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(result.rows_affected() > 0)
}

pub(super) async fn delete_credential_by_field_mysql(
    pool: &Pool<MySql>,
    field: &CredentialSearchField,
) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();
    let (query, value) = match field {
        CredentialSearchField::CredentialId(credential_id) => (
            &format!(r#"DELETE FROM {passkey_table} WHERE credential_id = ?"#),
            credential_id.as_str(),
        ),
        CredentialSearchField::UserId(id) => (
            &format!(r#"DELETE FROM {passkey_table} WHERE user_id = ?"#),
            id.as_str(),
        ),
        CredentialSearchField::UserHandle(handle) => (
            &format!(r#"DELETE FROM {passkey_table} WHERE user_handle = ?"#),
            handle.as_str(),
        ),
        CredentialSearchField::UserName(name) => (
            &format!(r#"DELETE FROM {passkey_table} WHERE user_name = ?"#),
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

pub(super) async fn update_credential_user_details_mysql(
    pool: &Pool<MySql>,
    credential_id: CredentialId,
    name: &str,
    display_name: &str,
) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query(&format!(
        r#"UPDATE {passkey_table} SET user_name = ?, user_display_name = ? WHERE credential_id = ?"#
    ))
    .bind(name)
    .bind(display_name)
    .bind(credential_id.as_str())
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

// Implement FromRow for PasskeyCredential to handle the flattened database structure for MySQL
impl<'r> FromRow<'r, MySqlRow> for PasskeyCredential {
    fn from_row(row: &'r MySqlRow) -> Result<Self, sqlx::Error> {
        let sequence_number: Option<i64> = row.try_get("sequence_number")?;
        let credential_id: String = row.try_get("credential_id")?;
        let user_id: String = row.try_get("user_id")?;
        let public_key: String = row.try_get("public_key")?;
        let counter: i32 = row.try_get("counter")?;
        let user_handle: String = row.try_get("user_handle")?;
        let user_name: String = row.try_get("user_name")?;
        let user_display_name: String = row.try_get("user_display_name")?;
        let aaguid: String = row.try_get("aaguid")?;
        let rp_id: String = row.try_get("rp_id")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let updated_at: DateTime<Utc> = row.try_get("updated_at")?;
        let last_used_at: DateTime<Utc> = row.try_get("last_used_at")?;

        Ok(PasskeyCredential {
            sequence_number,
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
            rp_id,
            created_at,
            updated_at,
            last_used_at,
        })
    }
}

pub(super) async fn update_credential_last_used_at_mysql(
    pool: &Pool<MySql>,
    credential_id: CredentialId,
    last_used_at: DateTime<Utc>,
) -> Result<(), PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query(&format!(
        r#"UPDATE {passkey_table} SET last_used_at = ? WHERE credential_id = ?"#
    ))
    .bind(last_used_at)
    .bind(credential_id.as_str())
    .execute(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}
