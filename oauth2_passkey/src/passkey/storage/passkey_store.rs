use crate::storage::GENERIC_DATA_STORE;
use crate::storage::{DB_TABLE_PASSKEY_CREDENTIALS, DB_TABLE_USERS};
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres, Sqlite};

use crate::passkey::errors::PasskeyError;
use crate::passkey::types::{
    CredentialSearchField, PublicKeyCredentialUserEntity, StoredCredential,
};

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
        credential: StoredCredential,
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
    ) -> Result<Option<StoredCredential>, PasskeyError> {
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
    ) -> Result<Vec<StoredCredential>, PasskeyError> {
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
}

// SQLite implementations
async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), PasskeyError> {
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

async fn store_credential_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
    credential: &StoredCredential,
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

async fn get_credential_sqlite(
    pool: &Pool<Sqlite>,
    credential_id: &str,
) -> Result<Option<StoredCredential>, PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query_as::<_, StoredCredential>(&format!(
        r#"SELECT * FROM {} WHERE credential_id = ?"#,
        passkey_table
    ))
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))
}

async fn get_credentials_by_field_sqlite(
    pool: &Pool<Sqlite>,
    field: &CredentialSearchField,
) -> Result<Vec<StoredCredential>, PasskeyError> {
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

    sqlx::query_as::<_, StoredCredential>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

async fn update_credential_counter_sqlite(
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

async fn delete_credential_by_field_sqlite(
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

// PostgreSQL implementations
async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), PasskeyError> {
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
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
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

async fn store_credential_postgres(
    pool: &Pool<Postgres>,
    credential_id: &str,
    credential: &StoredCredential,
) -> Result<(), PasskeyError> {
    let counter_i32 = credential.counter as i32;
    let public_key = &credential.public_key;
    let user_id = &credential.user_id;
    let user_handle = &credential.user.user_handle;
    let user_name = &credential.user.name;
    let user_display_name = &credential.user.display_name;
    let created_at = &credential.created_at;
    let updated_at = &credential.updated_at;
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query_as::<_, (i32,)>(&format!(
        r#"
        INSERT INTO {}
        (credential_id, user_id, public_key, counter, user_handle, user_name, user_display_name, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (credential_id) DO UPDATE
        SET user_id = $2, public_key = $3, counter = $4, user_handle = $5, user_name = $6, user_display_name = $7, updated_at = CURRENT_TIMESTAMP
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
    .bind(created_at)
    .bind(updated_at)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    Ok(())
}

async fn get_credential_postgres(
    pool: &Pool<Postgres>,
    credential_id: &str,
) -> Result<Option<StoredCredential>, PasskeyError> {
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    sqlx::query_as::<_, StoredCredential>(&format!(
        r#"SELECT * FROM {} WHERE credential_id = $1"#,
        passkey_table
    ))
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| PasskeyError::Storage(e.to_string()))
}

async fn get_credentials_by_field_postgres(
    pool: &Pool<Postgres>,
    field: &CredentialSearchField,
) -> Result<Vec<StoredCredential>, PasskeyError> {
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

    sqlx::query_as::<_, StoredCredential>(query)
        .bind(value)
        .fetch_all(pool)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

async fn update_credential_counter_postgres(
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

async fn delete_credential_by_field_postgres(
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

use sqlx::{FromRow, Row, postgres::PgRow, sqlite::SqliteRow};

// Implement FromRow for StoredCredential to handle the flattened database structure for SQLite
impl<'r> FromRow<'r, SqliteRow> for StoredCredential {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let credential_id: String = row.try_get("credential_id")?;
        let user_id: String = row.try_get("user_id")?;
        let public_key: String = row.try_get("public_key")?;
        let counter: i64 = row.try_get("counter")?;
        let user_handle: String = row.try_get("user_handle")?;
        let user_name: String = row.try_get("user_name")?;
        let user_display_name: String = row.try_get("user_display_name")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let updated_at: DateTime<Utc> = row.try_get("updated_at")?;

        Ok(StoredCredential {
            credential_id,
            user_id,
            public_key,
            counter: counter as u32,
            user: PublicKeyCredentialUserEntity {
                user_handle,
                name: user_name,
                display_name: user_display_name,
            },
            created_at,
            updated_at,
        })
    }
}

// Implement FromRow for StoredCredential to handle the flattened database structure for PostgreSQL
impl<'r> FromRow<'r, PgRow> for StoredCredential {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let credential_id: String = row.try_get("credential_id")?;
        let user_id: String = row.try_get("user_id")?;
        let public_key: String = row.try_get("public_key")?;
        let counter: i32 = row.try_get("counter")?;
        let user_handle: String = row.try_get("user_handle")?;
        let user_name: String = row.try_get("user_name")?;
        let user_display_name: String = row.try_get("user_display_name")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let updated_at: DateTime<Utc> = row.try_get("updated_at")?;

        Ok(StoredCredential {
            credential_id,
            user_id,
            public_key,
            counter: counter as u32,
            user: PublicKeyCredentialUserEntity {
                user_handle,
                name: user_name,
                display_name: user_display_name,
            },
            created_at,
            updated_at,
        })
    }
}
