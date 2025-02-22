use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

use crate::{
    CacheDataKind, PermanentDataKind, QueryField, QueryRelation,
    Store, PermanentStore, StorageError,
};

pub struct SqlitePermanentStore {
    pool: SqlitePool,
}

impl SqlitePermanentStore {
    pub async fn connect(path: &str) -> Result<Self, StorageError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1) // SQLite supports only one writer
            .connect(&format!("sqlite:{}", path))
            .await?;
        Ok(Self { pool })
    }

    async fn create_tables(&self) -> Result<(), StorageError> {
        // Enable foreign key support
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&self.pool)
            .await?;

        // Create users table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create credentials table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
                credential_id TEXT PRIMARY KEY,
                credential BLOB NOT NULL,
                public_key BLOB NOT NULL,
                counter INTEGER NOT NULL,
                user_handle TEXT NOT NULL,
                user_name TEXT NOT NULL,
                user_display_name TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_handle) REFERENCES users(user_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn store_user<T: Serialize>(&self, key: &str, value: &T) -> Result<(), StorageError> {
        let value_json: serde_json::Value = serde_json::to_value(value)?;
        
        sqlx::query(
            r#"
            INSERT INTO users (user_id, email, name)
            VALUES (?1, ?2, ?3)
            ON CONFLICT (user_id) DO UPDATE
            SET email = ?2, name = ?3
            "#,
        )
        .bind(key)
        .bind(value_json.get("email").and_then(|v| v.as_str()).ok_or_else(|| StorageError::Config("Missing email".into()))?)
        .bind(value_json.get("name").and_then(|v| v.as_str()).ok_or_else(|| StorageError::Config("Missing name".into()))?)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn store_credential<T: Serialize>(&self, key: &str, value: &T) -> Result<(), StorageError> {
        let value_json: serde_json::Value = serde_json::to_value(value)?;
        
        sqlx::query(
            r#"
            INSERT INTO credentials (
                credential_id, credential, public_key, counter,
                user_handle, user_name, user_display_name
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT (credential_id) DO UPDATE
            SET credential = ?2,
                public_key = ?3,
                counter = ?4,
                user_handle = ?5,
                user_name = ?6,
                user_display_name = ?7
            "#,
        )
        .bind(key)
        .bind(value_json.get("credential").and_then(|v| v.as_array()).ok_or_else(|| StorageError::Config("Missing credential".into()))?)
        .bind(value_json.get("public_key").and_then(|v| v.as_array()).ok_or_else(|| StorageError::Config("Missing public_key".into()))?)
        .bind(value_json.get("counter").and_then(|v| v.as_i64()).ok_or_else(|| StorageError::Config("Missing counter".into()))?)
        .bind(value_json.get("user_handle").and_then(|v| v.as_str()).ok_or_else(|| StorageError::Config("Missing user_handle".into()))?)
        .bind(value_json.get("user_name").and_then(|v| v.as_str()).ok_or_else(|| StorageError::Config("Missing user_name".into()))?)
        .bind(value_json.get("user_display_name").and_then(|v| v.as_str()).ok_or_else(|| StorageError::Config("Missing user_display_name".into()))?)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[async_trait]
impl Store for SqlitePermanentStore {
    fn requires_schema(&self) -> bool {
        true
    }

    async fn init(&self) -> Result<(), StorageError> {
        self.create_tables().await
    }
}

#[async_trait]
impl PermanentStore for SqlitePermanentStore {
    async fn store<T: Serialize + Send + Sync>(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
        value: &T,
    ) -> Result<(), StorageError> {
        match kind {
            PermanentDataKind::User => self.store_user(key, value).await?,
            PermanentDataKind::Credential => self.store_credential(key, value).await?,
        }
        Ok(())
    }

    async fn get<T: DeserializeOwned>(
        &self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let row = match kind {
            PermanentDataKind::User => {
                sqlx::query("SELECT * FROM users WHERE user_id = ?1")
                    .bind(key)
                    .fetch_optional(&self.pool)
                    .await?
            }
            PermanentDataKind::Credential => {
                sqlx::query("SELECT * FROM credentials WHERE credential_id = ?1")
                    .bind(key)
                    .fetch_optional(&self.pool)
                    .await?
            }
        };

        match row {
            Some(row) => {
                let json = match kind {
                    PermanentDataKind::User => {
                        serde_json::json!({
                            "user_id": row.get::<String, _>("user_id"),
                            "email": row.get::<String, _>("email"),
                            "name": row.get::<String, _>("name"),
                        })
                    }
                    PermanentDataKind::Credential => {
                        serde_json::json!({
                            "credential_id": row.get::<String, _>("credential_id"),
                            "credential": row.get::<Vec<u8>, _>("credential"),
                            "public_key": row.get::<Vec<u8>, _>("public_key"),
                            "counter": row.get::<i32, _>("counter"),
                            "user_handle": row.get::<String, _>("user_handle"),
                            "user_name": row.get::<String, _>("user_name"),
                            "user_display_name": row.get::<String, _>("user_display_name"),
                        })
                    }
                };
                Ok(Some(serde_json::from_value(json)?))
            }
            None => Ok(None),
        }
    }

    async fn delete(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<(), StorageError> {
        match kind {
            PermanentDataKind::User => {
                sqlx::query("DELETE FROM users WHERE user_id = ?1")
                    .bind(key)
                    .execute(&self.pool)
                    .await?;
            }
            PermanentDataKind::Credential => {
                sqlx::query("DELETE FROM credentials WHERE credential_id = ?1")
                    .bind(key)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn query<T: DeserializeOwned>(
        &self,
        relation: QueryRelation,
        field: QueryField,
    ) -> Result<Vec<T>, StorageError> {
        // Replace PostgreSQL's $1 with SQLite's ?1 in the SQL
        let sql = relation.to_sql().replace("$1", "?1");
        
        let rows = sqlx::query(&sql)
            .bind(match &field {
                QueryField::UserId(id) => id,
                QueryField::Email(email) => email,
                _ => return Err(StorageError::InvalidQuery),
            })
            .fetch_all(&self.pool)
            .await?;

        let mut results = Vec::new();
        for row in rows {
            let json = match relation {
                QueryRelation::CredentialsByUser | QueryRelation::CredentialsByEmail => {
                    serde_json::json!({
                        "credential_id": row.get::<String, _>("credential_id"),
                        "credential": row.get::<Vec<u8>, _>("credential"),
                        "public_key": row.get::<Vec<u8>, _>("public_key"),
                        "counter": row.get::<i32, _>("counter"),
                        "user_handle": row.get::<String, _>("user_handle"),
                        "user_name": row.get::<String, _>("user_name"),
                        "user_display_name": row.get::<String, _>("user_display_name"),
                    })
                }
                QueryRelation::UserByEmail => {
                    serde_json::json!({
                        "user_id": row.get::<String, _>("user_id"),
                        "email": row.get::<String, _>("email"),
                        "name": row.get::<String, _>("name"),
                    })
                }
            };
            results.push(serde_json::from_value(json)?);
        }

        Ok(results)
    }
}
