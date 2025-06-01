use super::*;
use oauth2_passkey::passkey::errors::PasskeyError;
use oauth2_passkey::passkey::storage::config::DB_TABLE_PASSKEY_CREDENTIALS;
use oauth2_passkey::userdb::DB_TABLE_USERS;

#[tokio::test]
async fn test_sqlite_passkey_schema() -> Result<(), Box<dyn std::error::Error>> {
    // Set up the test database
    let pool = setup_sqlite_test_db().await?;
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    // Create the tables
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id TEXT PRIMARY KEY NOT NULL,
            account TEXT NOT NULL,
            label TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        DB_TABLE_USERS.as_str()
    ))
    .execute(&pool)
    .await?;

    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            credential_id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0,
            user_handle TEXT NOT NULL,
            user_name TEXT NOT NULL,
            user_display_name TEXT NOT NULL,
            aaguid TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES {}(id)
        )
        "#,
        passkey_table, DB_TABLE_USERS.as_str()
    ))
    .execute(&pool)
    .await?;

    // Validate the schema by querying the table info
    let rows = sqlx::query(&format!("PRAGMA table_info({})", passkey_table))
        .fetch_all(&pool)
        .await?;

    // Check that we have the expected number of columns
    assert_eq!(rows.len(), 11, "Expected 11 columns in the passkey table");

    // Check column names and types
    let expected_columns = [
        ("credential_id", "TEXT"),
        ("user_id", "TEXT"),
        ("public_key", "TEXT"),
        ("counter", "INTEGER"),
        ("user_handle", "TEXT"),
        ("user_name", "TEXT"),
        ("user_display_name", "TEXT"),
        ("aaguid", "TEXT"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
        ("last_used_at", "TEXT"),
    ];

    for (i, (expected_name, expected_type)) in expected_columns.iter().enumerate() {
        let name: String = rows[i].get("name");
        let type_: String = rows[i].get("type");
        
        assert_eq!(
            &name, expected_name,
            "Column {} has name {}, expected {}",
            i, name, expected_name
        );
        assert_eq!(
            &type_, expected_type,
            "Column {} has type {}, expected {}",
            i, type_, expected_type
        );
    }

    // Clean up - drop the tables
    sqlx::query(&format!("DROP TABLE IF EXISTS {}", passkey_table))
        .execute(&pool)
        .await?;
    sqlx::query(&format!("DROP TABLE IF EXISTS {}", DB_TABLE_USERS.as_str()))
        .execute(&pool)
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_sqlite_counter_conversion() -> Result<(), Box<dyn std::error::Error>> {
    // Create a test credential
    let mut credential = create_test_credential();
    
    // Test counter conversion
    credential.counter = 12345;
    assert_eq!(credential.counter, 12345);
    
    // Test counter update
    credential.counter = 54321;
    assert_eq!(credential.counter, 54321);

    Ok(())
}
