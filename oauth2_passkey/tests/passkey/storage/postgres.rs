use super::*;
use oauth2_passkey::passkey::errors::PasskeyError;
use oauth2_passkey::passkey::storage::config::DB_TABLE_PASSKEY_CREDENTIALS;
use oauth2_passkey::userdb::DB_TABLE_USERS;

#[tokio::test]
#[ignore = "Requires PostgreSQL database"]
async fn test_postgres_passkey_schema() -> Result<(), Box<dyn std::error::Error>> {
    // Skip this test if TEST_POSTGRES_URL is not set
    if env::var("TEST_POSTGRES_URL").is_err() {
        println!("Skipping PostgreSQL test: TEST_POSTGRES_URL not set");
        return Ok(());
    }

    // Set up the test database
    let pool = setup_postgres_test_db().await?;
    let passkey_table = DB_TABLE_PASSKEY_CREDENTIALS.as_str();

    // Create the tables
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id TEXT PRIMARY KEY NOT NULL,
            account TEXT NOT NULL,
            label TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
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
        passkey_table, DB_TABLE_USERS.as_str(), DB_TABLE_USERS.as_str()
    ))
    .execute(&pool)
    .await?;

    // Validate the schema
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
        &pool,
        passkey_table,
        &expected_columns,
        |e| PasskeyError::Storage(e),
    )
    .await?;

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
#[ignore = "Requires PostgreSQL database"]
async fn test_passkey_credential_creation() -> Result<(), Box<dyn std::error::Error>> {
    // Skip this test if TEST_POSTGRES_URL is not set
    if env::var("TEST_POSTGRES_URL").is_err() {
        println!("Skipping PostgreSQL test: TEST_POSTGRES_URL not set");
        return Ok(());
    }

    // Create a test credential
    let credential = create_test_credential();
    
    // Verify all fields are correctly set
    assert_eq!(credential.credential_id, "test_credential_id");
    assert_eq!(credential.user_id, "test_user_id");
    assert_eq!(credential.public_key, "test_public_key");
    assert_eq!(credential.aaguid, "00000000-0000-0000-0000-000000000000");
    assert_eq!(credential.counter, 0);
    assert_eq!(credential.user.user_handle, "test_user_handle");
    assert_eq!(credential.user.name, "test_user_name");
    assert_eq!(credential.user.display_name, "Test User");
    
    // Verify timestamps are reasonable
    let now = Utc::now();
    let one_second_ago = now - chrono::Duration::seconds(1);
    assert!(credential.created_at > one_second_ago);
    assert!(credential.updated_at > one_second_ago);
    assert!(credential.last_used_at > one_second_ago);

    Ok(())
}
