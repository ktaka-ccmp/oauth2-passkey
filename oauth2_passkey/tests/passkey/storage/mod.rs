use chrono::{DateTime, TimeZone, Utc};
use oauth2_passkey::passkey::types::{
    CredentialSearchField, PasskeyCredential, PublicKeyCredentialUserEntity,
};
use oauth2_passkey::storage::data_store::config::get_data_store;
use oauth2_passkey::storage::schema_validation::validate_postgres_table_schema;
use sqlx::{Pool, Postgres, Sqlite};
use std::env;

// Helper function to set up a test database
async fn setup_test_db() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a unique timestamp for this test run to avoid conflicts
    let timestamp = chrono::Utc::now().timestamp_millis();
    let table_prefix = format!("test_o2p_{}_", timestamp);

    // Use a file-based SQLite database for testing
    let db_path = format!(
        "/tmp/test_passkey_{}_{}.db",
        timestamp,
        uuid::Uuid::new_v4()
    );
    let db_url = format!("sqlite:{}", db_path);

    // Set environment variables for the test
    unsafe {
        env::set_var("GENERIC_DATA_STORE_TYPE", "sqlite");
        env::set_var("GENERIC_DATA_STORE_URL", &db_url);
        env::set_var("DB_TABLE_PREFIX", &table_prefix);
    }

    Ok(())
}

// Helper function to set up a PostgreSQL test database
// This requires a PostgreSQL server to be running
async fn setup_postgres_test_db() -> Result<Pool<Postgres>, Box<dyn std::error::Error>> {
    // Generate a unique timestamp for this test run to avoid conflicts
    let timestamp = chrono::Utc::now().timestamp_millis();
    let table_prefix = format!("test_o2p_{}_", timestamp);

    // PostgreSQL connection string - should be configurable for CI/CD
    let db_url = env::var("TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/postgres".to_string());

    // Set environment variables for the test
    unsafe {
        env::set_var("GENERIC_DATA_STORE_TYPE", "postgres");
        env::set_var("GENERIC_DATA_STORE_URL", &db_url);
        env::set_var("DB_TABLE_PREFIX", &table_prefix);
    }

    // Connect to the database
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    Ok(pool)
}

// Helper function to set up a SQLite test database
async fn setup_sqlite_test_db() -> Result<Pool<Sqlite>, Box<dyn std::error::Error>> {
    // Generate a unique timestamp for this test run to avoid conflicts
    let timestamp = chrono::Utc::now().timestamp_millis();
    let table_prefix = format!("test_o2p_{}_", timestamp);

    // Use a file-based SQLite database for testing
    let db_path = format!(
        "/tmp/test_passkey_{}_{}.db",
        timestamp,
        uuid::Uuid::new_v4()
    );
    let db_url = format!("sqlite:{}", db_path);

    // Set environment variables for the test
    unsafe {
        env::set_var("GENERIC_DATA_STORE_TYPE", "sqlite");
        env::set_var("GENERIC_DATA_STORE_URL", &db_url);
        env::set_var("DB_TABLE_PREFIX", &table_prefix);
    }

    // Connect to the database
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    Ok(pool)
}

// Helper function to create a sample PasskeyCredential for testing
fn create_test_credential() -> PasskeyCredential {
    let now = Utc::now();

    PasskeyCredential {
        credential_id: "test_credential_id".to_string(),
        user_id: "test_user_id".to_string(),
        public_key: "test_public_key".to_string(),
        aaguid: "00000000-0000-0000-0000-000000000000".to_string(),
        counter: 0,
        user: PublicKeyCredentialUserEntity {
            user_handle: "test_user_handle".to_string(),
            name: "test_user_name".to_string(),
            display_name: "Test User".to_string(),
        },
        created_at: now,
        updated_at: now,
        last_used_at: now,
    }
}

// The actual tests will be implemented in separate files:
// - postgres.rs for PostgreSQL-specific tests
// - sqlite.rs for SQLite-specific tests
