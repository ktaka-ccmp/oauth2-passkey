use super::*;
use oauth2_passkey::oauth2::storage::config::DB_TABLE_OAUTH2_ACCOUNTS;

#[tokio::test]
#[ignore = "Requires PostgreSQL database"]
async fn test_postgres_oauth2_schema() -> Result<(), Box<dyn std::error::Error>> {
    // Skip this test if TEST_POSTGRES_URL is not set
    if env::var("TEST_POSTGRES_URL").is_err() {
        println!("Skipping PostgreSQL test: TEST_POSTGRES_URL not set");
        return Ok(());
    }

    // Set up the test database
    let pool = setup_postgres_test_db().await?;
    let oauth2_table = DB_TABLE_OAUTH2_ACCOUNTS.as_str();

    // Create the table
    sqlx::query(&format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            access_token TEXT NOT NULL,
            refresh_token TEXT,
            expires_at TIMESTAMPTZ,
            scope TEXT,
            token_type TEXT,
            id_token TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        oauth2_table
    ))
    .execute(&pool)
    .await?;

    // Validate the schema
    let expected_columns = [
        ("id", "text"),
        ("user_id", "text"),
        ("provider", "text"),
        ("provider_user_id", "text"),
        ("access_token", "text"),
        ("refresh_token", "text"),
        ("expires_at", "timestamp with time zone"),
        ("scope", "text"),
        ("token_type", "text"),
        ("id_token", "text"),
        ("created_at", "timestamp with time zone"),
        ("updated_at", "timestamp with time zone"),
    ];

    validate_postgres_table_schema(
        &pool,
        oauth2_table,
        &expected_columns,
        |e| OAuth2Error::Storage(e),
    )
    .await?;

    // Clean up
    cleanup_postgres_test_db(&pool, &[oauth2_table]).await?;

    Ok(())
}
