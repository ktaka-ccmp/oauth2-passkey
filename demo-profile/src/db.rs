use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, postgres::PgPoolOptions};

/// User profile with extended attributes
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserProfile {
    pub user_id: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub theme: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for UserProfile {
    fn default() -> Self {
        Self {
            user_id: String::new(),
            display_name: None,
            bio: None,
            avatar_url: None,
            theme: "light".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// Initialize database connection pool and return it
pub async fn init_db() -> Result<PgPool, Box<dyn std::error::Error>> {
    let database_url = std::env::var("APP_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://demo:demo@localhost:5432/demo".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Create table if not exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id TEXT PRIMARY KEY,
            display_name TEXT,
            bio TEXT,
            avatar_url TEXT,
            theme TEXT NOT NULL DEFAULT 'light',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(&pool)
    .await?;

    tracing::info!("Profile database initialized");
    Ok(pool)
}

/// Get a user profile by user_id
pub async fn get_profile(pool: &PgPool, user_id: &str) -> Result<Option<UserProfile>, sqlx::Error> {
    sqlx::query_as::<_, UserProfile>(
        "SELECT user_id, display_name, bio, avatar_url, theme, created_at, updated_at
         FROM user_profiles WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Create or update a user profile
pub async fn upsert_profile(
    pool: &PgPool,
    profile: &UserProfile,
) -> Result<UserProfile, sqlx::Error> {
    sqlx::query_as::<_, UserProfile>(
        r#"
        INSERT INTO user_profiles (user_id, display_name, bio, avatar_url, theme, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        ON CONFLICT (user_id) DO UPDATE SET
            display_name = EXCLUDED.display_name,
            bio = EXCLUDED.bio,
            avatar_url = EXCLUDED.avatar_url,
            theme = EXCLUDED.theme,
            updated_at = NOW()
        RETURNING user_id, display_name, bio, avatar_url, theme, created_at, updated_at
        "#,
    )
    .bind(&profile.user_id)
    .bind(&profile.display_name)
    .bind(&profile.bio)
    .bind(&profile.avatar_url)
    .bind(&profile.theme)
    .fetch_one(pool)
    .await
}

/// Create a new profile with avatar from OAuth2 if available
pub async fn create_profile_with_avatar(
    pool: &PgPool,
    user_id: &str,
    avatar_url: Option<String>,
) -> Result<UserProfile, sqlx::Error> {
    let profile = UserProfile {
        user_id: user_id.to_string(),
        avatar_url,
        ..Default::default()
    };
    upsert_profile(pool, &profile).await
}
