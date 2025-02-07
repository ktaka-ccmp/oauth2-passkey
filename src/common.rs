use ring::rand::SecureRandom;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};

// Use anyhow, define error and enable '?'
// For a simplified example of using anyhow in axum check /examples/anyhow-error-response
#[derive(Debug)]
pub struct AppError(pub(crate) anyhow::Error);

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

pub(crate) fn gen_random_string(len: usize) -> Result<String, AppError> {
    let rng = ring::rand::SystemRandom::new();
    let mut session_id = vec![0u8; len];
    rng.fill(&mut session_id)?;
    Ok(URL_SAFE.encode(session_id))
}
