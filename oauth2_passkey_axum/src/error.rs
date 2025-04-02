use http::{Result as HttpResponse, StatusCode};
use oauth2_passkey::CoordinationError;

/// Helper trait for converting errors to a standard response error format
pub(super) trait IntoResponseError<T> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)>;
}

/// Implementation for CoordinationError to map variants to appropriate status codes
impl<T> IntoResponseError<T> for Result<T, CoordinationError> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)> {
        self.map_err(|e| {
            let status = match e {
                CoordinationError::Unauthorized => StatusCode::UNAUTHORIZED,
                CoordinationError::OAuth2Error(_) => StatusCode::BAD_REQUEST,
                CoordinationError::PasskeyError(_) => StatusCode::BAD_REQUEST,
                CoordinationError::UserError(_) => StatusCode::BAD_REQUEST,
                CoordinationError::SessionError(_) => StatusCode::BAD_REQUEST,
                CoordinationError::InvalidState => StatusCode::BAD_REQUEST,
                CoordinationError::NoContent => StatusCode::NO_CONTENT,
                CoordinationError::ResourceNotFound { .. } => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, e.to_string())
        })
    }
}

/// Implementation for http::Error (used by Response::builder())
impl<T> IntoResponseError<T> for HttpResponse<T> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)> {
        self.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }
}
