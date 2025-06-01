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
                CoordinationError::InvalidState(_) => StatusCode::BAD_REQUEST,
                CoordinationError::InvalidResponseMode(_) => StatusCode::BAD_REQUEST,
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

#[cfg(test)]
mod tests {
    use super::*;
    use oauth2_passkey::CoordinationError;

    #[test]
    fn test_coordination_error_unauthorized() {
        // Create a Result with CoordinationError::Unauthorized
        let result: Result<(), CoordinationError> = Err(CoordinationError::Unauthorized);

        // Convert to response
        let response_error = result.into_response_error();

        // Verify status code is UNAUTHORIZED (401)
        assert!(response_error.is_err());
        if let Err((status, _)) = response_error {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn test_coordination_error_no_content() {
        // Create a Result with CoordinationError::NoContent
        let result: Result<(), CoordinationError> = Err(CoordinationError::NoContent);

        // Convert to response
        let response_error = result.into_response_error();

        // Verify status code is NO_CONTENT (204)
        assert!(response_error.is_err());
        if let Err((status, _)) = response_error {
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
    }

    #[test]
    fn test_coordination_error_bad_request() {
        // Test with InvalidState variant which maps to BAD_REQUEST
        let result: Result<(), CoordinationError> =
            Err(CoordinationError::InvalidState("Invalid state".to_string()));

        // Convert to response
        let response_error = result.into_response_error();

        // Verify status code is BAD_REQUEST (400)
        assert!(response_error.is_err());
        if let Err((status, _)) = response_error {
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn test_coordination_error_not_found() {
        // Test with ResourceNotFound variant
        let result: Result<(), CoordinationError> = Err(CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: "123".to_string(),
        });

        // Convert to response error
        let response_error = result.into_response_error();

        // Verify the status code is NOT_FOUND
        assert!(response_error.is_err());
        if let Err((status, _)) = response_error {
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
    }

    #[test]
    fn test_coordination_error_invalid_response_mode() {
        // Test with InvalidResponseMode error
        let result: Result<(), CoordinationError> = Err(CoordinationError::InvalidResponseMode(
            "Invalid mode".to_string(),
        ));

        // Convert to response error
        let response_error = result.into_response_error();

        // Verify the status code is BAD_REQUEST
        assert!(response_error.is_err());
        if let Err((status, _)) = response_error {
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn test_success_case() {
        // Create a successful Result
        let result: Result<String, CoordinationError> = Ok("Success".to_string());

        // Convert to response error
        let response_error = result.into_response_error();

        // Verify the result is Ok
        assert!(response_error.is_ok());
        if let Ok(value) = response_error {
            assert_eq!(value, "Success");
        }
    }

    #[test]
    fn test_http_error() {
        // Create a simple HTTP error directly
        // We'll use a method that's guaranteed to fail: trying to parse an invalid status code
        // 1000 is definitely invalid as status codes are 3 digits
        let result: HttpResponse<String> = Err(StatusCode::from_u16(1000).unwrap_err().into());

        // Convert to response error
        let response_error = result.into_response_error();

        // Verify the status code is INTERNAL_SERVER_ERROR
        assert!(response_error.is_err());
        if let Err((status, _)) = response_error {
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}
