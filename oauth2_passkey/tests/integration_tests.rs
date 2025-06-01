// Integration tests for oauth2-passkey
//
// These tests require external dependencies like databases to run.
// To run all integration tests, including those that require databases:
//
// ```
// TEST_POSTGRES_URL=postgres://username:password@localhost/database cargo test --test integration_tests
// ```
//
// Or to run just the SQLite tests (which don't require external setup):
//
// ```
// cargo test --test integration_tests
// ```

// Import the test modules
mod oauth2;
mod passkey;
