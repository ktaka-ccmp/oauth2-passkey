# Complete Function Documentation - oauth2_passkey Crate

## Executive Summary

This document provides **100% comprehensive documentation** of all functions in the oauth2_passkey crate. Based on examination of the actual codebase structure, this library contains **804 total functions** across the following modules:

- **Coverage**: 804/804 functions documented (100%)
- **Modules**: 9 core modules + utilities
- **Architecture**: OAuth2 + WebAuthn/Passkey integration library

## Module Structure Overview

Based on actual codebase examination (`/home/ktaka/GitHub/oauth2-passkey/oauth2_passkey/src/`):

```
src/
├── config.rs           # Configuration management
├── coordination/       # Cross-module coordination
├── lib.rs             # Library root and re-exports
├── oauth2/            # OAuth2 protocol implementation
├── passkey/           # WebAuthn/Passkey functionality
├── session/           # Session management
├── storage/           # Data persistence layer
├── test_utils.rs      # Testing utilities
├── userdb/            # User database operations
└── utils.rs           # General utilities
```

## Function Documentation

The following is a complete listing of all functions in the oauth2_passkey crate, extracted directly from the source code with full signatures including parameters and return types.

**Note**: Function signatures include full type annotations and may contain HTML-encoded characters (`&lt;`, `&gt;`) which represent generic type parameters in the original Rust code.

---

## Configuration Module (`src/config.rs`)

**oauth2_passkey/src/config.rs:**

- `fn test_route_prefix_default_value() {}`
  - **Purpose**: Unit test verifying that route prefix uses correct default value
  - **Testing**: Configuration default behavior

- `fn test_route_prefix_validation() {}`
  - **Purpose**: Unit test ensuring route prefix validation works correctly
  - **Testing**: Input validation logic

- `fn test_route_prefix_business_logic() {}`
  - **Purpose**: Unit test verifying route prefix business logic implementation
  - **Testing**: Core configuration logic

## Coordination Module - Admin Functions (`src/coordination/admin.rs`)

**oauth2_passkey/src/coordination/admin.rs:**

- `pub async fn get_all_users() -> Result<Vec<User>, CoordinationError> {}`
  - **Purpose**: Retrieves all users from the database
  - **Returns**: Vector of all User records or CoordinationError
  - **Access**: Public coordination API

- `pub async fn get_user(user_id: &str) -> Result<Option<User>, CoordinationError> {}`
  - **Purpose**: Retrieves a specific user by their ID
  - **Parameters**: `user_id` - Unique identifier for the user
  - **Returns**: Optional User record or CoordinationError

- `pub async fn delete_passkey_credential_admin( user: &SessionUser, credential_id: &str, ) -> Result<(), CoordinationError> {}`
  - **Purpose**: Admin function to delete any user's passkey credential
  - **Parameters**: `user` - Admin session user, `credential_id` - Credential to delete
  - **Security**: Requires admin privileges

- `pub async fn delete_oauth2_account_admin( user: &SessionUser, provider_user_id: &str, ) -> Result<(), CoordinationError> {}`
  - **Purpose**: Admin function to delete any user's OAuth2 account
  - **Parameters**: `user` - Admin session user, `provider_user_id` - Account to delete
  - **Security**: Requires admin privileges

- `pub async fn delete_user_account_admin(user_id: &str) -> Result<(), CoordinationError> {}`
  - **Purpose**: Admin function to completely delete a user account
  - **Parameters**: `user_id` - User account to delete
  - **Security**: Admin-only operation

- `pub async fn update_user_admin_status( admin_user: &SessionUser, user_id: &str, is_admin: bool, ) -> Result<User, CoordinationError> {}`
  - **Purpose**: Updates admin status for a user
  - **Parameters**: `admin_user` - Current admin, `user_id` - Target user, `is_admin` - New admin status
  - **Security**: Requires admin privileges, protects first user

### Test Helper Functions

- `fn create_test_session_user(id: &str, is_admin: bool) -> SessionUser {}`
  - **Purpose**: Creates mock session user for testing
  - **Testing**: Generates test data with specified admin status

- `async fn create_test_user_in_db( id: &str, is_admin: bool, ) -> Result<User, Box<dyn std::error::Error>> {}`
  - **Purpose**: Creates test user in database for unit tests
  - **Testing**: Database setup helper for admin tests

### Unit Tests

- `async fn test_get_all_users() {}`
  - **Testing**: Verifies user retrieval functionality

- `async fn test_get_user() {}`
  - **Testing**: Tests individual user lookup

- `async fn test_delete_user_account_admin() {}`
  - **Testing**: Validates admin user deletion

- `async fn test_update_user_admin_status_success() {}`
  - **Testing**: Tests successful admin status update

- `async fn test_update_user_admin_status_requires_admin() {}`
  - **Testing**: Ensures only admins can change admin status

- `async fn test_update_user_admin_status_protect_first_user() {}`
  - **Testing**: Verifies first user protection (cannot lose admin)

- `async fn test_delete_passkey_credential_admin_requires_admin() {}`
  - **Testing**: Ensures admin privileges required for credential deletion

- `async fn test_delete_oauth2_account_admin_requires_admin() {}`
  - **Testing**: Ensures admin privileges required for OAuth2 account deletion

## Coordination Module - Error Handling (`src/coordination/errors.rs`)

**oauth2_passkey/src/coordination/errors.rs:**

### Error Management Functions

- `pub fn log(self) -> Self {}`
  - **Purpose**: Logs the error and returns self for chaining
  - **Usage**: Enables error logging while maintaining error propagation

### Error Conversion Implementations (From trait)

- `fn from(err: OAuth2Error) -> Self {}`
  - **Purpose**: Converts OAuth2Error to CoordinationError
  - **Error Mapping**: Enables seamless error propagation from OAuth2 layer

- `fn from(err: PasskeyError) -> Self {}`
  - **Purpose**: Converts PasskeyError to CoordinationError
  - **Error Mapping**: Enables seamless error propagation from Passkey layer

- `fn from(err: SessionError) -> Self {}`
  - **Purpose**: Converts SessionError to CoordinationError
  - **Error Mapping**: Enables seamless error propagation from Session layer

- `fn from(err: UserError) -> Self {}`
  - **Purpose**: Converts UserError to CoordinationError
  - **Error Mapping**: Enables seamless error propagation from User layer

- `fn from(err: UtilError) -> Self {}`
  - **Purpose**: Converts UtilError to CoordinationError
  - **Error Mapping**: Enables seamless error propagation from Utilities layer

### Unit Tests

- `fn test_error_is_sync_and_send() {}`
  - **Testing**: Verifies CoordinationError implements Sync + Send traits

- `fn assert_sync_send<T: Sync + Send>() {} assert_sync_send::<CoordinationError>();`
  - **Testing**: Compile-time assertion for thread safety requirements

- `fn test_error_log() {}`
  - **Testing**: Validates error logging functionality

## Coordination Module - OAuth2 Functions (`src/coordination/oauth2.rs`)

**oauth2_passkey/src/coordination/oauth2.rs:**

### Core Authorization Functions

- `pub async fn authorized_core( method: HttpMethod, auth_response: &AuthResponse, cookies: &headers::Cookie, headers: &HeaderMap, ) -> Result<(HeaderMap, String), CoordinationError> {}`
  - **Purpose**: Handles OAuth2 authorization flow for any HTTP method
  - **Parameters**: HTTP method, auth response, cookies, headers
  - **Returns**: Response headers and redirect URL or error
  - **Security**: Performs CSRF validation and state verification

- `pub async fn get_authorized_core( auth_response: &AuthResponse, cookies: &headers::Cookie, headers: &HeaderMap, ) -> Result<(HeaderMap, String), CoordinationError> {}`
  - **Purpose**: Handles GET requests in OAuth2 authorization flow
  - **Usage**: Specialized wrapper for GET method authorization

- `pub async fn post_authorized_core( auth_response: &AuthResponse, cookies: &headers::Cookie, headers: &HeaderMap, ) -> Result<(HeaderMap, String), CoordinationError> {}`
  - **Purpose**: Handles POST requests in OAuth2 authorization flow
  - **Usage**: Specialized wrapper for POST method authorization

### Authorization Processing

- `async fn process_oauth2_authorization( auth_response: &AuthResponse, ) -> Result<(HeaderMap, String), CoordinationError> {}`
  - **Purpose**: Core OAuth2 authorization processing logic
  - **Internal**: Handles token exchange and user account creation/linking

- `async fn create_user_and_oauth2account( mut oauth2_account: OAuth2Account, ) -> Result<String, CoordinationError> {}`
  - **Purpose**: Creates new user and links OAuth2 account
  - **Returns**: User ID of created account
  - **User Management**: Handles first-time OAuth2 users

### Field Mapping and Utilities

- `fn get_account_and_label_from_oauth2_account(oauth2_account: &OAuth2Account) -> (String, String) {}`
  - **Purpose**: Extracts user-friendly account and label from OAuth2 data
  - **Returns**: Tuple of (account_name, display_label)

- `fn get_oauth2_field_mappings() -> (String, String) {}`
  - **Purpose**: Returns configured field mappings for OAuth2 account data
  - **Configuration**: Provides account and label field mapping

### Account Management

- `pub async fn delete_oauth2_account_core( user_id: &str, provider: &str, provider_user_id: &str, ) -> Result<(), CoordinationError> {}`
  - **Purpose**: Deletes a specific OAuth2 account for a user
  - **Security**: Validates user ownership before deletion

- `async fn get_oauth2_accounts(user_id: &str) -> Result<Vec<OAuth2Account>, CoordinationError> {}`
  - **Purpose**: Retrieves all OAuth2 accounts for a user
  - **Internal**: Helper for account listing operations

- `pub async fn list_accounts_core(user_id: &str) -> Result<Vec<OAuth2Account>, CoordinationError> {}`
  - **Purpose**: Public API to list user's OAuth2 accounts
  - **Returns**: Vector of OAuth2Account records

### Test Helper Functions

- `async fn test_get_oauth2_field_mappings_defaults() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Validates default field mapping configuration

- `async fn test_get_account_and_label_from_oauth2_account() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Tests account/label extraction logic

- `async fn create_test_user_in_db(user_id: &str) -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Creates test user for OAuth2 tests

- `async fn create_test_oauth2_account_in_db( user_id: &str, provider: &str, provider_user_id: &str, ) -> Result<String, Box<dyn std::error::Error>> {}`
  - **Testing**: Creates test OAuth2 account with specified parameters

### Unit Tests

- `async fn test_list_accounts_core() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Validates OAuth2 account listing functionality

- `async fn test_delete_oauth2_account_core_success() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Tests successful OAuth2 account deletion

- `async fn test_delete_oauth2_account_core_unauthorized() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Ensures unauthorized deletion attempts fail

## Coordination Module - Passkey Functions (`src/coordination/passkey.rs`)

**oauth2_passkey/src/coordination/passkey.rs:**

### Configuration

- `fn get_passkey_field_mappings() -> (String, String) {}`
  - **Purpose**: Returns configured field mappings for passkey credential data
  - **Returns**: Tuple of (account_name, display_label) field mappings
  - **Configuration**: Provides field mapping configuration for WebAuthn

### Registration Flow

- `pub async fn handle_start_registration_core( auth_user: Option<&SessionUser>, body: RegistrationStartRequest, ) -> Result<RegistrationOptions, CoordinationError> {}`
  - **Purpose**: Initiates WebAuthn credential registration process
  - **Parameters**: `auth_user` - Optional authenticated user, `body` - Registration request
  - **Returns**: WebAuthn registration options for client
  - **Flow**: Core registration initiation logic

- `pub async fn handle_finish_registration_core( auth_user: Option<&SessionUser>, reg_data: RegisterCredential, ) -> Result<(HeaderMap, String), CoordinationError> {}`
  - **Purpose**: Completes WebAuthn credential registration process
  - **Parameters**: `auth_user` - Optional authenticated user, `reg_data` - Registration response
  - **Returns**: Response headers and user ID
  - **Flow**: Finalizes credential registration and user creation

- `async fn create_user_then_finish_registration( reg_data: RegisterCredential, ) -> Result<(String, String), CoordinationError> {}`
  - **Purpose**: Creates new user account and completes registration
  - **Parameters**: `reg_data` - WebAuthn registration credential
  - **Returns**: Tuple of (user_id, session_id)
  - **Internal**: Helper for new user registration flow

- `async fn get_account_and_label_from_passkey(reg_data: &RegisterCredential) -> (String, String) {}`
  - **Purpose**: Extracts account name and display label from passkey registration
  - **Parameters**: `reg_data` - WebAuthn registration credential
  - **Returns**: Tuple of (account_name, display_label)
  - **Data**: Field extraction from WebAuthn response

### Authentication Flow

- `pub async fn handle_start_authentication_core( body: &Value, ) -> Result<AuthenticationOptions, CoordinationError> {}`
  - **Purpose**: Initiates WebAuthn authentication challenge
  - **Parameters**: `body` - Authentication request JSON
  - **Returns**: WebAuthn authentication options for client
  - **Flow**: Core authentication initiation logic

- `pub async fn handle_finish_authentication_core( auth_response: AuthenticatorResponse, ) -> Result<(String, String, HeaderMap), CoordinationError> {}`
  - **Purpose**: Completes WebAuthn authentication process
  - **Parameters**: `auth_response` - Client authentication response
  - **Returns**: Tuple of (user_id, session_id, headers)
  - **Flow**: Finalizes authentication and creates session

### Credential Management

- `pub async fn list_credentials_core( user_id: &str, ) -> Result<Vec<PasskeyCredential>, CoordinationError> {}`
  - **Purpose**: Lists all passkey credentials for a user
  - **Parameters**: `user_id` - User identifier
  - **Returns**: Vector of user's passkey credentials
  - **Management**: Credential listing API

- `pub async fn delete_passkey_credential_core( user_id: &str, credential_id: &str, ) -> Result<(), CoordinationError> {}`
  - **Purpose**: Deletes a specific passkey credential
  - **Parameters**: `user_id` - Owner user ID, `credential_id` - Credential to delete
  - **Security**: Validates user ownership before deletion
  - **Management**: Credential deletion API

- `pub async fn update_passkey_credential_core( credential_id: &str, name: &str, display_name: &str, session_user: Option<SessionUser>, ) -> Result<serde_json::Value, CoordinationError> {}`
  - **Purpose**: Updates passkey credential name and display name
  - **Parameters**: `credential_id` - Target credential, `name`/`display_name` - New values, `session_user` - Current user
  - **Returns**: Updated credential data as JSON
  - **Security**: Validates user ownership
  - **Management**: Credential update API

### Test Helper Functions

- `async fn create_test_user_in_db(user_id: &str) -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Creates test user in database for passkey tests
  - **Setup**: Database initialization helper

- `async fn insert_test_passkey_credential( credential_id: &str, user_id: &str, ) -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Inserts test passkey credential for testing
  - **Setup**: Test data creation helper

### Unit Tests

- `async fn test_delete_passkey_credential_core_success() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Validates successful credential deletion

- `async fn test_delete_passkey_credential_core_unauthorized() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Ensures unauthorized deletion attempts fail
  - **Security**: Access control validation

- `async fn test_delete_passkey_credential_core_not_found() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Handles non-existent credential deletion

- `async fn test_list_credentials_core() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Validates credential listing functionality

- `async fn test_update_passkey_credential_core_success() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Tests successful credential updates

- `async fn test_update_passkey_credential_core_unauthorized() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Ensures unauthorized updates fail
  - **Security**: Access control validation

- `async fn test_update_passkey_credential_core_no_session() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Testing**: Handles updates without session

- `fn test_get_passkey_field_mappings_defaults() {}`
  - **Testing**: Validates default passkey field mappings

- `fn test_get_passkey_field_mappings_logic() {}`
  - **Testing**: Tests passkey field mapping logic

## Coordination Module - User Functions (`src/coordination/user.rs`)

**oauth2_passkey/src/coordination/user.rs:**

### User Account Management

- `pub async fn update_user_account( user_id: &str, account: Option<String>, label: Option<String>, ) -> Result<User, CoordinationError> {}`
  - **Purpose**: Updates user account name and display label
  - **Parameters**: `user_id` - Target user, `account`/`label` - Optional new values
  - **Returns**: Updated User record
  - **Management**: User profile update API

- `pub async fn delete_user_account(user_id: &str) -> Result<Vec<String>, CoordinationError> {}`
  - **Purpose**: Completely deletes a user account and all associated data
  - **Parameters**: `user_id` - User account to delete
  - **Returns**: Vector of deleted session IDs
  - **Cascading**: Removes credentials, OAuth2 accounts, and sessions

### User ID Generation

- `pub(super) async fn gen_new_user_id() -> Result<String, CoordinationError> {}`
  - **Purpose**: Generates a unique user ID with collision detection
  - **Returns**: New unique user identifier
  - **Internal**: Helper for user creation
  - **Reliability**: Includes retry logic for ID conflicts

### Test Helper Functions

- `fn create_test_user(id: &str, account: &str, label: &str) -> User {}`
  - **Testing**: Creates mock User struct for testing
  - **Parameters**: ID, account name, and display label

- `fn create_test_credential(id: &str, user_id: &str) -> PasskeyCredential {}`
  - **Testing**: Creates mock PasskeyCredential for testing
  - **Parameters**: Credential ID and owner user ID

- `fn create_test_oauth2_account( id: &str, user_id: &str, provider: &str, provider_user_id: &str, ) -> crate::OAuth2Account {}`
  - **Testing**: Creates mock OAuth2Account for testing
  - **Parameters**: Account ID, owner, provider, and provider user ID

- `async fn gen_new_user_id_with_mock(uuids: &[&str]) -> Result<String, CoordinationError> {}`
  - **Testing**: Mock version of user ID generation with predefined UUIDs
  - **Mocking**: Allows testing of collision scenarios

### Unit Tests

- `async fn test_update_user_account_success() {}`
  - **Testing**: Validates successful user account updates

- `async fn test_update_user_account_not_found() {}`
  - **Testing**: Handles updates for non-existent users

- `async fn test_delete_user_account_success() {}`
  - **Testing**: Validates successful user account deletion
  - **Cascading**: Tests removal of all associated data

- `async fn test_delete_user_account_not_found() {}`
  - **Testing**: Handles deletion of non-existent users

- `async fn test_gen_new_user_id_success() {}`
  - **Testing**: Validates unique user ID generation

- `async fn test_get_all_users() {}`
  - **Testing**: Tests user listing functionality

- `async fn test_get_user() {}`
  - **Testing**: Tests individual user retrieval

- `async fn test_upsert_user() {}`
  - **Testing**: Tests user creation/update logic

- `async fn test_delete_user() {}`
  - **Testing**: Tests user deletion functionality

- `async fn test_gen_new_user_id_max_retries() {}`
  - **Testing**: Tests behavior when max retry limit is reached
  - **Edge Case**: ID collision handling limits

## Library Root Functions (`src/lib.rs`)

**oauth2_passkey/src/lib.rs:**

### Library Initialization

- `pub async fn init() -> Result<(), Box<dyn std::error::Error>> {}`
  - **Purpose**: Initializes the oauth2_passkey library
  - **Returns**: Result indicating successful initialization or error
  - **Setup**: Performs necessary library setup and configuration
  - **Public API**: Main entry point for library initialization

## OAuth2 Module - Configuration Functions (`src/oauth2/config.rs`)

**oauth2_passkey/src/oauth2/config.rs:**

### Unit Tests

- `fn test_oauth2_response_mode_validation_logic() {}`
  - **Testing**: Validates OAuth2 response mode configuration logic
  - **Configuration**: Tests response mode validation rules

- `fn test_oauth2_response_mode_invalid_validation() {}`
  - **Testing**: Ensures invalid response modes are rejected
  - **Validation**: Tests error handling for invalid configurations

- `fn test_oauth2_query_string_construction_logic() {}`
  - **Testing**: Validates OAuth2 query string construction
  - **URL Building**: Tests parameter encoding and formatting

- `fn test_oauth2_redirect_uri_construction_logic() {}`
  - **Testing**: Tests OAuth2 redirect URI construction logic
  - **URL Building**: Validates proper URI formatting

- `fn test_host_prefix_cookie_naming_convention() {}`
  - **Testing**: Tests cookie naming convention based on host prefix
  - **Security**: Validates proper cookie isolation by host

- `fn test_oauth2_csrf_cookie_max_age_parsing_logic() {}`
  - **Testing**: Tests CSRF cookie max age parsing and validation
  - **Security**: Validates CSRF token expiration logic

## OAuth2 Module - Error Functions (`src/oauth2/errors.rs`)

**oauth2_passkey/src/oauth2/errors.rs:**

### Unit Tests

- `fn test_from_util_error() {}`
  - **Testing**: Tests conversion from UtilError to OAuth2Error
  - **Error Mapping**: Validates error type conversion

- `fn test_from_session_error() {}`
  - **Testing**: Tests conversion from SessionError to OAuth2Error
  - **Error Mapping**: Validates session error propagation

- `fn test_error_source_chaining() {}`
  - **Testing**: Tests error source chaining functionality
  - **Error Handling**: Validates error cause tracking

- `fn test_error_conversion_edge_cases() {}`
  - **Testing**: Tests edge cases in error conversion
  - **Error Handling**: Validates unusual error scenarios

## OAuth2 Module - Core Functions (`src/oauth2/main/core.rs`)

**oauth2_passkey/src/oauth2/main/core.rs:**

### Core OAuth2 Functions

- `pub async fn prepare_oauth2_auth_request( headers: HeaderMap, mode: Option<&str>, ) -> Result<(String, HeaderMap), OAuth2Error> {}`
  - **Purpose**: Prepares OAuth2 authorization request with CSRF protection
  - **Parameters**: `headers` - Request headers, `mode` - Optional response mode
  - **Returns**: Tuple of (authorization_url, response_headers)
  - **Security**: Generates CSRF tokens and PKCE challenge

- `pub(crate) async fn get_idinfo_userinfo( auth_response: &AuthResponse, ) -> Result<(GoogleIdInfo, GoogleUserInfo), OAuth2Error> {}`
  - **Purpose**: Retrieves and validates Google ID token and user info
  - **Parameters**: `auth_response` - OAuth2 authorization response
  - **Returns**: Tuple of (GoogleIdInfo, GoogleUserInfo)
  - **Flow**: Token exchange and user data retrieval

### PKCE and Security Functions

- `async fn get_pkce_verifier(auth_response: &AuthResponse) -> Result<String, OAuth2Error> {}`
  - **Purpose**: Retrieves PKCE verifier for authorization code exchange
  - **Parameters**: `auth_response` - OAuth2 authorization response
  - **Returns**: PKCE code verifier string
  - **Security**: PKCE flow implementation

- `async fn verify_nonce( auth_response: &AuthResponse, idinfo: GoogleIdInfo, ) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Verifies nonce in ID token against stored value
  - **Parameters**: `auth_response` - OAuth2 response, `idinfo` - Google ID token info
  - **Security**: Prevents replay attacks

- `pub(crate) async fn csrf_checks( cookies: Cookie, query: &AuthResponse, headers: HeaderMap, ) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Performs comprehensive CSRF validation
  - **Parameters**: `cookies` - Request cookies, `query` - OAuth2 response, `headers` - Request headers
  - **Security**: Multi-layered CSRF protection

### Unit Tests

- `async fn test_oauth2_request_preparation_with_session() {}`
  - **Testing**: Tests OAuth2 request preparation with existing session

- `async fn test_oauth2_request_preparation_without_session() {}`
  - **Testing**: Tests OAuth2 request preparation without session

- `async fn test_state_encoding_decoding_roundtrip() {}`
  - **Testing**: Validates state parameter encoding/decoding

- `async fn test_state_decoding_invalid_base64() {}`
  - **Testing**: Tests error handling for invalid base64 state

- `async fn test_state_decoding_invalid_json() {}`
  - **Testing**: Tests error handling for invalid JSON in state

- `async fn test_oauth2_csrf_cookie_samesite_based_on_response_mode() {}`
  - **Testing**: Validates CSRF cookie SameSite attribute based on response mode

## OAuth2 Module - Google Integration (`src/oauth2/main/google.rs`)

**oauth2_passkey/src/oauth2/main/google.rs:**

### Google API Integration Functions

- `pub(super) async fn fetch_user_data_from_google( access_token: String, ) -> Result<GoogleUserInfo, OAuth2Error> {}`
  - **Purpose**: Fetches user profile data from Google's UserInfo API
  - **Parameters**: `access_token` - Valid Google OAuth2 access token
  - **Returns**: GoogleUserInfo containing user profile details
  - **External**: Makes HTTP request to Google UserInfo endpoint

- `pub(super) async fn exchange_code_for_token( code: String, code_verifier: String, ) -> Result<(String, String), OAuth2Error> {}`
  - **Purpose**: Exchanges authorization code for OAuth2 tokens using PKCE
  - **Parameters**: `code` - Authorization code, `code_verifier` - PKCE code verifier
  - **Returns**: Tuple of (access_token, id_token)
  - **Security**: Implements PKCE flow for secure token exchange

### Unit Tests

- `fn test_google_user_info_deserialization() {}`
  - **Testing**: Tests deserialization of Google UserInfo API response
  - **Data Validation**: Validates JSON parsing of user profile data

- `fn test_oidc_token_response_deserialization() {}`
  - **Testing**: Tests deserialization of OIDC token response
  - **Token Handling**: Validates OAuth2 token response parsing

- `fn test_oidc_token_response_missing_id_token() {}`
  - **Testing**: Tests error handling when ID token is missing
  - **Error Handling**: Validates required field validation

- `fn test_google_user_info_deserialization_missing_required_fields() {}`
  - **Testing**: Tests error handling for missing required user info fields
  - **Data Validation**: Validates field requirement enforcement

- `fn test_google_user_info_deserialization_invalid_json() {}`
  - **Testing**: Tests error handling for malformed JSON responses
  - **Error Handling**: Validates JSON parsing error cases

- `fn test_oidc_token_response_missing_access_token() {}`
  - **Testing**: Tests error handling when access token is missing
  - **Token Handling**: Validates required token field validation

- `fn test_oidc_token_response_invalid_json() {}`
  - **Testing**: Tests error handling for invalid JSON in token response
  - **Error Handling**: Validates token response parsing robustness

- `fn test_id_token_validation_logic() {}`
  - **Testing**: Tests ID token validation and verification logic
  - **Security**: Validates JWT token verification process

## OAuth2 Module - ID Token Verification (`src/oauth2/main/idtoken.rs`)

**oauth2_passkey/src/oauth2/main/idtoken.rs:**

### JWT Token Verification Functions

- `async fn fetch_jwks(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {}`
  - **Purpose**: Fetches JSON Web Key Set (JWKS) from provider with caching
  - **Parameters**: `jwks_url` - URL of the JWKS endpoint
  - **Returns**: JWKS containing public keys for token verification
  - **External**: Makes HTTP request to OAuth2 provider's JWKS endpoint

- `async fn fetch_jwks_no_cache(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {}`
  - **Purpose**: Fetches JWKS directly without caching mechanism
  - **Parameters**: `jwks_url` - URL of the JWKS endpoint
  - **Returns**: Fresh JWKS data from provider
  - **Internal**: Used when cache is disabled or invalid

- `fn from(cache: JwksCache) -> Self {}`
  - **Purpose**: Converts JwksCache into JWKS format
  - **Parameters**: `cache` - Cached JWKS data structure
  - **Conversion**: Type conversion for cached JWKS data

- `fn try_from(cache_data: CacheData) -> Result<Self, Self::Error> {}`
  - **Purpose**: Attempts to convert CacheData into JwksCache
  - **Parameters**: `cache_data` - Generic cache data structure
  - **Returns**: JwksCache or conversion error
  - **Error Handling**: Validates cache data format

- `async fn fetch_jwks_cache(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {}`
  - **Purpose**: Fetches JWKS with intelligent caching strategy
  - **Parameters**: `jwks_url` - URL of the JWKS endpoint
  - **Returns**: JWKS from cache or fresh from provider
  - **Performance**: Optimizes token verification performance

### Key Management Functions

- `fn find_jwk<'a>(jwks: &'a Jwks, kid: &str) -> Option<&'a Jwk> {}`
  - **Purpose**: Finds specific JSON Web Key by key ID
  - **Parameters**: `jwks` - JWKS containing multiple keys, `kid` - Key identifier
  - **Returns**: Reference to matching JWK or None
  - **Lookup**: Key selection for token verification

- `fn decode_base64_url_safe(input: &str) -> Result<Vec<u8>, TokenVerificationError> {}`
  - **Purpose**: Decodes base64url-encoded data safely
  - **Parameters**: `input` - Base64url-encoded string
  - **Returns**: Decoded byte vector
  - **Security**: Safe decoding with proper error handling

- `fn convert_jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, TokenVerificationError> {}`
  - **Purpose**: Converts JWK to format suitable for JWT verification
  - **Parameters**: `jwk` - JSON Web Key from provider
  - **Returns**: DecodingKey for JWT library
  - **Crypto**: Handles RSA, ECDSA, and HMAC key formats

### Token Verification Functions

- `fn decode_token(token: &str) -> Result<IdInfo, TokenVerificationError> {}`
  - **Purpose**: Decodes JWT token payload without verification
  - **Parameters**: `token` - JWT token string
  - **Returns**: IdInfo containing token claims
  - **Parsing**: Extracts claims from token structure

- `fn verify_signature( token: &str, decoding_key: &DecodingKey, alg: Algorithm, ) -> Result<bool, TokenVerificationError> {}`
  - **Purpose**: Verifies JWT token signature using provided key
  - **Parameters**: `token` - JWT token, `decoding_key` - Verification key, `alg` - Signing algorithm
  - **Returns**: Boolean indicating signature validity
  - **Security**: Cryptographic signature verification

- `pub(super) async fn verify_idtoken( token: String, audience: String, ) -> Result<IdInfo, TokenVerificationError> {}`
  - **Purpose**: Complete ID token verification including signature and claims
  - **Parameters**: `token` - ID token string, `audience` - Expected audience claim
  - **Returns**: Verified IdInfo containing token claims
  - **Security**: Full JWT verification with JWKS fetching

### Unit Tests

- `fn test_find_jwk_existing_key() {}`
  - **Testing**: Tests successful JWK lookup with valid key ID
  - **Key Management**: Validates key selection logic

- `fn test_find_jwk_non_existing_key() {}`
  - **Testing**: Tests JWK lookup with non-existent key ID
  - **Error Handling**: Validates None return for missing keys

- `fn test_find_jwk_empty_jwks() {}`
  - **Testing**: Tests JWK lookup in empty key set
  - **Edge Cases**: Validates behavior with no available keys

- `fn test_decode_base64_url_safe_valid() {}`
  - **Testing**: Tests base64url decoding with valid input
  - **Data Validation**: Validates successful decoding

- `fn test_decode_base64_url_safe_empty() {}`
  - **Testing**: Tests base64url decoding with empty input
  - **Edge Cases**: Validates empty string handling

- `fn test_decode_base64_url_safe_invalid() {}`
  - **Testing**: Tests base64url decoding with invalid characters
  - **Error Handling**: Validates malformed input rejection

- `fn test_decode_base64_url_safe_padding() {}`
  - **Testing**: Tests base64url decoding with padding characters
  - **Format Validation**: Validates URL-safe base64 handling

- `fn test_convert_jwk_to_decoding_key_missing_n_component() {}`
  - **Testing**: Tests RSA key conversion with missing modulus
  - **Error Handling**: Validates required RSA component validation

- `fn test_convert_jwk_to_decoding_key_missing_e_component() {}`
  - **Testing**: Tests RSA key conversion with missing exponent
  - **Error Handling**: Validates RSA key completeness

- `fn test_convert_jwk_to_decoding_key_missing_x_component_es256() {}`
  - **Testing**: Tests ECDSA key conversion with missing X coordinate
  - **Crypto Validation**: Validates ECDSA key component requirements

- `fn test_convert_jwk_to_decoding_key_missing_y_component_es256() {}`
  - **Testing**: Tests ECDSA key conversion with missing Y coordinate
  - **Crypto Validation**: Validates elliptic curve key completeness

- `fn test_convert_jwk_to_decoding_key_missing_k_component_hs256() {}`
  - **Testing**: Tests HMAC key conversion with missing key material
  - **Security**: Validates HMAC key requirements

- `fn test_convert_jwk_to_decoding_key_unsupported_algorithm() {}`
  - **Testing**: Tests key conversion with unsupported algorithm
  - **Algorithm Support**: Validates supported crypto algorithms

- `fn test_convert_jwk_to_decoding_key_hs256_valid() {}`
  - **Testing**: Tests successful HMAC key conversion
  - **Crypto**: Validates HMAC key processing

- `fn test_decode_token_invalid_format_too_few_parts() {}`
  - **Testing**: Tests token decoding with insufficient JWT parts
  - **Format Validation**: Validates JWT structure requirements

- `fn test_decode_token_invalid_format_too_many_parts() {}`
  - **Testing**: Tests token decoding with excess JWT parts
  - **Format Validation**: Validates JWT part count

- `fn test_decode_token_invalid_base64_payload() {}`
  - **Testing**: Tests token decoding with malformed base64 payload
  - **Error Handling**: Validates payload decoding

- `fn test_decode_token_invalid_json_payload() {}`
  - **Testing**: Tests token decoding with invalid JSON in payload
  - **Data Validation**: Validates JSON parsing in token

- `fn test_decode_token_valid_payload() {}`
  - **Testing**: Tests successful token payload decoding
  - **Token Processing**: Validates normal decoding flow

- `fn test_verify_signature_invalid_token_format() {}`
  - **Testing**: Tests signature verification with malformed token
  - **Security**: Validates signature verification robustness

- `fn test_verify_signature_invalid_base64_signature() {}`
  - **Testing**: Tests signature verification with invalid signature encoding
  - **Crypto**: Validates signature format requirements

- `fn test_token_verification_error_display() {}`
  - **Testing**: Tests error message formatting for token verification failures
  - **Error Handling**: Validates user-friendly error messages

- `fn test_jwks_cache_conversion() {}`
  - **Testing**: Tests conversion between JWKS cache formats
  - **Data Conversion**: Validates cache data transformations

- `fn test_jwks_cache_invalid_json() {}`
  - **Testing**: Tests JWKS cache handling with invalid JSON data
  - **Error Handling**: Validates cache data validation

## OAuth2 Module - Utility Functions (`src/oauth2/main/utils.rs`)

**oauth2_passkey/src/oauth2/main/utils.rs:**

### State Management Functions

- `pub(super) fn encode_state(state_params: StateParams) -> Result<String, OAuth2Error> {}`
  - **Purpose**: Encodes OAuth2 state parameters into base64url string
  - **Parameters**: `state_params` - State data including CSRF token and session info
  - **Returns**: Base64url-encoded state string
  - **Security**: Enables secure state transfer in OAuth2 flow

- `pub(crate) fn decode_state(state: &str) -> Result<StateParams, OAuth2Error> {}`
  - **Purpose**: Decodes base64url state string back to StateParams
  - **Parameters**: `state` - Base64url-encoded state string
  - **Returns**: Decoded StateParams structure
  - **Security**: Validates and reconstructs OAuth2 state

### Token Storage Functions

- `pub(super) async fn store_token_in_cache( token_type: &str, token: &str, ttl: u64, expires_at: DateTime<Utc>, user_agent: Option<String>, ) -> Result<String, OAuth2Error> {}`
  - **Purpose**: Stores OAuth2 token in cache with metadata
  - **Parameters**: Token type, token value, TTL, expiration time, user agent
  - **Returns**: Token identifier for retrieval
  - **Management**: Handles token lifecycle and expiration

- `pub(super) async fn generate_store_token( token_type: &str, ttl: u64, expires_at: DateTime<Utc>, user_agent: Option<String>, ) -> Result<(String, String), OAuth2Error> {}`
  - **Purpose**: Generates new token and stores it in cache
  - **Parameters**: Token type, TTL, expiration time, user agent
  - **Returns**: Tuple of (token_value, token_id)
  - **Security**: Creates cryptographically secure tokens

- `pub(super) async fn get_token_from_store<T>( token_type: &str, token_id: &str, ) -> Result<T, OAuth2Error> where T: TryFrom<CacheData, Error = OAuth2Error>, {}`
  - **Purpose**: Retrieves and deserializes token from cache store
  - **Parameters**: Token type and identifier
  - **Returns**: Deserialized token data
  - **Generic**: Type-safe token retrieval

- `pub(super) async fn remove_token_from_store( token_type: &str, token_id: &str, ) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Removes token from cache store
  - **Parameters**: Token type and identifier
  - **Management**: Cleanup and token invalidation

### Security Validation Functions

- `pub(crate) async fn validate_origin( headers: &HeaderMap, auth_url: &str, ) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Validates request origin against authorization URL
  - **Parameters**: Request headers and expected authorization URL
  - **Security**: Prevents CSRF attacks by validating request origin

- `pub(super) fn get_client() -> reqwest::Client {}`
  - **Purpose**: Returns configured HTTP client for OAuth2 requests
  - **Returns**: Pre-configured reqwest client
  - **Internal**: Centralized HTTP client configuration

### Session Management Functions

- `pub(crate) async fn get_uid_from_stored_session_by_state_param( state_params: &StateParams, ) -> Result<Option<SessionUser>, OAuth2Error> {}`
  - **Purpose**: Retrieves user session data using state parameters
  - **Parameters**: OAuth2 state parameters
  - **Returns**: Optional SessionUser if session exists
  - **Flow**: Links OAuth2 flow to existing user session

- `pub(crate) async fn delete_session_and_misc_token_from_store( state_params: &StateParams, ) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Cleans up session and temporary tokens after OAuth2 flow
  - **Parameters**: State parameters containing cleanup identifiers
  - **Management**: Post-flow cleanup operations

- `pub(crate) async fn get_mode_from_stored_session( mode_id: &str, ) -> Result<Option<OAuth2Mode>, OAuth2Error> {}`
  - **Purpose**: Retrieves OAuth2 response mode from stored session
  - **Parameters**: Mode identifier
  - **Returns**: Optional OAuth2Mode configuration
  - **Flow**: Determines response handling based on stored mode

### Unit Tests

- `fn test_encode_decode_state() {}`
  - **Testing**: Tests state encoding and decoding roundtrip
  - **Data Integrity**: Validates state parameter preservation

- `fn test_encode_decode_state_minimal() {}`
  - **Testing**: Tests state handling with minimal required fields
  - **Edge Cases**: Validates minimal state parameter handling

- `fn test_decode_state_invalid_base64() {}`
  - **Testing**: Tests error handling for malformed base64 state
  - **Error Handling**: Validates input validation

- `fn test_decode_state_invalid_json() {}`
  - **Testing**: Tests error handling for invalid JSON in state
  - **Data Validation**: Validates JSON parsing error handling

- `async fn test_validate_origin_success() {}`
  - **Testing**: Tests successful origin validation
  - **Security**: Validates proper origin checking

- `async fn test_validate_origin_with_referer() {}`
  - **Testing**: Tests origin validation using Referer header
  - **Security**: Validates fallback origin validation

- `async fn test_validate_origin_mismatch() {}`
  - **Testing**: Tests rejection of mismatched origins
  - **Security**: Validates CSRF protection

- `async fn test_validate_origin_missing() {}`
  - **Testing**: Tests handling of missing origin headers
  - **Security**: Validates strict origin requirements

- `async fn test_store_and_get_token_from_cache() {}`
  - **Testing**: Tests token storage and retrieval cycle
  - **Token Management**: Validates cache operations

- `async fn test_get_token_from_store_not_found() {}`
  - **Testing**: Tests handling of non-existent tokens
  - **Error Handling**: Validates missing token behavior

- `async fn test_remove_token_from_store() {}`
  - **Testing**: Tests token removal from cache
  - **Management**: Validates cleanup operations

- `async fn test_generate_store_token() {}`
  - **Testing**: Tests token generation and storage
  - **Security**: Validates token creation process

- `async fn test_generate_store_token_randomness() {}`
  - **Testing**: Tests token uniqueness and randomness
  - **Security**: Validates cryptographic randomness

- `async fn test_get_uid_from_stored_session_no_misc_id() {}`
  - **Testing**: Tests session retrieval without misc ID
  - **Edge Cases**: Validates optional parameter handling

- `async fn test_get_uid_from_stored_session_token_not_found() {}`
  - **Testing**: Tests handling of missing session tokens
  - **Error Handling**: Validates session not found scenarios

- `async fn test_delete_session_and_misc_token_no_misc_id() {}`
  - **Testing**: Tests cleanup without misc token ID
  - **Management**: Validates partial cleanup operations

- `async fn test_delete_session_and_misc_token_token_not_found() {}`
  - **Testing**: Tests cleanup with non-existent tokens
  - **Error Handling**: Validates cleanup robustness

- `async fn test_get_mode_from_stored_session_not_found() {}`
  - **Testing**: Tests mode retrieval for non-existent sessions
  - **Error Handling**: Validates missing mode handling

- `async fn test_get_mode_from_stored_session_valid_mode() {}`
  - **Testing**: Tests successful mode retrieval
  - **Flow**: Validates mode configuration retrieval

- `async fn test_get_mode_from_stored_session_invalid_mode() {}`
  - **Testing**: Tests handling of invalid mode data
  - **Data Validation**: Validates mode data integrity

- `async fn test_cache_token_with_zero_ttl() {}`
  - **Testing**: Tests token caching with zero TTL
  - **Edge Cases**: Validates immediate expiration handling

- `async fn test_cache_token_with_max_ttl() {}`
  - **Testing**: Tests token caching with maximum TTL
  - **Edge Cases**: Validates long-term caching

- `async fn test_concurrent_token_operations() {}`
  - **Testing**: Tests concurrent token operations
  - **Concurrency**: Validates thread safety

- `async fn test_token_storage_with_different_prefixes() {}`
  - **Testing**: Tests token isolation by prefix
  - **Management**: Validates token namespace separation

### Additional Utility Tests

- `async fn test_token_storage_edge_cases() {}`
  - **Testing**: Tests edge cases in token storage operations
  - **Edge Cases**: Validates unusual parameter combinations

- `async fn test_token_overwrite_same_id() {}`
  - **Testing**: Tests behavior when overwriting existing token IDs
  - **Management**: Validates token replacement logic

- `async fn test_multiple_remove_operations() {}`
  - **Testing**: Tests multiple consecutive remove operations
  - **Concurrency**: Validates idempotent removal

- `async fn test_cache_operations_with_past_expiration() {}`
  - **Testing**: Tests cache operations with already expired tokens
  - **Edge Cases**: Validates expiration handling

- `async fn test_cache_serialization_round_trip() {}`
  - **Testing**: Tests cache data serialization and deserialization
  - **Data Integrity**: Validates data preservation

- `async fn test_generate_store_token_consistency() {}`
  - **Testing**: Tests consistency of token generation process
  - **Security**: Validates deterministic aspects of token creation

## OAuth2 Module - Main Module (`src/oauth2/mod.rs`)

**oauth2_passkey/src/oauth2/mod.rs:**

### Module Initialization

- `pub(crate) async fn init() -> Result<(), errors::OAuth2Error> {}`
  - **Purpose**: Initializes OAuth2 module including storage and cache
  - **Returns**: Result indicating successful initialization
  - **Setup**: Configures OAuth2 subsystem dependencies

## OAuth2 Storage - PostgreSQL Implementation (`src/oauth2/storage/postgres.rs`)

**oauth2_passkey/src/oauth2/storage/postgres.rs:**

### Database Schema Management

- `pub(super) async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Creates OAuth2 account tables in PostgreSQL database
  - **Parameters**: `pool` - PostgreSQL connection pool
  - **Database**: Initializes required schema for OAuth2 accounts

- `pub(super) async fn validate_oauth2_tables_postgres( pool: &Pool<Postgres>, ) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Validates existing OAuth2 tables in PostgreSQL
  - **Parameters**: `pool` - PostgreSQL connection pool
  - **Database**: Ensures table structure matches expected schema

### Account Query Functions

- `pub(super) async fn get_oauth2_accounts_by_field_postgres( pool: &Pool<Postgres>, field: &AccountSearchField, ) -> Result<Vec<OAuth2Account>, OAuth2Error> {}`
  - **Purpose**: Retrieves OAuth2 accounts by specified search field
  - **Parameters**: `pool` - Database pool, `field` - Search criteria
  - **Returns**: Vector of matching OAuth2Account records
  - **Database**: Flexible account lookup functionality

- `pub(super) async fn get_oauth2_account_by_provider_postgres( pool: &Pool<Postgres>, provider: &str, provider_user_id: &str, ) -> Result<Option<OAuth2Account>, OAuth2Error> {}`
  - **Purpose**: Retrieves specific OAuth2 account by provider and user ID
  - **Parameters**: Database pool, provider name, provider-specific user ID
  - **Returns**: Optional OAuth2Account if found
  - **Database**: Provider-specific account lookup

### Account Modification Functions

- `pub(super) async fn upsert_oauth2_account_postgres( pool: &Pool<Postgres>, account: OAuth2Account, ) -> Result<OAuth2Account, OAuth2Error> {}`
  - **Purpose**: Creates new or updates existing OAuth2 account in PostgreSQL
  - **Parameters**: Database pool and OAuth2Account data
  - **Returns**: Updated OAuth2Account with database-generated fields
  - **Database**: Atomic account creation/update operation

- `pub(super) async fn delete_oauth2_accounts_by_field_postgres( pool: &Pool<Postgres>, field: &AccountSearchField, ) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Deletes OAuth2 accounts matching specified criteria
  - **Parameters**: Database pool and search field criteria
  - **Database**: Bulk account deletion functionality

## OAuth2 Storage - SQLite Implementation (`src/oauth2/storage/sqlite.rs`)

**oauth2_passkey/src/oauth2/storage/sqlite.rs:**

### Database Schema Management

- `pub(super) async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Creates OAuth2 account tables in SQLite database
  - **Parameters**: `pool` - SQLite connection pool
  - **Database**: Initializes required schema for OAuth2 accounts

- `pub(super) async fn validate_oauth2_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Validates existing OAuth2 tables in SQLite
  - **Parameters**: `pool` - SQLite connection pool
  - **Database**: Ensures table structure matches expected schema

### Account Query Functions

- `pub(super) async fn get_oauth2_accounts_by_field_sqlite( pool: &Pool<Sqlite>, field: &AccountSearchField, ) -> Result<Vec<OAuth2Account>, OAuth2Error> {}`
  - **Purpose**: Retrieves OAuth2 accounts by specified search field
  - **Parameters**: Database pool and search criteria
  - **Returns**: Vector of matching OAuth2Account records
  - **Database**: Flexible account lookup for SQLite

- `pub(super) async fn get_oauth2_account_by_provider_sqlite( pool: &Pool<Sqlite>, provider: &str, provider_user_id: &str, ) -> Result<Option<OAuth2Account>, OAuth2Error> {}`
  - **Purpose**: Retrieves specific OAuth2 account by provider and user ID
  - **Parameters**: Database pool, provider name, provider-specific user ID
  - **Returns**: Optional OAuth2Account if found
  - **Database**: Provider-specific account lookup for SQLite

### Account Modification Functions

- `pub(super) async fn upsert_oauth2_account_sqlite( pool: &Pool<Sqlite>, account: OAuth2Account, ) -> Result<OAuth2Account, OAuth2Error> {}`
  - **Purpose**: Creates new or updates existing OAuth2 account in SQLite
  - **Parameters**: Database pool and OAuth2Account data
  - **Returns**: Updated OAuth2Account with database-generated fields
  - **Database**: Atomic account creation/update operation

- `pub(super) async fn delete_oauth2_accounts_by_field_sqlite( pool: &Pool<Sqlite>, field: &AccountSearchField, ) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Deletes OAuth2 accounts matching specified criteria
  - **Parameters**: Database pool and search field criteria
  - **Database**: Bulk account deletion functionality

## OAuth2 Storage - Store Type Interface (`src/oauth2/storage/store_type.rs`)

**oauth2_passkey/src/oauth2/storage/store_type.rs:**

### Account Management Functions

- `pub(crate) async fn gen_unique_account_id() -> Result<String, OAuth2Error> {}`
  - **Purpose**: Generates unique identifier for new OAuth2 account
  - **Returns**: Cryptographically secure unique account ID
  - **Security**: Ensures account ID uniqueness across system

- `pub(crate) async fn init() -> Result<(), OAuth2Error> {}`
  - **Purpose**: Initializes OAuth2 storage subsystem and creates required tables
  - **Returns**: Result indicating successful initialization
  - **Setup**: Database schema setup and validation

- `pub(crate) async fn get_oauth2_accounts( user_id: &str, ) -> Result<Vec<OAuth2Account>, OAuth2Error> {}`
  - **Purpose**: Retrieves all OAuth2 accounts for specified user
  - **Parameters**: `user_id` - User identifier
  - **Returns**: Vector of OAuth2Account records for user
  - **Database**: User-specific account lookup

- `pub(crate) async fn get_oauth2_accounts_by( field: AccountSearchField, ) -> Result<Vec<OAuth2Account>, OAuth2Error> {}`
  - **Purpose**: Retrieves OAuth2 accounts using flexible search criteria
  - **Parameters**: `field` - Search criteria (user ID, account ID, provider)
  - **Returns**: Vector of matching OAuth2Account records
  - **Database**: Flexible account search functionality

- `pub(crate) async fn get_oauth2_account_by_provider( provider: &str, provider_user_id: &str, ) -> Result<Option<OAuth2Account>, OAuth2Error> {}`
  - **Purpose**: Retrieves specific OAuth2 account by provider and provider user ID
  - **Parameters**: Provider name and provider-specific user identifier
  - **Returns**: Optional OAuth2Account if found
  - **Database**: Provider-specific account lookup

- `pub(crate) async fn upsert_oauth2_account( mut account: OAuth2Account, ) -> Result<OAuth2Account, OAuth2Error> {}`
  - **Purpose**: Creates new or updates existing OAuth2 account
  - **Parameters**: OAuth2Account data structure
  - **Returns**: Updated OAuth2Account with database-generated fields
  - **Database**: Atomic account creation/update operation

- `pub(crate) async fn delete_oauth2_accounts_by( field: AccountSearchField, ) -> Result<(), OAuth2Error> {}`
  - **Purpose**: Deletes OAuth2 accounts matching specified search criteria
  - **Parameters**: `field` - Search criteria for account selection
  - **Database**: Bulk account deletion with flexible criteria

### Test Helper Functions

- `async fn create_test_account( user_id: &str, provider: &str, provider_user_id: &str, ) -> OAuth2Account {}`
  - **Testing**: Creates test OAuth2 account with specified parameters
  - **Test Helpers**: Provides consistent test data creation

- `async fn create_test_user_and_account( user_id: &str, provider: &str, provider_user_id: &str, ) -> OAuth2Account {}`
  - **Testing**: Creates test user and associated OAuth2 account
  - **Test Helpers**: Comprehensive test setup with user and account

- `fn generate_unique_test_id(base: &str) -> String {}`
  - **Testing**: Generates unique identifier for test scenarios
  - **Test Helpers**: Ensures unique test data across test runs

### Unit Tests

- `async fn test_gen_unique_account_id() {}`
  - **Testing**: Tests unique account ID generation
  - **Security**: Validates ID uniqueness and randomness

- `async fn test_init_creates_tables() {}`
  - **Testing**: Tests initialization creates required database tables
  - **Database**: Validates schema creation

- `async fn test_upsert_oauth2_account_create() {}`
  - **Testing**: Tests creation of new OAuth2 account
  - **Database**: Validates account creation workflow

- `async fn test_upsert_oauth2_account_empty_user_id() {}`
  - **Testing**: Tests account creation with empty user ID
  - **Error Handling**: Validates required field validation

- `async fn test_upsert_oauth2_account_update() {}`
  - **Testing**: Tests update of existing OAuth2 account
  - **Database**: Validates account update workflow

- `async fn test_get_oauth2_accounts_by_user_id() {}`
  - **Testing**: Tests account retrieval by user ID
  - **Database**: Validates user-specific account lookup

- `async fn test_get_oauth2_accounts_by_id() {}`
  - **Testing**: Tests account retrieval by account ID
  - **Database**: Validates account ID lookup

- `async fn test_get_oauth2_accounts_by_provider() {}`
  - **Testing**: Tests account retrieval by provider
  - **Database**: Validates provider-based account lookup

- `async fn test_get_oauth2_account_by_provider() {}`
  - **Testing**: Tests single account retrieval by provider and provider user ID
  - **Database**: Validates provider-specific account lookup

- `async fn test_delete_oauth2_accounts_by_id() {}`
  - **Testing**: Tests account deletion by account ID
  - **Database**: Validates targeted account deletion

- `async fn test_delete_oauth2_accounts_by_user_id() {}`
  - **Testing**: Tests deletion of all accounts for specific user
  - **Database**: Validates user account cleanup

- `async fn test_get_oauth2_accounts_empty_result() {}`
  - **Testing**: Tests account queries with no matching results
  - **Edge Cases**: Validates empty result handling

- `async fn test_account_search_field_variants() {}`
  - **Purpose**: Tests OAuth2 account search functionality with different field types
  - **Testing**: Tests search by different account field criteria and filters
  - **Type**: Async unit test function for account search field validation

- `async fn test_concurrent_account_operations() {}`
  - **Purpose**: Tests OAuth2 account operations under concurrent access patterns
  - **Testing**: Tests thread safety and concurrent operation handling for accounts
  - **Type**: Async unit test function for account operation concurrency validation

**oauth2_passkey/src/oauth2/types.rs:**
- `fn default() -> Self {}`
  - **Purpose**: Creates default instance for OAuth2 types
  - **Flow**: Provides default initialization for OAuth2 data structures
  - **Type**: Default implementation for OAuth2 types

- `fn from(google_user: GoogleUserInfo) -> Self {}`
  - **Purpose**: Converts Google user info into OAuth2 user representation
  - **Parameters**: google_user - Google user information from API
  - **Conversion**: Maps Google-specific fields to OAuth2 standard fields
  - **Type**: Google OAuth2 user conversion

- `fn from(idinfo: GoogleIdInfo) -> Self {}`
  - **Purpose**: Converts Google ID token info into OAuth2 user representation
  - **Parameters**: idinfo - Google ID token information
  - **Conversion**: Maps Google ID token claims to OAuth2 user fields
  - **Type**: Google ID token conversion

- `fn from(data: StoredToken) -> Self {}`
  - **Purpose**: Converts stored token data into OAuth2 token representation
  - **Parameters**: data - Token data from storage
  - **Conversion**: Maps storage format to OAuth2 token structure
  - **Type**: Token data conversion

- `fn try_from(data: CacheData) -> Result<Self, Self::Error> {}`
  - **Purpose**: Attempts to convert cache data into OAuth2 representation
  - **Parameters**: data - Cached OAuth2 data
  - **Returns**: Result with converted data or conversion error
  - **Conversion**: Fallible conversion from cache format
  - **Type**: Cache data conversion

- `pub fn as_str(&self) -> &'static str {}`
  - **Purpose**: Returns string representation of OAuth2 type
  - **Returns**: Static string representing the type
  - **Type**: String representation for OAuth2 enums

- `fn from_str(s: &str) -> Result<Self, Self::Err> {}`
  - **Purpose**: Parses string into OAuth2 type
  - **Parameters**: s - String to parse
  - **Returns**: Result with parsed type or parsing error
  - **Type**: String parsing for OAuth2 enums

- `fn test_from_google_user_info() {}`
  - **Testing**: Tests conversion from Google user information to OAuth2 user
  - **Type**: Google user conversion test

- `fn test_from_google_id_info() {}`
  - **Testing**: Tests conversion from Google ID token info to OAuth2 user
  - **Type**: Google ID token conversion test

- `fn test_stored_token_cache_data_conversion() {}`
  - **Testing**: Tests conversion between stored token and cache data formats
  - **Type**: Token conversion test

**oauth2_passkey/src/passkey/main/aaguid.rs:**

- `fn default() -> Self {}`
  - **Purpose**: Creates default instance for AAGUID-related types
  - **Type**: Default implementation for AAGUID data structures

- `pub(crate) async fn store_aaguids() -> Result<(), PasskeyError> {}`
  - **Purpose**: Stores AAGUID metadata from FIDO Alliance in cache
  - **Returns**: Result with success or passkey error
  - **Management**: Populates authenticator information database
  - **Type**: AAGUID metadata initialization

- `async fn store_aaguid_in_cache(json: String) -> Result<(), PasskeyError> {}`
  - **Purpose**: Caches individual AAGUID metadata from JSON
  - **Parameters**: json - AAGUID metadata in JSON format
  - **Returns**: Result with success or passkey error
  - **Internal**: Helper for AAGUID storage operations
  - **Type**: AAGUID cache storage

- `pub async fn get_authenticator_info( aaguid: &str, ) -> Result<Option<AuthenticatorInfo>, PasskeyError> {}`
  - **Purpose**: Retrieves authenticator information by AAGUID
  - **Parameters**: aaguid - Authenticator Attestation GUID
  - **Returns**: Result with optional authenticator info or error
  - **Type**: AAGUID information lookup

- `pub async fn get_authenticator_info_batch( aaguids: &[String], ) -> Result<HashMap<String, AuthenticatorInfo>, PasskeyError> {}`
  - **Purpose**: Retrieves multiple authenticator information records by AAGUIDs
  - **Parameters**: aaguids - Array of Authenticator Attestation GUIDs
  - **Returns**: Result with HashMap of AAGUID to authenticator info or error
  - **Type**: Batch AAGUID information lookup

- `async fn test_store_aaguid_in_cache_success() {}`
  - **Testing**: Tests successful AAGUID metadata storage in cache
  - **Type**: AAGUID cache storage test

- `async fn test_store_aaguid_in_cache_invalid_json() {}`
  - **Testing**: Tests AAGUID cache storage with invalid JSON input
  - **Type**: AAGUID cache error handling test

- `fn test_authenticator_info_parsing() {}`
  - **Testing**: Tests parsing of authenticator information from JSON
  - **Type**: AAGUID JSON parsing test

- `fn test_authenticator_info_parsing_null_icons() {}`
  - **Testing**: Tests parsing authenticator info with null icon fields
  - **Type**: AAGUID parsing edge case test

- `fn test_authenticator_info_parsing_missing_fields() {}`
  - **Testing**: Tests parsing authenticator info with missing required fields
  - **Type**: AAGUID parsing error handling test

- `fn test_aaguid_format_validation() {}`
  - **Testing**: Tests AAGUID format validation and UUID parsing
  - **Type**: AAGUID format validation test

- `async fn test_get_authenticator_info_not_found() {}`
  - **Testing**: Tests retrieval of non-existent authenticator info
  - **Type**: AAGUID lookup error handling test

- `async fn test_get_authenticator_info_batch_empty() {}`
  - **Testing**: Tests batch retrieval with empty AAGUID array
  - **Type**: AAGUID batch processing edge case test

- `async fn test_get_authenticator_info_success() {}`
  - **Testing**: Tests successful single AAGUID info retrieval
  - **Type**: AAGUID lookup success test

- `async fn test_get_authenticator_info_batch_with_data() {}`
  - **Testing**: Tests successful batch AAGUID info retrieval
  - **Type**: AAGUID batch processing success test

- `async fn test_get_authenticator_info_corrupted_cache() {}`
  - **Testing**: Tests handling of corrupted cache data
  - **Type**: AAGUID cache corruption handling test

- `async fn test_store_aaguid_in_cache_empty_object() {}`
  - **Testing**: Tests caching of empty JSON objects
  - **Type**: AAGUID cache edge case test

- `async fn test_get_authenticator_info_batch_duplicates() {}`
  - **Testing**: Tests batch retrieval with duplicate AAGUID entries
  - **Type**: AAGUID batch processing duplicate handling test

**oauth2_passkey/src/passkey/main/attestation/core.rs:**

- `pub(crate) fn verify_attestation( attestation: &AttestationObject, client_data: &[u8], ) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies WebAuthn attestation object and client data
  - **Parameters**: attestation - WebAuthn attestation object, client_data - Client data JSON bytes
  - **Returns**: Result with success or passkey error
  - **Security**: Core attestation verification for WebAuthn registration
  - **Type**: WebAuthn attestation verification

- `pub(crate) fn extract_aaguid(attestation: &AttestationObject) -> Result<String, PasskeyError> {}`
  - **Purpose**: Extracts AAGUID from attestation object for authenticator identification
  - **Parameters**: attestation - WebAuthn attestation object
  - **Returns**: Result with AAGUID string or passkey error
  - **Type**: AAGUID extraction from attestation

- `fn create_test_attestation(fmt: &str, auth_data_len: usize) -> AttestationObject {}`
  - **Testing**: Creates test attestation object with specified format and data length
  - **Parameters**: fmt - Attestation format, auth_data_len - Authentication data length
  - **Returns**: Test attestation object
  - **Type**: Test attestation creation helper

- `fn test_verify_attestation_unsupported_format() {}`
  - **Testing**: Tests attestation verification with unsupported formats
  - **Type**: Attestation format validation test

- `fn test_extract_aaguid_success() {}`
  - **Testing**: Tests successful AAGUID extraction from attestation
  - **Type**: AAGUID extraction success test

- `fn test_extract_aaguid_too_short() {}`
  - **Testing**: Tests AAGUID extraction with insufficient authentication data
  - **Type**: AAGUID extraction error handling test

- `fn test_verify_attestation_format_recognition() {}`
  - **Testing**: Tests recognition of different attestation formats
  - **Type**: Attestation format recognition test

- `fn test_verify_attestation_client_data_hash_created() {}`
  - **Testing**: Tests attestation verification with proper client data hash
  - **Type**: Client data hash verification test

- `fn test_extract_aaguid_with_different_uuids() {}`
  - **Testing**: Tests AAGUID extraction with various UUID formats
  - **Type**: AAGUID UUID format test

- `fn test_extract_aaguid_boundary_conditions() {}`
  - **Testing**: Tests AAGUID extraction with boundary conditions
  - **Type**: AAGUID extraction edge case test

- `fn test_verify_attestation_error_propagation() {}`
  - **Testing**: Tests proper error propagation in attestation verification
  - **Type**: Attestation error handling test

- `fn test_extract_aaguid_malformed_data() {}`
  - **Testing**: Tests AAGUID extraction with malformed authentication data
  - **Type**: AAGUID extraction malformed data test

- `fn test_verify_attestation_empty_client_data() {}`
  - **Testing**: Tests attestation verification with empty client data
  - **Type**: Client data validation test

- `fn test_verify_attestation_large_client_data() {}`
  - **Testing**: Tests attestation verification with large client data payloads
  - **Type**: Client data size validation test

**oauth2_passkey/src/passkey/main/attestation/none.rs:**

- `pub(super) fn verify_none_attestation(attestation: &AttestationObject) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies "none" format attestation which provides no cryptographic attestation
  - **Parameters**: attestation - WebAuthn attestation object with "none" format
  - **Returns**: Result with success or passkey error
  - **Security**: Validates basic attestation structure without certificate verification
  - **Type**: None attestation verification

- `fn verify_none_attestation_with_config( attestation: &AttestationObject, test_rp_id: &str, user_verification_required: bool, ) -> Result<(), PasskeyError> {}`
  - **Testing**: Helper for testing none attestation with configurable parameters
  - **Parameters**: attestation - Test attestation, test_rp_id - RP ID for testing, user_verification_required - UV requirement
  - **Returns**: Result with success or passkey error
  - **Type**: Test helper for none attestation

- `fn create_valid_public_key_cbor() -> Vec<u8> {}`
  - **Testing**: Creates valid CBOR-encoded public key for testing
  - **Returns**: CBOR-encoded public key bytes
  - **Type**: Test data generation helper

- `fn create_auth_data( rp_id: &str, user_present: bool, user_verified: bool, attested_cred_data: bool, cred_id_len: u16, include_public_key: bool, ) -> Vec<u8> {}`
  - **Testing**: Creates authentication data with specified parameters
  - **Parameters**: Various flags and options for authentication data structure
  - **Returns**: Authentication data bytes
  - **Type**: Test authentication data generation

- `fn create_test_attestation_with_params( empty_att_stmt: bool, rp_id: &str, user_present: bool, user_verified: bool, attested_cred_data: bool, cred_id_len: u16, include_public_key: bool, ) -> AttestationObject {}`
  - **Testing**: Creates test attestation object with configurable parameters
  - **Parameters**: Various attestation configuration options
  - **Returns**: Test attestation object
  - **Type**: Test attestation generation helper

- `fn create_valid_attestation() -> AttestationObject {}`
  - **Testing**: Creates valid test attestation object for none format
  - **Returns**: Valid test attestation object
  - **Type**: Test data generation helper

- `fn test_verify_none_attestation_success() {}`
  - **Testing**: Tests successful none attestation verification
  - **Type**: None attestation success test

- `fn test_verify_none_attestation_non_empty_att_stmt() {}`
  - **Testing**: Tests none attestation with non-empty attestation statement
  - **Type**: None attestation validation test

- `fn test_verify_none_attestation_invalid_rp_id_hash() {}`
  - **Testing**: Tests none attestation with invalid RP ID hash
  - **Type**: RP ID validation test

- `fn test_verify_none_attestation_user_present_not_set() {}`
  - **Testing**: Tests none attestation without user presence flag
  - **Type**: User presence validation test

- `fn test_verify_none_attestation_no_attested_cred_data() {}`
  - **Testing**: Tests none attestation without attested credential data
  - **Type**: Credential data validation test

- `fn test_verify_none_attestation_user_verification_required() {}`
  - **Testing**: Tests none attestation with user verification requirements
  - **Type**: User verification validation test

- `fn test_verify_none_attestation_invalid_public_key() {}`
  - **Testing**: Tests none attestation with invalid public key
  - **Type**: Public key validation test

- `fn test_verify_none_attestation_auth_data_too_short_basic() {}`
  - **Testing**: Tests none attestation with insufficient authentication data
  - **Type**: Authentication data length validation test

- `fn test_verify_none_attestation_auth_data_too_short_for_attested_data() {}`
  - **Testing**: Tests none attestation with insufficient data for attested credentials
  - **Type**: Attested credential data length validation test

- `fn test_verify_none_attestation_invalid_credential_id_length() {}`
  - **Testing**: Tests none attestation with invalid credential ID length
  - **Type**: Credential ID validation test

- `fn test_verify_none_attestation_zero_credential_id_length() {}`
  - **Testing**: Tests none attestation with zero-length credential ID
  - **Type**: Credential ID edge case test

- `fn test_verify_none_attestation_malformed_cbor_public_key() {}`
  - **Testing**: Tests none attestation with malformed CBOR public key
  - **Type**: CBOR public key validation test

- `fn test_verify_none_attestation_different_flag_combinations() {}`
  - **Testing**: Tests none attestation with various flag combinations
  - **Type**: Authentication data flag validation test

- `fn test_verify_none_attestation_boundary_credential_id_lengths() {}`
  - **Testing**: Tests none attestation with boundary credential ID lengths
  - **Type**: Credential ID boundary condition test

- `fn test_verify_none_attestation_empty_rp_id() {}`
  - **Testing**: Tests none attestation with empty RP ID
  - **Type**: RP ID edge case test

- `fn test_verify_none_attestation_very_long_rp_id() {}`
  - **Testing**: Tests none attestation with very long RP ID
  - **Type**: RP ID length validation test

- `fn test_verify_none_attestation_minimal_auth_data_length() {}`
  - **Testing**: Tests none attestation with minimal authentication data length
  - **Type**: Authentication data minimum length test

- `fn test_verify_none_attestation_invalid_public_key_coordinates() {}`
  - **Testing**: Tests none attestation with invalid public key coordinates
  - **Type**: Public key coordinate validation test

- `fn test_verify_none_attestation_exactly_minimum_attested_data_length() {}`
  - **Testing**: Tests none attestation with exact minimum attested data length
  - **Type**: Boundary condition test for attested data

- `fn test_verify_none_attestation_maximum_valid_credential_id() {}`
  - **Testing**: Tests none attestation with maximum valid credential ID length
  - **Type**: Credential ID maximum length test

- `fn test_verify_none_attestation_truncated_public_key_cbor() {}`
  - **Testing**: Tests none attestation with truncated CBOR public key
  - **Type**: CBOR public key truncation test

- `fn test_verify_none_attestation_all_optional_flags_set() {}`
  - **Testing**: Tests none attestation with all optional flags enabled
  - **Type**: Authentication data flag combination test

- `fn test_verify_none_attestation_rp_id_unicode_characters() {}`
  - **Testing**: Tests none attestation with Unicode characters in RP ID
  - **Type**: RP ID Unicode handling test

- `fn test_verify_none_attestation_user_verification_edge_cases() {}`
  - **Testing**: Tests edge cases in user verification for none attestation
  - **Type**: User verification boundary condition test

**oauth2_passkey/src/passkey/main/attestation/packed.rs:**

- `pub(super) fn verify_packed_attestation( auth_data: &[u8], client_data_hash: &[u8], att_stmt: &Vec<(CborValue, CborValue)>, ) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies "packed" format attestation with certificate or self-attestation
  - **Parameters**: auth_data - Authentication data, client_data_hash - Hash of client data, att_stmt - Attestation statement
  - **Returns**: Result with success or passkey error
  - **Security**: Validates packed attestation format with cryptographic verification
  - **Type**: Packed attestation verification

- `fn verify_packed_attestation_cert( cert: &X509Certificate, auth_data: &[u8], ) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies packed attestation using X.509 certificate
  - **Parameters**: cert - X.509 certificate, auth_data - Authentication data
  - **Returns**: Result with success or passkey error
  - **Security**: Certificate-based attestation verification
  - **Type**: Certificate attestation verification

- `fn verify_certificate_chain(x5c: &[Vec<u8>]) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies X.509 certificate chain validity
  - **Parameters**: x5c - Array of certificate bytes
  - **Returns**: Result with success or passkey error
  - **Security**: Certificate chain validation
  - **Type**: Certificate chain verification

- `fn verify_self_attestation( auth_data: &[u8], signed_data: &[u8], signature: &[u8], ) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies self-attestation using embedded credential public key
  - **Parameters**: auth_data - Authentication data, signed_data - Data to verify, signature - Cryptographic signature
  - **Returns**: Result with success or passkey error
  - **Security**: Self-attestation verification without external certificates
  - **Type**: Self-attestation verification

- `fn create_basic_auth_data() -> Vec<u8> {}`
  - **Testing**: Creates basic authentication data for packed attestation tests
  - **Returns**: Basic authentication data bytes
  - **Type**: Test data generation helper

- `fn create_auth_data_with_aaguid(aaguid: &[u8; 16]) -> Vec<u8> {}`
  - **Testing**: Creates authentication data with specific AAGUID
  - **Parameters**: aaguid - 16-byte Authenticator Attestation GUID
  - **Returns**: Authentication data with AAGUID
  - **Type**: Test data generation with AAGUID

- `fn create_auth_data_no_attested_cred() -> Vec<u8> {}`
  - **Testing**: Creates authentication data without attested credential data
  - **Returns**: Authentication data without credential info
  - **Type**: Test data for non-attested scenarios

- `fn create_client_data_hash() -> Vec<u8> {}`
  - **Testing**: Creates test client data hash
  - **Returns**: Client data hash bytes
  - **Type**: Test data generation helper

- `fn create_att_stmt(alg: i64, sig: &[u8]) -> Vec<(CborValue, CborValue)> {}`
  - **Testing**: Creates basic attestation statement
  - **Parameters**: alg - Algorithm identifier, sig - Signature bytes
  - **Returns**: CBOR-encoded attestation statement
  - **Type**: Basic attestation statement generator

- `fn create_att_stmt_with_x5c( alg: i64, sig: &[u8], cert_bytes: Vec<u8>, ) -> Vec<(CborValue, CborValue)> {}`
  - **Testing**: Creates attestation statement with X.509 certificate
  - **Parameters**: alg - Algorithm, sig - Signature, cert_bytes - Certificate
  - **Returns**: CBOR attestation statement with certificate
  - **Type**: Certificate-based attestation statement generator

- `fn create_att_stmt_with_ecdaa( alg: i64, sig: &[u8], key_id: Vec<u8>, ) -> Vec<(CborValue, CborValue)> {}`
  - **Testing**: Creates attestation statement with ECDAA key
  - **Parameters**: alg - Algorithm, sig - Signature, key_id - ECDAA key identifier
  - **Returns**: CBOR attestation statement with ECDAA
  - **Type**: ECDAA attestation statement generator

- `fn create_dummy_cert() -> Vec<u8> {}`
  - **Testing**: Creates dummy X.509 certificate for testing
  - **Returns**: Dummy certificate bytes
  - **Type**: Test certificate generator

- `fn create_empty_cert_chain() -> Vec<u8> {}`
  - **Testing**: Creates empty certificate chain for testing
  - **Returns**: Empty certificate chain
  - **Type**: Test certificate chain generator

- `fn test_verify_packed_attestation_unsupported_alg() {}`
  - **Testing**: Tests packed attestation with unsupported algorithm
  - **Type**: Algorithm support validation test

- `fn test_verify_packed_attestation_ecdaa_not_supported() {}`
  - **Testing**: Tests that ECDAA attestation is not supported
  - **Type**: ECDAA unsupported feature test

- `fn test_verify_packed_attestation_both_x5c_and_ecdaa() {}`
  - **Testing**: Tests packed attestation with both X.509 and ECDAA (invalid)
  - **Type**: Mutually exclusive attestation type test

- `fn test_verify_packed_attestation_invalid_cert() {}`
  - **Testing**: Tests packed attestation with invalid X.509 certificate
  - **Type**: Certificate validation test

- `fn test_verify_packed_attestation_empty_cert_chain() {}`
  - **Testing**: Tests packed attestation with empty certificate chain
  - **Type**: Certificate chain validation test

- `fn test_verify_packed_attestation_malformed_x5c() {}`
  - **Testing**: Tests packed attestation with malformed x5c certificate array
  - **Type**: CBOR certificate array validation test

- `fn test_verify_packed_attestation_self_attestation_no_cred_data() {}`
  - **Testing**: Tests self-attestation without credential data in auth data
  - **Type**: Self-attestation credential data validation test

- `fn test_verify_packed_attestation_self_attestation_invalid_sig() {}`
  - **Testing**: Tests self-attestation with invalid signature
  - **Type**: Self-attestation signature validation test

- `fn test_verify_self_attestation_missing_attested_cred_flag() {}`
  - **Testing**: Tests self-attestation with missing attested credential flag
  - **Type**: Authentication data flag validation test

- `fn test_verify_self_attestation_truncated_auth_data() {}`
  - **Testing**: Tests self-attestation with truncated authentication data
  - **Type**: Authentication data length validation test

- `fn test_verify_self_attestation_invalid_cbor() {}`
  - **Testing**: Tests self-attestation with invalid CBOR in public key
  - **Type**: CBOR public key validation test

- `fn test_verify_certificate_chain_empty() {}`
  - **Testing**: Tests certificate chain verification with no certificates
  - **Type**: Certificate chain boundary condition test

- `fn test_verify_certificate_chain_invalid_cert() {}`
  - **Testing**: Tests certificate chain with invalid certificate data
  - **Type**: Certificate parsing validation test

- `fn test_verify_certificate_chain_multiple_invalid_certs() {}`
  - **Testing**: Tests certificate chain with multiple invalid certificates
  - **Type**: Certificate chain robustness test

- `fn test_verify_packed_attestation_cert_with_dummy_data() {}`
  - **Testing**: Tests certificate attestation with dummy test data
  - **Type**: Certificate attestation integration test

- `fn test_verify_packed_attestation_missing_alg() {}`
  - **Testing**: Tests packed attestation without algorithm field
  - **Type**: Required field validation test

- `fn test_verify_packed_attestation_missing_sig() {}`
  - **Testing**: Tests packed attestation without signature field
  - **Type**: Required signature validation test

- `fn test_verify_packed_attestation_empty_att_stmt() {}`
  - **Testing**: Tests packed attestation with empty attestation statement
  - **Type**: Attestation statement validation test

- `fn test_verify_packed_attestation_x5c_empty_array() {}`
  - **Testing**: Tests packed attestation with empty x5c certificate array
  - **Type**: Certificate array validation test

- `fn test_verify_packed_attestation_large_credential_id() {}`
  - **Testing**: Tests packed attestation with large credential ID
  - **Type**: Credential ID size validation test

- `fn test_verify_packed_attestation_zero_credential_id_length() {}`
  - **Testing**: Tests packed attestation with zero-length credential ID
  - **Type**: Credential ID boundary condition test

## Passkey Module - TPM Attestation (`src/passkey/main/attestation/tpm.rs`)

**oauth2_passkey/src/passkey/main/attestation/tpm.rs:**

### TPM Attestation Verification Functions

- `pub(super) fn verify_tpm_attestation( auth_data: &[u8], client_data_hash: &[u8], att_stmt: &Vec<(CborValue, CborValue)>, ) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies TPM (Trusted Platform Module) format attestation
  - **Parameters**: auth_data - Authentication data, client_data_hash - Hash of client data, att_stmt - TPM attestation statement
  - **Returns**: Result with success or passkey error
  - **Security**: Validates TPM-based attestation with certificate chain and signature verification
  - **Type**: TPM attestation verification

- `fn verify_aik_certificate_fallback( cert_bytes: &[u8], auth_data: &[u8], ) -> Result<(), PasskeyError> {}`
  - **Purpose**: Fallback verification using AIK (Attestation Identity Key) certificate
  - **Parameters**: cert_bytes - AIK certificate bytes, auth_data - Authentication data
  - **Returns**: Result with success or passkey error
  - **Security**: Alternative TPM verification path using AIK certificate
  - **Internal**: TPM certificate verification fallback

- `fn extract_aaguid_from_extension(ext: &X509Extension) -> Result<[u8; 16], PasskeyError> {}`
  - **Purpose**: Extracts AAGUID from X.509 certificate extension
  - **Parameters**: ext - X.509 certificate extension
  - **Returns**: Result with 16-byte AAGUID or passkey error
  - **Type**: AAGUID extraction from certificate

- `fn verify_aaguid_match(aaguid: [u8; 16], auth_data: &[u8]) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies AAGUID in certificate matches AAGUID in authentication data
  - **Parameters**: aaguid - AAGUID from certificate, auth_data - Authentication data
  - **Returns**: Result with success or passkey error
  - **Security**: Ensures AAGUID consistency between certificate and auth data

- `fn verify_public_key_match(auth_data: &[u8], pub_area: &[u8]) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies public key in auth data matches TPM public area
  - **Parameters**: auth_data - Authentication data, pub_area - TPM public area
  - **Returns**: Result with success or passkey error
  - **Security**: Validates public key consistency in TPM attestation

- `fn extract_public_key_from_pub_area(pub_area: &[u8]) -> Result<KeyDetails, PasskeyError> {}`
  - **Purpose**: Extracts public key details from TPM public area structure
  - **Parameters**: pub_area - TPM public area bytes
  - **Returns**: Result with KeyDetails or passkey error
  - **Type**: TPM public key extraction

- `fn verify_cert_info( cert_info: &[u8], auth_data: &[u8], client_data_hash: &[u8], pub_area: &[u8], ) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies TPM certificate info structure and contents
  - **Parameters**: cert_info - TPM certificate info, auth_data - Authentication data, client_data_hash - Client data hash, pub_area - TPM public area
  - **Returns**: Result with success or passkey error
  - **Security**: Comprehensive TPM certificate info validation

- `fn extract_credential_public_key(auth_data: &[u8]) -> Result<CborValue, PasskeyError> {}`
  - **Purpose**: Extracts credential public key from authentication data
  - **Parameters**: auth_data - Authentication data bytes
  - **Returns**: Result with CBOR-encoded public key or passkey error
  - **Type**: Public key extraction from auth data

### Test Helper Functions

- `fn create_test_auth_data() -> Vec<u8> {}`
  - **Testing**: Creates test authentication data for TPM attestation tests
  - **Returns**: Test authentication data bytes
  - **Type**: Test data generation helper

- `fn create_test_auth_data_rsa() -> Vec<u8> {}`
  - **Testing**: Creates test authentication data with RSA public key
  - **Returns**: Test auth data with RSA key
  - **Type**: RSA-specific test data generator

- `fn create_test_client_data_hash() -> Vec<u8> {}`
  - **Testing**: Creates test client data hash for TPM tests
  - **Returns**: Test client data hash bytes
  - **Type**: Test data generation helper

- `fn create_test_tpm_att_stmt( include_ver: bool, include_alg: bool, include_sig: bool, include_x5c: bool, include_pub_area: bool, include_cert_info: bool, ) -> Vec<(CborValue, CborValue)> {}`
  - **Testing**: Creates configurable TPM attestation statement for testing
  - **Parameters**: Flags to include/exclude specific TPM attestation fields
  - **Returns**: CBOR-encoded TPM attestation statement
  - **Type**: Configurable TPM attestation statement generator

- `fn create_test_x509_certificate() -> Vec<u8> {}`
  - **Testing**: Creates test X.509 certificate for TPM tests
  - **Returns**: Test certificate bytes
  - **Type**: Test certificate generator

- `fn create_test_rsa_pub_area() -> Vec<u8> {}`
  - **Testing**: Creates test TPM public area with RSA key
  - **Returns**: Test RSA public area bytes
  - **Type**: RSA TPM public area generator

- `fn create_test_ecc_pub_area() -> Vec<u8> {}`
  - **Testing**: Creates test TPM public area with ECC key
  - **Returns**: Test ECC public area bytes
  - **Type**: ECC TPM public area generator

- `fn create_test_cert_info() -> Vec<u8> {}`
  - **Testing**: Creates test TPM certificate info structure
  - **Returns**: Test certificate info bytes
  - **Type**: TPM certificate info generator

### Unit Tests

- `fn test_verify_tpm_attestation_missing_ver() {}`
  - **Testing**: Tests TPM attestation verification with missing version field
  - **Type**: Required field validation test

- `fn test_verify_tpm_attestation_missing_alg() {}`
  - **Testing**: Tests TPM attestation verification with missing algorithm field
  - **Type**: Required algorithm validation test

- `fn test_verify_tpm_attestation_missing_sig() {}`
  - **Testing**: Tests TPM attestation verification with missing signature field
  - **Type**: Required signature validation test

- `fn test_verify_tpm_attestation_missing_x5c() {}`
  - **Testing**: Tests TPM attestation verification with missing x5c certificate field
  - **Type**: Required certificate validation test

- `fn test_verify_tpm_attestation_missing_pub_area() {}`
  - **Testing**: Tests TPM attestation verification with missing public area field
  - **Type**: Required TPM public area validation test

- `fn test_verify_tpm_attestation_missing_cert_info() {}`
  - **Testing**: Tests TPM attestation verification with missing certificate info field
  - **Type**: Required certificate info validation test

- `fn test_verify_tpm_attestation_invalid_version() {}`
  - **Testing**: Tests TPM attestation verification with invalid version value
  - **Type**: Version field validation test

- `fn test_verify_tpm_attestation_unsupported_algorithm() {}`
  - **Testing**: Tests TPM attestation verification with unsupported algorithm
  - **Type**: Algorithm support validation test

- `fn test_verify_tpm_attestation_empty_x5c() {}`
  - **Testing**: Tests TPM attestation verification with empty certificate chain
  - **Type**: Certificate chain validation test

- `fn test_verify_aaguid_match_mismatch() {}`
  - **Testing**: Tests AAGUID mismatch between certificate and auth data
  - **Type**: AAGUID consistency validation test

- `fn test_verify_aaguid_match_short_auth_data() {}`
  - **Testing**: Tests AAGUID verification with insufficient auth data
  - **Type**: Authentication data length validation test

- `fn test_extract_public_key_from_pub_area_too_short() {}`
  - **Testing**: Tests public key extraction from insufficient TPM public area data
  - **Type**: TPM public area length validation test

- `fn test_extract_public_key_from_pub_area_unsupported_algorithm() {}`
  - **Testing**: Tests public key extraction with unsupported TPM algorithm
  - **Type**: TPM algorithm support validation test

- `fn test_extract_rsa_pub_area_insufficient_data() {}`
  - **Testing**: Tests RSA public key extraction with insufficient data
  - **Type**: RSA key data validation test

- `fn test_extract_ecc_public_key_from_pub_area() {}`
  - **Testing**: Tests ECC public key extraction from TPM public area
  - **Type**: ECC key extraction validation test

- `fn test_verify_public_key_match_key_type_mismatch() {}`
  - **Testing**: Tests public key verification with mismatched key types
  - **Type**: Public key type consistency validation test

- `fn test_verify_public_key_match_rsa_success() {}`
  - **Testing**: Tests successful RSA public key matching
  - **Type**: RSA key verification success test

- `fn test_verify_public_key_match_rsa_modulus_mismatch() {}`
  - **Testing**: Tests RSA public key verification with modulus mismatch
  - **Type**: RSA modulus validation test

- `fn test_verify_cert_info_too_short() {}`
  - **Testing**: Tests certificate info verification with insufficient data
  - **Type**: Certificate info length validation test

- `fn test_verify_cert_info_invalid_magic() {}`
  - **Testing**: Tests certificate info verification with invalid magic number
  - **Type**: Certificate info format validation test

- `fn test_verify_cert_info_invalid_type() {}`
  - **Testing**: Tests certificate info verification with invalid type field
  - **Type**: Certificate info type validation test

- `fn test_extract_credential_public_key_no_at_flag() {}`
  - **Testing**: Tests credential public key extraction without AT flag set
  - **Type**: Authentication data flag validation test

- `fn test_extract_credential_public_key_short_auth_data() {}`
  - **Testing**: Tests credential public key extraction with insufficient auth data
  - **Type**: Authentication data length validation test

- `fn test_extract_credential_public_key_insufficient_cred_id_length() {}`
  - **Testing**: Tests credential public key extraction with insufficient credential ID length
  - **Type**: Credential ID length validation test

- `fn test_extract_credential_public_key_success() {}`
  - **Testing**: Tests successful credential public key extraction
  - **Type**: Public key extraction success test

- `fn test_verify_tpm_attestation_success() {}`
  - **Testing**: Tests successful complete TPM attestation verification
  - **Type**: TPM attestation integration success test

## Passkey Module - U2F Attestation (`src/passkey/main/attestation/u2f.rs`)

**oauth2_passkey/src/passkey/main/attestation/u2f.rs:**

### U2F Attestation Verification Functions

- `pub(super) fn verify_u2f_attestation( auth_data: &[u8], client_data_hash: &[u8], att_stmt: &Vec<(CborValue, CborValue)>, ) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies U2F (Universal 2nd Factor) format attestation
  - **Parameters**: auth_data - Authentication data, client_data_hash - Hash of client data, att_stmt - U2F attestation statement
  - **Returns**: Result with success or passkey error
  - **Security**: Validates U2F-based attestation with certificate and signature verification
  - **Type**: U2F attestation verification

### Test Setup Functions

- `unsafe fn setup() {}`
  - **Testing**: Unsafe test setup function for U2F attestation tests
  - **Type**: Test environment initialization

### Test Helper Functions

- `fn create_test_auth_data() -> Vec<u8> {}`
  - **Testing**: Creates test authentication data for U2F attestation tests
  - **Returns**: Test authentication data bytes
  - **Type**: Test data generation helper

- `fn create_test_client_data_hash() -> Vec<u8> {}`
  - **Testing**: Creates test client data hash for U2F tests
  - **Returns**: Test client data hash bytes
  - **Type**: Test data generation helper

- `fn create_test_u2f_att_stmt( include_sig: bool, include_x5c: bool, empty_x5c: bool, ) -> Vec<(CborValue, CborValue)> {}`
  - **Testing**: Creates configurable U2F attestation statement for testing
  - **Parameters**: Flags to include/exclude specific U2F attestation fields
  - **Returns**: CBOR-encoded U2F attestation statement
  - **Type**: Configurable U2F attestation statement generator

### Unit Tests

- `fn test_verify_u2f_attestation_missing_sig() {}`
  - **Testing**: Tests U2F attestation verification with missing signature field
  - **Type**: Required signature validation test

- `fn test_verify_u2f_attestation_missing_x5c() {}`
  - **Testing**: Tests U2F attestation verification with missing x5c certificate field
  - **Type**: Required certificate validation test

- `fn test_verify_u2f_attestation_empty_x5c() {}`
  - **Testing**: Tests U2F attestation verification with empty certificate chain
  - **Type**: Certificate chain validation test

- `fn test_verify_u2f_attestation_invalid_certificate() {}`
  - **Testing**: Tests U2F attestation verification with invalid certificate
  - **Type**: Certificate validation test

- `fn test_verify_u2f_attestation_short_auth_data() {}`
  - **Testing**: Tests U2F attestation verification with insufficient authentication data
  - **Type**: Authentication data length validation test

- `fn test_verify_u2f_attestation_invalid_credential_id_length() {}`
  - **Testing**: Tests U2F attestation verification with invalid credential ID length
  - **Type**: Credential ID length validation test

- `fn test_verify_u2f_attestation_malformed_public_key() {}`
  - **Testing**: Tests U2F attestation verification with malformed public key
  - **Type**: Public key format validation test

- `fn test_verify_u2f_attestation_truly_empty_x5c() {}`
  - **Testing**: Tests U2F attestation verification with truly empty x5c array
  - **Type**: Certificate array boundary condition test

- `fn test_verify_u2f_attestation_invalid_public_key_coords() {}`
  - **Testing**: Tests U2F attestation verification with invalid public key coordinates
  - **Type**: Public key coordinate validation test

- `fn test_auth_data_bounds_check_position() {}`
  - **Testing**: Tests authentication data bounds checking at various positions
  - **Type**: Authentication data boundary validation test

**oauth2_passkey/src/passkey/main/attestation/utils.rs:**

### Attestation Utility Functions

- `pub(super) fn get_sig_from_stmt( att_stmt: &Vec<(CborValue, CborValue)>, ) -> Result<(i64, Vec<u8>), PasskeyError> {}`
  - **Purpose**: Extracts algorithm identifier and signature from attestation statement
  - **Parameters**: att_stmt - CBOR-encoded attestation statement as key-value pairs
  - **Returns**: Result with tuple of (algorithm_id, signature_bytes) or passkey error
  - **Type**: Attestation signature extraction utility

- `pub(super) fn integer_to_i64(i: &Integer) -> i64 {}`
  - **Purpose**: Converts CBOR Integer to i64 with fallback handling
  - **Parameters**: i - CBOR Integer value
  - **Returns**: i64 representation of the integer
  - **Type**: CBOR integer conversion utility

- `pub(super) fn extract_public_key_coords( public_key_cbor: &CborValue, ) -> Result<(Vec<u8>, Vec<u8>), PasskeyError> {}`
  - **Purpose**: Extracts X and Y coordinates from CBOR-encoded ECDSA public key
  - **Parameters**: public_key_cbor - CBOR-encoded public key
  - **Returns**: Result with tuple of (x_coordinate, y_coordinate) or passkey error
  - **Type**: ECDSA public key coordinate extraction

### Unit Tests

- `fn test_get_sig_from_stmt_success() {}`
  - **Testing**: Tests successful signature extraction from attestation statement
  - **Type**: Signature extraction success test

- `fn test_get_sig_from_stmt_missing_alg() {}`
  - **Testing**: Tests signature extraction with missing algorithm field
  - **Type**: Required algorithm field validation test

- `fn test_get_sig_from_stmt_missing_sig() {}`
  - **Testing**: Tests signature extraction with missing signature field
  - **Type**: Required signature field validation test

- `fn test_get_sig_from_stmt_wrong_types() {}`
  - **Testing**: Tests signature extraction with incorrect CBOR value types
  - **Type**: CBOR type validation test

- `fn test_get_sig_from_stmt_empty_statement() {}`
  - **Testing**: Tests signature extraction from empty attestation statement
  - **Type**: Empty statement handling test

- `fn test_get_sig_from_stmt_irrelevant_keys() {}`
  - **Testing**: Tests signature extraction with irrelevant keys in statement
  - **Type**: Statement parsing robustness test

- `fn test_get_sig_from_stmt_empty_signature() {}`
  - **Testing**: Tests signature extraction with empty signature value
  - **Type**: Empty signature validation test

- `fn test_integer_to_i64_common_values() {}`
  - **Testing**: Tests integer conversion with common CBOR integer values
  - **Type**: Integer conversion validation test

- `fn test_integer_to_i64_fallback_case() {}`
  - **Testing**: Tests integer conversion fallback behavior
  - **Type**: Integer conversion edge case test

- `fn test_integer_to_i64_simplified_powers_of_two() {}`
  - **Testing**: Tests integer conversion with powers of two values
  - **Type**: Integer conversion boundary condition test

- `fn test_extract_public_key_coords_success() {}`
  - **Testing**: Tests successful public key coordinate extraction
  - **Type**: Public key coordinate extraction success test

- `fn test_extract_public_key_coords_invalid_key_type() {}`
  - **Testing**: Tests coordinate extraction with invalid key type
  - **Type**: Key type validation test

- `fn test_extract_public_key_coords_invalid_algorithm() {}`
  - **Testing**: Tests coordinate extraction with invalid algorithm
  - **Type**: Algorithm validation test

- `fn test_extract_public_key_coords_missing_x() {}`
  - **Testing**: Tests coordinate extraction with missing X coordinate
  - **Type**: Required X coordinate validation test

- `fn test_extract_public_key_coords_missing_y() {}`
  - **Testing**: Tests coordinate extraction with missing Y coordinate
  - **Type**: Required Y coordinate validation test

- `fn test_extract_public_key_coords_invalid_coordinate_length() {}`
  - **Testing**: Tests coordinate extraction with invalid coordinate lengths
  - **Type**: Coordinate length validation test

- `fn test_extract_public_key_coords_invalid_format() {}`
  - **Testing**: Tests coordinate extraction with invalid CBOR format
  - **Type**: CBOR format validation test

- `fn test_extract_public_key_coords_missing_both_coordinates() {}`
  - **Testing**: Tests coordinate extraction with both coordinates missing
  - **Type**: Required coordinates validation test

- `fn test_extract_public_key_coords_zero_length_coordinates() {}`
  - **Testing**: Tests coordinate extraction with zero-length coordinates
  - **Type**: Coordinate length boundary condition test

- `fn test_extract_public_key_coords_boundary_lengths() {}`
  - **Testing**: Tests coordinate extraction with boundary coordinate lengths
  - **Type**: Coordinate boundary validation test

- `fn test_extract_public_key_coords_empty_map() {}`
  - **Testing**: Tests coordinate extraction from empty CBOR map
  - **Type**: Empty map handling test

**oauth2_passkey/src/passkey/main/auth.rs:**

- `pub(crate) async fn start_authentication(username: Option<String>) -> Result<AuthenticationOptions, PasskeyError> {}`
  - **Purpose**: Initiates WebAuthn authentication flow by generating challenge and authentication options
  - **Parameters**: 
    - `username`: Optional username to filter credentials for authentication
  - **Returns**: `Result<AuthenticationOptions, PasskeyError>` - Authentication options including challenge and allowed credentials
  - **Type**: Public crate-level async API function for authentication initiation

- `pub(crate) async fn finish_authentication(auth_response: AuthenticatorResponse) -> Result<(String, String), PasskeyError> {}`
  - **Purpose**: Completes WebAuthn authentication by verifying authenticator response and challenge
  - **Parameters**: 
    - `auth_response`: Authenticator response containing signed challenge and authentication data
  - **Returns**: `Result<(String, String), PasskeyError>` - Tuple of (username, credential_id) on successful authentication
  - **Type**: Public crate-level async API function for authentication completion

- `fn verify_user_handle(auth_response: &AuthenticatorResponse, stored_credential: &PasskeyCredential, is_discoverable: bool) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies user handle consistency between authentication response and stored credential
  - **Parameters**: 
    - `auth_response`: Reference to authenticator response containing user handle
    - `stored_credential`: Reference to stored passkey credential for comparison
    - `is_discoverable`: Boolean flag indicating if credential supports discoverable authentication
  - **Returns**: `Result<(), PasskeyError>` - Success or validation error
  - **Type**: Internal validation function for user handle verification

- `async fn verify_counter(credential_id: &str, auth_data: &AuthenticatorData, stored_credential: &PasskeyCredential) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies and updates authenticator counter to prevent replay attacks
  - **Parameters**: 
    - `credential_id`: String identifier of the credential being verified
    - `auth_data`: Authenticator data containing current counter value
    - `stored_credential`: Stored credential containing previous counter value
  - **Returns**: `Result<(), PasskeyError>` - Success or counter validation error
  - **Type**: Internal async security function for replay attack prevention

- `async fn verify_signature(auth_response: &AuthenticatorResponse, client_data: &ParsedClientData, auth_data: &AuthenticatorData, stored_credential: &PasskeyCredential) -> Result<(), PasskeyError> {}`
  - **Purpose**: Cryptographically verifies the authentication signature using stored public key
  - **Parameters**: 
    - `auth_response`: Authenticator response containing the signature
    - `client_data`: Parsed client data JSON containing challenge
    - `auth_data`: Authenticator data used in signature generation
    - `stored_credential`: Stored credential containing public key for verification
  - **Returns**: `Result<(), PasskeyError>` - Success or signature verification error
  - **Type**: Internal async cryptographic verification function

- `fn create_test_authenticator_response(user_handle: Option<String>, auth_id: String) -> AuthenticatorResponse {}`
  - **Purpose**: Creates mock authenticator response for testing authentication flows
  - **Parameters**: 
    - `user_handle`: Optional user handle to include in test response
    - `auth_id`: Authentication ID for the test response
  - **Returns**: `AuthenticatorResponse` - Mock authenticator response with test data
  - **Type**: Test utility function for authentication response creation

- `fn create_test_passkey_credential(user_handle: String) -> PasskeyCredential {}`
  - **Purpose**: Creates mock passkey credential for testing authentication verification
  - **Parameters**: 
    - `user_handle`: User handle to associate with test credential
  - **Returns**: `PasskeyCredential` - Mock credential with test data
  - **Type**: Test utility function for credential creation

- `fn create_test_authenticator_data(counter: u32) -> AuthenticatorData {}`
  - **Purpose**: Creates mock authenticator data for testing counter verification
  - **Parameters**: 
    - `counter`: Counter value to include in test authenticator data
  - **Returns**: `AuthenticatorData` - Mock authenticator data with specified counter
  - **Type**: Test utility function for authenticator data creation

- `async fn test_start_authentication_no_username() {}`
  - **Testing**: Tests authentication start without specifying a username
  - **Type**: Authentication initiation test for discoverable credentials

- `async fn test_start_authentication_generates_unique_ids() {}`
  - **Testing**: Tests that authentication start generates unique challenge IDs
  - **Type**: Challenge uniqueness validation test

- `fn test_verify_user_handle_real_function_matching_handles() {}`
  - **Testing**: Tests user handle verification with matching handles
  - **Type**: User handle validation success test

- `fn test_verify_user_handle_real_function_mismatched_handles() {}`
  - **Testing**: Tests user handle verification with mismatched handles
  - **Type**: User handle validation error test

- `fn test_verify_user_handle_real_function_missing_handle() {}`
  - **Testing**: Tests user handle verification with missing handle
  - **Type**: Missing user handle validation test

- `fn test_verify_user_handle_edge_cases() {}`
  - **Testing**: Tests user handle verification edge cases and boundary conditions
  - **Type**: User handle validation edge case test

- `async fn test_verify_counter_authenticator_no_counter_support() {}`
  - **Testing**: Tests counter verification when authenticator doesn't support counters
  - **Type**: Counter support detection test

- `async fn test_verify_counter_replay_attack_detection() {}`
  - **Testing**: Tests counter verification detects replay attacks with decreasing counters
  - **Type**: Replay attack detection security test

- `async fn test_verify_counter_equal_counter_replay_attack() {}`
  - **Testing**: Tests counter verification detects replay attacks with equal counters
  - **Type**: Equal counter replay attack detection test

- `async fn test_verify_counter_valid_increment() {}`
  - **Testing**: Tests counter verification with valid counter increments
  - **Type**: Valid counter increment test

- `async fn test_verify_counter_zero_to_positive() {}`
  - **Testing**: Tests counter verification transitioning from zero to positive value
  - **Type**: Counter initialization test

- `async fn test_verify_counter_large_increment() {}`
  - **Testing**: Tests counter verification with large counter increments
  - **Type**: Large counter increment validation test

- `async fn verify_counter_with_mock(credential_id: &str, auth_data: &AuthenticatorData, stored_credential: &PasskeyCredential, skip_db_update: bool) -> Result<(), PasskeyError> {}`
  - **Purpose**: Test helper function to verify counter with database update control
  - **Parameters**: 
    - `credential_id`: String identifier of credential being tested
    - `auth_data`: Authenticator data containing counter to verify
    - `stored_credential`: Stored credential for counter comparison
    - `skip_db_update`: Boolean to control database update during testing
  - **Returns**: `Result<(), PasskeyError>` - Counter verification result
  - **Type**: Test utility function for counter verification with mock control

- `fn create_test_parsed_client_data(challenge: &str) -> ParsedClientData {}`
  - **Purpose**: Creates mock parsed client data for testing signature verification
  - **Parameters**: 
    - `challenge`: Challenge string to include in test client data
  - **Returns**: `ParsedClientData` - Mock parsed client data with specified challenge
  - **Type**: Test utility function for client data creation

- `fn create_test_authenticator_data_with_raw(counter: u32, raw_data: Vec<u8>) -> AuthenticatorData {}`
  - **Purpose**: Creates mock authenticator data with custom raw data for advanced testing
  - **Parameters**: 
    - `counter`: Counter value for the authenticator data
    - `raw_data`: Raw byte data to include in authenticator data
  - **Returns**: `AuthenticatorData` - Mock authenticator data with custom raw data
  - **Type**: Advanced test utility function for authenticator data with raw data control

- `async fn test_verify_signature_invalid_public_key_format() {}`
  - **Testing**: Tests signature verification with invalid public key format
  - **Type**: Public key format validation test

- `async fn test_verify_signature_invalid_signature_format() {}`
  - **Testing**: Tests signature verification with invalid signature format
  - **Type**: Signature format validation test

- `async fn test_verify_signature_verification_failure() {}`
  - **Testing**: Tests signature verification when cryptographic verification fails
  - **Type**: Cryptographic verification failure test

- `async fn test_verify_signature_empty_signature() {}`
  - **Testing**: Tests signature verification with empty signature data
  - **Type**: Empty signature validation test

- `async fn test_verify_signature_empty_public_key() {}`
  - **Testing**: Tests signature verification with empty public key data
  - **Type**: Empty public key validation test

- `async fn test_verify_signature_malformed_data_structures() {}`
  - **Testing**: Tests signature verification with malformed data structures
  - **Type**: Data structure validation test

- `async fn test_finish_authentication_integration_test() {}`
  - **Testing**: Integration test for complete authentication finish flow
  - **Type**: Authentication integration test

- `async fn test_start_authentication_integration() {}`
  - **Testing**: Integration test for authentication start flow
  - **Type**: Authentication initiation integration test

- `async fn test_verify_counter_and_update() {}`
  - **Testing**: Tests counter verification and database update functionality
  - **Type**: Counter verification and update test

- `async fn test_verify_user_handle() {}`
  - **Testing**: Tests user handle verification functionality
  - **Type**: User handle verification test

**oauth2_passkey/src/passkey/main/challenge.rs:**

- `pub(super) async fn get_and_validate_options(challenge_type: &str, id: &str) -> Result<StoredOptions, PasskeyError> {}`
  - **Purpose**: Retrieves and validates stored challenge options from cache, checking expiration
  - **Parameters**: 
    - `challenge_type`: String identifying the type of challenge (registration/authentication)
    - `id`: String identifier for the specific challenge options
  - **Returns**: `Result<StoredOptions, PasskeyError>` - Valid stored options or retrieval/validation error
  - **Type**: Public super-level async function for challenge options validation

- `pub(super) async fn remove_options(challenge_type: &str, id: &str) -> Result<(), PasskeyError> {}`
  - **Purpose**: Removes stored challenge options from cache after use or expiration
  - **Parameters**: 
    - `challenge_type`: String identifying the type of challenge to remove
    - `id`: String identifier for the specific challenge options to remove
  - **Returns**: `Result<(), PasskeyError>` - Success or removal error
  - **Type**: Public super-level async function for challenge cleanup

- `fn create_valid_stored_options() -> StoredOptions {}`
  - **Purpose**: Creates valid stored options for testing challenge validation
  - **Returns**: `StoredOptions` - Mock stored options with valid expiration
  - **Type**: Test utility function for valid options creation

- `fn create_expired_stored_options() -> StoredOptions {}`
  - **Purpose**: Creates expired stored options for testing expiration handling
  - **Returns**: `StoredOptions` - Mock stored options with expired timestamp
  - **Type**: Test utility function for expired options creation

- `async fn test_get_and_validate_options_success() {}`
  - **Testing**: Tests successful retrieval and validation of stored challenge options
  - **Type**: Challenge options retrieval success test

- `async fn test_get_and_validate_options_not_found() {}`
  - **Testing**: Tests challenge options retrieval when options don't exist
  - **Type**: Missing challenge options handling test

- `async fn test_get_and_validate_options_expired() {}`
  - **Testing**: Tests challenge options validation with expired options
  - **Type**: Challenge expiration validation test

- `async fn test_remove_options_success() {}`
  - **Testing**: Tests successful removal of challenge options from cache
  - **Type**: Challenge options removal success test

- `async fn test_remove_options_nonexistent() {}`
  - **Testing**: Tests removal of non-existent challenge options
  - **Type**: Non-existent challenge options removal test

- `async fn test_ttl_validation_with_passkey_timeout() {}`
  - **Testing**: Tests TTL validation against passkey timeout configuration
  - **Type**: TTL validation test

- `async fn test_options_cache_basics() {}`
  - **Testing**: Tests basic challenge options caching functionality
  - **Type**: Basic cache operations test

- `async fn test_challenge_lifecycle_integration() {}`
  - **Testing**: Integration test for complete challenge lifecycle
  - **Type**: Challenge lifecycle integration test

- `async fn test_challenge_expiration() {}`
  - **Testing**: Tests challenge expiration behavior and cleanup
  - **Type**: Challenge expiration test

**oauth2_passkey/src/passkey/main/register.rs:**

- `async fn get_or_create_user_handle(session_user: &Option<SessionUser>) -> Result<String, PasskeyError> {}`
  - **Purpose**: Gets existing user handle from session or creates new one for registration
  - **Parameters**: 
    - `session_user`: Optional reference to authenticated session user
  - **Returns**: `Result<String, PasskeyError>` - User handle string or creation error
  - **Type**: Internal async function for user handle management

- `pub(crate) async fn start_registration(session_user: Option<SessionUser>, username: String, displayname: String) -> Result<RegistrationOptions, PasskeyError> {}`
  - **Purpose**: Initiates WebAuthn registration flow by generating registration options and challenge
  - **Parameters**: 
    - `session_user`: Optional authenticated session user for context
    - `username`: Username for the new credential being registered
    - `displayname`: Display name for user-friendly credential identification
  - **Returns**: `Result<RegistrationOptions, PasskeyError>` - Registration options including challenge
  - **Type**: Public crate-level async API function for registration initiation

- `async fn create_registration_options(user_info: PublicKeyCredentialUserEntity) -> Result<RegistrationOptions, PasskeyError> {}`
  - **Purpose**: Creates WebAuthn registration options with user entity and challenge data
  - **Parameters**: 
    - `user_info`: User entity containing ID, name, and display name information
  - **Returns**: `Result<RegistrationOptions, PasskeyError>` - Complete registration options structure
  - **Type**: Internal async function for registration options creation

- `pub(crate) async fn verify_session_then_finish_registration(session_user: SessionUser, reg_data: RegisterCredential) -> Result<String, PasskeyError> {}`
  - **Purpose**: Verifies session validity then completes registration with credential data
  - **Parameters**: 
    - `session_user`: Authenticated session user for authorization
    - `reg_data`: Registration credential data from authenticator
  - **Returns**: `Result<String, PasskeyError>` - Credential ID string on successful registration
  - **Type**: Public crate-level async API function for session-based registration completion

- `pub(crate) async fn finish_registration(user_id: &str, reg_data: &RegisterCredential) -> Result<String, PasskeyError> {}`
  - **Purpose**: Completes WebAuthn registration by verifying and storing new credential
  - **Parameters**: 
    - `user_id`: String identifier of user registering the credential
    - `reg_data`: Reference to registration credential data for verification
  - **Returns**: `Result<String, PasskeyError>` - Credential ID string on successful storage
  - **Type**: Public crate-level async API function for registration completion

- `fn extract_credential_public_key(reg_data: &RegisterCredential) -> Result<String, PasskeyError> {}`
  - **Purpose**: Extracts and encodes public key from registration credential data
  - **Parameters**: 
    - `reg_data`: Reference to registration credential containing attestation object
  - **Returns**: `Result<String, PasskeyError>` - Base64-encoded public key string or extraction error
  - **Type**: Internal function for public key extraction from attestation

- `fn parse_attestation_object(attestation_base64: &str) -> Result<AttestationObject, PasskeyError> {}`
  - **Purpose**: Parses base64-encoded attestation object into structured CBOR data
  - **Parameters**: 
    - `attestation_base64`: Base64-encoded attestation object string
  - **Returns**: `Result<AttestationObject, PasskeyError>` - Parsed attestation object or parsing error
  - **Type**: Internal function for attestation object CBOR parsing

- `fn extract_public_key_from_auth_data(auth_data: &[u8]) -> Result<String, PasskeyError> {}`
  - **Purpose**: Extracts public key from authenticator data and converts to base64 string
  - **Parameters**: 
    - `auth_data`: Byte slice containing authenticator data with embedded public key
  - **Returns**: `Result<String, PasskeyError>` - Base64-encoded public key or extraction error
  - **Type**: Internal function for public key extraction from authenticator data

- `fn parse_credential_data(auth_data: &[u8]) -> Result<&[u8], PasskeyError> {}`
  - **Purpose**: Parses credential data section from authenticator data byte array
  - **Parameters**: 
    - `auth_data`: Byte slice containing full authenticator data
  - **Returns**: `Result<&[u8], PasskeyError>` - Credential data slice or parsing error
  - **Type**: Internal function for credential data section parsing

- `fn extract_key_coordinates(credential_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PasskeyError> {}`
  - **Purpose**: Extracts X and Y coordinates from ECDSA public key in credential data
  - **Parameters**: 
    - `credential_data`: Byte slice containing CBOR-encoded credential public key
  - **Returns**: `Result<(Vec<u8>, Vec<u8>), PasskeyError>` - Tuple of (X, Y) coordinate vectors or extraction error
  - **Type**: Internal function for ECDSA coordinate extraction

- `async fn verify_client_data(reg_data: &RegisterCredential) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies client data JSON from registration credential against stored challenge
  - **Parameters**: 
    - `reg_data`: Reference to registration credential containing client data JSON
  - **Returns**: `Result<(), PasskeyError>` - Success or client data verification error
  - **Type**: Internal async function for client data validation

- `fn test_parse_attestation_object_success_none_fmt() {}`
  - **Testing**: Tests successful parsing of attestation object with 'none' format
  - **Type**: Attestation object parsing success test

- `fn test_parse_attestation_object_invalid_base64() {}`
  - **Testing**: Tests attestation object parsing with invalid base64 encoding
  - **Type**: Base64 decoding error handling test

- `fn test_parse_attestation_object_valid_base64_invalid_cbor() {}`
  - **Testing**: Tests attestation object parsing with valid base64 but invalid CBOR
  - **Type**: CBOR parsing error handling test

- `fn test_parse_attestation_object_cbor_map_missing_fmt() {}`
  - **Testing**: Tests attestation object parsing with missing format field
  - **Type**: Required CBOR field validation test

- `fn test_parse_attestation_object_cbor_map_missing_auth_data() {}`
  - **Testing**: Tests attestation object parsing with missing authenticator data field
  - **Type**: Required authenticator data validation test

- `fn test_parse_attestation_object_cbor_map_missing_att_stmt() {}`
  - **Testing**: Tests attestation object parsing with missing attestation statement field
  - **Type**: Required attestation statement validation test

- `fn test_parse_attestation_object_cbor_not_a_map() {}`
  - **Testing**: Tests attestation object parsing when CBOR data is not a map
  - **Type**: CBOR data structure validation test

- `fn test_extract_key_coordinates_success() {}`
  - **Testing**: Tests successful extraction of ECDSA key coordinates
  - **Type**: Key coordinate extraction success test

- `fn test_extract_key_coordinates_missing_x() {}`
  - **Testing**: Tests key coordinate extraction with missing X coordinate
  - **Type**: Missing X coordinate validation test

- `fn test_extract_key_coordinates_missing_y() {}`
  - **Testing**: Tests key coordinate extraction with missing Y coordinate
  - **Type**: Missing Y coordinate validation test

- `fn test_parse_credential_data_success() {}`
  - **Testing**: Tests successful parsing of credential data from authenticator data
  - **Type**: Credential data parsing success test

- `fn test_parse_credential_data_too_short() {}`
  - **Testing**: Tests credential data parsing with insufficient data length
  - **Type**: Data length validation test

- `fn test_parse_credential_data_invalid_length() {}`
  - **Testing**: Tests credential data parsing with invalid length field
  - **Type**: Length field validation test

- `fn test_parse_credential_data_too_short_for_credential_id() {}`
  - **Testing**: Tests credential data parsing when data is too short for credential ID
  - **Type**: Credential ID length validation test

- `fn test_parse_credential_data_large_credential_id_length() {}`
  - **Testing**: Tests credential data parsing with unusually large credential ID length
  - **Type**: Large credential ID boundary test

- `fn test_extract_key_coordinates_invalid_cbor() {}`
  - **Testing**: Tests key coordinate extraction with invalid CBOR data
  - **Type**: CBOR validation test for key coordinates

- `async fn test_create_registration_options_integration() {}`
  - **Testing**: Integration test for registration options creation flow
  - **Type**: Registration options integration test

- `async fn test_get_or_create_user_handle() {}`
  - **Testing**: Tests user handle retrieval and creation functionality
  - **Type**: User handle management test

- `async fn test_verify_session_then_finish_registration_success() {}`
  - **Testing**: Tests successful session verification and registration completion
  - **Type**: Session-based registration success test

- `async fn test_verify_session_then_finish_registration_missing_user_handle() {}`
  - **Testing**: Tests session registration completion with missing user handle
  - **Type**: Missing user handle validation test

- `async fn test_verify_session_then_finish_registration_session_not_found() {}`
  - **Testing**: Tests session registration completion when session is not found
  - **Type**: Session existence validation test

- `async fn test_verify_session_then_finish_registration_user_id_mismatch() {}`
  - **Testing**: Tests session registration completion with mismatched user IDs
  - **Type**: User ID consistency validation test

- `fn create_test_register_credential_for_verify_client_data(client_data_json: String, user_handle: Option<String>) -> RegisterCredential {}`
  - **Purpose**: Creates mock registration credential for client data verification testing
  - **Parameters**: 
    - `client_data_json`: JSON string containing client data for testing
    - `user_handle`: Optional user handle to include in test credential
  - **Returns**: `RegisterCredential` - Mock registration credential with specified client data
  - **Type**: Test utility function for registration credential creation

- `fn create_test_client_data_json(type_: &str, challenge: &str, origin: &str) -> String {}`
  - **Purpose**: Creates JSON client data string for testing client data verification
  - **Parameters**: 
    - `type_`: Type field value for the client data (e.g., "webauthn.create")
    - `challenge`: Challenge string to include in client data
    - `origin`: Origin string for client data verification
  - **Returns**: `String` - JSON-formatted client data string
  - **Type**: Test utility function for client data JSON creation

- `async fn test_verify_client_data_success() {}`
  - **Testing**: Tests successful client data verification with valid data
  - **Type**: Client data verification success test

- `async fn test_verify_client_data_invalid_base64() {}`
  - **Testing**: Tests client data verification with invalid base64 encoding
  - **Type**: Base64 decoding error handling test

- `async fn test_verify_client_data_invalid_utf8() {}`
  - **Testing**: Tests client data verification with invalid UTF-8 encoding
  - **Type**: UTF-8 encoding validation test

- `async fn test_verify_client_data_invalid_json() {}`
  - **Testing**: Tests client data verification with malformed JSON
  - **Type**: JSON parsing error handling test

- `async fn test_verify_client_data_wrong_type() {}`
  - **Testing**: Tests client data verification with incorrect type field
  - **Type**: Client data type validation test

- `async fn test_verify_client_data_missing_user_handle() {}`
  - **Testing**: Tests client data verification when user handle is missing
  - **Type**: Missing user handle validation test

- `async fn test_verify_client_data_challenge_not_found() {}`
  - **Testing**: Tests client data verification when challenge is not found in cache
  - **Type**: Challenge existence validation test

- `async fn test_verify_client_data_challenge_mismatch() {}`
  - **Testing**: Tests client data verification with mismatched challenge values
  - **Type**: Challenge consistency validation test

- `async fn test_verify_client_data_origin_mismatch() {}`
  - **Testing**: Tests client data verification with mismatched origin values
  - **Type**: Origin validation test

- `fn create_test_register_credential_for_extract_credential_public_key() -> RegisterCredential {}`
  - **Purpose**: Creates mock registration credential for public key extraction testing
  - **Returns**: `RegisterCredential` - Mock credential with test attestation object
  - **Type**: Test utility function for credential creation

- `fn create_simple_test_attestation_object() -> Result<String, String> {}`
  - **Purpose**: Creates simple test attestation object with basic CBOR structure
  - **Returns**: `Result<String, String>` - Base64-encoded attestation object or creation error
  - **Type**: Test utility function for attestation object creation

- `async fn test_extract_credential_public_key_success() {}`
  - **Testing**: Tests successful extraction of public key from registration credential
  - **Type**: Public key extraction success test

- `fn test_extract_credential_public_key_invalid_client_data() {}`
  - **Testing**: Tests public key extraction with invalid client data
  - **Type**: Client data validation test

- `fn test_extract_credential_public_key_invalid_attestation_object() {}`
  - **Testing**: Tests public key extraction with invalid attestation object
  - **Type**: Attestation object validation test

- `fn test_extract_credential_public_key_malformed_attestation_object() {}`
  - **Testing**: Tests public key extraction with malformed attestation object structure
  - **Type**: Malformed attestation object handling test

**oauth2_passkey/src/passkey/main/related_origin.rs:**

- `pub fn get_related_origin_json() -> Result<String, PasskeyError> {}`
  - **Purpose**: Generates JSON configuration for related origins from application configuration
  - **Returns**: `Result<String, PasskeyError>` - JSON string containing related origins or configuration error
  - **Type**: Public function for related origins JSON generation

- `fn get_related_origin_json_with_core(rp_id: String, origin: String, additional_origins: Vec<String>) -> Result<String, PasskeyError> {}`
  - **Purpose**: Creates related origins JSON with core origin and additional origins list
  - **Parameters**: 
    - `rp_id`: Relying party identifier for WebAuthn
    - `origin`: Primary origin for the application
    - `additional_origins`: Vector of additional trusted origins
  - **Returns**: `Result<String, PasskeyError>` - JSON configuration string or creation error
  - **Type**: Internal function for related origins JSON construction

- `fn test_get_related_origin_json_with_core_with_additional() {}`
  - **Testing**: Tests related origins JSON generation with additional origins
  - **Type**: Related origins configuration test

- `fn test_get_related_origin_json_with_core_no_additional() {}`
  - **Testing**: Tests related origins JSON generation without additional origins
  - **Type**: Basic related origins configuration test

- `fn test_get_related_origin_json_with_core_duplicate_origins() {}`
  - **Testing**: Tests related origins JSON generation with duplicate origins in list
  - **Type**: Duplicate origins handling test

- `fn test_get_related_origin_json_with_core_empty_strings() {}`
  - **Testing**: Tests related origins JSON generation with empty string inputs
  - **Type**: Empty input validation test

- `fn test_get_related_origin_json_with_core_special_characters() {}`
  - **Testing**: Tests related origins JSON generation with special characters in origins
  - **Type**: Special character handling test

**oauth2_passkey/src/passkey/main/test_utils.rs:**

- `pub async fn insert_test_user(user_id: &str, account: &str, label: &str, is_admin: bool) -> Result<User, PasskeyError> {}`
  - **Purpose**: Inserts test user into database for testing passkey functionality
  - **Parameters**: 
    - `user_id`: String identifier for the test user
    - `account`: Account name for the test user
    - `label`: Display label for the test user
    - `is_admin`: Boolean flag indicating admin privileges
  - **Returns**: `Result<User, PasskeyError>` - Created user object or insertion error
  - **Type**: Public async test utility function for user creation

- `pub async fn insert_test_credential(credential_id: &str, user_id: &str, user_handle: &str, name: &str, display_name: &str, public_key: &str, aaguid: &str, counter: u32) -> Result<(), PasskeyError> {}`
  - **Purpose**: Inserts test passkey credential into database for testing authentication flows
  - **Parameters**: 
    - `credential_id`: String identifier for the credential
    - `user_id`: String identifier of the user owning the credential
    - `user_handle`: User handle associated with the credential
    - `name`: Name of the credential
    - `display_name`: Display name for user-friendly identification
    - `public_key`: Base64-encoded public key for signature verification
    - `aaguid`: Authenticator AAGUID (Authenticator Attestation GUID)
    - `counter`: Initial counter value for replay attack prevention
  - **Returns**: `Result<(), PasskeyError>` - Success or insertion error
  - **Type**: Public async test utility function for credential creation

- `pub async fn insert_test_user_and_credential(credential_id: &str, user_id: &str, user_handle: &str, name: &str, display_name: &str, public_key: &str, aaguid: &str, counter: u32) -> Result<(), PasskeyError> {}`
  - **Purpose**: Inserts both test user and credential in single operation for comprehensive testing
  - **Parameters**: 
    - `credential_id`: String identifier for the credential
    - `user_id`: String identifier for the user
    - `user_handle`: User handle for WebAuthn operations
    - `name`: Name of the credential
    - `display_name`: User-friendly display name
    - `public_key`: Base64-encoded public key
    - `aaguid`: Authenticator AAGUID
    - `counter`: Initial counter value
  - **Returns**: `Result<(), PasskeyError>` - Success or insertion error
  - **Type**: Public async test utility function for combined user and credential creation

- `pub async fn delete_test_credential(credential_id: &str) -> Result<(), PasskeyError> {}`
  - **Purpose**: Deletes test credential from database for test cleanup
  - **Parameters**: 
    - `credential_id`: String identifier of credential to delete
  - **Returns**: `Result<(), PasskeyError>` - Success or deletion error
  - **Type**: Public async test utility function for credential cleanup

- `pub async fn remove_from_cache(category: &str, key: &str) -> Result<(), PasskeyError> {}`
  - **Purpose**: Removes specific item from cache for testing cache operations
  - **Parameters**: 
    - `category`: Cache category string for item organization
    - `key`: Specific key for the cached item to remove
  - **Returns**: `Result<(), PasskeyError>` - Success or cache operation error
  - **Type**: Public async test utility function for cache cleanup

- `pub async fn cleanup_test_credential(credential_id: &str) -> Result<(), PasskeyError> {}`
  - **Purpose**: Comprehensive cleanup of test credential from database and cache
  - **Parameters**: 
    - `credential_id`: String identifier of credential to clean up
  - **Returns**: `Result<(), PasskeyError>` - Success or cleanup error
  - **Type**: Public async test utility function for comprehensive credential cleanup

- `pub async fn create_test_challenge( challenge_type: &str, id: &str, challenge: &str, user_handle: &str, name: &str, display_name: &str, ttl: u64, ) -> Result<(), PasskeyError> {}`
  - **Purpose**: Creates a test challenge entry in storage for testing authentication/registration flows
  - **Parameters**: 
    - `challenge_type`: Challenge type identifier (authentication/registration)
    - `id`: Unique challenge identifier
    - `challenge`: Base64-encoded challenge data
    - `user_handle`: User handle associated with the challenge
    - `name`: Display name for the challenge
    - `display_name`: Human-readable display name
    - `ttl`: Time-to-live in seconds for challenge expiration
  - **Returns**: `Result<(), PasskeyError>` - Success or storage error
  - **Type**: Public async test utility function for challenge creation

- `pub async fn check_cache_exists(category: &str, key: &str) -> bool {}`
  - **Purpose**: Checks if a cache entry exists for the given category and key
  - **Parameters**: 
    - `category`: Cache category/prefix to check
    - `key`: Cache key to verify existence
  - **Returns**: `bool` - True if cache entry exists, false otherwise
  - **Type**: Public async utility function for cache existence verification

**oauth2_passkey/src/passkey/main/types.rs:**

- `pub(super) fn new_for_test(id: String, response: AuthenticatorAssertionResponse, auth_id: String) -> Self {}`
  - **Purpose**: Creates new test authenticator response for testing authentication flows
  - **Parameters**: 
    - `id`: String identifier for the test response
    - `response`: Authenticator assertion response data
    - `auth_id`: Authentication ID for the test
  - **Returns**: `Self` - Test authenticator response instance
  - **Type**: Test constructor for authenticator response

- `pub(crate) async fn get_registration_user_fields(&self) -> (String, String) {}`
  - **Purpose**: Extracts user fields (account name and display name) from registration data
  - **Returns**: `(String, String)` - Tuple of (account_name, display_name)
  - **Type**: Public crate-level async method for user field extraction

- `pub(super) fn from_base64(client_data_json: &str) -> Result<Self, PasskeyError> {}`
  - **Purpose**: Parses base64-encoded client data JSON into structured format
  - **Parameters**: 
    - `client_data_json`: Base64-encoded client data JSON string
  - **Returns**: `Result<Self, PasskeyError>` - Parsed client data or parsing error
  - **Type**: Public super-level constructor for client data parsing

- `pub(super) fn verify(&self, stored_challenge: &str) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies client data against stored challenge and validates origin
  - **Parameters**: 
    - `stored_challenge`: Previously stored challenge string for verification
  - **Returns**: `Result<(), PasskeyError>` - Success or verification error
  - **Type**: Public super-level verification method

- `pub(super) fn from_base64(auth_data: &str) -> Result<Self, PasskeyError> {}`
  - **Purpose**: Parses base64-encoded authenticator data into structured format
  - **Parameters**: 
    - `auth_data`: Base64-encoded authenticator data string
  - **Returns**: `Result<Self, PasskeyError>` - Parsed authenticator data or parsing error
  - **Type**: Public super-level constructor for authenticator data parsing

- `pub(super) fn is_user_present(&self) -> bool {}`
  - **Purpose**: Checks if user presence flag is set in authenticator data
  - **Returns**: `bool` - True if user was present during authentication
  - **Type**: Public super-level flag accessor method

- `pub(super) fn is_user_verified(&self) -> bool {}`
  - **Purpose**: Checks if user verification flag is set in authenticator data
  - **Returns**: `bool` - True if user was verified during authentication
  - **Type**: Public super-level flag accessor method

- `pub(super) fn is_discoverable(&self) -> bool {}`
  - **Purpose**: Checks if credential is discoverable (resident key)
  - **Returns**: `bool` - True if credential supports discoverable authentication
  - **Type**: Public super-level credential type accessor

- `pub(super) fn is_backed_up(&self) -> bool {}`
  - **Purpose**: Checks if credential is backed up on the authenticator
  - **Returns**: `bool` - True if credential has backup capability
  - **Type**: Public super-level backup status accessor

- `pub(super) fn has_attested_credential_data(&self) -> bool {}`
  - **Purpose**: Checks if authenticator data contains attested credential data
  - **Returns**: `bool` - True if attested credential data is present
  - **Type**: Public super-level data presence check

- `pub(super) fn has_extension_data(&self) -> bool {}`
  - **Purpose**: Checks if authenticator data contains extension data
  - **Returns**: `bool` - True if extension data is present
  - **Type**: Public super-level extension data presence check

- `pub(super) fn verify(&self) -> Result<(), PasskeyError> {}`
  - **Purpose**: Verifies authenticator data integrity and RP ID hash
  - **Returns**: `Result<(), PasskeyError>` - Success or verification error
  - **Type**: Public super-level verification method

- `fn test_authentication_options_serialization() {}`
  - **Testing**: Tests serialization of authentication options to JSON
  - **Type**: Authentication options serialization test

- `fn test_webauthn_client_data_serialization() {}`
  - **Testing**: Tests serialization of WebAuthn client data structures
  - **Type**: Client data serialization test

- `fn test_webauthn_client_data_field_mapping() {}`
  - **Testing**: Tests field mapping for WebAuthn client data
  - **Type**: Client data field mapping test

- `fn create_parsed_client_data(challenge: &str, origin: &str, type_: &str) -> ParsedClientData {}`
  - **Purpose**: Creates test parsed client data with specified parameters
  - **Parameters**: 
    - `challenge`: Challenge string for test data
    - `origin`: Origin string for test data
    - `type_`: WebAuthn ceremony type
  - **Returns**: `ParsedClientData` - Test parsed client data
  - **Type**: Test utility function for parsed client data creation

- `fn test_from_base64_success() {}`
  - **Testing**: Tests successful base64 decoding and parsing of client data
  - **Type**: Base64 parsing success test

- `fn test_from_base64_invalid_base64() {}`
  - **Testing**: Tests base64 decoding with invalid base64 encoding
  - **Type**: Base64 decoding error handling test

- `fn test_from_base64_invalid_utf8() {}`
  - **Testing**: Tests base64 decoding with invalid UTF-8 encoding
  - **Type**: UTF-8 encoding validation test

- `fn test_from_base64_invalid_json() {}`
  - **Testing**: Tests base64 decoding with invalid JSON structure
  - **Type**: JSON parsing error handling test

- `fn test_from_base64_missing_challenge() {}`
  - **Testing**: Tests client data parsing with missing challenge field
  - **Type**: Required challenge field validation test

- `fn test_from_base64_missing_origin() {}`
  - **Testing**: Tests client data parsing with missing origin field
  - **Type**: Required origin field validation test

- `fn test_from_base64_missing_type() {}`
  - **Testing**: Tests client data parsing with missing type field
  - **Type**: Required type field validation test

- `fn test_verify_success() {}`
  - **Testing**: Tests successful client data verification
  - **Type**: Client data verification success test

- `fn test_verify_challenge_mismatch() {}`
  - **Testing**: Tests client data verification with mismatched challenge
  - **Type**: Challenge mismatch validation test

- `fn test_verify_origin_mismatch() {}`
  - **Testing**: Tests client data verification with mismatched origin
  - **Type**: Origin mismatch validation test

- `fn test_verify_invalid_type() {}`
  - **Testing**: Tests client data verification with invalid ceremony type
  - **Type**: Invalid type validation test

- `fn create_test_auth_data(rp_id_hash: Vec<u8>, flags: u8, counter: u32, extra_data: Option<Vec<u8>>) -> Vec<u8> {}`
  - **Purpose**: Creates test authenticator data with specified parameters
  - **Parameters**: 
    - `rp_id_hash`: RP ID hash bytes
    - `flags`: Authenticator flags byte
    - `counter`: Signature counter value
    - `extra_data`: Optional additional data
  - **Returns**: `Vec<u8>` - Authenticator data bytes
  - **Type**: Test utility function for authenticator data creation

- `fn test_from_base64_success() {}`
  - **Testing**: Tests successful authenticator data base64 parsing
  - **Type**: Authenticator data parsing success test

- `fn test_from_base64_invalid_base64() {}`
  - **Testing**: Tests authenticator data parsing with invalid base64
  - **Type**: Base64 decoding error handling test

- `fn test_from_base64_too_short() {}`
  - **Testing**: Tests authenticator data parsing with insufficient data length
  - **Type**: Data length validation test

- `fn test_individual_flag_methods() {}`
  - **Testing**: Tests individual authenticator flag accessor methods
  - **Type**: Flag accessor method test

- `fn test_flag_methods() {}`
  - **Testing**: Tests authenticator flag parsing and interpretation
  - **Type**: Flag parsing functionality test

- `fn test_verify_success() {}`
  - **Testing**: Tests successful authenticator data verification
  - **Type**: Authenticator data verification success test

- `fn test_verify_invalid_rp_id_hash() {}`
  - **Testing**: Tests authenticator data verification with invalid RP ID hash
  - **Type**: RP ID hash validation test

- `fn test_verify_user_not_present() {}`
  - **Testing**: Tests authenticator data verification when user presence flag is not set
  - **Type**: User presence requirement validation test

- `fn test_verify_user_verification_required_but_not_verified() {}`
  - **Testing**: Tests authenticator data verification when user verification is required but not performed
  - **Type**: User verification requirement validation test

**oauth2_passkey/src/passkey/main/utils.rs:**

- `async fn get_credential_id_strs_by(field: CredentialSearchField) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {}`
  - **Purpose**: Retrieves credential ID strings filtered by search field criteria
  - **Parameters**: 
    - `field`: Search criteria for filtering credentials
  - **Returns**: `Result<Vec<UserIdCredentialIdStr>, PasskeyError>` - Vector of user-credential ID pairs or error
  - **Type**: Internal async function for credential lookup

- `pub(super) async fn name2cid_str_vec(name: &str) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {}`
  - **Purpose**: Converts username to credential ID string vector for credential lookup
  - **Parameters**: 
    - `name`: Username string for credential search
  - **Returns**: `Result<Vec<UserIdCredentialIdStr>, PasskeyError>` - Vector of associated credential IDs or error
  - **Type**: Public super-level async function for username-to-credential mapping

- `pub(super) async fn store_in_cache<T>(category: &str, key: &str, data: T, ttl: usize) -> Result<(), PasskeyError> where T: Into<CacheData> {}`
  - **Purpose**: Stores typed data in cache with specified category, key, and TTL
  - **Parameters**: 
    - `category`: Cache category for organization
    - `key`: Cache key for retrieval
    - `data`: Data to store (must convert to CacheData)
    - `ttl`: Time-to-live in seconds
  - **Returns**: `Result<(), PasskeyError>` - Success or cache storage error
  - **Type**: Public super-level generic async function for cache storage

- `pub(super) async fn get_from_cache<T>(category: &str, key: &str) -> Result<Option<T>, PasskeyError> where T: TryFrom<CacheData, Error = PasskeyError> {}`
  - **Purpose**: Retrieves and converts typed data from cache by category and key
  - **Parameters**: 
    - `category`: Cache category for organization
    - `key`: Cache key for lookup
  - **Returns**: `Result<Option<T>, PasskeyError>` - Optional converted data or error
  - **Type**: Public super-level generic async function for cache retrieval

- `pub(super) async fn remove_from_cache(category: &str, key: &str) -> Result<(), PasskeyError> {}`
  - **Purpose**: Removes cached item by category and key
  - **Parameters**: 
    - `category`: Cache category for organization
    - `key`: Cache key for item removal
  - **Returns**: `Result<(), PasskeyError>` - Success or cache removal error
  - **Type**: Public super-level async function for cache cleanup

- `fn test_stored_options_cache_data_conversion() {}`
  - **Testing**: Tests conversion of stored options to and from cache data format
  - **Type**: Cache data conversion test

- `fn test_stored_options_cache_data_conversion_edge_cases() {}`
  - **Testing**: Tests cache data conversion with edge cases and boundary conditions
  - **Type**: Cache conversion edge case test

- `async fn test_cache_operations() {}`
  - **Testing**: Tests basic cache operations (store, get, remove)
  - **Type**: Cache operations functionality test

- `async fn test_cache_operations_different_keys() {}`
  - **Testing**: Tests cache operations with different key patterns
  - **Type**: Cache key isolation test

- `async fn test_comprehensive_cache_operations() {}`
  - **Testing**: Comprehensive test of all cache operations and edge cases
  - **Type**: Comprehensive cache functionality test

**oauth2_passkey/src/passkey/mod.rs:**

- `pub(crate) async fn init() -> Result<(), PasskeyError> {}`
  - **Purpose**: Initializes the passkey module and its dependencies
  - **Returns**: `Result<(), PasskeyError>` - Success or initialization error
  - **Type**: Public crate-level async initialization function

**oauth2_passkey/src/passkey/storage/postgres.rs:**

- `pub(super) async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), PasskeyError> {}`
  - **Purpose**: Creates PostgreSQL tables required for passkey credential storage
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool for database operations
  - **Returns**: `Result<(), PasskeyError>` - Success or table creation error
  - **Type**: Public super-level async function for database schema setup

- `pub(super) async fn validate_passkey_tables_postgres(pool: &Pool<Postgres>) -> Result<(), PasskeyError> {}`
  - **Purpose**: Validates PostgreSQL table schema matches expected passkey table structure
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool for schema validation
  - **Returns**: `Result<(), PasskeyError>` - Success or validation error
  - **Type**: Public super-level async function for schema validation

- `pub(super) async fn store_credential_postgres(pool: &Pool<Postgres>, credential_id: &str, credential: &PasskeyCredential) -> Result<(), PasskeyError> {}`
  - **Purpose**: Stores passkey credential in PostgreSQL database
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool
    - `credential_id`: Unique identifier for the credential
    - `credential`: Passkey credential data to store
  - **Returns**: `Result<(), PasskeyError>` - Success or storage error
  - **Type**: Public super-level async function for credential persistence

- `pub(super) async fn get_credential_postgres(pool: &Pool<Postgres>, credential_id: &str) -> Result<Option<PasskeyCredential>, PasskeyError> {}`
  - **Purpose**: Retrieves passkey credential from PostgreSQL database by ID
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool
    - `credential_id`: Unique identifier for credential lookup
  - **Returns**: `Result<Option<PasskeyCredential>, PasskeyError>` - Optional credential or error
  - **Type**: Public super-level async function for credential retrieval

- `pub(super) async fn get_credentials_by_field_postgres(pool: &Pool<Postgres>, field: &CredentialSearchField) -> Result<Vec<PasskeyCredential>, PasskeyError> {}`
  - **Purpose**: Retrieves multiple passkey credentials from PostgreSQL filtered by search field
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool
    - `field`: Search criteria for filtering credentials
  - **Returns**: `Result<Vec<PasskeyCredential>, PasskeyError>` - Vector of matching credentials or error
  - **Type**: Public super-level async function for filtered credential retrieval

- `pub(super) async fn update_credential_counter_postgres(pool: &Pool<Postgres>, credential_id: &str, counter: u32) -> Result<(), PasskeyError> {}`
  - **Purpose**: Updates authenticator counter for specific credential in PostgreSQL
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool
    - `credential_id`: Unique identifier for credential
    - `counter`: New counter value for replay attack prevention
  - **Returns**: `Result<(), PasskeyError>` - Success or update error
  - **Type**: Public super-level async function for counter management

- `pub(super) async fn delete_credential_by_field_postgres(pool: &Pool<Postgres>, field: &CredentialSearchField) -> Result<(), PasskeyError> {}`
  - **Purpose**: Deletes passkey credentials from PostgreSQL filtered by search field
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool
    - `field`: Search criteria for identifying credentials to delete
  - **Returns**: `Result<(), PasskeyError>` - Success or deletion error
  - **Type**: Public super-level async function for credential cleanup

- `pub(super) async fn update_credential_user_details_postgres(pool: &Pool<Postgres>, credential_id: &str, name: &str, display_name: &str) -> Result<(), PasskeyError> {}`
  - **Purpose**: Updates user-visible details for passkey credential in PostgreSQL
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool
    - `credential_id`: Unique identifier for credential
    - `name`: Updated user name
    - `display_name`: Updated display name
  - **Returns**: `Result<(), PasskeyError>` - Success or update error
  - **Type**: Public super-level async function for user detail management

- `fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {}`
  - **Purpose**: Converts SQLite database row to PasskeyCredential struct
  - **Parameters**: 
    - `row`: SQLite row reference for data conversion
  - **Returns**: `Result<Self, sqlx::Error>` - Converted credential or conversion error
  - **Type**: Trait implementation for SQLite row mapping

- `fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {}`
  - **Purpose**: Converts PostgreSQL database row to PasskeyCredential struct
  - **Parameters**: 
    - `row`: PostgreSQL row reference for data conversion
  - **Returns**: `Result<Self, sqlx::Error>` - Converted credential or conversion error
  - **Type**: Trait implementation for PostgreSQL row mapping

- `pub(super) async fn update_credential_last_used_at_postgres(pool: &Pool<Postgres>, credential_id: &str, last_used_at: DateTime<Utc>) -> Result<(), PasskeyError> {}`
  - **Purpose**: Updates last used timestamp for passkey credential in PostgreSQL
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool
    - `credential_id`: Unique identifier for credential
    - `last_used_at`: UTC timestamp of last credential usage
  - **Returns**: `Result<(), PasskeyError>` - Success or update error
  - **Type**: Public super-level async function for usage tracking

**oauth2_passkey/src/passkey/storage/sqlite.rs:**

- `pub(super) async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), PasskeyError> {}`
  - **Purpose**: Creates SQLite tables required for passkey credential storage
  - **Parameters**: 
    - `pool`: SQLite connection pool for database operations
  - **Returns**: `Result<(), PasskeyError>` - Success or table creation error
  - **Type**: Public super-level async function for database schema setup

- `pub(super) async fn validate_passkey_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), PasskeyError> {}`
  - **Purpose**: Validates SQLite table schema matches expected passkey table structure
  - **Parameters**: 
    - `pool`: SQLite connection pool for schema validation
  - **Returns**: `Result<(), PasskeyError>` - Success or validation error
  - **Type**: Public super-level async function for schema validation

- `pub(super) async fn store_credential_sqlite(pool: &Pool<Sqlite>, credential_id: &str, credential: &PasskeyCredential) -> Result<(), PasskeyError> {}`
  - **Purpose**: Stores passkey credential in SQLite database
  - **Parameters**: 
    - `pool`: SQLite connection pool
    - `credential_id`: Unique identifier for the credential
    - `credential`: Passkey credential data to store
  - **Returns**: `Result<(), PasskeyError>` - Success or storage error
  - **Type**: Public super-level async function for credential persistence

- `pub(super) async fn get_credential_sqlite(pool: &Pool<Sqlite>, credential_id: &str) -> Result<Option<PasskeyCredential>, PasskeyError> {}`
  - **Purpose**: Retrieves passkey credential from SQLite database by ID
  - **Parameters**: 
    - `pool`: SQLite connection pool
    - `credential_id`: Unique identifier for credential lookup
  - **Returns**: `Result<Option<PasskeyCredential>, PasskeyError>` - Optional credential or error
  - **Type**: Public super-level async function for credential retrieval

- `pub(super) async fn get_credentials_by_field_sqlite(pool: &Pool<Sqlite>, field: &CredentialSearchField) -> Result<Vec<PasskeyCredential>, PasskeyError> {}`
  - **Purpose**: Retrieves multiple passkey credentials from SQLite filtered by search field
  - **Parameters**: 
    - `pool`: SQLite connection pool
    - `field`: Search criteria for filtering credentials
  - **Returns**: `Result<Vec<PasskeyCredential>, PasskeyError>` - Vector of matching credentials or error
  - **Type**: Public super-level async function for filtered credential retrieval

- `pub(super) async fn update_credential_counter_sqlite(pool: &Pool<Sqlite>, credential_id: &str, counter: u32) -> Result<(), PasskeyError> {}`
  - **Purpose**: Updates authenticator counter for specific credential in SQLite
  - **Parameters**: 
    - `pool`: SQLite connection pool
    - `credential_id`: Unique identifier for credential
    - `counter`: New counter value for replay attack prevention
  - **Returns**: `Result<(), PasskeyError>` - Success or update error
  - **Type**: Public super-level async function for counter management

- `pub(super) async fn delete_credential_by_field_sqlite(pool: &Pool<Sqlite>, field: &CredentialSearchField) -> Result<(), PasskeyError> {}`
  - **Purpose**: Deletes passkey credentials from SQLite filtered by search field
  - **Parameters**: 
    - `pool`: SQLite connection pool
    - `field`: Search criteria for identifying credentials to delete
  - **Returns**: `Result<(), PasskeyError>` - Success or deletion error
  - **Type**: Public super-level async function for credential cleanup

- `pub(super) async fn update_credential_user_details_sqlite(pool: &Pool<Sqlite>, credential_id: &str, name: &str, display_name: &str) -> Result<(), PasskeyError> {}`
  - **Purpose**: Updates user-visible details for passkey credential in SQLite
  - **Parameters**: 
    - `pool`: SQLite connection pool
    - `credential_id`: Unique identifier for credential
    - `name`: Updated user name
    - `display_name`: Updated display name
  - **Returns**: `Result<(), PasskeyError>` - Success or update error
  - **Type**: Public super-level async function for user detail management

- `pub(super) async fn update_credential_last_used_at_sqlite(pool: &Pool<Sqlite>, credential_id: &str, last_used_at: DateTime<Utc>) -> Result<(), PasskeyError> {}`
  - **Purpose**: Updates last used timestamp for passkey credential in SQLite
  - **Parameters**: 
    - `pool`: SQLite connection pool
    - `credential_id`: Unique identifier for credential
    - `last_used_at`: UTC timestamp of last credential usage
  - **Returns**: `Result<(), PasskeyError>` - Success or update error
  - **Type**: Public super-level async function for usage tracking

**oauth2_passkey/src/passkey/storage/store_type.rs:**

- `pub(crate) async fn init() -> Result<(), PasskeyError> {}`
  - **Purpose**: Initializes the passkey storage system with database connections
  - **Returns**: `Result<(), PasskeyError>` - Success or initialization error
  - **Type**: Public crate-level async function for storage initialization

- `pub(crate) async fn store_credential(credential_id: String, credential: PasskeyCredential) -> Result<(), PasskeyError> {}`
  - **Purpose**: Stores passkey credential in the configured database backend
  - **Parameters**: 
    - `credential_id`: Unique identifier for the credential
    - `credential`: Passkey credential data to store
  - **Returns**: `Result<(), PasskeyError>` - Success or storage error
  - **Type**: Public crate-level async function for credential storage

- `pub(crate) async fn get_credential(credential_id: &str) -> Result<Option<PasskeyCredential>, PasskeyError> {}`
  - **Purpose**: Retrieves passkey credential from database by credential ID
  - **Parameters**: 
    - `credential_id`: Unique identifier for credential lookup
  - **Returns**: `Result<Option<PasskeyCredential>, PasskeyError>` - Optional credential or error
  - **Type**: Public crate-level async function for credential retrieval

- `pub(crate) async fn get_credentials_by(field: CredentialSearchField) -> Result<Vec<PasskeyCredential>, PasskeyError> {}`
  - **Purpose**: Retrieves multiple passkey credentials filtered by search criteria
  - **Parameters**: 
    - `field`: Search criteria for filtering credentials
  - **Returns**: `Result<Vec<PasskeyCredential>, PasskeyError>` - Vector of matching credentials or error
  - **Type**: Public crate-level async function for filtered credential retrieval

- `pub(crate) async fn update_credential_counter(credential_id: &str, counter: u32) -> Result<(), PasskeyError> {}`
  - **Purpose**: Updates authenticator counter for replay attack prevention
  - **Parameters**: 
    - `credential_id`: Unique identifier for credential
    - `counter`: New counter value
  - **Returns**: `Result<(), PasskeyError>` - Success or update error
  - **Type**: Public crate-level async function for counter management

- `pub(crate) async fn delete_credential_by(field: CredentialSearchField) -> Result<(), PasskeyError> {}`
  - **Purpose**: Deletes passkey credentials filtered by search criteria
  - **Parameters**: 
    - `field`: Search criteria for identifying credentials to delete
  - **Returns**: `Result<(), PasskeyError>` - Success or deletion error
  - **Type**: Public crate-level async function for credential cleanup

- `pub(crate) async fn update_credential(credential_id: &str, name: &str, display_name: &str) -> Result<(), PasskeyError> {}`
  - **Purpose**: Updates user-visible details for passkey credential
  - **Parameters**: 
    - `credential_id`: Unique identifier for credential
    - `name`: Updated user name
    - `display_name`: Updated display name
  - **Returns**: `Result<(), PasskeyError>` - Success or update error
  - **Type**: Public crate-level async function for user detail management

- `pub(crate) async fn update_credential_last_used_at(credential_id: &str, last_used_at: DateTime<Utc>) -> Result<(), PasskeyError> {}`
  - **Purpose**: Updates last used timestamp for passkey credential
  - **Parameters**: 
    - `credential_id`: Unique identifier for credential
    - `last_used_at`: UTC timestamp of last credential usage
  - **Returns**: `Result<(), PasskeyError>` - Success or update error
  - **Type**: Public crate-level async function for usage tracking

- `fn create_test_credential(credential_id: &str, user_id: &str, user_handle: &str) -> PasskeyCredential {}`
  - **Purpose**: Creates mock passkey credential for testing storage operations
  - **Parameters**: 
    - `credential_id`: Unique identifier for test credential
    - `user_id`: User ID for test credential
    - `user_handle`: User handle for test credential
  - **Returns**: `PasskeyCredential` - Mock credential for testing
  - **Type**: Test utility function for credential creation

- `async fn create_test_user(user_id: &str) -> Result<User, Box<dyn std::error::Error>> {}`
  - **Purpose**: Creates test user in database for storage testing
  - **Parameters**: 
    - `user_id`: Unique identifier for test user
  - **Returns**: `Result<User, Box<dyn std::error::Error>>` - Created user or error
  - **Type**: Test utility function for user creation

- `async fn test_passkey_store_init() {}`
  - **Testing**: Tests passkey storage system initialization
  - **Type**: Storage initialization test

- `async fn test_store_and_get_credential() {}`
  - **Testing**: Tests storing and retrieving passkey credentials
  - **Type**: Credential storage and retrieval test

- `async fn test_get_nonexistent_credential() {}`
  - **Testing**: Tests credential retrieval for non-existent credentials
  - **Type**: Non-existent credential handling test

- `async fn test_get_credentials_by_user_id() {}`
  - **Testing**: Tests credential retrieval filtered by user ID
  - **Type**: User ID based credential filtering test

- `async fn test_get_credentials_by_user_handle() {}`
  - **Testing**: Tests credential retrieval filtered by user handle
  - **Type**: User handle based credential filtering test

- `async fn test_get_credentials_by_username() {}`
  - **Testing**: Tests credential retrieval filtered by username
  - **Type**: Username based credential filtering test

- `async fn test_update_credential_counter() {}`
  - **Testing**: Tests authenticator counter updates for credentials
  - **Type**: Counter update functionality test

- `async fn test_update_credential_user_details() {}`
  - **Testing**: Tests updating user-visible credential details
  - **Type**: User detail update functionality test

- `async fn test_update_credential_last_used_at() {}`
  - **Testing**: Tests updating credential last used timestamps
  - **Type**: Last used timestamp update test

- `async fn test_delete_credential_by_credential_id() {}`
  - **Testing**: Tests credential deletion by credential ID
  - **Type**: Credential ID based deletion test

- `async fn test_delete_credentials_by_user_id() {}`
  - **Testing**: Tests credential deletion by user ID
  - **Type**: User ID based credential deletion test

- `async fn test_credential_isolation() {}`
  - **Testing**: Tests credential isolation between different users
  - **Type**: Credential isolation security test

- `async fn test_concurrent_operations() {}`
  - **Testing**: Tests concurrent storage operations for thread safety
  - **Type**: Concurrent access safety test

**oauth2_passkey/src/passkey/types.rs:**

- `fn from(data: SessionInfo) -> Self {}`
  - **Purpose**: Converts SessionInfo data into CacheData format for storage
  - **Parameters**: 
    - `data`: SessionInfo instance to convert
  - **Returns**: `Self` - CacheData instance containing session information
  - **Type**: Trait implementation for data conversion

- `fn try_from(data: CacheData) -> Result<Self, Self::Error> {}`
  - **Purpose**: Attempts to convert CacheData back to SessionInfo with error handling
  - **Parameters**: 
    - `data`: CacheData instance to convert
  - **Returns**: `Result<Self, Self::Error>` - SessionInfo instance or conversion error
  - **Type**: Trait implementation for fallible data conversion

- `fn from(data: StoredOptions) -> Self {}`
  - **Purpose**: Converts StoredOptions data into CacheData format for storage
  - **Parameters**: 
    - `data`: StoredOptions instance to convert
  - **Returns**: `Self` - CacheData instance containing stored options
  - **Type**: Trait implementation for data conversion

- `fn try_from(data: CacheData) -> Result<Self, Self::Error> {}`
  - **Purpose**: Attempts to convert CacheData back to StoredOptions with error handling
  - **Parameters**: 
    - `data`: CacheData instance to convert
  - **Returns**: `Result<Self, Self::Error>` - StoredOptions instance or conversion error
  - **Type**: Trait implementation for fallible data conversion

**oauth2_passkey/src/session/main/mod.rs:**

- `pub(crate) async fn new_session_header(user_id: String) -> Result<HeaderMap, SessionError> {}`
  - **Purpose**: Creates new session headers with authentication cookies for user
  - **Parameters**: 
    - `user_id`: String identifier for the user to create session for
  - **Returns**: `Result<HeaderMap, SessionError>` - Headers with session cookies or session creation error
  - **Type**: Public crate-level async function for session header creation

**oauth2_passkey/src/session/main/page_session_token.rs:**

- `pub fn generate_page_session_token(token: &str) -> String {}`
  - **Purpose**: Generates HMAC-based page session token for CSRF protection
  - **Parameters**: 
    - `token`: Input token string to generate HMAC for
  - **Returns**: `String` - HMAC-based page session token
  - **Type**: Public function for CSRF token generation

- `pub async fn verify_page_session_token( headers: &HeaderMap, page_session_token: Option<&String>, ) -> Result<(), SessionError> {}`
  - **Purpose**: Verifies page session token against session data to prevent CSRF attacks
  - **Parameters**: 
    - `headers`: HTTP headers containing session information
    - `page_session_token`: Optional page session token to verify
  - **Returns**: `Result<(), SessionError>` - Success or token verification error
  - **Type**: Public async function for CSRF token verification

- `fn test_generate_page_session_token() {}`
  - **Testing**: Tests page session token generation functionality
  - **Type**: Token generation test

- `fn test_generate_page_session_token_hmac_properties() {}`
  - **Testing**: Tests HMAC properties of generated page session tokens
  - **Type**: HMAC token properties test

- `fn test_generate_page_session_token_with_empty_string() {}`
  - **Testing**: Tests page session token generation with empty input string
  - **Type**: Empty input validation test

- `fn create_test_session(csrf_token: &str) -> serde_json::Value {}`
  - **Purpose**: Creates test session JSON object with specified CSRF token
  - **Parameters**: 
    - `csrf_token`: CSRF token string for test session
  - **Returns**: `serde_json::Value` - JSON session object for testing
  - **Type**: Test utility function for session creation

- `fn get_session_cookie_name() -> &'static str {}`
  - **Purpose**: Returns the standard session cookie name used by the application
  - **Returns**: `&'static str` - Session cookie name string
  - **Type**: Configuration function for cookie naming

- `async fn test_verify_page_session_token_success() {}`
  - **Testing**: Tests successful page session token verification
  - **Type**: Token verification success test

- `async fn test_verify_page_session_token_invalid_token() {}`
  - **Testing**: Tests page session token verification with invalid token
  - **Type**: Invalid token validation test

- `async fn test_verify_page_session_token_missing_token() {}`
  - **Testing**: Tests page session token verification with missing token
  - **Type**: Missing token validation test

- `async fn test_verify_page_session_token_missing_session() {}`
  - **Testing**: Tests page session token verification with missing session
  - **Type**: Missing session validation test

**oauth2_passkey/src/session/main/session.rs:**

- `pub async fn prepare_logout_response(cookies: headers::Cookie) -> Result<HeaderMap, SessionError> {}`
  - **Purpose**: Prepares HTTP response headers for user logout with session cleanup
  - **Parameters**: 
    - `cookies`: Cookie header containing session information to clean up
  - **Returns**: `Result<HeaderMap, SessionError>` - Headers with logout cookies or error
  - **Type**: Public async function for logout handling

- `pub(super) async fn create_new_session_with_uid(user_id: &str) -> Result<HeaderMap, SessionError> {}`
  - **Purpose**: Creates new authenticated session for specified user ID
  - **Parameters**: 
    - `user_id`: String identifier for user to create session for
  - **Returns**: `Result<HeaderMap, SessionError>` - Headers with session cookies or error
  - **Type**: Public super-level async function for session creation

- `async fn delete_session_from_store( cookies: Cookie, cookie_name: String, ) -> Result<(), SessionError> {}`
  - **Purpose**: Deletes session from storage using cookie information
  - **Parameters**: 
    - `cookies`: Cookie data containing session information
    - `cookie_name`: Name of session cookie to delete
  - **Returns**: `Result<(), SessionError>` - Success or deletion error
  - **Type**: Internal async function for session cleanup

- `pub(crate) async fn delete_session_from_store_by_session_id( session_id: &str, ) -> Result<(), SessionError> {}`
  - **Purpose**: Deletes session from storage using session ID directly
  - **Parameters**: 
    - `session_id`: Session identifier to delete from storage
  - **Returns**: `Result<(), SessionError>` - Success or deletion error
  - **Type**: Public crate-level async function for session cleanup

- `pub async fn get_user_from_session(session_cookie: &str) -> Result<SessionUser, SessionError> {}`
  - **Purpose**: Retrieves user information from active session cookie
  - **Parameters**: 
    - `session_cookie`: Session cookie string for user lookup
  - **Returns**: `Result<SessionUser, SessionError>` - User session data or error
  - **Type**: Public async function for user retrieval

- `pub(crate) fn get_session_id_from_headers( headers: &HeaderMap, ) -> Result<Option<&str>, SessionError> {}`
  - **Purpose**: Extracts session ID from HTTP headers cookie data
  - **Parameters**: 
    - `headers`: HTTP headers containing cookie information
  - **Returns**: `Result<Option<&str>, SessionError>` - Optional session ID or parsing error
  - **Type**: Public crate-level function for session ID extraction

- `async fn is_authenticated( headers: &HeaderMap, method: &Method, verify_user_exists: bool, ) -> Result< ( AuthenticationStatus, Option<UserId>, Option<CsrfToken>, CsrfHeaderVerified, ), SessionError, > {}`
  - **Purpose**: Comprehensive authentication check with optional user verification and CSRF validation
  - **Parameters**: 
    - `headers`: HTTP headers containing session information
    - `method`: HTTP method for CSRF validation requirements
    - `verify_user_exists`: Whether to verify user exists in database
  - **Returns**: `Result<(AuthenticationStatus, Option<UserId>, Option<CsrfToken>, CsrfHeaderVerified), SessionError>` - Authentication details or error
  - **Type**: Internal async function for comprehensive authentication

- `pub async fn is_authenticated_basic( headers: &HeaderMap, method: &Method, ) -> Result<AuthenticationStatus, SessionError> {}`
  - **Purpose**: Basic authentication check without user verification or CSRF validation
  - **Parameters**: 
    - `headers`: HTTP headers containing session information
    - `method`: HTTP method for context
  - **Returns**: `Result<AuthenticationStatus, SessionError>` - Authentication status or error
  - **Type**: Public async function for basic authentication check

- `pub async fn is_authenticated_basic_then_csrf( headers: &HeaderMap, method: &Method, ) -> Result<(CsrfToken, CsrfHeaderVerified), SessionError> {}`
  - **Purpose**: Basic authentication check followed by CSRF token validation
  - **Parameters**: 
    - `headers`: HTTP headers containing session and CSRF information
    - `method`: HTTP method for CSRF validation requirements
  - **Returns**: `Result<(CsrfToken, CsrfHeaderVerified), SessionError>` - CSRF tokens or error
  - **Type**: Public async function for authentication with CSRF validation

- `pub async fn is_authenticated_strict( headers: &HeaderMap, method: &Method, ) -> Result<AuthenticationStatus, SessionError> {}`
  - **Purpose**: Strict authentication check with user existence verification
  - **Parameters**: 
    - `headers`: HTTP headers containing session information
    - `method`: HTTP method for context
  - **Returns**: `Result<AuthenticationStatus, SessionError>` - Authentication status or error
  - **Type**: Public async function for strict authentication check

- `pub async fn is_authenticated_strict_then_csrf( headers: &HeaderMap, method: &Method, ) -> Result<(CsrfToken, CsrfHeaderVerified), SessionError> {}`
  - **Purpose**: Strict authentication check with user verification followed by CSRF validation
  - **Parameters**: 
    - `headers`: HTTP headers containing session and CSRF information
    - `method`: HTTP method for CSRF validation requirements
  - **Returns**: `Result<(CsrfToken, CsrfHeaderVerified), SessionError>` - CSRF tokens or error
  - **Type**: Public async function for strict authentication with CSRF

- `pub async fn is_authenticated_basic_then_user_and_csrf( headers: &HeaderMap, method: &Method, ) -> Result<(SessionUser, CsrfToken, CsrfHeaderVerified), SessionError> {}`
  - **Purpose**: Basic authentication followed by user data and CSRF token retrieval
  - **Parameters**: 
    - `headers`: HTTP headers containing session and CSRF information
    - `method`: HTTP method for CSRF validation requirements
  - **Returns**: `Result<(SessionUser, CsrfToken, CsrfHeaderVerified), SessionError>` - User and CSRF data or error
  - **Type**: Public async function for comprehensive session data retrieval

- `pub async fn get_csrf_token_from_session(session_id: &str) -> Result<CsrfToken, SessionError> {}`
  - **Purpose**: Retrieves CSRF token from session storage by session ID
  - **Parameters**: 
    - `session_id`: Session identifier for CSRF token lookup
  - **Returns**: `Result<CsrfToken, SessionError>` - CSRF token or retrieval error
  - **Type**: Public async function for CSRF token retrieval

- `pub async fn get_user_and_csrf_token_from_session( session_id: &str, ) -> Result<(SessionUser, CsrfToken), SessionError> {}`
  - **Purpose**: Retrieves both user data and CSRF token from session storage
  - **Parameters**: 
    - `session_id`: Session identifier for data lookup
  - **Returns**: `Result<(SessionUser, CsrfToken), SessionError>` - User and CSRF data or error
  - **Type**: Public async function for combined session data retrieval

- `fn create_header_map_with_cookie(cookie_name: &str, cookie_value: &str) -> HeaderMap {}`
  - **Purpose**: Creates HTTP header map with specified cookie for testing
  - **Parameters**: 
    - `cookie_name`: Name of the cookie to set
    - `cookie_value`: Value of the cookie to set
  - **Returns**: `HeaderMap` - Headers with cookie set
  - **Type**: Test utility function for header creation

- `fn test_get_session_id_from_headers() {}`
  - **Testing**: Tests successful session ID extraction from headers
  - **Type**: Session ID extraction test

- `fn test_get_session_id_from_headers_no_cookie() {}`
  - **Testing**: Tests session ID extraction when no cookie is present
  - **Type**: Missing cookie validation test

- `fn test_get_session_id_from_headers_wrong_cookie() {}`
  - **Testing**: Tests session ID extraction with incorrect cookie name
  - **Type**: Wrong cookie name validation test

- `fn test_csrf_token_verification() {}`
  - **Testing**: Tests successful CSRF token verification functionality
  - **Type**: CSRF token verification test

- `fn test_csrf_token_verification_mismatch() {}`
  - **Testing**: Tests CSRF token verification with mismatched tokens
  - **Type**: CSRF token mismatch validation test

- `fn create_test_session(csrf_token: &str, user_id: &str) -> serde_json::Value {}`
  - **Purpose**: Creates test session JSON object with CSRF token and user ID
  - **Parameters**: 
    - `csrf_token`: CSRF token for test session
    - `user_id`: User ID for test session
  - **Returns**: `serde_json::Value` - JSON session object for testing
  - **Type**: Test utility function for session creation

- `async fn test_get_csrf_token_from_session_success() {}`
  - **Testing**: Tests successful CSRF token retrieval from session
  - **Type**: CSRF token retrieval success test

- `async fn test_get_csrf_token_from_session_not_found() {}`
  - **Testing**: Tests CSRF token retrieval when session is not found
  - **Type**: Session not found validation test

- `async fn test_get_user_from_session_success() {}`
  - **Testing**: Tests successful user retrieval from session
  - **Type**: User retrieval success test

- `async fn test_get_user_from_session_session_not_found() {}`
  - **Testing**: Tests user retrieval when session is not found
  - **Type**: Session not found for user retrieval test

- `async fn test_create_new_session_with_uid() {}`
  - **Testing**: Tests new session creation with user ID
  - **Type**: Session creation test

- `async fn test_delete_session_from_store_by_session_id() {}`
  - **Testing**: Tests session deletion using session ID
  - **Type**: Session deletion test

- `async fn test_is_authenticated_success() {}`
  - **Testing**: Tests successful authentication verification
  - **Type**: Authentication success test

- `async fn test_is_authenticated_no_session_cookie() {}`
  - **Testing**: Tests authentication check with missing session cookie
  - **Type**: Missing session cookie validation test

- `async fn test_is_authenticated_session_not_found() {}`
  - **Testing**: Tests authentication check when session is not found
  - **Type**: Session not found authentication test

- `async fn test_is_authenticated_expired_session() {}`
  - **Testing**: Tests authentication check with expired session
  - **Type**: Expired session validation test

- `async fn test_is_authenticated_post_with_valid_csrf_header() {}`
  - **Testing**: Tests POST authentication with valid CSRF header
  - **Type**: Valid CSRF header authentication test

- `async fn test_is_authenticated_post_with_invalid_csrf_header() {}`
  - **Testing**: Tests POST authentication with invalid CSRF header
  - **Type**: Invalid CSRF header validation test

- `async fn test_get_user_and_csrf_token_from_session_success() {}`
  - **Testing**: Tests successful retrieval of user and CSRF token from session
  - **Type**: Combined user and CSRF retrieval success test

- `async fn test_get_user_and_csrf_token_from_session_session_not_found() {}`
  - **Testing**: Tests user and CSRF retrieval when session is not found
  - **Type**: Session not found for combined retrieval test

- `async fn test_get_user_and_csrf_token_from_session_expired_session() {}`
  - **Testing**: Tests user and CSRF retrieval with expired session
  - **Type**: Expired session for combined retrieval test

- `async fn test_get_user_and_csrf_token_from_session_invalid_cache_data() {}`
  - **Testing**: Tests user and CSRF retrieval with invalid cache data
  - **Type**: Invalid cache data validation test

- `async fn test_create_new_session_with_uid_success() {}`
  - **Testing**: Tests successful new session creation with user ID
  - **Type**: Session creation success test

- `async fn test_get_csrf_token_from_session_comprehensive() {}`
  - **Testing**: Comprehensive test of CSRF token retrieval functionality
  - **Type**: Comprehensive CSRF token test

- `async fn test_is_authenticated_basic_success() {}`
  - **Testing**: Tests successful basic authentication check
  - **Type**: Basic authentication success test

- `async fn test_delete_session_from_store_by_session_id_success() {}`
  - **Testing**: Tests successful session deletion by session ID
  - **Type**: Session deletion success test

- `async fn test_get_csrf_token_from_session_missing() {}`
  - **Testing**: Tests CSRF token retrieval when token is missing
  - **Type**: Missing CSRF token validation test

- `async fn test_session_expiration_workflow() {}`
  - **Testing**: Tests complete session expiration workflow
  - **Type**: Session expiration workflow test

- `async fn test_is_authenticated_basic_then_csrf_success() {}`
  - **Testing**: Tests successful basic authentication followed by CSRF validation
  - **Type**: Basic authentication with CSRF success test

- `async fn test_prepare_logout_response_success() {}`
  - **Testing**: Tests successful logout response preparation
  - **Type**: Logout response preparation test

- `async fn test_get_user_from_session_requires_database() {}`
  - **Testing**: Tests user retrieval from session requiring database access
  - **Type**: Database-dependent user retrieval test

- `async fn test_is_authenticated_strict_requires_database() {}`
  - **Testing**: Tests strict authentication requiring database verification
  - **Type**: Database-dependent strict authentication test

**oauth2_passkey/src/session/main/session_edge_cases_tests.rs:**

- `async fn test_expired_session_direct() {}`
  - **Testing**: Tests direct handling of expired session scenarios
  - **Type**: Expired session direct handling test

- `async fn test_malformed_session_data() {}`
  - **Testing**: Tests handling of malformed session data in storage
  - **Type**: Malformed session data validation test

- `async fn test_missing_fields_in_session() {}`
  - **Testing**: Tests handling of sessions with missing required fields
  - **Type**: Missing session fields validation test

- `async fn test_is_authenticated_post_missing_csrf_token() {}`
  - **Testing**: Tests POST authentication when CSRF token is missing
  - **Type**: Missing CSRF token for POST validation test

- `async fn test_is_authenticated_strict_then_csrf() {}`
  - **Testing**: Tests strict authentication followed by CSRF validation
  - **Type**: Strict authentication with CSRF test

- `async fn test_is_authenticated_basic_then_user_and_csrf() {}`
  - **Testing**: Tests basic authentication followed by user and CSRF retrieval
  - **Type**: Basic authentication with user and CSRF test

**oauth2_passkey/src/session/main/test_utils.rs:**

- `pub async fn insert_test_user( user_id: &str, account: &str, label: &str, is_admin: bool, ) -> Result<User, SessionError> {}`
  - **Purpose**: Inserts test user into database for session testing scenarios
  - **Parameters**: 
    - `user_id`: String identifier for the test user
    - `account`: Account name for the test user
    - `label`: Display label for the test user
    - `is_admin`: Boolean flag indicating admin privileges
  - **Returns**: `Result<User, SessionError>` - Created user object or insertion error
  - **Type**: Public async test utility function for user creation

- `pub async fn insert_test_session( session_id: &str, user_id: &str, csrf_token: &str, ttl: u64, ) -> Result<(), SessionError> {}`
  - **Purpose**: Inserts test session into cache for session testing scenarios
  - **Parameters**: 
    - `session_id`: String identifier for the test session
    - `user_id`: String identifier of the user for this session
    - `csrf_token`: CSRF token for the test session
    - `ttl`: Time-to-live for the session in seconds
  - **Returns**: `Result<(), SessionError>` - Success or insertion error
  - **Type**: Public async test utility function for session creation

- `pub async fn create_test_user_and_session( user_id: &str, account: &str, label: &str, is_admin: bool, session_id: &str, csrf_token: &str, ttl: u64, ) -> Result<User, SessionError> {}`
  - **Purpose**: Creates both test user and session in single operation for comprehensive testing
  - **Parameters**: 
    - `user_id`: String identifier for the user
    - `account`: Account name for the user
    - `label`: Display label for the user
    - `is_admin`: Boolean flag for admin privileges
    - `session_id`: String identifier for the session
    - `csrf_token`: CSRF token for the session
    - `ttl`: Time-to-live for the session in seconds
  - **Returns**: `Result<User, SessionError>` - Created user object or creation error
  - **Type**: Public async test utility function for combined user and session creation

- `pub async fn delete_test_session(session_id: &str) -> Result<(), SessionError> {}`
  - **Purpose**: Deletes test session from cache for test cleanup
  - **Parameters**: 
    - `session_id`: String identifier of session to delete
  - **Returns**: `Result<(), SessionError>` - Success or deletion error
  - **Type**: Public async test utility function for session cleanup

- `pub async fn delete_test_user(user_id: &str) -> Result<(), SessionError> {}`
  - **Purpose**: Deletes test user from database for test cleanup
  - **Parameters**: 
    - `user_id`: String identifier of user to delete
  - **Returns**: `Result<(), SessionError>` - Success or deletion error
  - **Type**: Public async test utility function for user cleanup

- `pub async fn cleanup_test_resources(user_id: &str, session_id: &str) -> Result<(), SessionError> {}`
  - **Purpose**: Comprehensive cleanup of test user and session resources
  - **Parameters**: 
    - `user_id`: String identifier of user to clean up
    - `session_id`: String identifier of session to clean up
  - **Returns**: `Result<(), SessionError>` - Success or cleanup error
  - **Type**: Public async test utility function for comprehensive resource cleanup

**oauth2_passkey/src/session/types.rs:**

- `fn from(db_user: DbUser) -> Self {}`
  - **Purpose**: Converts database user representation to session user
  - **Parameters**: 
    - `db_user`: Database user object to convert
  - **Returns**: `Self` - Session user representation
  - **Type**: Trait implementation for user conversion

- `fn from(data: StoredSession) -> Self {}`
  - **Purpose**: Converts stored session data into cache data format
  - **Parameters**: 
    - `data`: Stored session data to convert
  - **Returns**: `Self` - Cache data representation of session
  - **Type**: Trait implementation for session data conversion

- `fn try_from(data: CacheData) -> Result<Self, Self::Error> {}`
  - **Purpose**: Attempts to convert cache data back to stored session with error handling
  - **Parameters**: 
    - `data`: Cache data to convert back to session
  - **Returns**: `Result<Self, Self::Error>` - Stored session or conversion error
  - **Type**: Trait implementation for fallible session conversion

- `fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {}`
  - **Purpose**: Formats session user for debug display output
  - **Parameters**: 
    - `f`: Formatter for writing display output
  - **Returns**: `std::fmt::Result` - Formatting result
  - **Type**: Debug trait implementation for session user

- `fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {}`
  - **Purpose**: Formats CSRF token for debug display output
  - **Parameters**: 
    - `f`: Formatter for writing display output
  - **Returns**: `std::fmt::Result` - Formatting result
  - **Type**: Debug trait implementation for CSRF token

- `pub fn new(token: String) -> Self {}`
  - **Purpose**: Creates new CSRF token from provided string
  - **Parameters**: 
    - `token`: String value for the CSRF token
  - **Returns**: `Self` - CSRF token instance
  - **Type**: Constructor for CSRF token

- `pub fn as_str(&self) -> &str {}`
  - **Purpose**: Returns string reference to CSRF token value
  - **Returns**: `&str` - String reference to token value
  - **Type**: Accessor method for CSRF token

- `pub fn new(id: String) -> Self {}`
  - **Purpose**: Creates new user ID from provided string
  - **Parameters**: 
    - `id`: String value for the user ID
  - **Returns**: `Self` - User ID instance
  - **Type**: Constructor for user ID

- `pub fn as_str(&self) -> &str {}`
  - **Purpose**: Returns string reference to user ID value
  - **Returns**: `&str` - String reference to user ID value
  - **Type**: Accessor method for user ID

**oauth2_passkey/src/storage/cache_store/memory.rs:**

- `pub(crate) fn new() -> Self {}`
  - **Purpose**: Creates a new in-memory cache store instance with empty hash map
  - **Returns**: `Self` - New MemoryCacheStore instance
  - **Type**: Public crate-level constructor function for memory cache initialization

- `fn make_key(prefix: &str, key: &str) -> String {}`
  - **Purpose**: Constructs a cache key by combining prefix and key with separator
  - **Parameters**: 
    - `prefix`: Namespace prefix for the cache key
    - `key`: Individual key identifier
  - **Returns**: `String` - Combined cache key in format "prefix:key"
  - **Type**: Private utility function for key construction

- `async fn init(&self) -> Result<(), StorageError> {}`
  - **Purpose**: Initializes the memory cache store (no-op for in-memory implementation)
  - **Returns**: `Result<(), StorageError>` - Success (always succeeds for memory cache)
  - **Type**: Async trait implementation for cache initialization

- `async fn put(&mut self, prefix: &str, key: &str, value: CacheData) -> Result<(), StorageError> {}`
  - **Purpose**: Stores a cache entry with the given prefix, key, and value
  - **Parameters**: 
    - `prefix`: Namespace prefix for organization
    - `key`: Cache key identifier
    - `value`: CacheData to store
  - **Returns**: `Result<(), StorageError>` - Success or storage error
  - **Type**: Async trait implementation for cache storage

- `async fn put_with_ttl( &mut self, prefix: &str, key: &str, value: CacheData, _ttl: usize, ) -> Result<(), StorageError> {}`
  - **Purpose**: Stores cache entry with TTL (TTL ignored for memory implementation)
  - **Parameters**: 
    - `prefix`: Namespace prefix for organization
    - `key`: Cache key identifier
    - `value`: CacheData to store
    - `_ttl`: Time-to-live in seconds (unused in memory implementation)
  - **Returns**: `Result<(), StorageError>` - Success or storage error
  - **Type**: Async trait implementation for TTL-aware cache storage

- `async fn get(&self, prefix: &str, key: &str) -> Result<Option<CacheData>, StorageError> {}`
  - **Purpose**: Retrieves cache entry for the given prefix and key
  - **Parameters**: 
    - `prefix`: Namespace prefix for lookup
    - `key`: Cache key identifier
  - **Returns**: `Result<Option<CacheData>, StorageError>` - Optional cached data or error
  - **Type**: Async trait implementation for cache retrieval

- `async fn remove(&mut self, prefix: &str, key: &str) -> Result<(), StorageError> {}`
  - **Purpose**: Removes cache entry with the specified prefix and key
  - **Parameters**: 
    - `prefix`: Namespace prefix for removal
    - `key`: Cache key identifier
  - **Returns**: `Result<(), StorageError>` - Success or removal error
  - **Type**: Async trait implementation for cache entry removal

- `fn test_make_key() {}`
  - **Purpose**: Tests the make_key function with various prefix and key combinations
  - **Testing**: Tests key construction with different input patterns
  - **Type**: Unit test function for key generation utility

- `async fn test_init() {}`
  - **Purpose**: Tests cache store initialization functionality
  - **Testing**: Tests successful initialization of memory cache store
  - **Type**: Async unit test function for initialization validation

- `async fn test_put_and_get() {}`
  - **Purpose**: Tests storing and retrieving cache entries
  - **Testing**: Tests round-trip cache operations with put and get
  - **Type**: Async unit test function for basic cache operations

- `async fn test_put_with_ttl() {}`
  - **Purpose**: Tests cache storage with TTL parameter (behavior in memory implementation)
  - **Testing**: Tests TTL-aware storage functionality
  - **Type**: Async unit test function for TTL cache operations

- `async fn test_remove() {}`
  - **Purpose**: Tests cache entry removal functionality
  - **Testing**: Tests deletion of cached entries
  - **Type**: Async unit test function for cache removal operations

- `async fn test_get_nonexistent_key() {}`
  - **Purpose**: Tests retrieval behavior when cache key doesn't exist
  - **Testing**: Tests None return for missing cache entries
  - **Type**: Async unit test function for missing key handling

- `async fn test_multiple_prefixes() {}`
  - **Purpose**: Tests cache operations with different namespace prefixes
  - **Testing**: Tests prefix isolation and separation in cache storage
  - **Type**: Async unit test function for prefix-based organization

- `async fn test_overwrite_existing_key() {}`
  - **Purpose**: Tests cache behavior when overwriting existing cache entries
  - **Testing**: Tests replacement of existing cached values with new ones
  - **Type**: Async unit test function for cache overwrite operations

- `async fn test_remove_nonexistent_key() {}`
  - **Purpose**: Tests cache removal behavior when key doesn't exist
  - **Testing**: Tests graceful handling of removal attempts on missing keys
  - **Type**: Async unit test function for missing key removal handling

- `async fn test_empty_prefix_and_key() {}`
  - **Purpose**: Tests cache operations with empty strings for prefix and key
  - **Testing**: Tests edge case handling with empty prefix and key values
  - **Type**: Async unit test function for edge case validation

- `async fn test_cache_store_integration() {}`
  - **Purpose**: Tests comprehensive cache store integration scenarios
  - **Testing**: Tests end-to-end cache store functionality integration
  - **Type**: Async unit test function for integration testing

- `async fn test_cache_store_concurrent_access() {}`
  - **Purpose**: Tests cache store behavior under concurrent access patterns
  - **Testing**: Tests thread safety and concurrent operation handling
  - **Type**: Async unit test function for concurrency validation

- `async fn test_cache_store_prefix_isolation() {}`
  - **Purpose**: Tests isolation between different cache prefixes
  - **Testing**: Tests that different prefixes don't interfere with each other
  - **Type**: Async unit test function for prefix isolation verification

- `async fn test_cache_store_ttl_behavior() {}`
  - **Purpose**: Tests time-to-live functionality in cache store implementations
  - **Testing**: Tests TTL expiration and cleanup behavior
  - **Type**: Async unit test function for TTL functionality validation

- `async fn test_cache_store_large_data() {}`
  - **Purpose**: Tests cache store behavior with large data payloads
  - **Testing**: Tests performance and correctness with large cache values
  - **Type**: Async unit test function for large data handling

- `async fn test_cache_store_special_characters() {}`
  - **Purpose**: Tests cache operations with special characters in keys and values
  - **Testing**: Tests handling of special characters, Unicode, and edge cases
  - **Type**: Async unit test function for special character handling

**oauth2_passkey/src/storage/cache_store/redis.rs:**

- `fn make_key(prefix: &str, key: &str) -> String {}`
  - **Purpose**: Constructs Redis cache key by combining prefix and key with separator
  - **Parameters**: 
    - `prefix`: Namespace prefix for the cache key
    - `key`: Individual key identifier
  - **Returns**: `String` - Combined cache key in format "prefix:key"
  - **Type**: Private utility function for Redis key construction

- `async fn init(&self) -> Result<(), StorageError> {}`
  - **Purpose**: Initializes the Redis cache store connection and validates connectivity
  - **Returns**: `Result<(), StorageError>` - Success or Redis connection error
  - **Type**: Async trait implementation for Redis cache initialization

- `async fn put(&mut self, prefix: &str, key: &str, value: CacheData) -> Result<(), StorageError> {}`
  - **Purpose**: Stores a cache entry in Redis with the given prefix, key, and value
  - **Parameters**: 
    - `prefix`: Namespace prefix for organization
    - `key`: Cache key identifier
    - `value`: CacheData to store in Redis
  - **Returns**: `Result<(), StorageError>` - Success or Redis storage error
  - **Type**: Async trait implementation for Redis cache storage

- `async fn put_with_ttl( &mut self, prefix: &str, key: &str, value: CacheData, ttl: usize, ) -> Result<(), StorageError> {}`
  - **Purpose**: Stores cache entry in Redis with automatic expiration after TTL seconds
  - **Parameters**: 
    - `prefix`: Namespace prefix for organization
    - `key`: Cache key identifier
    - `value`: CacheData to store in Redis
    - `ttl`: Time-to-live in seconds for automatic expiration
  - **Returns**: `Result<(), StorageError>` - Success or Redis storage error
  - **Type**: Async trait implementation for TTL-aware Redis cache storage

- `async fn get(&self, prefix: &str, key: &str) -> Result<Option<CacheData>, StorageError> {}`
  - **Purpose**: Retrieves cache entry from Redis for the given prefix and key
  - **Parameters**: 
    - `prefix`: Namespace prefix for lookup
    - `key`: Cache key identifier
  - **Returns**: `Result<Option<CacheData>, StorageError>` - Optional cached data or Redis error
  - **Type**: Async trait implementation for Redis cache retrieval

- `async fn remove(&mut self, prefix: &str, key: &str) -> Result<(), StorageError> {}`
  - **Purpose**: Removes cache entry from Redis with the specified prefix and key
  - **Parameters**: 
    - `prefix`: Namespace prefix for removal
    - `key`: Cache key identifier
  - **Returns**: `Result<(), StorageError>` - Success or Redis removal error
  - **Type**: Async trait implementation for Redis cache entry removal

**oauth2_passkey/src/storage/cache_store/types.rs:**

- `async fn init(&self) -> Result<(), StorageError>;`
  - **Purpose**: Trait method for initializing cache store implementation
  - **Returns**: `Result<(), StorageError>` - Success or storage initialization error
  - **Type**: Async trait method for cache store initialization

- `async fn put(&mut self, prefix: &str, key: &str, value: CacheData) -> Result<(), StorageError>;`
  - **Purpose**: Trait method for storing cache data with prefix and key
  - **Parameters**: 
    - `prefix`: Namespace prefix for the cache key
    - `key`: Cache key identifier
    - `value`: Cache data to store
  - **Returns**: `Result<(), StorageError>` - Success or storage error
  - **Type**: Async trait method for cache data storage

- `async fn put_with_ttl( &mut self, prefix: &str, key: &str, value: CacheData, ttl: usize, ) -> Result<(), StorageError>;`
  - **Purpose**: Trait method for storing cache data with time-to-live expiration  
  - **Parameters**: 
    - `prefix`: Namespace prefix for the cache key
    - `key`: Cache key identifier
    - `value`: Cache data to store
    - `ttl`: Time-to-live in seconds for cache expiration
  - **Returns**: `Result<(), StorageError>` - Success or storage error
  - **Type**: Async trait method for cache data storage with TTL

- `async fn get(&self, prefix: &str, key: &str) -> Result<Option<CacheData>, StorageError>;`
  - **Purpose**: Trait method for retrieving cache data by prefix and key
  - **Parameters**: 
    - `prefix`: Namespace prefix for the cache key
    - `key`: Cache key identifier
  - **Returns**: `Result<Option<CacheData>, StorageError>` - Optional cache data or storage error
  - **Type**: Async trait method for cache data retrieval

- `async fn remove(&mut self, prefix: &str, key: &str) -> Result<(), StorageError>;`
  - **Purpose**: Trait method for removing cache data by prefix and key
  - **Parameters**: 
    - `prefix`: Namespace prefix for the cache key
    - `key`: Cache key identifier
  - **Returns**: `Result<(), StorageError>` - Success or storage error
  - **Type**: Async trait method for cache data removal

**oauth2_passkey/src/storage/data_store/types.rs:**

- `fn as_sqlite(&self) -> Option<&Pool<Sqlite>>;`
  - **Purpose**: Trait method for accessing SQLite pool if available
  - **Returns**: `Option<&Pool<Sqlite>>` - Optional reference to SQLite connection pool
  - **Type**: Trait method for database type checking

- `fn as_postgres(&self) -> Option<&Pool<Postgres>>;`
  - **Purpose**: Trait method for accessing PostgreSQL pool if available
  - **Returns**: `Option<&Pool<Postgres>>` - Optional reference to PostgreSQL connection pool
  - **Type**: Trait method for database type checking

- `fn as_sqlite(&self) -> Option<&Pool<Sqlite>> {}`
  - **Purpose**: Implementation returning SQLite pool reference for SQLite data store
  - **Returns**: `Option<&Pool<Sqlite>>` - Some with SQLite pool reference
  - **Type**: Trait implementation for SQLite data store

- `fn as_postgres(&self) -> Option<&Pool<Postgres>> {}`
  - **Purpose**: Implementation returning None for SQLite data store (not PostgreSQL)
  - **Returns**: `Option<&Pool<Postgres>>` - None since this is SQLite store
  - **Type**: Trait implementation for SQLite data store

- `fn as_sqlite(&self) -> Option<&Pool<Sqlite>> {}`
  - **Purpose**: Implementation returning None for PostgreSQL data store (not SQLite)
  - **Returns**: `Option<&Pool<Sqlite>>` - None since this is PostgreSQL store
  - **Type**: Trait implementation for PostgreSQL data store

- `fn as_postgres(&self) -> Option<&Pool<Postgres>> {}`
  - **Purpose**: Implementation returning PostgreSQL pool reference for PostgreSQL data store
  - **Returns**: `Option<&Pool<Postgres>>` - Some with PostgreSQL pool reference
  - **Type**: Trait implementation for PostgreSQL data store

- `fn test_data_store_trait_bounds() {}`
  - **Testing**: Tests that data store types implement required trait bounds
  - **Type**: Trait bounds verification test

- `fn assert_send_sync<T: Send + Sync>() {} assert_send_sync::<SqliteDataStore>();`
  - **Testing**: Asserts SQLite data store implements Send + Sync traits
  - **Type**: Thread safety verification test

**oauth2_passkey/src/storage/errors.rs:**

- `fn from(err: redis::RedisError) -> Self {}`
  - **Purpose**: Converts Redis error into storage error type
  - **Parameters**: 
    - `err`: Redis error to convert
  - **Returns**: `Self` - Storage error representation of Redis error
  - **Type**: Error conversion trait implementation

- `fn from(err: serde_json::Error) -> Self {}`
  - **Purpose**: Converts JSON serialization error into storage error type
  - **Parameters**: 
    - `err`: JSON error to convert
  - **Returns**: `Self` - Storage error representation of JSON error
  - **Type**: Error conversion trait implementation

**oauth2_passkey/src/storage/mod.rs:**

- `pub(crate) async fn init() -> Result<(), errors::StorageError> {}`
  - **Purpose**: Initializes storage subsystem with configured data and cache stores
  - **Returns**: `Result<(), errors::StorageError>` - Success or storage initialization error
  - **Type**: Public crate-level storage initialization function

**oauth2_passkey/src/storage/schema_validation.rs:**

- `pub(crate) async fn validate_postgres_table_schema<E>( pool: &Pool<Postgres>, table_name: &str, expected_columns: &[(&str, &str)], error_mapper: impl Fn(String) -> E, ) -> Result<(), E> {}`
  - **Purpose**: Validates PostgreSQL table schema matches expected column definitions
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool reference
    - `table_name`: Name of table to validate
    - `expected_columns`: Array of expected column name and type pairs
    - `error_mapper`: Function to map validation errors to custom error type
  - **Returns**: `Result<(), E>` - Success or custom error type from mapper
  - **Type**: Public crate-level PostgreSQL schema validation function

- `pub(crate) async fn validate_sqlite_table_schema<E>( pool: &Pool<Sqlite>, table_name: &str, expected_columns: &[(&str, &str)], error_mapper: impl Fn(String) -> E, ) -> Result<(), E> {}`
  - **Purpose**: Validates SQLite table schema matches expected column definitions
  - **Parameters**: 
    - `pool`: SQLite connection pool reference
    - `table_name`: Name of table to validate
    - `expected_columns`: Array of expected column name and type pairs
    - `error_mapper`: Function to map validation errors to custom error type
  - **Returns**: `Result<(), E>` - Success or custom error type from mapper
  - **Type**: Public crate-level SQLite schema validation function

**oauth2_passkey/src/test_utils.rs:**

- `pub async fn init_test_environment() {}`
  - **Purpose**: Initializes test environment with required data stores and cache for testing
  - **Type**: Public async test environment initialization function

- `async fn ensure_database_initialized() {}`
  - **Purpose**: Ensures database is properly initialized and available for testing
  - **Type**: Private async database initialization verification function

**oauth2_passkey/src/userdb/errors.rs:**

- `fn from(err: serde_json::Error) -> Self {}`
  - **Purpose**: Converts JSON serialization error into user error type
  - **Parameters**: 
    - `err`: JSON error to convert
  - **Returns**: `Self` - User error representation of JSON error
  - **Type**: Error conversion trait implementation

- `fn from(err: redis::RedisError) -> Self {}`
  - **Purpose**: Converts Redis error into user error type
  - **Parameters**: 
    - `err`: Redis error to convert
  - **Returns**: `Self` - User error representation of Redis error
  - **Type**: Error conversion trait implementation

- `fn test_user_error_display() {}`
  - **Testing**: Tests user error display formatting functionality
  - **Type**: Error display test

- `fn test_from_serde_json_error() {}`
  - **Testing**: Tests conversion from JSON serialization error to user error
  - **Type**: JSON error conversion test

- `fn test_from_redis_error() {}`
  - **Testing**: Tests conversion from Redis error to user error
  - **Type**: Redis error conversion test

- `fn test_error_is_sync_and_send() {}`
  - **Testing**: Tests that user error type implements Sync and Send traits
  - **Type**: Thread safety verification test

- `fn assert_send_sync<T: Send + Sync>() {} // UserError should be Send + Sync assert_send_sync::<UserError>();`
  - **Testing**: Asserts user error implements Send + Sync traits for thread safety
  - **Type**: Thread safety assertion test

- `fn test_error_is_cloneable() {}`
  - **Testing**: Tests that user error type can be cloned
  - **Type**: Clone trait verification test

**oauth2_passkey/src/userdb/mod.rs:**

- `pub(crate) async fn init() -> Result<(), UserError> {}`
  - **Purpose**: Initializes the user database store and validates schema requirements
  - **Returns**: `Result<(), UserError>` - Success or user database initialization error
  - **Type**: Public crate-level async function for user database initialization

**oauth2_passkey/src/userdb/storage/postgres.rs:**

- `pub(super) async fn create_tables_postgres(pool: &Pool<Postgres>) -> Result<(), UserError> {}`
  - **Purpose**: Creates PostgreSQL user management tables with required schema
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool reference
  - **Returns**: `Result<(), UserError>` - Success or table creation error
  - **Type**: Module-level PostgreSQL table creation function

- `pub(super) async fn validate_user_tables_postgres(pool: &Pool<Postgres>) -> Result<(), UserError> {}`
  - **Purpose**: Validates PostgreSQL user tables have correct schema structure
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool reference
  - **Returns**: `Result<(), UserError>` - Success or validation error
  - **Type**: Module-level PostgreSQL schema validation function

- `pub(super) async fn get_all_users_postgres(pool: &Pool<Postgres>) -> Result<Vec<User>, UserError> {}`
  - **Purpose**: Retrieves all users from PostgreSQL database
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool reference
  - **Returns**: `Result<Vec<User>, UserError>` - Vector of users or database error
  - **Type**: Module-level PostgreSQL user retrieval function

- `pub(super) async fn get_user_postgres( pool: &Pool<Postgres>, id: &str, ) -> Result<Option<User>, UserError> {}`
  - **Purpose**: Retrieves specific user by ID from PostgreSQL database
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool reference
    - `id`: User ID to search for
  - **Returns**: `Result<Option<User>, UserError>` - Optional user or database error
  - **Type**: Module-level PostgreSQL user lookup function

- `pub(super) async fn upsert_user_postgres( pool: &Pool<Postgres>, user: User, ) -> Result<User, UserError> {}`
  - **Purpose**: Inserts new user or updates existing user in PostgreSQL database
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool reference
    - `user`: User object to insert or update
  - **Returns**: `Result<User, UserError>` - Saved user with updated sequence or database error
  - **Type**: Module-level PostgreSQL user upsert function

- `pub(super) async fn delete_user_postgres(pool: &Pool<Postgres>, id: &str) -> Result<(), UserError> {}`
  - **Purpose**: Deletes user by ID from PostgreSQL database
  - **Parameters**: 
    - `pool`: PostgreSQL connection pool reference
    - `id`: User ID to delete
  - **Returns**: `Result<(), UserError>` - Success or deletion error
  - **Type**: Module-level PostgreSQL user deletion function

**oauth2_passkey/src/userdb/storage/sqlite.rs:**

- `pub(super) async fn create_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), UserError> {}`
  - **Purpose**: Creates SQLite user management tables with required schema
  - **Parameters**: 
    - `pool`: SQLite connection pool reference
  - **Returns**: `Result<(), UserError>` - Success or table creation error
  - **Type**: Module-level SQLite table creation function

- `pub(super) async fn validate_user_tables_sqlite(pool: &Pool<Sqlite>) -> Result<(), UserError> {}`
  - **Purpose**: Validates SQLite user tables have correct schema structure
  - **Parameters**: 
    - `pool`: SQLite connection pool reference
  - **Returns**: `Result<(), UserError>` - Success or validation error
  - **Type**: Module-level SQLite schema validation function

- `pub(super) async fn get_all_users_sqlite(pool: &Pool<Sqlite>) -> Result<Vec<User>, UserError> {}`
  - **Purpose**: Retrieves all users from SQLite database
  - **Parameters**: 
    - `pool`: SQLite connection pool reference
  - **Returns**: `Result<Vec<User>, UserError>` - Vector of users or database error
  - **Type**: Module-level SQLite user retrieval function

- `pub(super) async fn get_user_sqlite( pool: &Pool<Sqlite>, id: &str, ) -> Result<Option<User>, UserError> {}`
  - **Purpose**: Retrieves specific user by ID from SQLite database
  - **Parameters**: 
    - `pool`: SQLite connection pool reference
    - `id`: User ID to search for
  - **Returns**: `Result<Option<User>, UserError>` - Optional user or database error
  - **Type**: Module-level SQLite user lookup function

- `pub(super) async fn upsert_user_sqlite(pool: &Pool<Sqlite>, user: User) -> Result<User, UserError> {}`
  - **Purpose**: Inserts new user or updates existing user in SQLite database
  - **Parameters**: 
    - `pool`: SQLite connection pool reference
    - `user`: User object to insert or update
  - **Returns**: `Result<User, UserError>` - Saved user with updated sequence or database error
  - **Type**: Module-level SQLite user upsert function

- `pub(super) async fn delete_user_sqlite(pool: &Pool<Sqlite>, id: &str) -> Result<(), UserError> {}`
  - **Purpose**: Deletes user by ID from SQLite database
  - **Parameters**: 
    - `pool`: SQLite connection pool reference
    - `id`: User ID to delete
  - **Returns**: `Result<(), UserError>` - Success or deletion error
  - **Type**: Module-level SQLite user deletion function

**oauth2_passkey/src/userdb/storage/store_type.rs:**

- `pub(crate) async fn init() -> Result<(), UserError> {}`
  - **Purpose**: Initializes user database storage layer based on configured store type
  - **Returns**: `Result<(), UserError>` - Success or initialization error
  - **Type**: Public crate-level storage initialization function

- `pub(crate) async fn get_all_users() -> Result<Vec<User>, UserError> {}`
  - **Purpose**: Retrieves all users from configured database store
  - **Returns**: `Result<Vec<User>, UserError>` - Vector of users or database error
  - **Type**: Public crate-level user retrieval function

- `pub(crate) async fn get_user(id: &str) -> Result<Option<User>, UserError> {}`
  - **Purpose**: Retrieves specific user by ID from configured database store
  - **Parameters**: 
    - `id`: User ID to search for
  - **Returns**: `Result<Option<User>, UserError>` - Optional user or database error
  - **Type**: Public crate-level user lookup function

- `pub(crate) async fn upsert_user(user: User) -> Result<User, UserError> {}`
  - **Purpose**: Inserts new user or updates existing user in configured database store
  - **Parameters**: 
    - `user`: User object to insert or update
  - **Returns**: `Result<User, UserError>` - Saved user with updated sequence or database error
  - **Type**: Public crate-level user upsert function

- `pub(crate) async fn delete_user(id: &str) -> Result<(), UserError> {}`
  - **Purpose**: Deletes user by ID from configured database store
  - **Parameters**: 
    - `id`: User ID to delete
  - **Returns**: `Result<(), UserError>` - Success or deletion error
  - **Type**: Public crate-level user deletion function

- `fn create_test_user(suffix: &str) -> User {}`
  - **Purpose**: Creates test user with specified suffix for testing purposes
  - **Parameters**: 
    - `suffix`: Suffix to append to test user identifier
  - **Returns**: `User` - Test user object
  - **Type**: Test utility function for user creation

- `async fn test_userstore_init() {}`
  - **Testing**: Tests user store initialization functionality
  - **Type**: Storage initialization test

- `async fn test_userstore_upsert_user_create() {}`
  - **Testing**: Tests user creation through upsert operation
  - **Type**: User creation test

- `async fn test_userstore_upsert_user_first_user_becomes_admin() {}`
  - **Testing**: Tests that first user automatically becomes admin
  - **Type**: Admin privileges assignment test

- `async fn test_userstore_upsert_user_update() {}`
  - **Testing**: Tests user update through upsert operation
  - **Type**: User update test

- `async fn test_userstore_get_user() {}`
  - **Testing**: Tests user retrieval by ID functionality
  - **Type**: User retrieval test

- `async fn test_userstore_get_all_users() {}`
  - **Testing**: Tests retrieval of all users functionality
  - **Type**: Bulk user retrieval test

- `async fn test_userstore_delete_user() {}`
  - **Testing**: Tests user deletion functionality
  - **Type**: User deletion test

- `async fn test_userstore_edge_cases() {}`
  - **Testing**: Tests edge cases and error conditions in user operations
  - **Type**: Edge case handling test

- `async fn test_userstore_concurrent_operations() {}`
  - **Testing**: Tests concurrent user operations for thread safety
  - **Type**: Concurrency test

**oauth2_passkey/src/userdb/types.rs:**

- `pub fn new(id: String, account: String, label: String) -> Self {}`
  - **Purpose**: Creates new User instance with provided identifier, account, and label
  - **Parameters**: 
    - `id`: Unique user identifier string
    - `account`: User account name string
    - `label`: User display label string
  - **Returns**: `Self` - New User instance
  - **Type**: Constructor for User type

- `pub fn has_admin_privileges(&self) -> bool {}`
  - **Purpose**: Checks if user has administrative privileges based on admin flag or sequence number
  - **Returns**: `bool` - True if user has admin privileges, false otherwise
  - **Type**: Public method for admin privilege checking

- `fn test_user_new() {}`
  - **Testing**: Tests User::new constructor functionality
  - **Type**: Constructor test

- `fn test_has_admin_privileges_with_is_admin_true() {}`
  - **Testing**: Tests admin privilege checking when is_admin flag is true
  - **Type**: Admin privilege test with flag

- `fn test_has_admin_privileges_with_sequence_number_1() {}`
  - **Testing**: Tests admin privilege checking when sequence number is 1 (first user)
  - **Type**: Admin privilege test with sequence

- `fn test_has_admin_privileges_with_no_privileges() {}`
  - **Testing**: Tests admin privilege checking when user has no admin privileges
  - **Type**: Non-admin privilege test

- `fn test_user_serialization() {}`
  - **Testing**: Tests User type serialization to JSON
  - **Type**: Serialization test

- `fn test_user_deserialization() {}`
  - **Testing**: Tests User type deserialization from JSON
  - **Type**: Deserialization test

- `fn test_user_sequence_number_serialization_when_none() {}`
  - **Testing**: Tests User serialization when sequence number is None
  - **Type**: Optional field serialization test

**oauth2_passkey/src/utils.rs:**

- `pub(crate) fn base64url_decode(input: &str) -> Result<Vec<u8>, UtilError> {}`
  - **Purpose**: Decodes base64url-encoded string to byte vector
  - **Parameters**: 
    - `input`: Base64url-encoded string to decode
  - **Returns**: `Result<Vec<u8>, UtilError>` - Decoded byte vector or decoding error
  - **Type**: Public crate-level utility function for base64url decoding

- `pub(crate) fn base64url_encode(input: Vec<u8>) -> Result<String, UtilError> {}`
  - **Purpose**: Encodes byte vector to base64url-encoded string
  - **Parameters**: 
    - `input`: Byte vector to encode
  - **Returns**: `Result<String, UtilError>` - Base64url-encoded string or encoding error
  - **Type**: Public crate-level utility function for base64url encoding

- `pub(crate) fn gen_random_string(len: usize) -> Result<String, UtilError> {}`
  - **Purpose**: Generates cryptographically secure random string of specified length
  - **Parameters**: 
    - `len`: Length of random string to generate
  - **Returns**: `Result<String, UtilError>` - Random string or generation error
  - **Type**: Public crate-level utility function for secure random generation

- `pub(crate) fn header_set_cookie(headers: &mut HeaderMap, name: String, value: String, _expires_at: DateTime<Utc>, max_age: i64) -> Result<&HeaderMap, UtilError> {}`
  - **Purpose**: Sets HTTP cookie header with specified name, value, and expiration
  - **Parameters**: 
    - `headers`: Mutable reference to HTTP header map
    - `name`: Cookie name string
    - `value`: Cookie value string
    - `_expires_at`: Cookie expiration timestamp (currently unused)
    - `max_age`: Cookie maximum age in seconds
  - **Returns**: `Result<&HeaderMap, UtilError>` - Reference to modified header map or error
  - **Type**: Public crate-level utility function for HTTP cookie management

- `fn test_base64url_encode_decode() {}`
  - **Testing**: Tests base64url encoding and decoding round-trip functionality
  - **Type**: Base64url encoding/decoding test

- `fn test_base64url_decode_invalid() {}`
  - **Testing**: Tests base64url decoding with invalid input strings
  - **Type**: Invalid base64url input handling test

- `fn test_gen_random_string() {}`
  - **Testing**: Tests random string generation with various lengths
  - **Type**: Random string generation test

- `fn test_header_set_cookie() {}`
  - **Testing**: Tests HTTP cookie header setting functionality
  - **Type**: Cookie header setting test

- `fn test_header_set_cookie_invalid() {}`
  - **Testing**: Tests cookie header setting with invalid input parameters
  - **Type**: Invalid cookie parameter handling test
