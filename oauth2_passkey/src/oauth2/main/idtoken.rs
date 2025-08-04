use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::oauth2::config::get_jwks_url;
use crate::storage::{CacheData, GENERIC_CACHE_STORE};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Jwk {
    kty: String,
    kid: String,
    alg: String,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
    crv: Option<String>,
    k: Option<String>,
}

#[allow(unused)]
#[derive(Debug, Deserialize, Clone)]
pub struct IdInfo {
    pub iss: String,
    pub sub: String,
    pub azp: String,
    pub aud: String,
    pub email: String,
    pub email_verified: bool,
    pub name: String,
    pub picture: Option<String>,
    pub given_name: String,
    pub family_name: String,
    pub locale: Option<String>,
    pub iat: i64,
    pub exp: i64,
    pub nbf: Option<i64>,
    pub jti: Option<String>,
    pub nonce: Option<String>,
    pub hd: Option<String>,
    pub at_hash: Option<String>,
}

#[derive(Error, Debug)]
pub enum TokenVerificationError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Base64 decoding failed: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid token format")]
    InvalidTokenFormat,
    #[error("Invalid token signature")]
    InvalidTokenSignature,
    #[error("Invalid token audience, expected: {0}, actual: {1}")]
    InvalidTokenAudience(String, String),
    #[error("Invalid token issuer, expected: {0}, actual: {1}")]
    InvalidTokenIssuer(String, String),
    #[error("Token expired")]
    TokenExpired,
    #[error("Token not yet valid, now: {0}, nbf: {1}")]
    TokenNotYetValidNotBeFore(u64, u64),
    #[error("Token not yet valid, now: {0}, iat: {1}")]
    TokenNotYetValidIssuedAt(u64, u64),
    #[error("No matching key found in JWKS")]
    NoMatchingKey,
    #[error("Missing key component: {0}")]
    MissingKeyComponent(String),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("JWKS parsing error: {0}")]
    JwksParsing(String),
    #[error("JWKS fetch error: {0}")]
    JwksFetch(String),
    #[error("OIDC Discovery error: {0}")]
    OidcDiscovery(#[from] crate::oauth2::discovery::OidcDiscoveryError),
}

const CACHE_MODE: &str = "cached";
const CACHE_EXPIRATION: Duration = Duration::from_secs(600);

async fn fetch_jwks(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {
    match CACHE_MODE {
        "nocache" => fetch_jwks_no_cache(jwks_url).await,
        "cached" => fetch_jwks_cache(jwks_url).await,
        _ => fetch_jwks_no_cache(jwks_url).await,
    }
}

// 0. Without caching:
async fn fetch_jwks_no_cache(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {
    let resp = reqwest::get(jwks_url).await?;
    let jwks: Jwks = resp.json().await?;
    Ok(jwks)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct JwksCache {
    jwks: Jwks,
    expires_at: DateTime<Utc>,
}

impl From<JwksCache> for CacheData {
    fn from(cache: JwksCache) -> Self {
        Self {
            value: serde_json::to_string(&cache).unwrap_or_default(),
            expires_at: cache.expires_at,
        }
    }
}

impl TryFrom<CacheData> for JwksCache {
    type Error = TokenVerificationError;

    fn try_from(cache_data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&cache_data.value)
            .map_err(|e| TokenVerificationError::JwksParsing(format!("{e}")))
    }
}

async fn fetch_jwks_cache(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {
    // Try to get from cache first
    let prefix = "jwks";
    let cache_key = jwks_url;

    if let Some(cached) = GENERIC_CACHE_STORE
        .lock()
        .await
        .get(prefix, cache_key)
        .await
        .map_err(|e| TokenVerificationError::JwksFetch(format!("Cache error: {e}")))?
    {
        let jwks_cache: JwksCache = cached.try_into()?;
        // tracing::debug!("JWKs found in cache: {:#?}", jwks_cache);

        if jwks_cache.expires_at > Utc::now() {
            tracing::debug!("Returning valid cached JWKs");
            return Ok(jwks_cache.jwks);
        }

        tracing::debug!("Removing expired JWKs from cache");
        GENERIC_CACHE_STORE
            .lock()
            .await
            .remove(prefix, cache_key)
            .await
            .map_err(|e| TokenVerificationError::JwksFetch(format!("Cache error: {e}")))?;
    }

    // If not in cache, fetch from the URL
    let resp = reqwest::get(jwks_url).await?;
    let jwks: Jwks = resp.json().await?;
    // tracing::debug!("JWKs fetched from URL: {:#?}", jwks);
    tracing::debug!("JWKs fetched from URL");

    // Store in cache
    let jwks_cache = JwksCache {
        jwks: jwks.clone(),
        expires_at: Utc::now() + CACHE_EXPIRATION,
    };

    GENERIC_CACHE_STORE
        .lock()
        .await
        // .put(prefix, cache_key, jwks_cache.into())
        .put_with_ttl(
            prefix,
            cache_key,
            jwks_cache.into(),
            CACHE_EXPIRATION.as_secs() as usize,
        )
        .await
        .map_err(|e| TokenVerificationError::JwksFetch(format!("Cache error: {e}")))?;

    Ok(jwks)
}

fn find_jwk<'a>(jwks: &'a Jwks, kid: &str) -> Option<&'a Jwk> {
    jwks.keys.iter().find(|key| key.kid == kid)
}

fn decode_base64_url_safe(input: &str) -> Result<Vec<u8>, TokenVerificationError> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(TokenVerificationError::from)
}

fn convert_jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, TokenVerificationError> {
    match jwk.alg.as_str() {
        "RS256" | "RS384" | "RS512" => {
            let n = jwk
                .n
                .as_ref()
                .ok_or(TokenVerificationError::MissingKeyComponent("n".to_string()))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or(TokenVerificationError::MissingKeyComponent("e".to_string()))?;
            Ok(DecodingKey::from_rsa_components(n, e)?)
        }
        "ES256" | "ES384" | "ES512" => {
            let x = jwk
                .x
                .as_ref()
                .ok_or(TokenVerificationError::MissingKeyComponent("x".to_string()))?;
            let y = jwk
                .y
                .as_ref()
                .ok_or(TokenVerificationError::MissingKeyComponent("y".to_string()))?;
            Ok(DecodingKey::from_ec_components(x, y)?)
        }
        "HS256" | "HS384" | "HS512" => {
            let k = decode_base64_url_safe(
                jwk.k
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("k".to_string()))?,
            )?;
            Ok(DecodingKey::from_secret(&k))
        }
        alg => Err(TokenVerificationError::UnsupportedAlgorithm(
            alg.to_string(),
        )),
    }
}

fn decode_token(token: &str) -> Result<IdInfo, TokenVerificationError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenVerificationError::InvalidTokenFormat);
    }
    let payload = parts[1];
    let decoded_payload = decode_base64_url_safe(payload)?;
    let idinfo: IdInfo = serde_json::from_slice(&decoded_payload)?;
    Ok(idinfo)
}

fn verify_signature(
    token: &str,
    decoding_key: &DecodingKey,
    alg: Algorithm,
) -> Result<bool, TokenVerificationError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenVerificationError::InvalidTokenFormat);
    }

    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = decode_base64_url_safe(parts[2])?;
    let signature_str = URL_SAFE_NO_PAD.encode(signature);

    match jsonwebtoken::crypto::verify(&signature_str, message.as_bytes(), decoding_key, alg) {
        Ok(valid) => Ok(valid),
        Err(err) => Err(TokenVerificationError::from(err)),
    }
}

pub(super) async fn _verify_idtoken(
    token: String,
    audience: String,
) -> Result<IdInfo, TokenVerificationError> {
    let (idinfo, _algorithm) = verify_idtoken_with_algorithm(token, audience).await?;
    Ok(idinfo)
}

pub(super) async fn verify_idtoken_with_algorithm(
    token: String,
    audience: String,
) -> Result<(IdInfo, Algorithm), TokenVerificationError> {
    let header = jsonwebtoken::decode_header(&token)?;

    let kid = header
        .kid
        .ok_or(TokenVerificationError::MissingKeyComponent(
            "kid".to_string(),
        ))?;
    let alg = header.alg;
    let idinfo: IdInfo = decode_token(&token)?;

    tracing::debug!("Algorithm from JWT header: {:?}", alg);
    tracing::debug!("Decoded id_token payload: {:#?}", idinfo);

    let jwks_url = get_jwks_url().await?;
    let jwks = fetch_jwks(&jwks_url).await?;
    let jwk = find_jwk(&jwks, &kid).ok_or(TokenVerificationError::NoMatchingKey)?;

    let decoding_key = convert_jwk_to_decoding_key(jwk)?;

    let signature_valid = verify_signature(&token, &decoding_key, alg)?;
    if !signature_valid {
        return Err(TokenVerificationError::InvalidTokenSignature);
    }

    if idinfo.aud != audience {
        return Err(TokenVerificationError::InvalidTokenAudience(
            audience,
            idinfo.aud.to_string(),
        ));
    }

    let expected_issuer = crate::oauth2::config::get_expected_issuer().await?;
    if idinfo.iss != expected_issuer {
        return Err(TokenVerificationError::InvalidTokenIssuer(
            idinfo.iss.to_string(),
            expected_issuer,
        ));
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let skew: u64 = 2; // allow 2 seconds of skew

    if let Some(nbf) = idinfo.nbf {
        if now + skew < (nbf as u64) {
            // tolerate the system clock to be the skew seconds behind
            return Err(TokenVerificationError::TokenNotYetValidNotBeFore(
                now, nbf as u64,
            ));
        }
    }

    if now + skew < (idinfo.iat as u64) {
        // tolerate the system clock to be the skew seconds behind
        return Err(TokenVerificationError::TokenNotYetValidIssuedAt(
            now,
            idinfo.iat as u64,
        ));
    } else if now > (idinfo.exp as u64) {
        return Err(TokenVerificationError::TokenExpired);
    }

    Ok((idinfo, alg))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test finding an existing JWK in a JWK set
    ///
    /// This test verifies that `find_jwk` correctly finds a JWK when it exists in the set.
    /// It creates a JWK set with two keys in memory, searches for an existing key ID,
    /// and verifies that the correct JWK is returned with matching properties.
    ///
    #[test]
    fn test_find_jwk_existing_key() {
        let jwks = Jwks {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    kid: "key1".to_string(),
                    alg: "RS256".to_string(),
                    n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
                    e: Some("AQAB".to_string()),
                    x: None,
                    y: None,
                    crv: None,
                    k: None,
                },
                Jwk {
                    kty: "RSA".to_string(),
                    kid: "key2".to_string(),
                    alg: "RS256".to_string(),
                    n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
                    e: Some("AQAB".to_string()),
                    x: None,
                    y: None,
                    crv: None,
                    k: None,
                },
            ],
        };

        let result = find_jwk(&jwks, "key1");
        assert!(result.is_some());
        assert_eq!(result.unwrap().kid, "key1");
        assert_eq!(result.unwrap().alg, "RS256");
    }

    /// Test finding a non-existing JWK in a JWK set
    ///
    /// This test verifies that `find_jwk` correctly returns None when searching for a key ID
    /// that doesn't exist in the JWK set. It creates a JWK set with one key in memory,
    /// searches for a non-existing key ID, and verifies that None is returned.
    ///
    #[test]
    fn test_find_jwk_non_existing_key() {
        let jwks = Jwks {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    kid: "key1".to_string(),
                    alg: "RS256".to_string(),
                    n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
                    e: Some("AQAB".to_string()),
                    x: None,
                    y: None,
                    crv: None,
                    k: None,
                },
            ],
        };

        let result = find_jwk(&jwks, "non_existing_key");
        assert!(result.is_none());
    }

    /// Test finding a JWK in an empty JWK set
    ///
    /// This test verifies that `find_jwk` correctly returns None when searching in an empty
    /// JWK set. It creates an empty JWK set in memory, searches for any key ID,
    /// and verifies that None is returned.
    ///
    #[test]
    fn test_find_jwk_empty_jwks() {
        let jwks = Jwks { keys: vec![] };

        let result = find_jwk(&jwks, "any_key");
        assert!(result.is_none());
    }

    /// Test decoding a valid base64 URL-safe string
    ///
    /// This test verifies that `decode_base64_url_safe` correctly decodes a valid base64
    /// URL-safe encoded string. It tests with a known input/output pair and verifies
    /// the decoded bytes match the expected result.
    ///
    #[test]
    fn test_decode_base64_url_safe_valid() {
        // Test valid base64 URL-safe encoding
        let input = "SGVsbG9Xb3JsZA"; // "HelloWorld" in base64
        let result = decode_base64_url_safe(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"HelloWorld");
    }

    /// Test decoding an empty base64 URL-safe string
    ///
    /// This test verifies that `decode_base64_url_safe` correctly handles an empty string
    /// input, returning an empty Vec<u8> as expected.
    ///
    #[test]
    fn test_decode_base64_url_safe_empty() {
        let result = decode_base64_url_safe("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    /// Test decoding an invalid base64 URL-safe string
    ///
    /// This test verifies that `decode_base64_url_safe` correctly rejects invalid base64
    /// input by returning a Base64Error. It tests with malformed input that contains
    /// invalid characters for base64 encoding.
    ///
    #[test]
    fn test_decode_base64_url_safe_invalid() {
        // Test invalid base64 input
        let input = "Invalid@Base64!";
        let result = decode_base64_url_safe(input);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenVerificationError::Base64Error(_)
        ));
    }

    /// Test decoding a base64 URL-safe string with padding
    ///
    /// This test verifies that the URL_SAFE_NO_PAD decoder correctly handles base64
    /// strings without padding. It tests with "Hello" encoded as base64 without
    /// padding and verifies the correct decoding.
    ///
    #[test]
    fn test_decode_base64_url_safe_padding() {
        // Test that URL_SAFE_NO_PAD works correctly
        let input = "SGVsbG8"; // "Hello" in base64 without padding
        let result = decode_base64_url_safe(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");
    }

    /// Test JWK to decoding key conversion with missing 'n' component
    ///
    /// This test verifies that `convert_jwk_to_decoding_key` returns a MissingKeyComponent
    /// error when the required 'n' component is missing from an RSA JWK.
    ///
    #[test]
    fn test_convert_jwk_to_decoding_key_missing_n_component() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test_key".to_string(),
            alg: "RS256".to_string(),
            n: None, // Missing n component
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
            k: None,
        };

        let result = convert_jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        match result {
            Err(TokenVerificationError::MissingKeyComponent(ref s)) => assert_eq!(s, "n"),
            _ => panic!("Expected MissingKeyComponent error for 'n'"),
        }
    }

    /// Test JWK to decoding key conversion with missing 'e' component
    ///
    /// This test verifies that `convert_jwk_to_decoding_key` returns a MissingKeyComponent
    /// error when the required 'e' component is missing from an RSA JWK.
    ///
    #[test]
    fn test_convert_jwk_to_decoding_key_missing_e_component() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test_key".to_string(),
            alg: "RS256".to_string(),
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: None, // Missing e component
            x: None,
            y: None,
            crv: None,
            k: None,
        };

        let result = convert_jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        match result {
            Err(TokenVerificationError::MissingKeyComponent(ref s)) => assert_eq!(s, "e"),
            Err(ref e) => panic!("Expected MissingKeyComponent error for 'e', got: {e:?}"),
            _ => panic!("Expected error"),
        }
    }

    /// Test JWK to decoding key conversion with missing 'x' component for ES256
    ///
    /// This test verifies that `convert_jwk_to_decoding_key` returns a MissingKeyComponent
    /// error when the required 'x' component is missing from an EC JWK using ES256.
    ///
    #[test]
    fn test_convert_jwk_to_decoding_key_missing_x_component_es256() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            kid: "test_key".to_string(),
            alg: "ES256".to_string(),
            n: None,
            e: None,
            x: None, // Missing x component
            y: Some("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4".to_string()),
            crv: Some("P-256".to_string()),
            k: None,
        };

        let result = convert_jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        match result {
            Err(TokenVerificationError::MissingKeyComponent(ref s)) => assert_eq!(s, "x"),
            _ => panic!("Expected MissingKeyComponent error for 'x'"),
        }
    }

    /// Test JWK to decoding key conversion with missing 'y' component for ES256
    ///
    /// This test verifies that `convert_jwk_to_decoding_key` returns a MissingKeyComponent
    /// error when the required 'y' component is missing from an EC JWK using ES256.
    ///
    #[test]
    fn test_convert_jwk_to_decoding_key_missing_y_component_es256() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            kid: "test_key".to_string(),
            alg: "ES256".to_string(),
            n: None,
            e: None,
            x: Some("WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXw".to_string()),
            y: None, // Missing y component
            crv: Some("P-256".to_string()),
            k: None,
        };

        let result = convert_jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        match result {
            Err(TokenVerificationError::MissingKeyComponent(ref s)) => assert_eq!(s, "y"),
            _ => panic!("Expected MissingKeyComponent error for 'y'"),
        }
    }

    /// Test JWK to decoding key conversion with missing 'k' component for HS256
    ///
    /// This test verifies that `convert_jwk_to_decoding_key` returns a MissingKeyComponent
    /// error when the required 'k' component is missing from an HMAC JWK using HS256.
    ///
    #[test]
    fn test_convert_jwk_to_decoding_key_missing_k_component_hs256() {
        let jwk = Jwk {
            kty: "oct".to_string(),
            kid: "test_key".to_string(),
            alg: "HS256".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
            k: None, // Missing k component
        };

        let result = convert_jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        match result {
            Err(TokenVerificationError::MissingKeyComponent(ref s)) => assert_eq!(s, "k"),
            _ => panic!("Expected MissingKeyComponent error for 'k'"),
        }
    }

    /// Test JWK to decoding key conversion with unsupported algorithm
    ///
    /// This test verifies that `convert_jwk_to_decoding_key` returns an UnsupportedAlgorithm
    /// error when given a JWK with an algorithm that is not supported.
    ///
    #[test]
    fn test_convert_jwk_to_decoding_key_unsupported_algorithm() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test_key".to_string(),
            alg: "UNSUPPORTED".to_string(),
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
            k: None,
        };

        let result = convert_jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
        match result {
            Err(TokenVerificationError::UnsupportedAlgorithm(ref s)) => {
                assert_eq!(s, "UNSUPPORTED")
            }
            _ => panic!("Expected UnsupportedAlgorithm error"),
        }
    }

    /// Test JWK to decoding key conversion with valid HS256 key
    ///
    /// This test verifies that `convert_jwk_to_decoding_key` successfully converts
    /// a valid HMAC JWK with HS256 algorithm to a DecodingKey.
    ///
    #[test]
    fn test_convert_jwk_to_decoding_key_hs256_valid() {
        let jwk = Jwk {
            kty: "oct".to_string(),
            kid: "test_key".to_string(),
            alg: "HS256".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
            k: Some("c2VjcmV0a2V5MTIz".to_string()), // "secretkey123" in base64
        };

        let result = convert_jwk_to_decoding_key(&jwk);
        assert!(result.is_ok());
    }

    /// Test token decoding with too few parts
    ///
    /// This test verifies that `decode_token` returns InvalidTokenFormat error
    /// when given a token with only 2 parts instead of the required 3.
    ///
    #[test]
    fn test_decode_token_invalid_format_too_few_parts() {
        let token = "header.payload"; // Only 2 parts instead of 3
        let result = decode_token(token);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenVerificationError::InvalidTokenFormat
        ));
    }

    /// Test token decoding with too many parts
    ///
    /// This test verifies that `decode_token` returns InvalidTokenFormat error
    /// when given a token with 4 parts instead of the required 3.
    ///
    #[test]
    fn test_decode_token_invalid_format_too_many_parts() {
        let token = "header.payload.signature.extra"; // 4 parts instead of 3
        let result = decode_token(token);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenVerificationError::InvalidTokenFormat
        ));
    }

    /// Test token decoding with invalid base64 payload
    ///
    /// This test verifies that `decode_token` returns a Base64Error when the payload
    /// contains invalid base64 characters that cannot be decoded.
    ///
    #[test]
    fn test_decode_token_invalid_base64_payload() {
        let token = "header.invalid@base64.signature";
        let result = decode_token(token);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenVerificationError::Base64Error(_)
        ));
    }

    /// Test token decoding with invalid JSON payload
    ///
    /// This test verifies that `decode_token` returns a JsonError when the payload
    /// contains valid base64 but invalid JSON that cannot be parsed.
    ///
    #[test]
    fn test_decode_token_invalid_json_payload() {
        // Valid base64 but invalid JSON
        let invalid_json_b64 = "aW52YWxpZGpzb24"; // "invalidjson" in base64
        let token = format!("header.{invalid_json_b64}.signature");
        let result = decode_token(&token);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenVerificationError::JsonError(_)
        ));
    }

    /// Test token decoding with valid payload
    ///
    /// This test verifies that `decode_token` successfully decodes a token with a valid
    /// JSON payload, creating a proper IdInfo struct with the expected field values.
    ///
    #[test]
    fn test_decode_token_valid_payload() {
        // Create a valid IdInfo JSON payload
        let id_info_json = r#"{
            "iss": "https://accounts.google.com",
            "sub": "123456789",
            "azp": "client_id",
            "aud": "audience",
            "email": "test@example.com",
            "email_verified": true,
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "iat": 1640995200,
            "exp": 1641001200
        }"#;

        // Encode to base64 URL-safe
        let payload_b64 = URL_SAFE_NO_PAD.encode(id_info_json.as_bytes());
        let token = format!("header.{payload_b64}.signature");

        let result = decode_token(&token);
        assert!(result.is_ok());
        let id_info = result.unwrap();
        assert_eq!(id_info.iss, "https://accounts.google.com");
        assert_eq!(id_info.sub, "123456789");
        assert_eq!(id_info.email, "test@example.com");
        assert!(id_info.email_verified);
        assert_eq!(id_info.name, "Test User");
    }

    /// Test signature verification with invalid token format
    ///
    /// This test verifies that `verify_signature` returns InvalidTokenFormat error
    /// when given a token with insufficient parts for signature verification.
    ///
    #[test]
    fn test_verify_signature_invalid_token_format() {
        let token = "header.payload"; // Only 2 parts instead of 3
        let decoding_key = DecodingKey::from_secret(b"secret");
        let result = verify_signature(token, &decoding_key, Algorithm::HS256);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenVerificationError::InvalidTokenFormat
        ));
    }

    /// Test signature verification with invalid base64 signature
    ///
    /// This test verifies that `verify_signature` returns a Base64Error when the signature
    /// part contains invalid base64 characters that cannot be decoded.
    ///
    #[test]
    fn test_verify_signature_invalid_base64_signature() {
        let token = "header.payload.invalid@base64";
        let decoding_key = DecodingKey::from_secret(b"secret");
        let result = verify_signature(token, &decoding_key, Algorithm::HS256);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenVerificationError::Base64Error(_)
        ));
    }

    /// Test TokenVerificationError display formatting
    ///
    /// This test verifies that all TokenVerificationError variants produce the correct
    /// error message strings when converted to string representation.
    ///
    #[test]
    fn test_token_verification_error_display() {
        // Test various error message formats
        let error = TokenVerificationError::InvalidTokenFormat;
        assert_eq!(error.to_string(), "Invalid token format");

        let error = TokenVerificationError::InvalidTokenSignature;
        assert_eq!(error.to_string(), "Invalid token signature");

        let error = TokenVerificationError::InvalidTokenAudience(
            "expected".to_string(),
            "actual".to_string(),
        );
        assert_eq!(
            error.to_string(),
            "Invalid token audience, expected: expected, actual: actual"
        );

        let error = TokenVerificationError::InvalidTokenIssuer(
            "expected".to_string(),
            "actual".to_string(),
        );
        assert_eq!(
            error.to_string(),
            "Invalid token issuer, expected: expected, actual: actual"
        );

        let error = TokenVerificationError::TokenExpired;
        assert_eq!(error.to_string(), "Token expired");

        let error = TokenVerificationError::TokenNotYetValidNotBeFore(1000, 2000);
        assert_eq!(
            error.to_string(),
            "Token not yet valid, now: 1000, nbf: 2000"
        );

        let error = TokenVerificationError::TokenNotYetValidIssuedAt(1000, 2000);
        assert_eq!(
            error.to_string(),
            "Token not yet valid, now: 1000, iat: 2000"
        );

        let error = TokenVerificationError::NoMatchingKey;
        assert_eq!(error.to_string(), "No matching key found in JWKS");

        let error = TokenVerificationError::MissingKeyComponent("n".to_string());
        assert_eq!(error.to_string(), "Missing key component: n");

        let error = TokenVerificationError::UnsupportedAlgorithm("UNKNOWN".to_string());
        assert_eq!(error.to_string(), "Unsupported algorithm: UNKNOWN");

        let error = TokenVerificationError::JwksParsing("parse error".to_string());
        assert_eq!(error.to_string(), "JWKS parsing error: parse error");

        let error = TokenVerificationError::JwksFetch("fetch error".to_string());
        assert_eq!(error.to_string(), "JWKS fetch error: fetch error");
    }

    /// Test JwksCache serialization and deserialization
    ///
    /// This test verifies that JwksCache can be properly converted to and from CacheData,
    /// ensuring the serialization roundtrip maintains data integrity.
    ///
    #[test]
    fn test_jwks_cache_conversion() {
        // Test JwksCache to CacheData conversion
        let jwks = Jwks {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    kid: "key1".to_string(),
                    alg: "RS256".to_string(),
                    n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
                    e: Some("AQAB".to_string()),
                    x: None,
                    y: None,
                    crv: None,
                    k: None,
                },
            ],
        };

        let expires_at = Utc::now() + chrono::Duration::seconds(600);
        let jwks_cache = JwksCache {
            jwks: jwks.clone(),
            expires_at,
        };

        // Test From conversion
        let cache_data: CacheData = jwks_cache.clone().into();
        assert!(!cache_data.value.is_empty());

        // Test TryFrom conversion back
        let restored_cache: Result<JwksCache, TokenVerificationError> = cache_data.try_into();
        assert!(restored_cache.is_ok());
        let restored = restored_cache.unwrap();
        assert_eq!(restored.jwks.keys.len(), 1);
        assert_eq!(restored.jwks.keys[0].kid, "key1");
    }

    /// Test JwksCache conversion with invalid JSON
    ///
    /// This test verifies that attempting to convert invalid JSON to JwksCache
    /// returns a JwksParsing error as expected.
    ///
    #[test]
    fn test_jwks_cache_invalid_json() {
        let invalid_cache_data = CacheData {
            value: "invalid json".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        let result: Result<JwksCache, TokenVerificationError> = invalid_cache_data.try_into();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TokenVerificationError::JwksParsing(_)
        ));
    }
}
