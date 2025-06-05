use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey};
use pkcs1::{EncodeRsaPublicKey, LineEnding};
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

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
    #[error("RSA error: {0}")]
    RsaError(#[from] rsa::Error),
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
    #[error("PKCS1 error: {0}")]
    Pkcs1Error(#[from] pkcs1::Error),
    #[error("JWKS parsing error: {0}")]
    JwksParsing(String),
    #[error("JWKS fetch error: {0}")]
    JwksFetch(String),
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
        }
    }
}

impl TryFrom<CacheData> for JwksCache {
    type Error = TokenVerificationError;

    fn try_from(cache_data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&cache_data.value)
            .map_err(|e| TokenVerificationError::JwksParsing(format!("{}", e)))
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
        .map_err(|e| TokenVerificationError::JwksFetch(format!("Cache error: {}", e)))?;

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
            let n = decode_base64_url_safe(
                jwk.n
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("n".to_string()))?,
            )?;
            let e = decode_base64_url_safe(
                jwk.e
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("e".to_string()))?,
            )?;
            let rsa_public_key = RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&n),
                rsa::BigUint::from_bytes_be(&e),
            )?;
            let pem = rsa_public_key.to_pkcs1_pem(LineEnding::default())?;
            Ok(DecodingKey::from_rsa_pem(pem.as_bytes())?)
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

pub(super) async fn verify_idtoken(
    token: String,
    audience: String,
) -> Result<IdInfo, TokenVerificationError> {
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

    let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";
    let jwks = fetch_jwks(jwks_url).await?;
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

    let supplied_issuer = "https://accounts.google.com";
    if idinfo.iss != supplied_issuer {
        return Err(TokenVerificationError::InvalidTokenIssuer(
            idinfo.iss.to_string(),
            supplied_issuer.to_string(),
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

    Ok(idinfo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use serde_json::json;

    #[test]
    fn test_error_display() {
        let test_cases = vec![
            (
                TokenVerificationError::InvalidTokenFormat,
                "Invalid token format",
            ),
            (
                TokenVerificationError::InvalidTokenSignature,
                "Invalid token signature",
            ),
            (
                TokenVerificationError::InvalidTokenAudience(
                    "expected".to_string(),
                    "actual".to_string(),
                ),
                "Invalid token audience, expected: expected, actual: actual",
            ),
            (
                TokenVerificationError::InvalidTokenIssuer(
                    "expected".to_string(),
                    "actual".to_string(),
                ),
                "Invalid token issuer, expected: expected, actual: actual",
            ),
            (TokenVerificationError::TokenExpired, "Token expired"),
            (
                TokenVerificationError::TokenNotYetValidNotBeFore(100, 200),
                "Token not yet valid, now: 100, nbf: 200",
            ),
            (
                TokenVerificationError::TokenNotYetValidIssuedAt(100, 200),
                "Token not yet valid, now: 100, iat: 200",
            ),
            (
                TokenVerificationError::NoMatchingKey,
                "No matching key found in JWKS",
            ),
            (
                TokenVerificationError::MissingKeyComponent("n".to_string()),
                "Missing key component: n",
            ),
            (
                TokenVerificationError::UnsupportedAlgorithm("HS384".to_string()),
                "Unsupported algorithm: HS384",
            ),
            (
                TokenVerificationError::JwksParsing("parse error".to_string()),
                "JWKS parsing error: parse error",
            ),
            (
                TokenVerificationError::JwksFetch("fetch error".to_string()),
                "JWKS fetch error: fetch error",
            ),
        ];

        for (error, expected_message) in test_cases {
            assert_eq!(error.to_string(), expected_message);
        }
    }

    #[test]
    fn test_find_jwk() {
        let jwks = Jwks {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    kid: "key1".to_string(),
                    alg: "RS256".to_string(),
                    n: Some("n_value".to_string()),
                    e: Some("e_value".to_string()),
                    x: None,
                    y: None,
                    crv: None,
                    k: None,
                },
                Jwk {
                    kty: "RSA".to_string(),
                    kid: "key2".to_string(),
                    alg: "RS256".to_string(),
                    n: Some("n_value2".to_string()),
                    e: Some("e_value2".to_string()),
                    x: None,
                    y: None,
                    crv: None,
                    k: None,
                },
            ],
        };

        // Should find the key with matching kid
        let jwk = find_jwk(&jwks, "key1");
        assert!(jwk.is_some());
        assert_eq!(jwk.expect("Should find key1").kid, "key1");

        // Should find the second key
        let jwk = find_jwk(&jwks, "key2");
        assert!(jwk.is_some());
        assert_eq!(jwk.expect("Should find key2").kid, "key2");

        // Should return None for non-existent key
        let jwk = find_jwk(&jwks, "key3");
        assert!(jwk.is_none());
    }

    #[test]
    fn test_jwks_cache_conversion() {
        let jwks = Jwks {
            keys: vec![Jwk {
                kty: "RSA".to_string(),
                kid: "key1".to_string(),
                alg: "RS256".to_string(),
                n: Some("n_value".to_string()),
                e: Some("e_value".to_string()),
                x: None,
                y: None,
                crv: None,
                k: None,
            }],
        };

        let expires_at = Utc::now() + Duration::seconds(600);
        let jwks_cache = JwksCache {
            jwks: jwks.clone(),
            expires_at,
        };

        // Convert to CacheData
        let cache_data: CacheData = jwks_cache.clone().into();

        // Convert back to JwksCache
        let recovered_cache: JwksCache = cache_data.try_into().unwrap();

        // Verify the keys are preserved
        assert_eq!(recovered_cache.jwks.keys.len(), 1);
        assert_eq!(recovered_cache.jwks.keys[0].kid, "key1");
        assert_eq!(recovered_cache.jwks.keys[0].kty, "RSA");
        assert_eq!(recovered_cache.jwks.keys[0].alg, "RS256");
        assert_eq!(recovered_cache.jwks.keys[0].n, Some("n_value".to_string()));
        assert_eq!(recovered_cache.jwks.keys[0].e, Some("e_value".to_string()));

        // Verify the expiration time is preserved (within a second)
        let time_diff = (recovered_cache.expires_at - jwks_cache.expires_at).num_seconds();
        assert!(time_diff.abs() < 1);
    }

    #[test]
    fn test_jwks_cache_invalid_data() {
        // Create invalid cache data
        let invalid_data = CacheData {
            value: "not valid json".to_string(),
        };

        // Try to convert to JwksCache
        let result: Result<JwksCache, TokenVerificationError> = invalid_data.try_into();

        // Should fail
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::JwksParsing(_)) => {}
            Err(other) => {
                assert!(false, "Expected JwksParsing error, got {:?}", other);
            }
        }
    }

    #[test]
    fn test_decode_base64_url_safe() {
        // Valid base64url encoded string
        let encoded = "SGVsbG8gV29ybGQ";
        let decoded = decode_base64_url_safe(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");

        // Invalid base64 string
        let result = decode_base64_url_safe("not!valid!base64");
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_jwk_to_decoding_key_rsa() {
        // Test RSA256 algorithm
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test_key".to_string(),
            alg: "RS256".to_string(),
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
            k: None,
        };

        let result = convert_jwk_to_decoding_key(&jwk);
        assert!(result.is_ok(), "Should successfully convert RSA key");

        // Test RS384
        let jwk_rs384 = Jwk {
            alg: "RS384".to_string(),
            ..jwk.clone()
        };
        let result = convert_jwk_to_decoding_key(&jwk_rs384);
        assert!(result.is_ok(), "Should successfully convert RS384 key");

        // Test RS512
        let jwk_rs512 = Jwk {
            alg: "RS512".to_string(),
            ..jwk.clone()
        };
        let result = convert_jwk_to_decoding_key(&jwk_rs512);
        assert!(result.is_ok(), "Should successfully convert RS512 key");
    }

    #[test]
    fn test_convert_jwk_to_decoding_key_ecdsa() {
        // Test ECDSA ES256 algorithm with valid P-256 coordinates
        let jwk = Jwk {
            kty: "EC".to_string(),
            kid: "test_ec_key".to_string(),
            alg: "ES256".to_string(),
            n: None,
            e: None,
            x: Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string()),
            y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string()),
            crv: Some("P-256".to_string()),
            k: None,
        };

        let result = convert_jwk_to_decoding_key(&jwk);
        assert!(
            result.is_ok(),
            "Should successfully convert ES256 key, but got error: {:?}",
            result.err()
        );

        // Test ES384
        let jwk_es384 = Jwk {
            alg: "ES384".to_string(),
            ..jwk.clone()
        };
        let result = convert_jwk_to_decoding_key(&jwk_es384);
        assert!(result.is_ok(), "Should successfully convert ES384 key");

        // Test ES512
        let jwk_es512 = Jwk {
            alg: "ES512".to_string(),
            ..jwk.clone()
        };
        let result = convert_jwk_to_decoding_key(&jwk_es512);
        assert!(result.is_ok(), "Should successfully convert ES512 key");
    }

    #[test]
    fn test_convert_jwk_to_decoding_key_hmac() {
        // Test HMAC HS256 algorithm
        let jwk = Jwk {
            kty: "oct".to_string(),
            kid: "test_hmac_key".to_string(),
            alg: "HS256".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
            k: Some("SGVsbG8gV29ybGQ".to_string()), // "Hello World" base64url encoded
        };

        let result = convert_jwk_to_decoding_key(&jwk);
        assert!(result.is_ok(), "Should successfully convert HS256 key");

        // Test HS384
        let jwk_hs384 = Jwk {
            alg: "HS384".to_string(),
            ..jwk.clone()
        };
        let result = convert_jwk_to_decoding_key(&jwk_hs384);
        assert!(result.is_ok(), "Should successfully convert HS384 key");

        // Test HS512
        let jwk_hs512 = Jwk {
            alg: "HS512".to_string(),
            ..jwk.clone()
        };
        let result = convert_jwk_to_decoding_key(&jwk_hs512);
        assert!(result.is_ok(), "Should successfully convert HS512 key");
    }

    #[test]
    fn test_convert_jwk_to_decoding_key_errors() {
        // Test unsupported algorithm
        let jwk_unsupported = Jwk {
            kty: "RSA".to_string(),
            kid: "test_key".to_string(),
            alg: "UNSUPPORTED".to_string(),
            n: Some("test".to_string()),
            e: Some("test".to_string()),
            x: None,
            y: None,
            crv: None,
            k: None,
        };

        let result = convert_jwk_to_decoding_key(&jwk_unsupported);
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::UnsupportedAlgorithm(alg)) => {
                assert_eq!(alg, "UNSUPPORTED");
            }
            Err(other) => {
                assert!(
                    false,
                    "Expected UnsupportedAlgorithm error, got {:?}",
                    other
                );
            }
        }

        // Test RSA key missing 'n' component
        let jwk_missing_n = Jwk {
            kty: "RSA".to_string(),
            kid: "test_key".to_string(),
            alg: "RS256".to_string(),
            n: None, // Missing
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
            k: None,
        };

        let result = convert_jwk_to_decoding_key(&jwk_missing_n);
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::MissingKeyComponent(component)) => {
                assert_eq!(component, "n");
            }
            Err(other) => {
                assert!(
                    false,
                    "Expected MissingKeyComponent error for 'n', got {:?}",
                    other
                );
            }
        }

        // Test ECDSA key missing 'x' component
        let jwk_missing_x = Jwk {
            kty: "EC".to_string(),
            kid: "test_key".to_string(),
            alg: "ES256".to_string(),
            n: None,
            e: None,
            x: None, // Missing
            y: Some("test".to_string()),
            crv: Some("P-256".to_string()),
            k: None,
        };

        let result = convert_jwk_to_decoding_key(&jwk_missing_x);
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::MissingKeyComponent(component)) => {
                assert_eq!(component, "x");
            }
            Err(other) => {
                assert!(
                    false,
                    "Expected MissingKeyComponent error for 'x', got {:?}",
                    other
                );
            }
        }

        // Test HMAC key missing 'k' component
        let jwk_missing_k = Jwk {
            kty: "oct".to_string(),
            kid: "test_key".to_string(),
            alg: "HS256".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
            k: None, // Missing
        };

        let result = convert_jwk_to_decoding_key(&jwk_missing_k);
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::MissingKeyComponent(component)) => {
                assert_eq!(component, "k");
            }
            Err(other) => {
                assert!(
                    false,
                    "Expected MissingKeyComponent error for 'k', got {:?}",
                    other
                );
            }
        }
    }

    #[test]
    fn test_verify_signature_invalid_token_format() {
        // Test with invalid number of parts
        let jwk = Jwk {
            kty: "oct".to_string(),
            kid: "test_key".to_string(),
            alg: "HS256".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
            k: Some("SGVsbG8gV29ybGQ".to_string()),
        };

        let decoding_key = convert_jwk_to_decoding_key(&jwk)
            .expect("Should successfully create decoding key for test");

        // Token with only 2 parts instead of 3
        let invalid_token = "header.payload";
        let result = verify_signature(invalid_token, &decoding_key, Algorithm::HS256);
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::InvalidTokenFormat) => {}
            Err(other) => {
                assert!(false, "Expected InvalidTokenFormat error, got {:?}", other);
            }
        }

        // Token with 4 parts instead of 3
        let invalid_token = "header.payload.signature.extra";
        let result = verify_signature(invalid_token, &decoding_key, Algorithm::HS256);
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::InvalidTokenFormat) => {}
            Err(other) => {
                assert!(false, "Expected InvalidTokenFormat error, got {:?}", other);
            }
        }

        // Empty token
        let result = verify_signature("", &decoding_key, Algorithm::HS256);
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::InvalidTokenFormat) => {}
            Err(other) => {
                assert!(false, "Expected InvalidTokenFormat error, got {:?}", other);
            }
        }
    }

    #[test]
    fn test_decode_token() {
        // Create a valid JWT payload (without signature verification, just parsing)
        let payload = json!({
            "iss": "https://accounts.google.com",
            "sub": "123456789",
            "azp": "client_id",
            "aud": "audience",
            "email": "test@example.com",
            "email_verified": true,
            "name": "Test User",
            "picture": "https://example.com/pic.jpg",
            "given_name": "Test",
            "family_name": "User",
            "locale": "en",
            "iat": 1609459200,
            "exp": 1609462800,
            "nbf": 1609459100,
            "jti": "token_id",
            "nonce": "nonce_value",
            "hd": "example.com",
            "at_hash": "hash_value"
        });

        let payload_str = serde_json::to_string(&payload).unwrap();
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload_str.as_bytes());

        // Create a mock JWT with dummy header and signature
        let dummy_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let dummy_signature = URL_SAFE_NO_PAD.encode("dummy_signature");
        let token = format!("{}.{}.{}", dummy_header, encoded_payload, dummy_signature);

        let result = decode_token(&token);
        assert!(result.is_ok(), "Should successfully decode valid token");

        let idinfo = result.unwrap();
        assert_eq!(idinfo.iss, "https://accounts.google.com");
        assert_eq!(idinfo.sub, "123456789");
        assert_eq!(idinfo.email, "test@example.com");
        assert_eq!(idinfo.email_verified, true);
        assert_eq!(idinfo.name, "Test User");
        assert_eq!(idinfo.iat, 1609459200);
        assert_eq!(idinfo.exp, 1609462800);
        assert_eq!(idinfo.nbf, Some(1609459100));
        assert_eq!(idinfo.nonce, Some("nonce_value".to_string()));
    }

    #[test]
    fn test_decode_token_errors() {
        // Test with invalid format (wrong number of parts)
        let result = decode_token("invalid.token");
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::InvalidTokenFormat) => {}
            Err(other) => {
                assert!(false, "Expected InvalidTokenFormat error, got {:?}", other);
            }
        }

        // Test with invalid base64 in payload
        let dummy_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let invalid_payload = "invalid!base64!";
        let dummy_signature = URL_SAFE_NO_PAD.encode("dummy_signature");
        let token = format!("{}.{}.{}", dummy_header, invalid_payload, dummy_signature);

        let result = decode_token(&token);
        assert!(result.is_err());
        // Should be a Base64Error

        // Test with invalid JSON in payload
        let invalid_json_payload = URL_SAFE_NO_PAD.encode("not valid json");
        let token = format!(
            "{}.{}.{}",
            dummy_header, invalid_json_payload, dummy_signature
        );

        let result = decode_token(&token);
        assert!(result.is_err());
        // Should be a JsonError

        // Test with missing required fields
        let incomplete_payload = json!({
            "iss": "https://accounts.google.com",
            // Missing required fields like "sub", "aud", etc.
        });
        let payload_str = serde_json::to_string(&incomplete_payload).unwrap();
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload_str.as_bytes());
        let token = format!("{}.{}.{}", dummy_header, encoded_payload, dummy_signature);

        let result = decode_token(&token);
        assert!(result.is_err());
        // Should be a JsonError due to missing required fields
    }

    #[test]
    fn test_verify_signature_with_valid_signature() {
        // Create a test JWT with HMAC signature that we can verify
        use jsonwebtoken::{EncodingKey, Header, encode};

        // Create a symmetric key for HMAC
        let secret = "test_secret_key_for_hmac_signature_verification";
        let encoding_key = EncodingKey::from_secret(secret.as_ref());
        let decoding_key = DecodingKey::from_secret(secret.as_ref());

        // Create test claims
        let claims = json!({
            "sub": "1234567890",
            "name": "Test User",
            "iat": 1516239022
        });

        // Create JWT with HS256 algorithm
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // Verify the signature
        let result = verify_signature(&token, &decoding_key, Algorithm::HS256);
        assert!(result.is_ok(), "Should successfully verify valid signature");
        assert!(result.unwrap(), "Signature should be valid");

        // Test with wrong key - should fail
        let wrong_key = DecodingKey::from_secret("wrong_secret".as_ref());
        let result = verify_signature(&token, &wrong_key, Algorithm::HS256);
        assert!(result.is_ok(), "Should not error but return false");
        assert!(
            !result.unwrap(),
            "Signature should be invalid with wrong key"
        );

        // Test with wrong algorithm - should fail
        let result = verify_signature(&token, &decoding_key, Algorithm::HS384);
        // This should either error or return false
        match result {
            Ok(valid) => assert!(!valid, "Should not be valid with wrong algorithm"),
            Err(_) => {} // Also acceptable to error
        }
    }

    #[test]
    fn test_jwt_time_validations() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Should get current time for test")
            .as_secs();
        let skew = 2; // 2 seconds skew tolerance as used in verify_idtoken

        // Test valid token (current time)
        let valid_idinfo = IdInfo {
            iss: "https://accounts.google.com".to_string(),
            sub: "123456789".to_string(),
            azp: "test_client".to_string(),
            aud: "test_audience".to_string(),
            email: "test@example.com".to_string(),
            email_verified: true,
            name: "Test User".to_string(),
            picture: None,
            given_name: "Test".to_string(),
            family_name: "User".to_string(),
            locale: None,
            iat: (now - 10) as i64,      // Issued 10 seconds ago
            exp: (now + 3600) as i64,    // Expires in 1 hour
            nbf: Some((now - 5) as i64), // Valid since 5 seconds ago
            jti: None,
            nonce: None,
            hd: None,
            at_hash: None,
        };

        // Test expired token
        let expired_idinfo = IdInfo {
            exp: (now - 10) as i64, // Expired 10 seconds ago
            ..valid_idinfo.clone()
        };

        // Test token not yet valid (nbf in future)
        let nbf_future_idinfo = IdInfo {
            nbf: Some((now + 10) as i64), // Valid 10 seconds from now
            ..valid_idinfo.clone()
        };

        // Test token with iat in future (beyond skew tolerance)
        let iat_future_idinfo = IdInfo {
            iat: (now + 10) as i64, // Issued 10 seconds from now
            ..valid_idinfo.clone()
        };

        // Test token with iat just within skew tolerance
        let iat_skew_ok_idinfo = IdInfo {
            iat: (now + skew) as i64, // Issued exactly at skew boundary
            ..valid_idinfo.clone()
        };

        // Helper function to check time validation logic
        fn check_time_validations(idinfo: &IdInfo) -> Result<(), TokenVerificationError> {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Should get current time for test")
                .as_secs();
            let skew: u64 = 2;

            if let Some(nbf) = idinfo.nbf {
                if now + skew < (nbf as u64) {
                    return Err(TokenVerificationError::TokenNotYetValidNotBeFore(
                        now, nbf as u64,
                    ));
                }
            }

            if now + skew < (idinfo.iat as u64) {
                return Err(TokenVerificationError::TokenNotYetValidIssuedAt(
                    now,
                    idinfo.iat as u64,
                ));
            }

            if now > (idinfo.exp as u64) {
                return Err(TokenVerificationError::TokenExpired);
            }

            Ok(())
        }

        // Test valid token - should pass
        let result = check_time_validations(&valid_idinfo);
        assert!(result.is_ok(), "Valid token should pass time validation");

        // Test expired token - should fail
        let result = check_time_validations(&expired_idinfo);
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::TokenExpired) => {}
            Err(other) => {
                assert!(false, "Expected TokenExpired error, got {:?}", other);
            }
        }

        // Test nbf in future - should fail
        let result = check_time_validations(&nbf_future_idinfo);
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::TokenNotYetValidNotBeFore(_, _)) => {}
            Err(other) => {
                assert!(
                    false,
                    "Expected TokenNotYetValidNotBeFore error, got {:?}",
                    other
                );
            }
        }

        // Test iat in future - should fail
        let result = check_time_validations(&iat_future_idinfo);
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected error but got Ok");
            }
            Err(TokenVerificationError::TokenNotYetValidIssuedAt(_, _)) => {}
            Err(other) => {
                assert!(
                    false,
                    "Expected TokenNotYetValidIssuedAt error, got {:?}",
                    other
                );
            }
        }

        // Test iat within skew tolerance - should pass
        let result = check_time_validations(&iat_skew_ok_idinfo);
        assert!(
            result.is_ok(),
            "Token with iat within skew tolerance should pass"
        );
    }

    #[test]
    fn test_audience_and_issuer_validation() {
        // Helper function to test audience validation logic
        fn check_audience_validation(
            idinfo_aud: &str,
            expected_aud: &str,
        ) -> Result<(), TokenVerificationError> {
            if idinfo_aud != expected_aud {
                return Err(TokenVerificationError::InvalidTokenAudience(
                    expected_aud.to_string(),
                    idinfo_aud.to_string(),
                ));
            }
            Ok(())
        }

        // Helper function to test issuer validation logic
        fn check_issuer_validation(idinfo_iss: &str) -> Result<(), TokenVerificationError> {
            let supplied_issuer = "https://accounts.google.com";
            if idinfo_iss != supplied_issuer {
                return Err(TokenVerificationError::InvalidTokenIssuer(
                    idinfo_iss.to_string(),
                    supplied_issuer.to_string(),
                ));
            }
            Ok(())
        }

        // Test valid audience
        let result = check_audience_validation("test_audience", "test_audience");
        assert!(result.is_ok(), "Matching audience should be valid");

        // Test invalid audience
        let result = check_audience_validation("wrong_audience", "correct_audience");
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected InvalidTokenAudience error but got Ok");
            }
            Err(TokenVerificationError::InvalidTokenAudience(expected, actual)) => {
                assert_eq!(expected, "correct_audience");
                assert_eq!(actual, "wrong_audience");
            }
            Err(other) => {
                assert!(
                    false,
                    "Expected InvalidTokenAudience error, got {:?}",
                    other
                );
            }
        }

        // Test empty audience
        let result = check_audience_validation("", "expected_audience");
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected InvalidTokenAudience error but got Ok");
            }
            Err(TokenVerificationError::InvalidTokenAudience(expected, actual)) => {
                assert_eq!(expected, "expected_audience");
                assert_eq!(actual, "");
            }
            Err(other) => {
                assert!(
                    false,
                    "Expected InvalidTokenAudience error, got {:?}",
                    other
                );
            }
        }

        // Test valid issuer (Google)
        let result = check_issuer_validation("https://accounts.google.com");
        assert!(result.is_ok(), "Google issuer should be valid");

        // Test invalid issuer
        let result = check_issuer_validation("https://evil.com");
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected InvalidTokenIssuer error but got Ok");
            }
            Err(TokenVerificationError::InvalidTokenIssuer(actual, expected)) => {
                assert_eq!(actual, "https://evil.com");
                assert_eq!(expected, "https://accounts.google.com");
            }
            Err(other) => {
                assert!(false, "Expected InvalidTokenIssuer error, got {:?}", other);
            }
        }

        // Test empty issuer
        let result = check_issuer_validation("");
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected InvalidTokenIssuer error but got Ok");
            }
            Err(TokenVerificationError::InvalidTokenIssuer(actual, expected)) => {
                assert_eq!(actual, "");
                assert_eq!(expected, "https://accounts.google.com");
            }
            Err(other) => {
                assert!(false, "Expected InvalidTokenIssuer error, got {:?}", other);
            }
        }

        // Test alternative Google issuer format (should fail)
        let result = check_issuer_validation("accounts.google.com");
        assert!(result.is_err());
        match result {
            Ok(_) => {
                assert!(false, "Expected InvalidTokenIssuer error but got Ok");
            }
            Err(TokenVerificationError::InvalidTokenIssuer(actual, expected)) => {
                assert_eq!(actual, "accounts.google.com");
                assert_eq!(expected, "https://accounts.google.com");
            }
            Err(other) => {
                assert!(false, "Expected InvalidTokenIssuer error, got {:?}", other);
            }
        }
    }
}
