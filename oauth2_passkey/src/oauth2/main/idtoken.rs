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
            let x = decode_base64_url_safe(
                jwk.x
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("x".to_string()))?,
            )?;
            let x_str = std::str::from_utf8(&x)?;
            let y = decode_base64_url_safe(
                jwk.y
                    .as_ref()
                    .ok_or(TokenVerificationError::MissingKeyComponent("y".to_string()))?,
            )?;
            let y_str = std::str::from_utf8(&y)?;
            Ok(DecodingKey::from_ec_components(x_str, y_str)?)
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
        if now + skew < nbf.try_into().unwrap() {
            // tolerate the system clock to be the skew seconds behind
            return Err(TokenVerificationError::TokenNotYetValidNotBeFore(
                now,
                nbf.try_into().unwrap(),
            ));
        }
    }

    if now + skew < idinfo.iat.try_into().unwrap() {
        // tolerate the system clock to be the skew seconds behind
        return Err(TokenVerificationError::TokenNotYetValidIssuedAt(
            now,
            idinfo.iat.try_into().unwrap(),
        ));
    } else if now > idinfo.exp.try_into().unwrap() {
        return Err(TokenVerificationError::TokenExpired);
    }

    Ok(idinfo)
}
