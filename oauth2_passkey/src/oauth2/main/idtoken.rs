use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize, Deserializer, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::oauth2::provider::ProviderConfig;
use crate::storage::{
    CacheData, CacheErrorConversion, CacheKey, CachePrefix, StorageError, get_data, remove_data,
    store_cache_keyed,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Jwk {
    kty: String,
    kid: String,
    /// Optional: some providers (e.g. Entra) omit `alg`; fall back to kty-derived default.
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
    crv: Option<String>,
    k: Option<String>,
}

#[allow(unused)]
#[derive(Debug, Deserialize, Clone)]
pub struct OidcIdInfo {
    pub iss: String,
    pub sub: String,
    /// Google-specific; absent in many other OIDC providers (e.g. Auth0).
    pub azp: Option<String>,
    /// OIDC Core 1.0 §2 allows `aud` to be either a single string or an array
    /// of strings. Normalized to `Vec<String>` for uniform validation.
    #[serde(deserialize_with = "deserialize_aud")]
    pub aud: Vec<String>,
    /// Optional per OIDC Core 1.0; absent for some Microsoft personal accounts.
    pub email: Option<String>,
    /// Some providers omit this claim; treat absence as unverified.
    pub email_verified: Option<bool>,
    /// Optional per OIDC Core 1.0; absent when profile scope not granted.
    pub name: Option<String>,
    pub picture: Option<String>,
    /// Absent in many non-Google OIDC providers.
    pub given_name: Option<String>,
    /// Absent in many non-Google OIDC providers.
    pub family_name: Option<String>,
    pub locale: Option<String>,
    pub iat: i64,
    pub exp: i64,
    pub nbf: Option<i64>,
    pub jti: Option<String>,
    pub nonce: Option<String>,
    pub hd: Option<String>,
    pub at_hash: Option<String>,
    /// Fallback for `email` when the provider omits the standard claim
    /// (e.g. Microsoft personal accounts).
    pub preferred_username: Option<String>,
}

fn deserialize_aud<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{Error, SeqAccess, Visitor};
    use std::fmt;

    struct AudVisitor;

    impl<'de> Visitor<'de> for AudVisitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a string or array of strings")
        }

        fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_string<E: Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(vec![v])
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out: Vec<String> = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            if out.is_empty() {
                return Err(Error::custom("aud array is empty"));
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(AudVisitor)
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
    #[error("OIDC Discovery error: {0}")]
    OidcDiscovery(#[from] crate::oauth2::discovery::OidcDiscoveryError),
    #[error("Storage error: {0}")]
    Storage(String),
}

impl CacheErrorConversion<TokenVerificationError> for TokenVerificationError {
    fn convert_storage_error(error: StorageError) -> TokenVerificationError {
        TokenVerificationError::Storage(error.to_string())
    }
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
    let client = crate::utils::get_client();
    let resp = client.get(jwks_url).send().await?;
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
            .map_err(|e| TokenVerificationError::JwksParsing(format!("{e}")))
    }
}

async fn fetch_jwks_cache(jwks_url: &str) -> Result<Jwks, TokenVerificationError> {
    // Create cache keys once for the entire function with earliest possible conversion
    let cache_prefix = CachePrefix::jwks();
    let cache_key = CacheKey::new(jwks_url.to_string())
        .map_err(TokenVerificationError::convert_storage_error)?;

    // Try to get from cache first
    // Uses cache_operations module to avoid holding MutexGuard across lock boundaries
    if let Some(jwks_cache) =
        get_data::<JwksCache, TokenVerificationError>(cache_prefix.clone(), cache_key.clone())
            .await?
    {
        if jwks_cache.expires_at > Utc::now() {
            tracing::debug!("Returning valid cached JWKs");
            return Ok(jwks_cache.jwks);
        }

        tracing::debug!("Removing expired JWKs from cache");
        remove_data::<TokenVerificationError>(cache_prefix.clone(), cache_key.clone()).await?;
    }

    // If not in cache, fetch from the URL
    let client = crate::utils::get_client();
    let resp = client.get(jwks_url).send().await?;
    let jwks: Jwks = resp.json().await?;
    tracing::debug!("JWKs fetched from URL");

    // Store in cache
    let jwks_cache = JwksCache {
        jwks: jwks.clone(),
        expires_at: Utc::now() + CACHE_EXPIRATION,
    };

    store_cache_keyed::<JwksCache, TokenVerificationError>(
        cache_prefix,
        cache_key,
        jwks_cache,
        CACHE_EXPIRATION.as_secs(),
    )
    .await?;

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
    // When `alg` is absent, infer from `kty` (Entra and some other providers omit `alg`).
    let alg_default = match jwk.kty.as_str() {
        "RSA" => "RS256",
        "EC" => "ES256",
        "oct" => "HS256",
        _ => "",
    };
    let alg = jwk.alg.as_deref().unwrap_or(alg_default);
    match alg {
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

fn decode_token(token: &str) -> Result<OidcIdInfo, TokenVerificationError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenVerificationError::InvalidTokenFormat);
    }
    let payload = parts[1];
    let decoded_payload = decode_base64_url_safe(payload)?;
    let idinfo: OidcIdInfo = serde_json::from_slice(&decoded_payload)?;
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

pub(super) async fn verify_idtoken_with_algorithm(
    ctx: &ProviderConfig,
    token: String,
) -> Result<(OidcIdInfo, Algorithm), TokenVerificationError> {
    let header = jsonwebtoken::decode_header(&token)?;

    let kid = header
        .kid
        .ok_or(TokenVerificationError::MissingKeyComponent(
            "kid".to_string(),
        ))?;
    let alg = header.alg;
    let idinfo: OidcIdInfo = decode_token(&token)?;

    tracing::debug!("Algorithm from JWT header: {:?}", alg);
    tracing::debug!("Decoded id_token payload: {:#?}", idinfo);

    let jwks_url = ctx.jwks_url().await?;
    let jwks = fetch_jwks(&jwks_url).await?;
    let jwk = find_jwk(&jwks, &kid).ok_or(TokenVerificationError::NoMatchingKey)?;

    let decoding_key = convert_jwk_to_decoding_key(jwk)?;

    let signature_valid = verify_signature(&token, &decoding_key, alg)?;
    if !signature_valid {
        return Err(TokenVerificationError::InvalidTokenSignature);
    }

    let audience = &ctx.client_id;
    if !idinfo.aud.iter().any(|a| a == audience) {
        return Err(TokenVerificationError::InvalidTokenAudience(
            audience.clone(),
            idinfo.aud.join(","),
        ));
    }

    let expected_issuer = ctx.expected_issuer().await?;
    if idinfo.iss != expected_issuer {
        return Err(TokenVerificationError::InvalidTokenIssuer(
            idinfo.iss.to_string(),
            expected_issuer,
        ));
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let skew: u64 = 2; // allow 2 seconds of skew

    if let Some(nbf) = idinfo.nbf
        && now + skew < (nbf as u64)
    {
        // tolerate the system clock to be the skew seconds behind
        return Err(TokenVerificationError::TokenNotYetValidNotBeFore(
            now, nbf as u64,
        ));
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
mod tests;
