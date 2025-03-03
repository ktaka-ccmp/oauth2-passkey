use chrono::{DateTime, Utc};
use http::header::{HeaderMap, SET_COOKIE};

use crate::errors::OAuth2Error;

pub fn header_set_cookie(
    headers: &mut HeaderMap,
    name: String,
    value: String,
    _expires_at: DateTime<Utc>,
    max_age: i64,
) -> Result<&HeaderMap, OAuth2Error> {
    let cookie =
        format!("{name}={value}; SameSite=Lax; Secure; HttpOnly; Path=/; Max-Age={max_age}");
    println!("Cookie: {:#?}", cookie);
    headers.append(
        SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| OAuth2Error::Cookie("Failed to parse cookie".to_string()))?,
    );
    Ok(headers)
}
