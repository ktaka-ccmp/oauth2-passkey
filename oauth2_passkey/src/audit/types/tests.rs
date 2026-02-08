use super::*;
use http::HeaderMap;

#[test]
fn from_headers_extracts_x_forwarded_for() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "192.168.1.100".parse().unwrap());
    headers.insert("user-agent", "TestBrowser/1.0".parse().unwrap());

    let context = LoginContext::from_headers(&headers);

    assert_eq!(context.ip_address, Some("192.168.1.100".to_string()));
    assert_eq!(context.user_agent, Some("TestBrowser/1.0".to_string()));
}

#[test]
fn from_headers_takes_first_ip_from_x_forwarded_for() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        "203.0.113.50, 70.41.3.18, 150.172.238.178".parse().unwrap(),
    );

    let context = LoginContext::from_headers(&headers);

    assert_eq!(context.ip_address, Some("203.0.113.50".to_string()));
}

#[test]
fn from_headers_trims_whitespace_in_x_forwarded_for() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        " 203.0.113.50 , 70.41.3.18".parse().unwrap(),
    );

    let context = LoginContext::from_headers(&headers);

    assert_eq!(context.ip_address, Some("203.0.113.50".to_string()));
}

#[test]
fn from_headers_falls_back_to_x_real_ip() {
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", "10.0.0.1".parse().unwrap());

    let context = LoginContext::from_headers(&headers);

    assert_eq!(context.ip_address, Some("10.0.0.1".to_string()));
}

#[test]
fn from_headers_prefers_x_forwarded_for_over_x_real_ip() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "192.168.1.100".parse().unwrap());
    headers.insert("x-real-ip", "10.0.0.1".parse().unwrap());

    let context = LoginContext::from_headers(&headers);

    assert_eq!(context.ip_address, Some("192.168.1.100".to_string()));
}

#[test]
fn from_headers_empty_headers() {
    let headers = HeaderMap::new();

    let context = LoginContext::from_headers(&headers);

    assert_eq!(context.ip_address, None);
    assert_eq!(context.user_agent, None);
}

#[test]
fn from_headers_user_agent_only() {
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", "Mozilla/5.0".parse().unwrap());

    let context = LoginContext::from_headers(&headers);

    assert_eq!(context.ip_address, None);
    assert_eq!(context.user_agent, Some("Mozilla/5.0".to_string()));
}
