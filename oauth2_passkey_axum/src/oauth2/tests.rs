use super::*;
use axum::http::StatusCode;

/// Test the `serve_oauth2_js` function to ensure it returns a valid JavaScript response
///
/// This test checks:
/// 1. The response is Ok
/// 2. The status code is 200 OK
/// 3. The Content-Type header is set to "application/javascript"
///
#[tokio::test]
async fn test_serve_oauth2_js() {
    // Call the function
    let response = serve_oauth2_js().await;

    // Verify the result is Ok
    assert!(response.is_ok());

    if let Ok(response) = response {
        // Verify status code
        assert_eq!(response.status(), StatusCode::OK);

        // Verify content type header
        let headers = response.headers();
        assert_eq!(
            headers
                .get(CONTENT_TYPE)
                .expect("Content-Type header should exist")
                .to_str()
                .expect("Content-Type header should be valid UTF-8"),
            "application/javascript"
        );
    }
}

#[test]
fn css_vars_block_from_returns_none_when_empty() {
    assert_eq!(css_vars_block_from(&[]), None);
}

#[test]
fn css_vars_block_from_emits_root_block_for_single_slot() {
    let block = css_vars_block_from(&[("custom1", "#abcdef", "#123456")])
        .expect("non-empty input must produce a block");
    assert_eq!(
        block,
        ":root {\n    --o2p-custom1: #abcdef;\n    --o2p-custom1-hover: #123456;\n}"
    );
}

#[test]
fn css_vars_block_from_emits_each_entry_for_multiple_slots() {
    let block = css_vars_block_from(&[
        ("custom1", "#111111", "#222222"),
        ("custom4", "tomato", "firebrick"),
    ])
    .expect("non-empty input must produce a block");
    assert_eq!(
        block,
        ":root {\n    --o2p-custom1: #111111;\n    --o2p-custom1-hover: #222222;\n    --o2p-custom4: tomato;\n    --o2p-custom4-hover: firebrick;\n}"
    );
}
