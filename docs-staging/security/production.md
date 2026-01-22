# Security Best Practices Guide for oauth2-passkey

This guide provides best practices for securely implementing authentication in your applications using the `oauth2-passkey` library. Following these guidelines will help ensure your application meets modern security standards.

## General Security Recommendations

### Environment Setup

1. **Use HTTPS in Production**

   Always run your authentication services over HTTPS. The library requires the `ORIGIN` environment variable to use `https://` in production.

   ```rust
   // Example check for ensuring HTTPS
   if cfg!(not(debug_assertions)) && !origin.starts_with("https://") {
       panic!("HTTPS required in production mode");
   }
   ```

2. **Secure Environment Variables**

   Store sensitive environment variables (OAuth2 client secrets, database credentials) securely:

   * Use a secrets manager in production environments
   * Don't commit `.env` files to source control
   * Set appropriate file permissions for production environment files

3. **Database Security**

   * Use parameterized queries (already implemented in the library)
   * Apply principle of least privilege for database users
   * Regularly back up and secure authentication databases

### Session Management

1. **Session Configuration**

   Configure appropriate session timeouts based on your application's security requirements:

   ```
   # Short timeouts for sensitive applications
   SESSION_COOKIE_MAX_AGE=300  # 5 minutes

   # Longer timeouts for general use
   SESSION_COOKIE_MAX_AGE=3600  # 1 hour
   ```

2. **Cookie Security**

   The library already sets secure cookie attributes:

   * `Secure` - Ensures cookies are only sent over HTTPS
   * `HttpOnly` - Prevents JavaScript access to cookies
   * `SameSite=Lax` - Mitigates CSRF attacks
   * `__Host-` prefix - Prevents subdomain cookie manipulation

   These are enabled by default and should not be disabled.

   📖 **For detailed information about `__Host-` cookies, browser compatibility, and localhost development considerations, see [Session Cookies and __Host- Prefix](session-cookies-and-host-prefix.md).**

3. **Session Invalidation**

   Implement proper session cleanup:

   * Always call logout functions when users log out
   * Use the library's automatic session expiration
   * Consider implementing server-side session revocation for sensitive operations

## OAuth2 Security

1. **Provider Configuration**

   * Register your exact redirect URIs with OAuth2 providers
   * Store client secrets securely
   * Verify email addresses when using OAuth2 for registration

2. **State Parameter Validation**

   The library handles this automatically, but be aware that it:

   * Generates cryptographically secure state parameters
   * Validates state parameters on return from providers
   * Uses short-lived state tokens to prevent replay attacks

3. **Scope Management**

   * Request only the minimum required scopes
   * Handle scope changes in your provider's dashboard
   * Clearly inform users which data you're accessing

## Passkey/WebAuthn Security

1. **Authenticator Selection**

   Configure authenticator requirements based on your security needs:

   ```
   # High security (requires biometrics or PIN)
   PASSKEY_USER_VERIFICATION=required

   # More flexible (allows presence-only authenticators)
   PASSKEY_USER_VERIFICATION=preferred
   ```

2. **Relying Party ID**

   * Match your RP ID to your domain name
   * The library automatically derives this from `ORIGIN`
   * For multi-domain support, explicitly set `PASSKEY_RP_ID`

3. **Credential Management**

   * Allow users to manage their passkey credentials
   * Implement recovery flows (e.g., backup passkeys or OAuth2 options)
   * Use the library's functions to list, update, and delete credentials

## CSRF Protection

1. **Cross-Site Request Forgery Mitigation**

   The library implements CSRF protection automatically:

   * Tokens are generated with cryptographically secure randomness
   * Constant-time comparison of tokens prevents timing attacks
   * Per-session unique tokens with secure storage

2. **Implementation in Forms**

   When creating forms, include the CSRF token:

   ```html
   <form method="POST">
     <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
     <!-- form fields -->
     <button type="submit">Submit</button>
   </form>
   ```

3. **Implementation in AJAX Requests**

   For JavaScript requests, set the CSRF header:

   ```javascript
   fetch('/api/endpoint', {
     method: 'POST',
     headers: {
       'X-CSRF-Token': csrfToken,
       'Content-Type': 'application/json'
     },
     body: JSON.stringify(data)
   });
   ```

## Advanced Security Considerations

1. **Rate Limiting**

   Implement rate limiting for authentication endpoints to prevent brute force attacks:

   * Use a proxy server (Nginx, Cloudflare) or middleware for rate limiting
   * Apply stricter limits for authentication attempts than regular API calls
   * Consider progressive delays for repeated failed attempts

2. **Event Logging**

   Log authentication events for security monitoring:

   * Login/logout events
   * Failed authentication attempts
   * Credential changes (registration, deletion)
   * Admin operations

3. **Multi-factor Authentication**

   When higher security is required:

   * Combine OAuth2 and Passkey authentication
   * Use WebAuthn's `userVerification: "required"` (enforced by `PASSKEY_USER_VERIFICATION=required`)
   * Consider additional verification for high-value operations

## Security Audit and Compliance

1. **Regular Testing**

   * Conduct periodic security reviews
   * Test authentication flows in your deployment environment
   * Verify session and token behaviors match expectations

2. **Security Headers**

   Implement additional security headers in your application:

   ```rust
   // Example middleware for adding security headers with Axum
   async fn security_headers(req: Request, next: Next) -> Response {
       let mut response = next.run(req).await;

       let headers = response.headers_mut();
       headers.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000; includeSubDomains"));
       headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
       headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
       // Add CSP header based on your application's needs

       response
   }

   // Use in your Router
   let app = Router::new()
       .route("/", get(handler))
       .layer(from_fn(security_headers));
   ```

   Key headers to implement:
   * Content-Security-Policy (CSP) - Limits which resources can be loaded
   * Strict-Transport-Security (HSTS) - Forces HTTPS connections
   * X-Content-Type-Options: nosniff - Prevents MIME type sniffing
   * X-Frame-Options: DENY - Prevents clickjacking attacks

3. **Rate Limiting**

   Implement rate limiting for authentication endpoints to prevent brute force attacks:

   ```rust
   use std::{sync::Arc, time::{Duration, Instant}, collections::HashMap};
   use tokio::sync::Mutex;

   // Simple in-memory rate limiter
   struct RateLimiter {
       attempts: HashMap<String, Vec<Instant>>,
       window: Duration,
       max_attempts: usize,
   }

   impl RateLimiter {
       fn new(window_seconds: u64, max_attempts: usize) -> Self {
           Self {
               attempts: HashMap::new(),
               window: Duration::from_secs(window_seconds),
               max_attempts,
           }
       }

       fn is_rate_limited(&mut self, key: &str) -> bool {
           let now = Instant::now();
           let attempts = self.attempts.entry(key.to_string()).or_insert_with(Vec::new);

           // Remove old attempts
           attempts.retain(|time| now.duration_since(*time) < self.window);

           // Check if too many attempts
           if attempts.len() >= self.max_attempts {
               return true;
           }

           // Record this attempt
           attempts.push(now);
           false
       }
   }

   // Example middleware for Axum
   async fn rate_limit(
       State(limiter): State<Arc<Mutex<RateLimiter>>>,
       ConnectInfo(addr): ConnectInfo<SocketAddr>,
       req: Request,
       next: Next,
   ) -> Response {
       let key = addr.ip().to_string(); // Or use something from the request

       // Check rate limit
       let is_limited = {
           let mut limiter = limiter.lock().await;
           limiter.is_rate_limited(&key)
       };

       if is_limited {
           return StatusCode::TOO_MANY_REQUESTS.into_response();
       }

       next.run(req).await
   }
   ```

   For production use, consider:
   * Using Redis or another distributed cache for rate limiting in multi-server setups
   * Implementing progressive delays for repeated failures
   * Different limits for different endpoints (stricter for authentication)

4. **Keep Dependencies Updated**

   * Regularly update the `oauth2-passkey` library
   * Monitor security advisories for dependencies
   * Use `cargo audit` to check for vulnerable dependencies

## References

* [OWASP Authentication Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [W3C WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
* [OAuth 2.0 Threat Model and Security Considerations](https://datatracker.ietf.org/doc/html/rfc6819)
* [oauth2-passkey Security Analysis](./security.md)
