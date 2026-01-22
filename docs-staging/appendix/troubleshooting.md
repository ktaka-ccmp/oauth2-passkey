# Appendix C: Troubleshooting

This guide covers common issues you may encounter when using oauth2-passkey and how to resolve them.

## Common Errors

### Database Connection Issues

**SQLite Problems**

- **Database errors during startup**
  - The SQLite database will be created automatically on first run
  - Ensure the directory for your SQLite file is writable
  - Check that the path specified by `GENERIC_DATA_STORE_URL` in your `.env` is accessible

- **How to reset the database**
  - Delete the database file (e.g., `auth.db`) to clear all data
  - Use `touch` to recreate the database file if needed
  - Restart the application to reinitialize

**PostgreSQL Problems**

- Verify the PostgreSQL server is running
- Check connection credentials in `GENERIC_DATA_STORE_URL`
- Ensure the database exists and the user has proper permissions

### OAuth2 Errors

**Redirect URI Mismatch**

- Verify the redirect URI in Google Cloud Console matches exactly
- The default redirect URI is `{ORIGIN}/o2p/oauth2/authorized`
- For example: `https://localhost:3443/o2p/oauth2/authorized`

**Invalid Credentials**

- Check your Google OAuth2 credentials in `.env`:
  - `OAUTH2_GOOGLE_CLIENT_ID`
  - `OAUTH2_GOOGLE_CLIENT_SECRET`
- Verify the credentials are from the correct Google Cloud project

**"Invalid origin" Error**

- Ensure `ORIGIN` in `.env` matches the URL you're visiting exactly
- Use `https://localhost:3443` (not `127.0.0.1` or `http://`)
- The scheme (https), hostname, and port must all match

**Google OAuth2 Not Working**

- Check your Google OAuth2 credentials in `.env`
- Verify authorized origins and redirect URIs in [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
- Ensure the OAuth consent screen is properly configured

### Passkey/WebAuthn Errors

**Origin Mismatch**

- Ensure `ORIGIN` in `.env` matches the URL exactly
- Use `https://localhost:3443` (not `127.0.0.1`)
- WebAuthn is strict about origin validation

**"Authenticator not found" Error**

- Ensure your device has biometric capabilities enabled
- Check that platform authenticator (Touch ID, Face ID, Windows Hello) is set up
- Try using a security key if available

**"WebAuthn not supported" Error**

- Ensure you're using a modern browser (Chrome, Firefox, Safari, Edge)
- Update your browser to the latest version
- WebAuthn support varies by browser version

**"HTTPS required" Error**

- WebAuthn requires HTTPS (except for localhost in some browsers)
- Use `https://localhost:3443` (not HTTP)
- Accept self-signed certificate warning when prompted

**WebAuthn/Passkey Not Working**

- Ensure you're using HTTPS (required for WebAuthn)
- Try a different browser if having issues (Chrome has the best support)
- Clear browser data for localhost if needed

### Session Issues

**Cookie Problems**

- Check that cookies are enabled in your browser
- For cross-site scenarios, ensure SameSite cookie settings are correct
- Clear browser cookies and try again

**CSRF Token Issues**

- Do not disable JavaScript (CSRF tokens require JavaScript)
- Ensure the session hasn't expired
- Try logging out and back in

## Debug Tips

### Logs

- Check console output for detailed error messages
- Set `RUST_LOG` environment variable to control log verbosity:
  - Log levels from least to most verbose: `error < warn < info < debug < trace`
  - Example: `RUST_LOG=debug cargo run`

### Database

- **SQLite**: File `auth.db` (or configured path) stores user data and sessions
- **Reset**: Delete the database file and restart to clear all data
- **Location**: Check `GENERIC_DATA_STORE_URL` in your `.env` for the actual path

### Self-Signed Certificates

- Browser will show security warning for self-signed certificates
- Click "Advanced" then "Proceed to localhost (unsafe)" to continue
- This is expected behavior for development with self-signed certs

### Browser-Specific Issues

- **Chrome**: Best WebAuthn support, recommended for development
- **Firefox**: Good support, may need to enable some WebAuthn features
- **Safari**: Works well on macOS/iOS with Touch ID/Face ID
- **Edge**: Similar to Chrome (Chromium-based)

## Development Tips

### Using Cloudflared Tunnel

For public HTTPS access without self-signed certificates:

1. Set up a cloudflared tunnel pointing to `https://localhost:3443`
2. Update `.env`:
   ```bash
   ORIGIN='https://your-tunnel-domain.example.com'
   ```
3. For OAuth2: Update Google OAuth2 redirect URI to:
   `https://your-tunnel-domain.example.com/o2p/oauth2/authorized`

### Environment Configuration

- Always use HTTPS for production and WebAuthn testing
- The `ORIGIN` environment variable must match the URL users access exactly
- Use SQLite and in-memory cache for quick local development
- Use PostgreSQL and Redis for production deployments

### Quick Reset Procedure

1. Stop the application
2. Delete the database file (e.g., `rm auth.db` or `rm /tmp/auth.db`)
3. Restart the application
4. Re-register users and credentials

### Testing Authentication Flows

- Create test users with different authentication methods
- Test both registration and sign-in flows
- Verify session persistence across page reloads
- Test logout functionality clears sessions properly
