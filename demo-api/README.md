# Demo API - Bearer Token Authentication

This demo application demonstrates Bearer token authentication mode for API/mobile clients using passkey authentication.

## Overview

Unlike browser-based demos that use cookie authentication, this API demo:

- Uses `SESSION_AUTH_MODE=bearer` for token-based authentication
- Returns Bearer tokens as JSON responses
- Requires `Authorization: Bearer <token>` header for protected endpoints
- No CSRF protection needed (token itself is proof of possession)

## Setup

1. Copy the example environment file:

```bash
cd demo-api
cp .env.example .env
```

2. Run the demo:

```bash
cargo run
```

The server will start on `http://localhost:3002`.

## API Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| GET | `/health` | No | Health check |
| POST | `/api/passkey/register/start` | No | Start passkey registration |
| POST | `/api/passkey/register/finish` | No | Complete registration, returns Bearer token |
| POST | `/api/passkey/auth/start` | No | Start passkey authentication |
| POST | `/api/passkey/auth/finish` | No | Complete authentication, returns Bearer token |
| GET | `/api/protected` | Yes | Protected resource example |
| GET | `/api/me` | Yes | Get current user info |

## Usage Examples

### Health Check

```bash
curl http://localhost:3002/health
```

Response:
```json
{
  "status": "ok",
  "auth_mode": "bearer"
}
```

### Authentication Flow

#### 1. Start Authentication

```bash
curl -X POST http://localhost:3002/api/passkey/auth/start \
  -H "Content-Type: application/json" \
  -d '{"account": "user@example.com"}'
```

Response contains WebAuthn challenge options.

#### 2. Complete Authentication

After processing the challenge with a WebAuthn authenticator:

```bash
curl -X POST http://localhost:3002/api/passkey/auth/finish \
  -H "Content-Type: application/json" \
  -d '{"id": "...", "rawId": "...", "response": {...}, "type": "public-key"}'
```

Response:
```json
{
  "token": "your-bearer-token-here",
  "token_type": "Bearer",
  "expires_in": 600
}
```

#### 3. Access Protected Resources

```bash
curl http://localhost:3002/api/protected \
  -H "Authorization: Bearer your-bearer-token-here"
```

Response:
```json
{
  "message": "Access granted to protected resource",
  "user_id": "...",
  "account": "API User"
}
```

#### 4. Get Current User

```bash
curl http://localhost:3002/api/me \
  -H "Authorization: Bearer your-bearer-token-here"
```

## Testing Notes

### WebAuthn Requirements

Passkey (WebAuthn) authentication requires:

1. A WebAuthn authenticator (hardware key, platform authenticator, or software authenticator)
2. HTTPS in production (localhost is allowed for development)
3. Proper origin configuration

### For Real Testing

Since WebAuthn requires browser interaction for credential creation:

1. Use the browser-based `demo-passkey` to register credentials first
2. Then use this API demo to authenticate with those credentials

Alternatively, use a WebAuthn testing library or tool that can simulate authenticator responses.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ORIGIN` | - | Application origin (required) |
| `SESSION_AUTH_MODE` | `cookie` | Set to `bearer` for this demo |
| `GENERIC_CACHE_STORE_TYPE` | - | `memory` or `redis` |
| `GENERIC_DATA_STORE_TYPE` | - | `sqlite` or `postgres` |
| `SESSION_COOKIE_MAX_AGE` | `600` | Token expiration in seconds |

## Differences from Cookie Mode

| Aspect | Cookie Mode | Bearer Mode |
|--------|-------------|-------------|
| Token delivery | Set-Cookie header | JSON response body |
| Token storage | Browser cookies | Client-managed |
| Request auth | Automatic (cookies) | Manual (Authorization header) |
| CSRF protection | Required | Not needed |
| Use case | Web browsers | API/Mobile clients |
