# Database Configuration Guide

This guide explains how to configure database storage for the `oauth2-passkey` authentication system. The library uses a unified storage architecture with two main components:

- **Data Store**: Persistent storage for user accounts, OAuth2 accounts, and passkey credentials
- **Cache Store**: Fast ephemeral storage for sessions, challenges, and temporary data

## Quick Start

Copy the example environment file and configure your storage backends:

```bash
cp dot.env.example .env
# Edit .env with your preferred storage configuration
```

## Storage Architecture

### Data Store (Persistent Storage)

Stores permanent data like user accounts and credentials. Choose one:

**SQLite** (recommended for development/small deployments):

```env
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:./db/sqlite/data/data.db'
```

**PostgreSQL** (recommended for production):

```env
GENERIC_DATA_STORE_TYPE=postgres
GENERIC_DATA_STORE_URL='postgresql://user:password@localhost:5432/database'
```

### Cache Store (Session Storage)

Stores temporary data like sessions and challenges. Choose one:

**Memory** (simple, but sessions lost on restart):

```env
GENERIC_CACHE_STORE_TYPE=memory
GENERIC_CACHE_STORE_URL=''
```

**Redis** (recommended for production/scalability):

```env
GENERIC_CACHE_STORE_TYPE=redis
GENERIC_CACHE_STORE_URL='redis://localhost:6379'
```

## Database Setup Instructions

### SQLite Setup

SQLite databases are created automatically. Ensure the directory exists:

```bash
mkdir -p db/sqlite/data
```

Monitor SQLite database:

```bash
# View user and credential data
echo "SELECT * FROM users; SELECT * FROM oauth2_accounts; SELECT * FROM passkey_credentials;" | sqlite3 db/sqlite/data/data.db
```

### PostgreSQL Setup

Start PostgreSQL using Docker Compose:

```bash
cd db/postgresql
docker compose up -d
docker compose ps
```

This creates a database with:

- Database: `passkey`
- Username: `passkey`
- Password: `passkey`
- Port: `5432`

Monitor PostgreSQL:

```bash
# Connect and view data
psql postgresql://passkey:passkey@localhost:5432/passkey
# Then run: \dt to see tables, SELECT * FROM users; etc.
```

### Redis Setup

Start Redis using Docker Compose:

```bash
cd db/redis
docker compose up -d
docker compose ps
```

Monitor Redis:

```bash
# View all keys and data
redis-cli
# Then run: KEYS *, GET key_name, etc.
```

## Configuration Examples

### Development Configuration

```env
# SQLite + Memory (simple, no external dependencies)
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:./db/sqlite/data/data.db'
GENERIC_CACHE_STORE_TYPE=memory
GENERIC_CACHE_STORE_URL=''
```

### Production Configuration

```env
# PostgreSQL + Redis (scalable, persistent)
GENERIC_DATA_STORE_TYPE=postgres
GENERIC_DATA_STORE_URL='postgresql://user:password@db-host:5432/dbname'
GENERIC_CACHE_STORE_TYPE=redis
GENERIC_CACHE_STORE_URL='redis://redis-host:6379'
```

### Testing Configuration

```env
# In-memory SQLite (fast, isolated tests)
GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL=':memory:'
GENERIC_CACHE_STORE_TYPE=memory
GENERIC_CACHE_STORE_URL=''
```

## Database Schema

The library automatically manages database schemas for:

- **`users`** - User account information
- **`oauth2_accounts`** - OAuth2 account linkages
- **`passkey_credentials`** - WebAuthn/passkey credentials
- **Cache data** - Session tokens, challenges (Redis/memory only)

All tables are prefixed with `o2p_` by default to avoid conflicts.

## Monitoring and Debugging

### SQLite Monitoring

```bash
# Real-time monitoring
watch -n 2 "echo 'SELECT COUNT(*) as users FROM o2p_users; SELECT COUNT(*) as creds FROM o2p_passkey_credentials;' | sqlite3 db/sqlite/data/data.db"
```

### PostgreSQL Monitoring

```bash
# Real-time monitoring
watch -n 2 "echo 'SELECT COUNT(*) as users FROM o2p_users; SELECT COUNT(*) as creds FROM o2p_passkey_credentials;' | psql postgresql://passkey:passkey@localhost:5432/passkey"
```

### Redis Monitoring

```bash
# View session data
redis-cli --scan --pattern "session:*" | head -10
redis-cli --scan --pattern "challenge:*" | head -10
```

## Troubleshooting

**Database Connection Issues:**

- Verify connection URLs are correct
- Ensure database servers are running
- Check firewall/network connectivity
- Review application logs for specific error messages

**Schema Issues:**

- The library automatically creates required tables
- For PostgreSQL, ensure the user has CREATE privileges
- Check database logs for permission or constraint errors

**Performance Issues:**

- Use Redis for cache in production (not memory)
- Use PostgreSQL for data in production (not SQLite)
- Connection pooling is automatically handled by the library

## Security Considerations

- Use strong database passwords
- Restrict database network access
- Use SSL/TLS for database connections in production
- Regularly backup persistent data stores
- Consider encrypting sensitive data at rest
