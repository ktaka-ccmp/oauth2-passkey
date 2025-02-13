# Database Configuration

The application supports multiple storage backends that can be configured through environment variables. Storage configuration is managed through `.env` file (copy `.env.example` to `.env` and modify as needed).

## Storage Types

### In-Memory Storage

Uses HashMap for temporary storage. Data is lost when the application restarts.

```env
PASSKEY_CHALLENGE_STORE=memory
PASSKEY_CREDENTIAL_STORE=memory
```

### SQLite Storage

Persistent storage using SQLite database.

```env
PASSKEY_CHALLENGE_STORE=sqlite
PASSKEY_CREDENTIAL_STORE=sqlite
PASSKEY_CHALLENGE_SQLITE_URL=sqlite:./db/sqlite/data/data.db
PASSKEY_CREDENTIAL_SQLITE_URL=sqlite:./db/sqlite/data/data.db
```

Prepare database:
```bash
db=sqlite/data/data.db
rm $db && sqlx database create --database-url sqlite:$db
```

Monitor database:
```bash
db=sqlite/data/data.db
watch -n 1 "echo 'select credential_id,counter,user_handle,user_name,user_display_name from credentials;select challenge_id,user_name,user_display_name,timestamp from challenges' | sqlite3 $db"
```

### PostgreSQL Storage

Persistent storage using PostgreSQL database.

```env
PASSKEY_CHALLENGE_STORE=postgres
PASSKEY_CREDENTIAL_STORE=postgres
PASSKEY_CHALLENGE_POSTGRES_URL=postgresql://passkey:passkey@localhost:5432/passkey
PASSKEY_CREDENTIAL_POSTGRES_URL=postgresql://passkey:passkey@localhost:5432/passkey
```

Start PostgreSQL:
```bash
docker compose -f postgresql/docker-compose.yaml up -d
docker compose -f postgresql/docker-compose.yaml ps
```

Monitor database:
```bash
watch -n 1 "echo 'select credential_id,counter,user_handle,user_name,user_display_name from credentials;select challenge_id,user_name,user_display_name,timestamp from challenges'|psql postgresql://passkey:passkey@localhost:5432/passkey"
```

### Redis Storage

Persistent storage using Redis.

```env
PASSKEY_CHALLENGE_STORE=redis
PASSKEY_CREDENTIAL_STORE=redis
PASSKEY_CHALLENGE_REDIS_URL=redis://localhost:6379
PASSKEY_CREDENTIAL_REDIS_URL=redis://localhost:6379
```

Start Redis:
```bash
docker compose -f redis/docker-compose.yaml up -d
docker compose -f redis/docker-compose.yaml ps
```

Monitor database:
```bash
watch -n 1 'redis-cli keys "*" | xargs redis-cli mget'
```

## Implementation Details

- Each storage type implements both `ChallengeStore` and `CredentialStore` traits
- Storage type is selected at runtime based on environment variables
- Default storage is in-memory if no environment variables are set
- Connection status is logged when storage is initialized

The application supports multiple storage backends that can be configured through environment variables.
Copy `.env.example` to `.env` and modify the values according to your needs.

## Environment Variables

- `PASSKEY_CHALLENGE_STORE`: Type of storage for challenges (memory, sqlite, postgres, or redis)
- `PASSKEY_CREDENTIAL_STORE`: Type of storage for credentials (memory, sqlite, postgres, or redis)

Depending on the chosen storage type, additional configuration is required:

### Memory Storage
No additional configuration needed. This is the default if no environment variables are set.

### SQLite Storage
- `PASSKEY_CHALLENGE_SQLITE_URL`: SQLite database URL for challenges
- `PASSKEY_CREDENTIAL_SQLITE_URL`: SQLite database URL for credentials

Default: `sqlite:./db/sqlite/data/data.db`

### PostgreSQL Storage
Required when using PostgreSQL:
- `PASSKEY_CHALLENGE_POSTGRES_URL`: PostgreSQL connection URL for challenges
- `PASSKEY_CREDENTIAL_POSTGRES_URL`: PostgreSQL connection URL for credentials

### Redis Storage
Required when using Redis:
- `PASSKEY_CHALLENGE_REDIS_URL`: Redis connection URL for challenges
- `PASSKEY_CREDENTIAL_REDIS_URL`: Redis connection URL for credentials
