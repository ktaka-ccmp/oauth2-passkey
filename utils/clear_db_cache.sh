#!/bin/bash

# Find the project root directory (where .env file is located)
find_project_root() {
    local current_dir="$(pwd)"
    local check_dir="$current_dir"

    # If script is being run from utils directory, go up one level
    if [[ "$(basename "$current_dir")" == "utils" ]]; then
        check_dir="$(dirname "$current_dir")"
    fi

    # Look for .env file in current directory and parent directories
    while [ "$check_dir" != "/" ]; do
        if [ -f "$check_dir/.env" ]; then
            echo "$check_dir"
            return 0
        fi
        check_dir="$(dirname "$check_dir")"
    done

    # If no .env found, assume current directory is project root
    echo "$current_dir"
}

PROJECT_ROOT="$(find_project_root)"
ENV_FILE="$PROJECT_ROOT/.env"

echo "Project root: $PROJECT_ROOT"
echo "Using .env file: $ENV_FILE"

# Load environment variables from .env file
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
    echo "Loaded environment from $ENV_FILE"
else
    echo "WARNING: .env file not found at $ENV_FILE"
    echo "Please ensure you have a .env file in the project root directory."
fi

# Check required environment variables
if [ -z "$GENERIC_DATA_STORE_TYPE" ] || [ -z "$GENERIC_DATA_STORE_URL" ] || [ -z "$GENERIC_CACHE_STORE_TYPE" ]; then
    echo "ERROR: Required environment variables are not set in .env file."
    echo "Please ensure the following variables are set:"
    echo "  GENERIC_DATA_STORE_TYPE (e.g., postgres, sqlite)"
    echo "  GENERIC_DATA_STORE_URL (e.g., postgresql://passkey:passkey@localhost:5432/passkey)"
    echo "  GENERIC_CACHE_STORE_TYPE (e.g., redis, memory)"
    echo "  GENERIC_CACHE_STORE_URL (e.g., redis://localhost:6379) - required for redis"
    exit 1
fi

# Use environment variables for database connection
case "$GENERIC_DATA_STORE_TYPE" in
    postgres)
        DB_STRING="psql $GENERIC_DATA_STORE_URL"
        ;;
    sqlite)
        # Handle SQLite path relative to project root
        DB_PATH="${GENERIC_DATA_STORE_URL#sqlite:}"
        DB_PATH="${DB_PATH#//}"

        # If path is relative, make it relative to project root
        if [[ "$DB_PATH" != /* ]]; then
            DB_PATH="$PROJECT_ROOT/$DB_PATH"
        fi

        # Handle special case for :memory:
        if [ "$DB_PATH" = ":memory:" ]; then
            echo "ERROR: Cannot clear in-memory SQLite database (it's already cleared on restart)"
            exit 1
        fi

        DB_STRING="sqlite3 \"$DB_PATH\""
        echo "SQLite database path: $DB_PATH"

        # Check if database file exists
        if [ ! -f "$DB_PATH" ]; then
            echo "INFO: SQLite database file does not exist: $DB_PATH"
            echo "Nothing to clear."
        fi
        ;;
    *)
        echo "ERROR: Unsupported data store type: $GENERIC_DATA_STORE_TYPE"
        echo "Supported types: postgres, sqlite"
        exit 1
        ;;
esac

# Confirm before clearing
echo ""
echo "WARNING: This will permanently delete all data from the following:"
echo "  - Database type: $GENERIC_DATA_STORE_TYPE"
echo "  - Cache type: $GENERIC_CACHE_STORE_TYPE"
echo ""
echo "Tables to be dropped:"
echo "  - o2p_users"
echo "  - o2p_oauth2_accounts"
echo "  - o2p_passkey_credentials"
echo ""

read -p "Are you sure you want to continue? (yes/no): " confirmation

if [[ "$confirmation" != "yes" ]]; then
    echo "Operation cancelled."
    exit 0
fi

echo ""
echo "Clearing database tables..."

# Clear database tables (only if database file exists for SQLite)
if [[ "$GENERIC_DATA_STORE_TYPE" == "sqlite" && ! -f "$DB_PATH" ]]; then
    echo "SQLite database file does not exist, skipping table drops."
else
    echo "DROP TABLE IF EXISTS o2p_passkey_credentials;" | $DB_STRING
    echo "DROP TABLE IF EXISTS o2p_oauth2_accounts;" | $DB_STRING
    echo "DROP TABLE IF EXISTS o2p_users;" | $DB_STRING
    echo "Database tables cleared."
fi

# Clear cache based on cache store type
case "$GENERIC_CACHE_STORE_TYPE" in
    redis)
        if [ -z "$GENERIC_CACHE_STORE_URL" ]; then
            echo "ERROR: GENERIC_CACHE_STORE_URL is required for Redis cache"
            exit 1
        fi
        echo "Clearing Redis cache..."
        redis-cli -u "$GENERIC_CACHE_STORE_URL" flushall
        echo "Redis cache cleared."
        ;;
    memory)
        echo "Memory cache will be cleared when the application restarts."
        ;;
    *)
        echo "WARNING: Clearing cache for $GENERIC_CACHE_STORE_TYPE is not implemented"
        ;;
esac

echo ""
echo "Database and cache clearing completed successfully."
echo ""
echo "Note: The application will recreate tables automatically when it starts."
