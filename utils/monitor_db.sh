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
if [ -z "$GENERIC_DATA_STORE_TYPE" ] || [ -z "$GENERIC_DATA_STORE_URL" ]; then
    echo "ERROR: Required environment variables are not set in .env file."
    echo "Please ensure the following variables are set:"
    echo "  GENERIC_DATA_STORE_TYPE (e.g., postgres, sqlite)"
    echo "  GENERIC_DATA_STORE_URL (e.g., postgresql://passkey:passkey@localhost:5432/passkey)"
    exit 1
fi

# Use environment variables for database connection
case "$GENERIC_DATA_STORE_TYPE" in
    postgres)
        # For PostgreSQL, use -q flag for quiet mode and set formatting options
        DB_STRING="psql -q $GENERIC_DATA_STORE_URL"
        # Use psql options to format output without confirmation messages
        FORMAT_COMMAND=""
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
            echo "ERROR: Cannot monitor in-memory SQLite database"
            exit 1
        fi

        DB_STRING="sqlite3 \"$DB_PATH\""
        echo "SQLite database path: $DB_PATH"

        # Check if database file exists
        if [ ! -f "$DB_PATH" ]; then
            echo "WARNING: SQLite database file does not exist: $DB_PATH"
            echo "The database will be created when the application first runs."
        fi

        # SQLite formatting options
        SQLITE_HEADERS=".headers on"
        SQLITE_MODE=".mode column"
        FORMAT_COMMAND="$SQLITE_HEADERS\n$SQLITE_MODE\n"
        ;;
    *)
        echo "ERROR: Unsupported data store type: $GENERIC_DATA_STORE_TYPE"
        echo "Supported types: postgres, sqlite"
        exit 1
        ;;
esac

# Define queries for each table
QUERY_USERS="SELECT sequence_number,is_admin,id,account,label,created_at FROM o2p_users;"
QUERY_PASSKEY_CREDENTIALS="SELECT user_id,user_name,credential_id,aaguid,created_at,last_used_at FROM o2p_passkey_credentials;"
QUERY_OAUTH2_ACCOUNTS="SELECT user_id,email,id,created_at FROM o2p_oauth2_accounts;"

# Show table counts first
QUERY_COUNTS="SELECT 'Users' as table_name, COUNT(*) as count FROM o2p_users UNION ALL SELECT 'Passkey Credentials', COUNT(*) FROM o2p_passkey_credentials UNION ALL SELECT 'OAuth2 Accounts', COUNT(*) FROM o2p_oauth2_accounts;"

# Combine all queries (can be customized by commenting out lines)
ALL_QUERIES=""
ALL_QUERIES+="$QUERY_COUNTS"
ALL_QUERIES+="$QUERY_USERS"
ALL_QUERIES+="$QUERY_PASSKEY_CREDENTIALS"
ALL_QUERIES+="$QUERY_OAUTH2_ACCOUNTS"

echo ""
echo "Starting database monitor..."
echo "Database type: $GENERIC_DATA_STORE_TYPE"
echo "Press Ctrl+C to stop monitoring"
echo ""

# Run the watch command
watch -n 1 'echo "'"$FORMAT_COMMAND$ALL_QUERIES"'" | '"$DB_STRING"
